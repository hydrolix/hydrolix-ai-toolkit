"""Evidence-packet builders for the scorecard-family reports.

Serves all four scorecard report types — ``scorecard_brief``,
``soc_triage``, ``crawler_governance``, ``edge_ops_impact`` — plus
the ``--fleet`` variant used by ``scorecard_brief`` for multi-entity
renders. The per-report interpretation_contract + template-sections
are kept as module-level constants so the report-type branches in
``build_scorecard_evidence_packet`` are flat lookups.
"""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


def selected_rank(index: dict, card: dict) -> int | None:
    for row in index.get("ranked_entities", []):
        if (
            isinstance(row, dict)
            and row.get("entity_type") == card.get("entity_type")
            and row.get("entity") == card.get("entity")
        ):
            rank = row.get("rank")
            return (
                int(rank)
                if isinstance(rank, int) and not isinstance(rank, bool)
                else None
            )
    return None


def select_scorecard(
    artifacts: dict,
    *,
    entity_type: str | None = None,
    entity_value: str | None = None,
) -> dict:
    scorecards = artifacts.get("scorecards")
    if not isinstance(scorecards, list) or not scorecards:
        raise SystemExit("Scorecard artifacts did not contain any emitted scorecards.")

    if entity_type or entity_value:
        if not entity_type or entity_value is None:
            raise SystemExit(
                "--entity-type and --entity-value must be supplied together."
            )
        for card in scorecards:
            if (
                isinstance(card, dict)
                and card.get("entity_type") == entity_type
                and str(card.get("entity")) == entity_value
            ):
                return card
        raise SystemExit(f"No scorecard found for {entity_type}={entity_value}.")

    index = artifacts.get("index")
    ranked = index.get("ranked_entities") if isinstance(index, dict) else None
    if isinstance(ranked, list) and ranked:
        top = ranked[0]
        if isinstance(top, dict):
            for card in scorecards:
                if (
                    isinstance(card, dict)
                    and card.get("entity_type") == top.get("entity_type")
                    and card.get("entity") == top.get("entity")
                ):
                    return card
    return scorecards[0]


SOC_INTERPRETATION_CONTRACT: dict[str, list[str]] = {
    "allowed": [
        "Summarize the SIEM-active SOC scorecard rows and emitted security_evidence features.",
        "Use score, band, confidence, blocked-request and auth-failure volumes, and recommended next steps.",
        "Describe SOC rowset limits and missing security inputs explicitly.",
    ],
    "forbidden": [
        "Do not call traffic malicious without additional artifacts.",
        "Do not invent SIEM metrics or other security evidence inputs.",
        "Do not query Hydrolix from the interpretation step.",
        "Do not emit final HTML or Markdown layout.",
    ],
}

SOC_TEMPLATE_SECTIONS = [
    "SOC Triage Summary",
    "Top Risky Entities",
    "Selected Entity",
    "Domain Scores",
    "Evaluated Security Evidence",
    "Missing Security Inputs",
    "Recommended Next Steps",
    "Method and Caveats",
]


CRAWLER_INTERPRETATION_CONTRACT: dict[str, list[str]] = {
    "allowed": [
        "Summarize the emitted crawler_governance scorecard features and rowset population.",
        "Use score, band, confidence, missing inputs, and recommended next steps.",
        "Describe rowset-limit caveats and missing crawler inputs explicitly.",
    ],
    "forbidden": [
        "Do not claim malicious crawler intent without additional artifacts.",
        "Do not invent missing feature inputs.",
        "Do not query Hydrolix from the interpretation step.",
        "Do not emit final HTML or Markdown layout.",
    ],
}

CRAWLER_TEMPLATE_SECTIONS = [
    "Crawler Governance Summary",
    "Top Crawler Entities",
    "Selected Entity",
    "Domain Scores",
    "Evaluated Crawler Evidence",
    "Missing Crawler Inputs",
    "Recommended Next Steps",
    "Method and Caveats",
]


EDGE_OPS_INTERPRETATION_CONTRACT: dict[str, list[str]] = {
    "allowed": [
        "Summarize the emitted edge_ops_impact scorecard features and entity population.",
        "Use score, band, confidence, missing inputs, and recommended next steps.",
        "Describe origin cost contribution and cache miss movement using only the emitted evidence.",
        "Describe rowset-limit caveats and missing edge/ops inputs explicitly.",
    ],
    "forbidden": [
        "Do not claim origin billing cost without real byte-level evidence.",
        "Do not invent missing feature inputs.",
        "Do not query Hydrolix from the interpretation step.",
        "Do not emit final HTML or Markdown layout.",
    ],
}

EDGE_OPS_TEMPLATE_SECTIONS = [
    "Edge & Origin Cost Summary",
    "Top Entities by Origin Pressure",
    "Selected Entity",
    "Domain Scores",
    "Evaluated Edge/Ops Evidence",
    "Top Cache-Impacting Paths",
    "Missing Edge/Ops Inputs",
    "Recommended Next Steps",
    "Method and Caveats",
]


def build_scorecard_fleet_evidence_packet(
    *,
    args: argparse.Namespace,
    artifacts: dict,
    raw_path: Path,
    artifact_path: Path,
    granularity: str,
    table_used: str,
    baseline_start: datetime,
) -> dict:
    """Fleet-shaped evidence packet for ``--fleet scorecard_brief``.

    The single-entity packet shape (``selected_entity`` +
    ``evaluated_feature_evidence``) anchors the LLM on one host's
    rules, which is exactly the wrong framing when the render is
    going to be a multi-entity ``scorecard_brief``. This builder
    swaps that section for fleet aggregates: band distribution, rule
    trigger counts across hosts, top-N entities by score, aggregate
    missing-input domains. The shape stays under the same
    ``bot_report_evidence.v1`` schema_version because the additions
    are additive — consumers that read only the universal fields
    (scope, query_context, interpretation_contract, rowset_context)
    keep working.
    """

    index = artifacts.get("index") if isinstance(artifacts.get("index"), dict) else {}
    scorecards = [
        sc for sc in (artifacts.get("scorecards") or []) if isinstance(sc, dict)
    ]
    # Fail closed here too, not just in the render path. The
    # documented two-pass skill flow starts with ``--mode evidence``;
    # an empty-fleet packet would silently feed the LLM an aggregate
    # block full of zeros and an empty rule-trigger list, which would
    # encourage prose like "no rules triggered across the fleet" when
    # the real condition is "this cluster has nothing to render". Make
    # the failure mode the same as the render path's.
    if not scorecards:
        raise SystemExit(
            "Scorecard artifacts did not contain any emitted "
            "scorecards; --fleet has nothing to summarize."
        )
    n_total = len(scorecards)

    band_distribution: dict[str, int] = {}
    confidence_distribution: dict[str, int] = {}
    primary_domain_distribution: dict[str, int] = {}
    rule_trigger_counts: Counter[str] = Counter()
    missing_input_domains: Counter[str] = Counter()
    aggregate_recommended: dict[str, dict] = {}
    for sc in scorecards:
        band = sc.get("band")
        if band:
            band_distribution[band] = band_distribution.get(band, 0) + 1
        confidence = sc.get("confidence")
        if confidence:
            confidence_distribution[confidence] = (
                confidence_distribution.get(confidence, 0) + 1
            )
        primary = sc.get("primary_domain")
        if primary:
            primary_domain_distribution[primary] = (
                primary_domain_distribution.get(primary, 0) + 1
            )
        for rule in sc.get("rule_results") or []:
            if isinstance(rule, dict) and rule.get("status") == "triggered":
                name = rule.get("name")
                if name:
                    rule_trigger_counts[name] += 1
        for feature in sc.get("not_evaluated_features") or []:
            if isinstance(feature, dict):
                domain = feature.get("domain")
                if domain:
                    missing_input_domains[domain] += 1
        for step in sc.get("recommended_next_steps") or []:
            if isinstance(step, dict):
                detail = step.get("detail") or step.get("summary") or ""
            else:
                detail = str(step)
            detail = detail.strip()
            if not detail:
                continue
            entry = aggregate_recommended.setdefault(
                detail,
                {"detail": detail, "host_count": 0, "hosts": []},
            )
            entry["host_count"] += 1
            entity = sc.get("entity")
            if entity and entity not in entry["hosts"]:
                entry["hosts"].append(str(entity))

    scored = [sc for sc in scorecards if isinstance(sc.get("score"), (int, float))]
    top_entities = [
        {
            "entity_type": sc.get("entity_type"),
            "entity": sc.get("entity"),
            "score": sc.get("score"),
            "band": sc.get("band"),
            "primary_domain": sc.get("primary_domain"),
            "confidence": sc.get("confidence"),
        }
        for sc in sorted(scored, key=lambda s: -float(s.get("score") or 0))[:5]
    ]
    lowest_entities = [
        {
            "entity_type": sc.get("entity_type"),
            "entity": sc.get("entity"),
            "score": sc.get("score"),
            "band": sc.get("band"),
            "primary_domain": sc.get("primary_domain"),
            "confidence": sc.get("confidence"),
        }
        for sc in sorted(scored, key=lambda s: float(s.get("score") or 0))[:5]
    ]

    rule_triggers = [
        {"name": name, "host_count": count}
        for name, count in rule_trigger_counts.most_common()
    ]

    recommended_next_steps = sorted(
        ({
            "detail": entry["detail"],
            "host_count": entry["host_count"],
            "hosts": entry["hosts"][:5],
        } for entry in aggregate_recommended.values()),
        key=lambda e: (-e["host_count"], e["detail"]),
    )

    current_window = None
    baseline_windows = None
    if scorecards:
        current_window = scorecards[0].get("current_window")
        baseline_windows = scorecards[0].get("baseline_windows")

    interpretation_contract = {
        "allowed": [
            "Summarize fleet aggregates: band distribution, rule trigger counts, top and lowest scoring entities.",
            "Use the rule_triggers_across_fleet counts and the top_entities / lowest_entities lists to describe the shape of the fleet's risk.",
            "Describe rowset_context.total_ranked_entities, result_truncated, and producer_limit as caveats when relevant.",
        ],
        "forbidden": [
            "Do not single out an individual entity's evidence as if it were the whole fleet.",
            "Do not invent rule names, band labels, or hosts not present in this packet.",
            "Do not query Hydrolix from the interpretation step.",
            "Do not claim root cause or malicious intent from scorecard rules alone.",
            "Do not emit final HTML or Markdown layout.",
        ],
    }
    template_sections = [
        "Scorecard Interpretation",
        "Fleet Summary",
        "Rule Triggers Across Fleet",
        "Top and Lowest Entities",
        "Recommended Next Steps",
        "Method and Caveats",
    ]

    return {
        "schema_version": "bot_report_evidence.v1",
        "report_type": args.report,
        "title": args.title or "Bot Insights Scorecard Brief — Fleet",
        "scope": {"cluster": args.cluster, "database": args.database},
        "query_context": {
            "cluster": args.cluster,
            "database": args.database,
            "table_used": table_used,
            "granularity": granularity,
            "raw_artifact_path": str(raw_path),
            "deterministic_artifact_path": str(artifact_path),
            "producer_limit": args.scorecard_limit,
            "entity_selection": "fleet",
        },
        "fleet_summary": {
            "n_ranked_entities": n_total,
            "band_distribution": band_distribution,
            "confidence_distribution": confidence_distribution,
            "primary_domain_distribution": primary_domain_distribution,
            "missing_input_domains": dict(missing_input_domains),
        },
        "top_entities": top_entities,
        "lowest_entities": lowest_entities,
        "rule_triggers_across_fleet": rule_triggers,
        "recommended_next_steps": recommended_next_steps,
        "rowset_context": {
            "producer_limit": artifacts.get("producer_limit")
            or index.get("producer_limit"),
            "result_row_count": artifacts.get("result_row_count")
            or index.get("result_row_count"),
            "result_truncated": artifacts.get("result_truncated")
            or index.get("result_truncated"),
            "total_ranked_entities": artifacts.get("total_ranked_entities")
            or index.get("total_ranked_entities"),
        },
        "current_window": current_window,
        "baseline_windows": baseline_windows,
        "analysis_domains": (
            (scorecards[0].get("analysis_domains") if scorecards else None)
            or index.get("analysis_domains")
        ),
        "interpretation_contract": interpretation_contract,
        "template": {"sections": template_sections},
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "baseline_start": baseline_start.isoformat().replace("+00:00", "Z"),
    }


def build_scorecard_evidence_packet(
    *,
    args: argparse.Namespace,
    artifacts: dict,
    selected_card: dict,
    raw_path: Path,
    artifact_path: Path,
    granularity: str,
    table_used: str,
    baseline_start: datetime,
) -> dict:
    index = artifacts.get("index") if isinstance(artifacts.get("index"), dict) else {}
    if args.report == "soc_triage":
        default_title = "Bot Insights SOC Triage"
        interpretation_contract = SOC_INTERPRETATION_CONTRACT
        template_sections = SOC_TEMPLATE_SECTIONS
    elif args.report == "crawler_governance":
        default_title = "Bot Insights Crawler Governance"
        interpretation_contract = CRAWLER_INTERPRETATION_CONTRACT
        template_sections = CRAWLER_TEMPLATE_SECTIONS
    elif args.report == "edge_ops_impact":
        default_title = "Bot Insights Edge & Origin Cost"
        interpretation_contract = EDGE_OPS_INTERPRETATION_CONTRACT
        template_sections = EDGE_OPS_TEMPLATE_SECTIONS
    else:
        default_title = "Bot Insights Scorecard Brief"
        interpretation_contract = {
            "allowed": [
                "Summarize only the selected scorecard entity and emitted feature evidence.",
                "Use score, band, confidence, domain scores, missing inputs, and recommended next steps.",
                "Describe rowset limits and provenance caveats when present.",
            ],
            "forbidden": [
                "Do not invent metrics or missing scorecard inputs.",
                "Do not query Hydrolix from the interpretation step.",
                "Do not claim root cause or malicious intent from scorecard rules alone.",
                "Do not emit final HTML or Markdown layout.",
            ],
        }
        template_sections = [
            "Scorecard Interpretation",
            "Selected Entity",
            "Domain Scores",
            "Evaluated Feature Evidence",
            "Missing Scorecard Inputs",
            "Recommended Next Steps",
            "Method and Caveats",
        ]
    return {
        "schema_version": "bot_report_evidence.v1",
        "report_type": args.report,
        "title": args.title or default_title,
        "scope": {"cluster": args.cluster, "database": args.database},
        "query_context": {
            "cluster": args.cluster,
            "database": args.database,
            "table_used": table_used,
            "granularity": granularity,
            "raw_artifact_path": str(raw_path),
            "deterministic_artifact_path": str(artifact_path),
            "producer_limit": args.scorecard_limit,
            "entity_selection": "explicit" if args.entity_value else "top_ranked",
        },
        "selected_entity": {
            "entity_type": selected_card.get("entity_type"),
            "entity": selected_card.get("entity"),
            "rank": selected_rank(index, selected_card),
            "score": selected_card.get("score"),
            "band": selected_card.get("band"),
            "primary_domain": selected_card.get("primary_domain"),
            "confidence": selected_card.get("confidence"),
            "confidence_reasons": selected_card.get("confidence_reasons", []),
        },
        "domain_scores": selected_card.get("domain_scores", {}),
        "rule_results": selected_card.get("rule_results", []),
        "evaluated_feature_evidence": selected_card.get("features", []),
        "not_evaluated_features": selected_card.get("not_evaluated_features", []),
        "missing_inputs": sorted(
            {
                str(missing_input)
                for feature in selected_card.get("not_evaluated_features", [])
                if isinstance(feature, dict)
                for missing_input in feature.get("missing_inputs", [])
            }
        ),
        "recommended_next_steps": selected_card.get("recommended_next_steps", []),
        "evidence_summary": selected_card.get("evidence_summary", []),
        "rowset_context": {
            "rowset_scope": selected_card.get("rowset_scope"),
            "feature_provenance": selected_card.get("feature_provenance"),
            "producer_limit": artifacts.get("producer_limit")
            or index.get("producer_limit"),
            "result_row_count": artifacts.get("result_row_count")
            or index.get("result_row_count"),
            "result_truncated": artifacts.get("result_truncated")
            or index.get("result_truncated"),
            "total_ranked_entities": artifacts.get("total_ranked_entities")
            or index.get("total_ranked_entities"),
        },
        "current_window": selected_card.get("current_window"),
        "baseline_windows": selected_card.get("baseline_windows"),
        "analysis_domains": selected_card.get("analysis_domains")
        or index.get("analysis_domains"),
        "interpretation_contract": interpretation_contract,
        "template": {"sections": template_sections},
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "baseline_start": baseline_start.isoformat().replace("+00:00", "Z"),
    }
