"""Fleet evidence-packet builder for scorecard brief reports."""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


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

    aggregates = _scorecard_fleet_aggregates(scorecards)
    scored = [sc for sc in scorecards if isinstance(sc.get("score"), (int, float))]
    current_window, baseline_windows = _scorecard_fleet_windows(scorecards)

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
            "band_distribution": aggregates["band_distribution"],
            "confidence_distribution": aggregates["confidence_distribution"],
            "primary_domain_distribution": aggregates["primary_domain_distribution"],
            "missing_input_domains": dict(aggregates["missing_input_domains"]),
        },
        "top_entities": _scorecard_fleet_entities(scored, reverse=True),
        "lowest_entities": _scorecard_fleet_entities(scored, reverse=False),
        "rule_triggers_across_fleet": [
            {"name": name, "host_count": count}
            for name, count in aggregates["rule_trigger_counts"].most_common()
        ],
        "recommended_next_steps": _scorecard_fleet_recommendations(
            aggregates["aggregate_recommended"]
        ),
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
        "interpretation_contract": _scorecard_fleet_interpretation_contract(),
        "template": {"sections": _scorecard_fleet_template_sections()},
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "baseline_start": baseline_start.isoformat().replace("+00:00", "Z"),
    }


def _scorecard_fleet_aggregates(scorecards: list[dict]) -> dict[str, Any]:
    band_distribution: dict[str, int] = {}
    confidence_distribution: dict[str, int] = {}
    primary_domain_distribution: dict[str, int] = {}
    rule_trigger_counts: Counter[str] = Counter()
    missing_input_domains: Counter[str] = Counter()
    aggregate_recommended: dict[str, dict] = {}
    for sc in scorecards:
        _scorecard_increment_distribution(band_distribution, sc.get("band"))
        _scorecard_increment_distribution(
            confidence_distribution, sc.get("confidence")
        )
        _scorecard_increment_distribution(
            primary_domain_distribution, sc.get("primary_domain")
        )
        _scorecard_count_rule_triggers(rule_trigger_counts, sc)
        _scorecard_count_missing_domains(missing_input_domains, sc)
        _scorecard_collect_recommendations(aggregate_recommended, sc)
    return {
        "band_distribution": band_distribution,
        "confidence_distribution": confidence_distribution,
        "primary_domain_distribution": primary_domain_distribution,
        "rule_trigger_counts": rule_trigger_counts,
        "missing_input_domains": missing_input_domains,
        "aggregate_recommended": aggregate_recommended,
    }


def _scorecard_increment_distribution(distribution: dict[str, int], value: object) -> None:
    if value:
        key = str(value)
        distribution[key] = distribution.get(key, 0) + 1


def _scorecard_count_rule_triggers(counts: Counter[str], sc: dict) -> None:
    for rule in sc.get("rule_results") or []:
        if isinstance(rule, dict) and rule.get("status") == "triggered":
            name = rule.get("name")
            if name:
                counts[name] += 1


def _scorecard_count_missing_domains(counts: Counter[str], sc: dict) -> None:
    for feature in sc.get("not_evaluated_features") or []:
        if isinstance(feature, dict):
            domain = feature.get("domain")
            if domain:
                counts[domain] += 1


def _scorecard_collect_recommendations(
    aggregate_recommended: dict[str, dict], sc: dict
) -> None:
    for step in sc.get("recommended_next_steps") or []:
        detail = _scorecard_recommendation_detail(step)
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


def _scorecard_recommendation_detail(step: object) -> str:
    if isinstance(step, dict):
        detail = step.get("detail") or step.get("summary") or ""
    else:
        detail = str(step)
    return detail.strip()


def _scorecard_fleet_entities(scored: list[dict], *, reverse: bool) -> list[dict]:
    return [
        {
            "entity_type": sc.get("entity_type"),
            "entity": sc.get("entity"),
            "score": sc.get("score"),
            "band": sc.get("band"),
            "primary_domain": sc.get("primary_domain"),
            "confidence": sc.get("confidence"),
        }
        for sc in sorted(
            scored,
            key=lambda s: float(s.get("score") or 0),
            reverse=reverse,
        )[:5]
    ]


def _scorecard_fleet_recommendations(
    aggregate_recommended: dict[str, dict],
) -> list[dict]:
    return sorted(
        (
            {
                "detail": entry["detail"],
                "host_count": entry["host_count"],
                "hosts": entry["hosts"][:5],
            }
            for entry in aggregate_recommended.values()
        ),
        key=lambda e: (-e["host_count"], e["detail"]),
    )


def _scorecard_fleet_windows(scorecards: list[dict]) -> tuple[object, object]:
    current_window = None
    baseline_windows = None
    if scorecards:
        current_window = scorecards[0].get("current_window")
        baseline_windows = scorecards[0].get("baseline_windows")
    return current_window, baseline_windows


def _scorecard_fleet_interpretation_contract() -> dict:
    return {
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


def _scorecard_fleet_template_sections() -> list[str]:
    return [
        "Scorecard Interpretation",
        "Fleet Summary",
        "Rule Triggers Across Fleet",
        "Top and Lowest Entities",
        "Recommended Next Steps",
        "Method and Caveats",
    ]
