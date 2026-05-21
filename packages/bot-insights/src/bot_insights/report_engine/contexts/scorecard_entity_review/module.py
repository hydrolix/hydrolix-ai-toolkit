"""SCHEMA / REPORT_TYPE / TEMPLATE / NOTE_ID_TO_SLOT / PURPOSE + assemble + prepare + bundle helper."""

from __future__ import annotations

from datetime import datetime, timezone
from collections import Counter
from ... import scorecards as scorecards_mod
from ... import verdicts as verdicts_mod
from ... import volume_impact as vi
from ...humanize import cluster_display
from ...theme import DOMAIN_LABELS

from .findings_view import (
    _actions,
    _build_findings,
    _coverage_detail,
    _triggered_row,
)
from .scoreboard import (
    _compute_dek,
    _score_summary,
    _windows,
)

__all__ = [
    'SCHEMA',
    'REPORT_TYPE',
    'TEMPLATE',
    'NOTE_ID_TO_SLOT',
    'PURPOSE',
    'assemble',
    '_from_brief_bundle',
    'prepare',
]


SCHEMA = "bot_entity_scorecard.v1"


REPORT_TYPE = "scorecard_entity_review"


TEMPLATE = "reports/scorecard_entity_review.html"


NOTE_ID_TO_SLOT = {
    "llm-interpretation": "executive_summary",
    "llm-operational": "operational_interpretation",
}


PURPOSE = {
    "kicker": "Bot & Cache Health Scorecard — entity review",
    "measures": (
        "A health score for one request host on a 0–100 scale. The host "
        "starts at 100 and loses points when mechanical signals — cache-miss "
        "rate, query-string churn, error rate, bot-share movement — cross "
        "thresholds. The current window is compared with the prior "
        "equivalent window."
    ),
    "score_legend": (
        "Higher is healthier (100 = clean); lower = more triggered rules. "
        "Bands: escalate 0–40, monitor 40–70, observe 70–100."
    ),
    "cant_say": (
        "Not a root-cause diagnosis or a malicious-traffic call. "
        "Missing inputs are reported as missing — they are not scored as safe."
    ),
}


def assemble(artifacts: list[dict]) -> dict:
    """Reshape a wrapper's artifact list into a single-entity bundle.

    Accepts both wrapper inputs (``[scorecard, index]``) and the
    scorecard-brief bundle shape (``{scorecards: [...], index: ...}``)
    produced when render.py promotes a singleton scorecard_brief wrapper.
    """
    # Bundle shape from scorecard_brief.assemble() being routed here.
    if isinstance(artifacts, dict) and "scorecards" in artifacts:
        return _from_brief_bundle(artifacts)

    # Raw wrapper artifact list.
    cards = [
        a for a in artifacts if a.get("schema_version") == "bot_entity_scorecard.v1"
    ]
    index = next(
        (a for a in artifacts if a.get("schema_version") == "bot_scorecard_index.v1"),
        None,
    )
    if not cards:
        raise ValueError(
            "scorecard_entity_review wrapper missing bot_entity_scorecard.v1"
        )
    if len(cards) > 1:
        raise ValueError(
            f"scorecard_entity_review expects exactly one scorecard, got {len(cards)}"
        )
    return {
        "schema_version": SCHEMA,
        "scorecard": cards[0],
        "index": index,
    }


def _from_brief_bundle(bundle: dict) -> dict:
    """Convert the scorecard_brief bundle shape into the entity-review shape."""
    cards = bundle.get("scorecards") or []
    if len(cards) != 1:
        raise ValueError(f"entity_review bundle expects 1 scorecard, got {len(cards)}")
    return {
        "schema_version": SCHEMA,
        "scorecard": cards[0],
        "index": bundle.get("index"),
    }


def _partition_rule_results(
    sc: dict,
) -> tuple[list[dict], list[dict], list[dict], Counter]:
    """Return ``(triggered_rows, below_threshold, missing, triggered_by_domain)``."""
    rule_results = scorecards_mod.normalize_rule_results(sc)
    triggered = [r for r in rule_results if r.get("status") == "triggered"]
    below_threshold = [r for r in rule_results if r.get("status") == "evaluated_zero"]
    missing = [r for r in rule_results if r.get("status") == "missing_input"]
    triggered_rows = [_triggered_row(r) for r in triggered]
    triggered_by_domain: Counter = Counter(
        (r.get("domain") or "") for r in triggered
    )
    return triggered_rows, below_threshold, missing, triggered_by_domain


def _resolve_fleet_context(
    index: dict | None, entity: str
) -> tuple[int, object, bool]:
    """Place this entity within a broader fleet review when the wrapper
    carries a multi-host index. Returns
    ``(fleet_total, fleet_rank, is_selected_from_fleet)``."""
    fleet_total = 0
    fleet_rank: object = None
    if index:
        ranked = index.get("ranked_entities") or []
        fleet_total = len(ranked)
        for r in ranked:
            if r.get("entity") == entity:
                fleet_rank = r.get("rank")
                break
    return fleet_total, fleet_rank, fleet_total > 1


def _build_entity_headline(
    cluster_label: str,
    entity: str,
    fleet_total: int,
    fleet_rank: object,
    is_selected_from_fleet: bool,
) -> str:
    if not is_selected_from_fleet:
        return f"{cluster_label} — {entity}"
    rank_clause = (
        f" (ranked {fleet_rank} of {fleet_total})"
        if fleet_rank
        else f" (1 of {fleet_total})"
    )
    return f"{cluster_label} — {entity}{rank_clause}"


def _build_orientation_block() -> dict:
    return {
        "measures": PURPOSE["measures"],
        "score_legend": PURPOSE["score_legend"],
        "cant_say": PURPOSE["cant_say"],
    }


def _build_entity_summary(sc: dict, entity: str, primary_domain: str) -> dict:
    return {
        "entity": entity,
        "score": sc["score"],
        "baseline_score": sc.get("baseline_score"),
        "delta": sc.get("score_delta_points", 0),
        "band": sc["band"],
        "confidence": sc["confidence"],
        "primary_domain": primary_domain,
        "primary_domain_label": DOMAIN_LABELS.get(primary_domain, primary_domain),
        "evidence_summary": sc.get("evidence_summary") or [],
    }


def _build_method_block(artifact: dict, sc: dict, index: dict | None) -> dict:
    idx = index or {}
    return {
        "schema_version": artifact.get("schema_version") or SCHEMA,
        "comparison_type": (
            idx.get("comparison_type") or sc.get("comparison_type")
        ),
        "producer_limit": idx.get("producer_limit"),
        "result_row_count": 1,
        "result_truncated": False,
        "interpretation_constraints": (
            idx.get("interpretation_constraints")
            or sc.get("interpretation_constraints")
            or []
        ),
    }


def prepare(artifact: dict) -> dict:
    """Pure transform from a single-scorecard bundle to template context."""
    sc = artifact.get("scorecard") or artifact
    index = artifact.get("index")
    scope = sc["scope"]
    entity = sc["entity"]
    primary_domain = sc.get("primary_domain") or "none"

    triggered_rows, below_threshold, missing, triggered_by_domain = (
        _partition_rule_results(sc)
    )
    fleet_total, fleet_rank, is_selected_from_fleet = _resolve_fleet_context(
        index, entity
    )
    rule_counts = scorecards_mod.rule_counts(sc)
    entity_metrics = sc.get("entity_metrics") or {}

    return {
        "title": "Bot Scorecard Entity Review",
        "kicker": PURPOSE["kicker"],
        "headline": _build_entity_headline(
            cluster_display(scope["cluster"]), entity,
            fleet_total, fleet_rank, is_selected_from_fleet,
        ),
        "dek": _compute_dek(
            verdicts_mod.classify(sc["band"], rule_counts),
            sc["score"], triggered_rows, missing, entity_metrics,
            is_selected_from_fleet, fleet_total,
        ),
        # Suppress base.html's purpose strip — orientation moves behind a
        # disclosure inside the content block.
        "purpose": None,
        # Orientation block is rendered behind a disclosure now — daily
        # readers don't see it, first-time readers can expand.
        "orientation": _build_orientation_block(),
        "scope": {
            "cluster": scope["cluster"],
            "database": scope["database"],
            "table_used": sc.get("table_used"),
        },
        "windows": _windows(sc, index),
        "entity_summary": _build_entity_summary(sc, entity, primary_domain),
        "verdict": verdicts_mod.classify(sc["band"], rule_counts),
        "confidence_chip": verdicts_mod.confidence_chip(rule_counts),
        "volume_impact": vi.project_entity(entity_metrics),
        "coverage_detail": _coverage_detail(missing),
        "score_summary": _score_summary(sc),
        "rule_counts": rule_counts,
        "deterministic_findings": _build_findings(
            sc["score"], sc.get("score_delta_points", 0),
            triggered_rows, missing, below_threshold, primary_domain,
        ),
        "triggered_rules_data": triggered_rows,
        "triggered_by_domain": [
            {"domain": d, "domain_label": DOMAIN_LABELS.get(d, d), "count": c}
            for d, c in triggered_by_domain.most_common()
        ],
        "actions": _actions(sc),
        "fleet_context": {
            "is_selected_from_fleet": is_selected_from_fleet,
            "fleet_total": fleet_total,
            "fleet_rank": fleet_rank,
        },
        "method": _build_method_block(artifact, sc, index),
        "confidence": {
            "counts": {sc["confidence"]: 1},
            "reasons": sorted(sc.get("confidence_reasons") or []),
        },
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    }
