"""SCHEMA / REPORT_TYPE / TEMPLATE / NOTE_ID_TO_SLOT / PURPOSE + assemble + prepare."""

from __future__ import annotations

from datetime import datetime, timezone
from collections import Counter
from statistics import median
from ... import scorecards as scorecards_mod
from ... import verdicts as verdicts_mod
from ... import volume_impact as vi
from ...findings import build_scorecard_brief_findings
from ...humanize import cluster_display

from .coverage_view import (
    _aggregate_actions,
    _aggregate_coverage,
    _coverage_rows,
    _rule_counts,
)
from .entity_groups import _group_entities
from .fleet_view import (
    _fleet_coverage_detail,
    _shared_signal,
)
from .queue_view import (
    _entity_row,
    _lowest_delta_pct,
    _lowest_host_callout,
    _queue_rows,
)
from .verdict_strip import (
    _actionable_summary,
    _compute_dek,
    _triage_strip,
)

__all__ = [
    'SCHEMA',
    'REPORT_TYPE',
    'TEMPLATE',
    'NOTE_ID_TO_SLOT',
    'PURPOSE',
    'assemble',
    'prepare',
]


SCHEMA = "bot_scorecard_artifacts.v1"


REPORT_TYPE = "scorecard_brief"


TEMPLATE = "reports/scorecard_brief.html"


NOTE_ID_TO_SLOT = {
    "llm-interpretation": "executive_summary",
    "llm-operational": "operational_interpretation",
    "llm-finding-overrides": "finding_overrides",
}


PURPOSE = {
    "report_class_fleet": "Bot & Cache Health Scorecard — fleet review",
    "report_class_single": "Bot & Cache Health Scorecard — entity review",
    "measures": (
        "A health score for each request host on a 0–100 scale. Every host "
        "starts at 100 and loses points when mechanical signals — cache-miss "
        "rate, query-string churn, error rate, bot-share movement — cross "
        "thresholds. This window's scores are compared with the prior "
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
    """Reassemble a `bot_report_input.v1` wrapper's artifacts into the dict
    shape `prepare()` expects.

    The wrapper sends `[<bot_entity_scorecard.v1>, <bot_scorecard_index.v1>]`
    as separate list entries. Raw artifacts (`bot_scorecard_artifacts.v1`)
    instead bundle them as `{"index": ..., "scorecards": [...]}`. We unify on
    the bundled shape since `prepare()` was written against it.
    """
    cards = [
        a for a in artifacts if a.get("schema_version") == "bot_entity_scorecard.v1"
    ]
    index = next(
        (a for a in artifacts if a.get("schema_version") == "bot_scorecard_index.v1"),
        None,
    )
    if not cards:
        raise ValueError(
            "scorecard_brief wrapper missing bot_entity_scorecard.v1 artifacts"
        )
    if index is None:
        raise ValueError(
            "scorecard_brief wrapper missing bot_scorecard_index.v1 artifact"
        )
    return {
        "schema_version": SCHEMA,
        "scorecards": cards,
        "index": index,
        # Mirror the producer fields prepare() reads from raw artifacts.
        "producer_limit": index.get("producer_limit"),
        "result_row_count": len(cards),
        "result_truncated": False,
        "total_ranked_entities": len(index.get("ranked_entities", [])),
    }


def _count_with_triggers(scorecards: list[dict]) -> int:
    return sum(
        1 for sc in scorecards
        if any(
            r.get("status") == "triggered"
            for r in scorecards_mod.normalize_rule_results(sc)
        )
    )


def _compute_band_counts(scorecards: list[dict]) -> Counter:
    band_counts = Counter(sc["band"] for sc in scorecards)
    for b in ("escalate", "monitor", "observe"):
        band_counts.setdefault(b, 0)
    return band_counts


def _confidence_reasons_set(scorecards: list[dict]) -> set[str]:
    reasons: set[str] = set()
    for sc in scorecards:
        reasons.update(sc.get("confidence_reasons") or [])
    return reasons


def _annotate_entity_verdict(e: dict, verdict: dict | None) -> None:
    e["verdict"] = verdict
    e["verdict_state"] = verdict["state"] if verdict else "watch"
    e["verdict_label"] = verdict["label"] if verdict else "Watch"
    e["verdict_tone"] = verdict["tone"] if verdict else "monitor"


def _build_ranked_entities(
    scorecards: list[dict], ranked_entities: list[dict]
) -> tuple[list[dict], dict[str, dict]]:
    """Build (entities, verdicts_by_entity) with per-row verdict annotations."""
    rank_lookup = {e["entity"]: e["rank"] for e in ranked_entities}
    ranked = sorted(scorecards, key=lambda s: rank_lookup.get(s["entity"], 999))
    entities = [_entity_row(sc, rank_lookup) for sc in ranked]
    verdicts_by_entity: dict[str, dict] = {
        sc["entity"]: verdicts_mod.classify(sc["band"], _rule_counts(sc))
        for sc in scorecards
    }
    for e in entities:
        _annotate_entity_verdict(e, verdicts_by_entity.get(e["entity"]))
    return entities, verdicts_by_entity


def _build_headline(
    *,
    is_single: bool,
    is_selected_from_fleet: bool,
    cluster_label: str,
    scorecards: list[dict],
    n_total: int,
    fleet_total: int,
) -> tuple[str, str]:
    """Return ``(kicker, headline)``."""
    if not is_single:
        return (
            PURPOSE["report_class_fleet"],
            f"{cluster_label} — {n_total} request hosts reviewed",
        )
    if is_selected_from_fleet:
        return (
            PURPOSE["report_class_single"],
            f"{cluster_label} — {scorecards[0]['entity']} (1 of {fleet_total} hosts)",
        )
    return (
        PURPOSE["report_class_single"],
        f"{cluster_label} — {scorecards[0]['entity']}",
    )


def _build_score_summary(
    scorecards: list[dict], scores: list[int], band_counts: Counter
) -> dict:
    score_dist = Counter(scores)
    return {
        "lowest": min(scores),
        "median": int(median(scores)),
        "highest": max(scores),
        "distribution": sorted(score_dist.items()),
        "bands": dict(band_counts),
        "lowest_delta_pct": _lowest_delta_pct(scorecards),
        "scores": scores,
    }


def _build_kpis_block(
    n_total: int, n_with_triggers: int, n_clean: int,
    n_moved: int, band_counts: Counter,
) -> dict:
    return {
        "n_total": n_total,
        "n_with_triggers": n_with_triggers,
        "n_clean": n_clean,
        "n_moved": n_moved,
        "bands": dict(band_counts),
    }


def _build_method_block(artifact: dict, index: dict) -> dict:
    return {
        "schema_version": artifact.get("schema_version"),
        "comparison_type": index.get("comparison_type"),
        "producer_limit": index.get("producer_limit"),
        "result_row_count": artifact.get("result_row_count"),
        "result_truncated": artifact.get("result_truncated"),
        "interpretation_constraints": index.get("interpretation_constraints") or [],
    }


def _build_orientation_block() -> dict:
    return {
        "measures": PURPOSE["measures"],
        "score_legend": PURPOSE["score_legend"],
        "cant_say": PURPOSE["cant_say"],
    }


def prepare(artifact: dict) -> dict:
    index = artifact["index"]
    scorecards = artifact["scorecards"]
    scope = scorecards[0]["scope"]
    table_used = scorecards[0]["table_used"]

    n_total = len(scorecards)
    n_with_triggers = _count_with_triggers(scorecards)
    n_clean = n_total - n_with_triggers
    n_moved = sum(1 for sc in scorecards if sc.get("score_delta_points", 0) != 0)
    band_counts = _compute_band_counts(scorecards)
    domain_counts = Counter(sc["primary_domain"] for sc in scorecards)

    coverage = _aggregate_coverage(scorecards)
    actions = _aggregate_actions(scorecards)
    scores = [sc["score"] for sc in scorecards]

    base_findings = build_scorecard_brief_findings(
        scorecards, n_total, n_with_triggers, n_clean, n_moved,
        domain_counts, coverage,
    )

    entities, verdicts_by_entity = _build_ranked_entities(
        scorecards, index["ranked_entities"]
    )
    triage_strip = _triage_strip(verdicts_by_entity, n_total)
    shared_signal = _shared_signal(scorecards, n_total)
    # Synthesize the actionable summary AFTER triage/shared-signal/actions
    # are computed, then prepend so the executive_summary macro lifts it as
    # the lead paragraph.
    actionable = _actionable_summary(
        triage_strip, shared_signal, actions, n_total, coverage,
    )
    findings = [actionable, *base_findings]

    queue_rows = _queue_rows(entities)
    is_single = n_total == 1
    fleet_total = artifact.get("total_ranked_entities") or len(
        index.get("ranked_entities") or []
    )
    # When the wrapper carries a single selected scorecard but the index
    # describes a larger fleet, frame the report as "1 of N" so the reader
    # knows this is a selected entity, not the whole fleet.
    is_selected_from_fleet = is_single and fleet_total > 1
    cluster_label = cluster_display(scope["cluster"])
    kicker, headline = _build_headline(
        is_single=is_single, is_selected_from_fleet=is_selected_from_fleet,
        cluster_label=cluster_label, scorecards=scorecards,
        n_total=n_total, fleet_total=fleet_total,
    )

    return {
        "title": "Bot Scorecard Brief",
        "kicker": kicker,
        "headline": headline,
        "dek": _compute_dek(
            n_total, n_with_triggers, n_moved, is_single,
            lowest=min(scores),
            fleet_total=fleet_total if is_selected_from_fleet else None,
        ),
        # Suppress base.html's above-the-fold purpose strip; orientation moves
        # behind a disclosure inside content. Same pattern as entity-review.
        "purpose": None,
        "orientation": _build_orientation_block(),
        "scope": {
            "cluster": scope["cluster"],
            "database": scope["database"],
            "table_used": table_used,
        },
        "windows": {
            "current": index["current_window"],
            "baseline": index["baseline_windows"][0],
        },
        "kpis": _build_kpis_block(
            n_total, n_with_triggers, n_clean, n_moved, band_counts
        ),
        "score_summary": _build_score_summary(scorecards, scores, band_counts),
        "findings": findings,
        "triage_strip": triage_strip,
        "lowest_host": _lowest_host_callout(queue_rows),
        "shared_signal": shared_signal,
        "fleet_volume_impact": vi.project_fleet(scorecards),
        "fleet_coverage_detail": _fleet_coverage_detail(scorecards, n_total),
        "queue_rows": queue_rows,
        "coverage_rows": _coverage_rows(coverage),
        "confidence": {
            "counts": dict(Counter(sc["confidence"] for sc in scorecards)),
            "reasons": sorted(_confidence_reasons_set(scorecards)),
        },
        "entities": entities,
        "entity_rows": _group_entities(entities),
        "actions": actions,
        "method": _build_method_block(artifact, index),
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    }
