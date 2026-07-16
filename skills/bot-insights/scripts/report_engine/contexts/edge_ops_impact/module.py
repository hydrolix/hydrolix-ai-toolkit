"""SCHEMA / REPORT_TYPE / TEMPLATE / NOTE_ID_TO_SLOT / PURPOSE + assemble + prepare."""

from __future__ import annotations

from datetime import datetime, timezone
from collections import Counter
from ... import scorecards as scorecards_mod
from ... import verdicts as verdicts_mod
from ...humanize import cluster_display
from ...humanize import humanize_entity_type
from ...humanize import humanize_entity_type_plural
from ...humanize import title_case_label
from .._shared import _aggregate_coverage
from .._shared import _queue_rows
from .._shared import _scorecard_rollup
from .._shared import _shadow_scorecard
from .._shared import _shadow_verdict
from .._shared import _triage_strip
from ..scorecard_brief import _aggregate_actions
from ..scorecard_brief import _entity_row

from .cache_view import _edge_evidence_cards
from .entity_view import (
    _entity_display,
    _resolve_entity_type,
)
from .origin_view import _actionable_summary
from .path_candidates import _build_path_candidates
from .scorecard_view import (
    _coverage_rows,
    _domain_score_matrix,
    _entity_actions,
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


REPORT_TYPE = "edge_ops_impact"


TEMPLATE = "reports/edge_ops_impact.html"


NOTE_ID_TO_SLOT = {
    "llm-interpretation": "executive_summary",
    "llm-operational": "operational_interpretation",
    "llm-finding-overrides": "finding_overrides",
}


PURPOSE = {
    "kicker": "Bot Insights — edge & origin cost",
    "measures": (
        "A cost-impact score for each ranked entity (ASN, host, or "
        "bot class) on a 0–100 scale. Higher scores reflect more "
        "triggered cache-busting and origin-impact signals — cache-miss "
        "rate / delta, query-string diversity, origin p95 delta, "
        "origin-cost contribution share."
    ),
    "score_legend": (
        "Higher score = more triggered edge/origin rules. "
        "Bands: escalate, monitor, observe."
    ),
    "cant_say": (
        "Origin cost is reported as a percentage share, not a billing "
        "figure. Missing inputs are reported as missing — they are "
        "not scored as zero cost."
    ),
}


def _first_artifact(artifacts: list[dict], schema: str) -> dict | None:
    return next((a for a in artifacts if a.get("schema_version") == schema), None)


def _unpack_bundled_packet(
    packet: dict,
) -> tuple[dict | None, list[dict], object, bool, object]:
    """Pull ``(index, scorecards, producer_limit, result_truncated,
    total_ranked)`` out of a bundled ``bot_scorecard_artifacts.v1`` packet."""
    return (
        packet.get("index"),
        list(packet.get("scorecards") or []),
        packet.get("producer_limit"),
        packet.get("result_truncated", False),
        packet.get("total_ranked_entities"),
    )


def _unpack_flat_artifacts(
    artifacts: list[dict],
) -> tuple[dict | None, list[dict], object, bool, object]:
    """Pull the same tuple out of separate
    ``bot_scorecard_index.v1`` + ``bot_entity_scorecard.v1`` artifacts."""
    index = _first_artifact(artifacts, "bot_scorecard_index.v1")
    scorecards = [
        a for a in artifacts if a.get("schema_version") == "bot_entity_scorecard.v1"
    ]
    return index, scorecards, (index or {}).get("producer_limit"), False, None


def assemble(artifacts: list[dict]) -> dict:
    """Reassemble a ``bot_report_input.v1`` wrapper's artifacts into the dict
    shape ``prepare()`` expects.

    Accepts both shapes the producer may emit:
    - Bundled: a single ``bot_scorecard_artifacts.v1`` packet that nests
      ``index`` + ``scorecards``.
    - Flat: separate ``bot_scorecard_index.v1`` and a list of
      ``bot_entity_scorecard.v1`` entries.

    Additionally extracts the first ``cache_origin_impact_report.v1``
    artifact (or None) into ``path_report``.
    """
    packet = _first_artifact(artifacts, "bot_scorecard_artifacts.v1")
    if packet is not None:
        index, scorecards, producer_limit, result_truncated, total_ranked = (
            _unpack_bundled_packet(packet)
        )
    else:
        index, scorecards, producer_limit, result_truncated, total_ranked = (
            _unpack_flat_artifacts(artifacts)
        )

    if index is None:
        raise ValueError(
            "edge_ops_impact wrapper missing bot_scorecard_index.v1 artifact"
        )
    if total_ranked is None:
        total_ranked = len(index.get("ranked_entities") or [])

    return {
        "schema_version": SCHEMA,
        "index": index,
        "scorecards": scorecards,
        "producer_limit": producer_limit,
        "result_row_count": len(scorecards),
        "result_truncated": result_truncated,
        "total_ranked_entities": total_ranked,
        "path_report": _first_artifact(artifacts, "cache_origin_impact_report.v1"),
    }


def _resolve_scorecards(
    artifact: dict, ranked_entities: list[dict]
) -> tuple[list[dict], bool]:
    """Return ``(scorecards, degraded)``. Degraded mode builds shadow
    cards from the ranking when the wrapper carries no scorecard
    artifacts — keeps the queue table rendering even though every
    per-rule view (edge evidence, domain matrix, actions) lands empty.
    """
    scorecards = artifact.get("scorecards") or []
    if scorecards or not ranked_entities:
        return scorecards, False
    return [_shadow_scorecard(e, artifact["index"]) for e in ranked_entities], True


def _resolve_scope_block(scope: dict, scope_host: str, table_used: str) -> dict:
    return {
        "cluster": scope.get("cluster") or "",
        "database": scope.get("database") or "",
        "table_used": table_used,
        "request_host": scope_host,
    }


def _entity_type_labels(entity_type: str) -> tuple[str, str, str]:
    """Return ``(label, label_plural, label_title)`` for a given entity type."""
    label = humanize_entity_type(entity_type)
    return label, humanize_entity_type_plural(entity_type), title_case_label(label)


def _build_verdicts_by_entity(
    scorecards: list[dict], degraded: bool
) -> dict[str, dict]:
    """Per-entity verdicts via the shared 4-state classifier, or a
    band-only fallback in degraded mode where rule_results is empty."""
    out: dict[str, dict] = {}
    for sc in scorecards:
        if degraded:
            out[sc["entity"]] = _shadow_verdict(sc["band"])
        else:
            rc = scorecards_mod.rule_counts(sc)
            out[sc["entity"]] = verdicts_mod.classify(sc["band"], rc)
    return out


def _annotate_entity_row(
    e: dict,
    verdicts_by_entity: dict[str, dict],
    entity_type: str,
    entity_type_label: str,
) -> None:
    v = verdicts_by_entity.get(e["entity"])
    e["verdict"] = v
    e["verdict_state"] = v["state"] if v else "watch"
    e["verdict_label"] = v["label"] if v else "Watch"
    e["verdict_tone"] = v["tone"] if v else "monitor"
    e["entity_type"] = entity_type
    e["entity_type_label"] = entity_type_label
    e["entity_display"] = _entity_display(e["entity"], entity_type)


def _build_evidence_views(
    scorecards: list[dict],
    verdicts_by_entity: dict[str, dict],
    rank_lookup: dict,
    entity_type: str,
    entities: list[dict],
    coverage: dict,
    degraded: bool,
) -> tuple[list[dict], list[dict], dict]:
    """Build ``(edge_cards, scorecard_rollup, domain_matrix)`` — empty in degraded mode."""
    if degraded:
        return [], [], {"domains": [], "rows": []}
    edge_cards = _edge_evidence_cards(
        scorecards, verdicts_by_entity, rank_lookup, entity_type
    )
    scorecard_rollup = _scorecard_rollup(entities)
    domain_matrix = _domain_score_matrix(
        scorecards, rank_lookup, entity_type, coverage
    )
    return edge_cards, scorecard_rollup, domain_matrix


def _build_windows_block(index: dict, scorecards: list[dict]) -> dict | None:
    current_window = index.get("current_window") or (
        scorecards[0].get("current_window") if scorecards else None
    )
    baseline_windows = index.get("baseline_windows") or (
        scorecards[0].get("baseline_windows") if scorecards else None
    )
    if not (current_window and baseline_windows):
        return None
    return {"current": current_window, "baseline": baseline_windows[0]}


def _build_method_block(artifact: dict, index: dict) -> dict:
    return {
        "schema_version": artifact.get("schema_version"),
        "comparison_type": index.get("comparison_type"),
        "producer_limit": (
            index.get("producer_limit") or artifact.get("producer_limit")
        ),
        "result_row_count": artifact.get("result_row_count"),
        "result_truncated": artifact.get("result_truncated"),
        "interpretation_constraints": index.get("interpretation_constraints") or [],
    }


def _build_confidence_block(scorecards: list[dict]) -> dict:
    confidence_counts = Counter(sc.get("confidence") or "low" for sc in scorecards)
    confidence_reasons: set[str] = set()
    for sc in scorecards:
        confidence_reasons.update(sc.get("confidence_reasons") or [])
    return {"counts": dict(confidence_counts), "reasons": sorted(confidence_reasons)}


def _build_orientation_block() -> dict:
    return {
        "measures": PURPOSE["measures"],
        "score_legend": PURPOSE["score_legend"],
        "cant_say": PURPOSE["cant_say"],
    }


def _resolve_scope_context(
    scorecards: list[dict], index: dict
) -> tuple[dict, str, str, str, str]:
    """Return ``(scope, scope_host, cluster, cluster_label, table_used)``."""
    scope = (scorecards[0]["scope"] if scorecards else index.get("scope")) or {}
    scope_host = scope.get("request_host") or ""
    cluster = scope.get("cluster") or ""
    cluster_label = cluster_display(cluster) if cluster else (scope_host or "")
    table_used = (scorecards[0].get("table_used") if scorecards else None) or (
        index.get("table_used") or ""
    )
    return scope, scope_host, cluster, cluster_label, table_used


def prepare(artifact: dict) -> dict:
    index = artifact["index"]
    ranked_entities = index.get("ranked_entities") or []
    scorecards, degraded = _resolve_scorecards(artifact, ranked_entities)

    scope, scope_host, cluster, cluster_label, table_used = _resolve_scope_context(
        scorecards, index
    )

    entity_type = _resolve_entity_type(ranked_entities, scorecards)
    entity_type_label, entity_type_label_plural, entity_type_label_title = (
        _entity_type_labels(entity_type)
    )
    n_total = len(scorecards)
    rank_lookup = {e.get("entity"): e.get("rank") for e in ranked_entities}

    verdicts_by_entity = _build_verdicts_by_entity(scorecards, degraded)
    entities = [_entity_row(sc, rank_lookup) for sc in scorecards]
    for e in entities:
        _annotate_entity_row(e, verdicts_by_entity, entity_type, entity_type_label)

    queue_rows = _queue_rows(entities)
    triage_strip = _triage_strip(
        verdicts_by_entity, n_total, entity_type_label, entity_type_label_plural
    )
    coverage = _aggregate_coverage(scorecards)
    actions = _aggregate_actions(scorecards)
    edge_cards, scorecard_rollup, domain_matrix = _build_evidence_views(
        scorecards, verdicts_by_entity, rank_lookup, entity_type,
        entities, coverage, degraded,
    )
    path_candidates = _build_path_candidates(artifact.get("path_report"))
    actionable = _actionable_summary(
        scorecards, queue_rows, triage_strip, actions, coverage,
        n_total, entity_type_label, path_candidates, entity_type_label_plural,
    )
    headline_scope = cluster_label or scope_host or "fleet"

    return {
        "title": "Edge & Origin Cost",
        "kicker": PURPOSE["kicker"],
        "headline": (
            f"Edge & Origin Cost — {headline_scope}, {entity_type_label} impact queue"
        ),
        "dek": (
            "Top entities ranked by triggered cache-busting and origin-impact "
            "signals for the current window."
        ),
        "purpose": None,
        "orientation": _build_orientation_block(),
        "scope": _resolve_scope_block(scope, scope_host, table_used),
        "windows": _build_windows_block(index, scorecards),
        "entity_type": entity_type,
        "entity_type_label": entity_type_label,
        "entity_type_label_plural": entity_type_label_plural,
        "entity_type_label_title": entity_type_label_title,
        "degraded": degraded,
        "triage_strip": triage_strip,
        "queue_rows": queue_rows,
        "edge_cards": edge_cards,
        "scorecard_rollup": scorecard_rollup,
        "domain_matrix": domain_matrix,
        "actions": _entity_actions(scorecards, entity_type),
        "aggregated_actions": actions,
        "coverage_rows": _coverage_rows(coverage),
        "path_candidates": path_candidates,
        "findings": [actionable],
        "method": _build_method_block(artifact, index),
        "confidence": _build_confidence_block(scorecards),
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    }
