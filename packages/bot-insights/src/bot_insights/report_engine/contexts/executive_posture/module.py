"""SCHEMA / REPORT_TYPE / TEMPLATE / NOTE_ID_TO_SLOT / PURPOSE + assemble + prepare."""

from __future__ import annotations

from datetime import datetime, timezone

from .formatters import (
    _cluster_label,
    _short_window,
)
from .metric_rows import _metric_row
from .movers import (
    _top_mover,
    _top_priority_metric,
)
from .narrative import _actionable_summary
from .triage import (
    _actions,
    _embedded_scorecards,
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


SCHEMA = "bot_posture_movement.v1"


REPORT_TYPE = "executive_posture"


TEMPLATE = "reports/executive_posture.html"


NOTE_ID_TO_SLOT = {
    "llm-interpretation": "executive_summary",
    "llm-operational": "operational_interpretation",
    "llm-finding-overrides": "finding_overrides",
}


PURPOSE = {
    "report_class_fleet": "Bot Insights — fleet movement brief",
    "report_class_single": "Bot Insights — segment movement brief",
    "measures": (
        "Fleet-wide edge metrics (request volume, bot-like share, cache miss "
        "rate, error rate, 429 rate) compared with the prior equivalent window."
    ),
    "score_legend": (
        "Movement is reported as percent change and percentage-point change. "
        "Confidence is qualitative based on volume and coverage."
    ),
    "cant_say": (
        "Not a root-cause diagnosis. Volume changes do not imply attack or "
        "intent without additional evidence."
    ),
}


def _first_artifact(artifacts: list[dict], schema: str) -> dict | None:
    return next((a for a in artifacts if a.get("schema_version") == schema), None)


def _resolve_scorecards_pair(artifacts: list[dict]) -> tuple[dict | None, list[dict]]:
    """Pull ``(index, scorecards)`` from a wrapper's artifact list.

    Accepts either bundled ``bot_scorecard_artifacts.v1`` or the flat
    legacy shape (separate index + per-entity scorecard list entries).
    """
    packet = _first_artifact(artifacts, "bot_scorecard_artifacts.v1")
    if packet is not None:
        return packet.get("index"), packet.get("scorecards") or []
    index = _first_artifact(artifacts, "bot_scorecard_index.v1")
    scorecards = [
        a for a in artifacts if a.get("schema_version") == "bot_entity_scorecard.v1"
    ]
    return index, scorecards


def assemble(artifacts: list[dict]) -> dict:
    """Reassemble a `bot_report_input.v1` wrapper's artifacts into the dict
    shape `prepare()` expects.

    Wrappers carry ``bot_posture_movement.v1`` (required), optionally
    ``bot_mover_attribution.v1`` (top movers for `requests`), and
    optionally ``bot_scorecard_artifacts.v1`` (a packet that nests
    ``index`` + ``scorecards``). Older wrappers may instead emit the
    flat shape (``bot_scorecard_index.v1`` and ``bot_entity_scorecard.v1``
    as separate list entries); handle both.
    """
    posture = _first_artifact(artifacts, "bot_posture_movement.v1")
    if posture is None:
        raise ValueError(
            "executive_posture wrapper missing bot_posture_movement.v1 artifact"
        )
    index, scorecards = _resolve_scorecards_pair(artifacts)
    return {
        "schema_version": SCHEMA,
        "posture": posture,
        "mover": _first_artifact(artifacts, "bot_mover_attribution.v1"),
        "index": index,
        "scorecards": scorecards,
    }


def _build_orientation_block() -> dict:
    return {
        "measures": PURPOSE["measures"],
        "score_legend": PURPOSE["score_legend"],
        "cant_say": PURPOSE["cant_say"],
    }


def _build_scope_block(scope: dict, cluster_label: str, posture: dict) -> dict:
    return {
        "cluster": scope.get("cluster") or cluster_label,
        "database": scope.get("database") or "",
        "table_used": posture.get("table_used") or "",
    }


def _build_method_block(posture: dict, n_metrics: int) -> dict:
    return {
        "schema_version": posture.get("schema_version"),
        "comparison_type": posture.get("comparison_type"),
        "producer_limit": None,
        "result_row_count": n_metrics,
        "result_truncated": False,
        "interpretation_constraints": posture.get("interpretation_constraints") or [],
    }


def _build_headline(cluster_label: str, current_window: dict) -> str:
    suffix = f"week of {_short_window(current_window)}"
    if cluster_label:
        return f"Bot & Edge Movement — {cluster_label}, {suffix}"
    return f"Bot & Edge Movement — {suffix}"


def prepare(artifact: dict) -> dict:
    posture = artifact["posture"]
    mover = artifact.get("mover")
    scorecards = artifact.get("scorecards") or []

    raw_metrics = posture.get("metrics") or []

    # Compute top mover first so each metric row knows whether a dominant
    # mover concentrates on it. A metric the mover attributes to with ≥ 50%
    # contribution gets an Investigate verdict and a synthesized
    # "investigate the volume mover" recommendation, even when its bare
    # pct_change is below the standard 50% volume threshold — traffic
    # concentration is the operative signal the operator needs to see.
    top_mover = _top_mover(mover)
    metric_rows = [_metric_row(m, top_mover) for m in raw_metrics]

    triage_strip = _triage_strip(metric_rows)
    top_metric = _top_priority_metric(metric_rows, top_mover)
    actions = _actions(metric_rows)
    actionable = _actionable_summary(
        metric_rows, top_metric, top_mover, triage_strip, actions,
    )

    scope = posture.get("scope") or {}
    cluster_label = _cluster_label(scope, posture)
    current_window = posture.get("current_window") or {}
    baselines = posture.get("baseline_windows") or []

    return {
        "title": "Bot & Edge Movement",
        "kicker": PURPOSE["report_class_fleet"],
        "headline": _build_headline(cluster_label, current_window),
        "dek": "How bot traffic and edge health shifted vs the prior week.",
        "purpose": None,
        "orientation": _build_orientation_block(),
        "scope": _build_scope_block(scope, cluster_label, posture),
        "windows": {
            "current": current_window,
            "baseline": baselines[0] if baselines else {},
        },
        "metrics": metric_rows,
        "top_metric": top_metric,
        "top_mover": top_mover,
        "triage_strip": triage_strip,
        "embedded_scorecards": _embedded_scorecards(scorecards),
        "actions": actions,
        "findings": [actionable],
        "method": _build_method_block(posture, len(raw_metrics)),
        "confidence": {
            "reasons": sorted(set(posture.get("confidence_reasons") or [])),
        },
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    }
