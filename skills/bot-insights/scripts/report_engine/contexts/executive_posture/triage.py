"""Triage strip + embedded scorecards + actions list."""

from __future__ import annotations

from collections import Counter

from .constants import (
    _STATE_LABELS,
    _STATE_ORDER,
    _STATE_TONE,
)
from .formatters import (
    _band_verdict_label,
    _band_verdict_tone,
)

__all__ = [
    '_triage_strip',
    '_embedded_scorecards',
    '_actions',
]


def _triage_pills(counts: Counter) -> list[dict]:
    return [
        {
            "state": state,
            "label": _STATE_LABELS[state],
            "tone": _STATE_TONE[state],
            "count": counts.get(state, 0),
        }
        for state in _STATE_ORDER
    ]


def _triage_rationale_parts(counts: Counter) -> list[str]:
    n_inv = counts.get("investigate", 0)
    n_watch = counts.get("watch", 0)
    n_stable = counts.get("stable", 0)
    n_insufficient = counts.get("insufficient_data", 0)
    parts: list[str] = []
    if n_inv:
        parts.append(
            f"{n_inv} metric needs attention"
            if n_inv == 1
            else f"{n_inv} metrics need attention"
        )
    if n_watch:
        parts.append(f"{n_watch} to watch")
    if n_insufficient:
        parts.append(f"{n_insufficient} cannot be judged from this report alone")
    if not parts and n_stable:
        parts.append(
            "the metric is stable"
            if n_stable == 1
            else f"all {n_stable} metrics stable"
        )
    return parts


def _triage_strip(metric_rows: list[dict]) -> dict:
    """Per-metric verdict counts in the same shape the scorecard brief's
    triage strip expects (``pills`` + ``rationale`` + ``counts``).
    """
    counts: Counter = Counter(r["verdict_state"] for r in metric_rows)
    for state in _STATE_ORDER:
        counts.setdefault(state, 0)
    parts = _triage_rationale_parts(counts)
    n_total = len(metric_rows)
    rationale = (
        "; ".join(parts) + (f" (out of {n_total})." if n_total else ".")
        if parts
        else ""
    )
    return {
        "pills": _triage_pills(counts),
        "rationale": rationale,
        "counts": dict(counts),
    }


def _embedded_scorecard_row(sc: dict) -> dict:
    band = sc.get("band") or ""
    triggered = sum(
        1 for r in (sc.get("rule_results") or []) if r.get("status") == "triggered"
    )
    return {
        "entity": sc.get("entity") or "",
        "score": sc.get("score"),
        "band": band,
        "primary_domain": sc.get("primary_domain") or "",
        "triggered_count": triggered,
        "verdict_label": _band_verdict_label(band, triggered),
        "verdict_tone": _band_verdict_tone(band),
    }


def _embedded_scorecards(scorecards: list[dict]) -> list[dict]:
    """Compact rollup rows when the wrapper bundles
    ``bot_scorecard_artifacts.v1``. Per-host scoring detail lives in the
    scorecard brief; this section only cross-references which hosts the
    movement applies to.
    """
    rows = [_embedded_scorecard_row(sc) for sc in scorecards]
    rows.sort(key=lambda r: (r.get("score") or 100,))
    return rows


def _actions(metric_rows: list[dict]) -> list[dict]:
    """Flatten per-metric recommendations into the same action shape the
    scorecard brief produces. Investigate metrics rank ahead of Watch.

    Each action entry carries both ``summary`` (executive-grade short
    form) and ``detail`` (analyst-grade) so downstream consumers don't
    re-derive copy. ``host_count`` reads as "metrics affected" in this
    report — the actions macro renders it as "N · preview".
    """
    state_rank = {"investigate": 0, "watch": 1, "stable": 2, "insufficient_data": 3}
    actionable = [
        r
        for r in metric_rows
        if r["recommendation_summary"]
        and r["verdict_state"] in {"investigate", "watch"}
    ]
    actionable.sort(
        key=lambda r: (state_rank.get(r["verdict_state"], 9), -r["magnitude"])
    )
    out: list[dict] = []
    for r in actionable:
        out.append(
            {
                "summary": r["recommendation_summary"],
                "detail": r["recommendation_detail"],
                "step": r["recommendation_detail"],
                "host_count": 1,
                "preview": r["label"],
                "extra": 0,
                "trigger": r["recommendation_trigger"],
                "metric_name": r["name"],
            }
        )
    return out
