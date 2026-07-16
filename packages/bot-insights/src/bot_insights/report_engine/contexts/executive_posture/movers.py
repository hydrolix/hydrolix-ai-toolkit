"""Top-mover / top-priority projections."""

from __future__ import annotations

from ...formatters import format_share_pct

from .formatters import (
    _metric_label,
    _to_float,
)

__all__ = [
    '_top_priority_metric',
    '_top_mover',
]


def _mover_anchored_metric(
    metric_rows: list[dict], top_mover: dict | None
) -> dict | None:
    """If a dominant mover names a metric whose row is Investigate or
    Watch, return that row; else None."""
    if not top_mover:
        return None
    target_name = top_mover.get("metric_name")
    actionable = {"investigate", "watch"}
    for r in metric_rows:
        if r["name"] == target_name and r["verdict_state"] in actionable:
            return r
    return None


def _confident_priority_candidates(metric_rows: list[dict]) -> list[dict]:
    """High/medium-confidence rows, preferring Investigate but falling
    back to Investigate-or-Watch."""
    confident = {"high", "medium"}
    candidates = [
        r for r in metric_rows
        if r["verdict_state"] == "investigate" and r["confidence"] in confident
    ]
    if candidates:
        return candidates
    return [
        r for r in metric_rows
        if r["verdict_state"] in {"investigate", "watch"}
        and r["confidence"] in confident
    ]


def _top_priority_metric(
    metric_rows: list[dict], top_mover: dict | None = None
) -> dict | None:
    """Pick the metric that should anchor the executive summary lead.

    When a dominant mover (≥ 50% concentration) attributes the move to a
    single metric, that metric anchors the lead — traffic concentration
    is the most readable signal the operator needs first. Otherwise fall
    back to the largest-magnitude Investigate (then Watch) row with
    confidence ≥ medium.
    """
    anchored = _mover_anchored_metric(metric_rows, top_mover)
    if anchored is not None:
        return anchored
    candidates = _confident_priority_candidates(metric_rows)
    if not candidates:
        return None
    return max(candidates, key=lambda r: r["magnitude"])


def _resolve_top_mover_entry(
    mover: dict | None,
) -> tuple[dict, list[dict], float] | None:
    """Return (top_entry, all_movers, contribution_pct) when contribution >= 50%."""
    if not mover:
        return None
    movers = mover.get("movers") or []
    if not movers:
        return None
    top = movers[0]
    contribution = _to_float(top.get("contribution_pct"))
    if contribution is None or contribution < 50:
        return None
    return top, movers, contribution


def _top_mover(mover: dict | None) -> dict | None:
    """Surface the top mover when its `contribution_pct` ≥ 50%.

    Analog of the scorecard brief's ``shared_signal``: when one entity
    (ASN, host, bot class) carries most of a metric's movement, lead with
    that — investigate as one cause, not N independent ones.
    """
    resolved = _resolve_top_mover_entry(mover)
    if resolved is None:
        return None
    top, movers, contribution = resolved
    metric_name = mover.get("metric") or top.get("metric") or "requests"
    metric_label = _metric_label(metric_name)
    dimension_label = (mover.get("dimension") or "").replace("_", " ")
    value = top.get("value") or ""
    pretty_dim = (dimension_label or "Dimension").upper().replace("CLIENT ASN", "ASN")
    headline = (
        f"{pretty_dim} {value} covers "
        f"{format_share_pct(contribution)} of the {metric_label.lower()} move"
    )
    return {
        "metric_name": metric_name,
        "metric_label": metric_label,
        "dimension": mover.get("dimension"),
        "dimension_label": pretty_dim,
        "value": value,
        "contribution_pct": contribution,
        "absolute_delta": _to_float(top.get("absolute_delta")),
        "pct_change": _to_float(top.get("pct_change")),
        "headline": headline,
        "movers": movers,
    }
