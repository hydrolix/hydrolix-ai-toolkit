"""Actionable summary + headline + coverage caveat."""

from __future__ import annotations

from ...findings import Finding
from ...formatters import format_share_pct

__all__ = [
    '_actionable_summary',
    '_headline_for',
    '_coverage_caveat',
]


def _summary_body(n_inv: int, n_watch: int, n_insufficient: int) -> str:
    """Bulleted queue-state clarification body."""
    inv_clause = (
        f"{n_inv} metric needs attention"
        if n_inv == 1
        else f"{n_inv} metrics need attention"
    )
    parts: list[str] = []
    if n_inv and n_watch:
        parts.append(f"{inv_clause}; {n_watch} to watch")
    elif n_inv:
        parts.append(inv_clause)
    elif n_watch:
        parts.append(
            f"{n_watch} metric needs watching"
            if n_watch == 1
            else f"{n_watch} metrics to watch"
        )
    if n_insufficient:
        parts.append(f"{n_insufficient} cannot be judged from this report alone")
    return "; ".join(parts) + "." if parts else ""


def _summary_recommendation(actions: list[dict]) -> str | None:
    if not actions:
        return None
    top = actions[0]
    short = (top.get("summary") or top.get("detail") or "").rstrip(".")
    return f"{short}." if short else None


def _actionable_summary(
    metric_rows: list[dict],
    top_metric: dict | None,
    top_mover: dict | None,
    triage_strip: dict,
    actions: list[dict],
) -> Finding:
    """Synthesize the executive-summary lead Finding.

    The headline names the dominant move (with traffic-weighted framing
    when a top mover is present); the body italicizes the queue-state
    clarification on its own line; ``recommendation`` carries the short
    form of the top metric's action; ``caveat`` fires on coverage gaps.
    """
    counts = triage_strip.get("counts", {})
    n_inv = counts.get("investigate", 0)
    n_watch = counts.get("watch", 0)
    n_insufficient = counts.get("insufficient_data", 0)
    headline = _headline_for(
        top_metric, top_mover, n_inv, n_watch, len(metric_rows)
    )
    return Finding(
        finding_id="actionable_summary",
        title=headline,
        headline=headline,
        body=_summary_body(n_inv, n_watch, n_insufficient),
        recommendation=_summary_recommendation(actions),
        caveat=_coverage_caveat(metric_rows),
        priority=100,
    )


def _format_pct_magnitude(pct_change: float | None) -> str:
    if pct_change is None:
        return ""
    return f"{pct_change:+.0f}%".replace("+-", "-")


def _share_metric_lead(top_metric: dict, label: str, direction_word: str) -> str:
    """Lead for a share-style metric — prefer pp framing when absolute_delta is available."""
    if top_metric.get("absolute_delta") is not None:
        pp = abs(top_metric["absolute_delta"])
        if pp >= 1:
            return f"{label} {direction_word} {pp:.1f}pp week-over-week"
        return f"{label} {direction_word} {pp:.2f}pp week-over-week"
    magnitude = _format_pct_magnitude(top_metric["pct_change"])
    return f"{label} {direction_word} {magnitude} week-over-week"


def _no_metric_headline(n_total: int) -> str:
    if n_total:
        return f"{n_total} metric{'s' if n_total != 1 else ''} reviewed — no material movement"
    return "No metrics in this artifact"


def _headline_for(
    top_metric: dict | None,
    top_mover: dict | None,
    n_inv: int,
    n_watch: int,
    n_total: int,
) -> str:
    """The single bold line that opens the executive summary."""
    if top_metric is None:
        return _no_metric_headline(n_total)
    label = top_metric["label"]
    direction_word = "up" if top_metric["direction"] == "increase" else "down"
    if top_metric["is_volume"]:
        magnitude = _format_pct_magnitude(top_metric["pct_change"])
        lead = f"{label} {direction_word} {magnitude} week-over-week"
    else:
        lead = _share_metric_lead(top_metric, label, direction_word)
    # Append traffic-weighted framing when a dominant mover is present
    # AND it's about the metric we're leading with.
    if top_mover and top_mover.get("metric_name") == top_metric["name"]:
        return (
            f"{lead} — {top_mover['dimension_label']} {top_mover['value']} covers "
            f"{format_share_pct(top_mover['contribution_pct'])} of the increase"
        )
    return lead


def _coverage_caveat(metric_rows: list[dict]) -> str | None:
    """Coverage-thin caveat when ≥ 50% of metrics carry low confidence
    or the artifact includes no comparable baseline.

    Phrasing matches the scorecard brief's caveat copy ("Real movement
    may be larger than the visible delta.") so the two reports read
    consistently.
    """
    if not metric_rows:
        return None
    low_conf = sum(1 for r in metric_rows if r["confidence"] == "low")
    insufficient = sum(
        1 for r in metric_rows if r["verdict_state"] == "insufficient_data"
    )
    suspect = low_conf + insufficient
    if suspect == 0:
        return None
    pct = 100 * suspect / len(metric_rows)
    if pct >= 50:
        return (
            f"Coverage is thin — {pct:.0f}% of metrics had low or insufficient "
            "confidence. Real movement may be larger than the visible delta."
        )
    return None
