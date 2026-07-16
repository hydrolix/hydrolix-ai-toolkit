"""Suspicious-target concentration chart view."""

from __future__ import annotations

__all__ = [
    '_concentration_chart_view',
]


def _concentration_chart_view(suspicious_targets: list[dict]) -> dict:
    """Project the top N suspicious targets into a horizontal-bar shape.

    Designed for C-level scannability: the C-suite reads the report in
    90 seconds; a chart that visually shows "look how few entities own
    most of this" lands faster than a ranked table does. The chart
    sits above the detailed Suspicious Targets table; the table is
    still authoritative.

    Bar widths normalize to 100% of the window (not to the chart max)
    so the lengths read honestly — a 43% bar is 43% of total window
    traffic, not "43% of the chart." Color follows the row's severity
    tone so the visual hierarchy carries through.
    """
    top_n = 5
    # Sort by share_pct desc so the longest bar leads. The detail table
    # below preserves the severity-first ordering; that one is for
    # analysts walking a triage list. This chart is for executives
    # scanning "which entities concentrate the traffic" in one glance.
    by_share = sorted(
        suspicious_targets,
        key=lambda t: -(float(t.get("share_pct") or 0)),
    )
    rows = []
    for target in by_share[:top_n]:
        share = target.get("share_pct") or 0
        try:
            share_value = float(share)
        except (TypeError, ValueError):
            share_value = 0.0
        rows.append(
            {
                "target_type": target.get("target_type"),
                "target_type_label": target.get("target_type_label"),
                "target_value": target.get("target_value"),
                "share_pct": share_value,
                "share_pct_display": target.get("share_pct_display") or "—",
                "severity_tone": target.get("severity_tone", "observe"),
                "severity": target.get("severity"),
                "severity_label": target.get("severity_label"),
                # CSS width in percent — clamped so a single-actor 100%+
                # would still render inside the bar track. The clamp is a
                # rendering-only choice; the displayed share_pct_display
                # text is the source-of-truth value.
                "bar_width_pct": max(0.0, min(100.0, share_value)),
            }
        )
    coverage_pct = sum(r["share_pct"] for r in rows)
    return {
        "rows": rows,
        "top_n": min(top_n, len(suspicious_targets)),
        "total_count": len(suspicious_targets),
        # Note: coverage_pct is informational only. Cross-field rows
        # (e.g. an IP and its containing ASN) do double-count traffic,
        # so this is "sum of named shares" not "share of all traffic."
        # The template uses it to phrase the caption honestly.
        "coverage_pct_display": (f"{coverage_pct:.0f}%" if coverage_pct > 0 else "—"),
    }
