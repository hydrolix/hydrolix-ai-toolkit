"""Incident chart helpers."""

from __future__ import annotations

from .constants import CURRENT_SERIES_COLOR
from .numbers import _fmt_compact
from ..theme import PALETTE


def incident_volume_chart_svg(
    current: list[float],
    baseline: list[float] | None = None,
    *,
    width: int = 720,
    height: int = 140,
    accent: str = PALETTE["escalate"],
    accent_fill: str = PALETTE["escalate_fill"],
    current_color: str = CURRENT_SERIES_COLOR,
    baseline_color: str = PALETTE["muted"],
    peak_label: str | None = None,
    left_label: str = "",
    right_label: str = "",
    y_axis_label: str = "requests / min",
    highlight_start_fraction: float | None = None,
    highlight_end_fraction: float | None = None,
    secondary_highlight_start_fraction: float | None = None,
    secondary_highlight_end_fraction: float | None = None,
) -> str:
    """Attack-shape chart for the incident report's Impact section.

    Renders the current window's request-volume series as a thick line
    in a categorical color. When ``baseline`` is provided, overlays it
    as a thin dashed line in muted color so the reader sees how far the
    current window has departed from normal. The incident window and
    peak marker use ``accent`` as the semantic severity cue.

    Designed for a C-level read at 6 feet: the shape of the attack is
    the headline, the numbers are secondary. Use ``accent`` matching
    the severity tone (critical / escalate / monitor / observe).
    """
    current = [v for v in current if v is not None]
    if len(current) < 2:
        return ""

    baseline = [v for v in (baseline or []) if v is not None]
    have_baseline = len(baseline) >= 2

    # Combined range so current + baseline share the same Y scale —
    # the visual "departure from normal" lands honestly only when the
    # axes match.
    all_values = current + (baseline if have_baseline else [])
    vmin = min(0, min(all_values))  # anchor at 0 so a flat baseline reads as flat
    vmax = max(all_values)
    span = (vmax - vmin) or 1.0

    # pad_left gives the Y-axis tick labels ~16 SVG units of margin
    # from the SVG's left edge (the widest tick "999.9M" is ~36 units,
    # right-anchored at pad_left-8). pad_top reserves headroom for the
    # peak label, which sits 7 units above the peak dot — when the
    # peak is at the top of the plot area, py = pad_top, so the label
    # extends from y=(pad_top-15) to y=(pad_top-1). pad_top=24 keeps
    # the topmost text edge at y≈9, safely inside the SVG even after
    # container-level borders/padding.
    pad_left, pad_right, pad_top, pad_bottom = 80, 16, 24, 26
    plot_w = width - pad_left - pad_right
    plot_h = height - pad_top - pad_bottom

    def _points(series: list[float]) -> tuple[str, list[tuple[float, float]]]:
        pts: list[tuple[float, float]] = []
        n = len(series)
        for i, v in enumerate(series):
            x = pad_left + (i / (n - 1)) * plot_w
            y = pad_top + (1 - (v - vmin) / span) * plot_h
            pts.append((x, y))
        return " ".join(f"{x:.1f},{y:.1f}" for x, y in pts), pts

    current_path, current_pts = _points(current)

    baseline_polyline = ""
    if have_baseline:
        baseline_path, _ = _points(baseline)
        baseline_polyline = (
            f'<polyline fill="none" stroke="{baseline_color}" '
            f'stroke-width="1" stroke-dasharray="3 3" stroke-opacity="0.65" '
            f'points="{baseline_path}" />'
        )

    incident_window = ""
    if highlight_start_fraction is not None and highlight_end_fraction is not None:
        start_f = max(0.0, min(1.0, float(highlight_start_fraction)))
        end_f = max(0.0, min(1.0, float(highlight_end_fraction)))
        if end_f > start_f:
            x = pad_left + start_f * plot_w
            w = max(3.0, (end_f - start_f) * plot_w)
            incident_window = (
                f'<rect x="{x:.1f}" y="{pad_top:.1f}" width="{w:.1f}" '
                f'height="{plot_h:.1f}" fill="{accent}" fill-opacity="0.10" />'
                f'<line x1="{x:.1f}" y1="{pad_top:.1f}" x2="{x:.1f}" '
                f'y2="{pad_top + plot_h:.1f}" stroke="{accent}" '
                f'stroke-width="1" stroke-opacity="0.35" />'
                f'<line x1="{x + w:.1f}" y1="{pad_top:.1f}" x2="{x + w:.1f}" '
                f'y2="{pad_top + plot_h:.1f}" stroke="{accent}" '
                f'stroke-width="1" stroke-opacity="0.35" />'
            )

    secondary_window = ""
    if (
        secondary_highlight_start_fraction is not None
        and secondary_highlight_end_fraction is not None
    ):
        start_f = max(0.0, min(1.0, float(secondary_highlight_start_fraction)))
        end_f = max(0.0, min(1.0, float(secondary_highlight_end_fraction)))
        if end_f > start_f:
            x = pad_left + start_f * plot_w
            w = max(3.0, (end_f - start_f) * plot_w)
            y = pad_top + plot_h - 8
            secondary_window = (
                f'<rect x="{x:.1f}" y="{y:.1f}" width="{w:.1f}" height="4" '
                f'fill="{accent}" fill-opacity="0.80" />'
            )

    # Peak annotation — finds the max point in current and draws a dot + label
    peak_marker = ""
    if peak_label and current_pts:
        peak_idx = max(range(len(current)), key=lambda i: current[i])
        px, py = current_pts[peak_idx]
        # Keep the label inside the plot area
        text_anchor = "end" if px > pad_left + plot_w * 0.7 else "start"
        text_x = px + (-6 if text_anchor == "end" else 6)
        peak_marker = (
            f'<circle cx="{px:.1f}" cy="{py:.1f}" r="3.5" fill="{accent}" />'
            f'<text x="{text_x:.1f}" y="{py - 7:.1f}" '
            f'text-anchor="{text_anchor}" font-size="11" font-weight="600" '
            f'fill="{accent}">{peak_label}</text>'
        )

    # Y-axis ticks: 0 and vmax as text labels on the left. The
    # ``y_axis_label`` argument is retained on the function signature
    # for backwards compatibility but no longer drawn inside the SVG —
    # the editorial caller (templates/reports/incident_report.html)
    # carries it in the figcaption above the chart, where it can be
    # styled and translated without fighting the Y-axis tick labels
    # for horizontal space. Other callers that relied on the in-SVG
    # label should switch to a CSS-styled label on the containing
    # ``<figure>``.
    del accent_fill, y_axis_label
    y_axis = (
        f'<text x="{pad_left - 8:.1f}" y="{pad_top + 4:.1f}" '
        f'text-anchor="end" font-size="10" fill="currentColor" opacity="0.55">{_fmt_compact(vmax)}</text>'
        f'<text x="{pad_left - 8:.1f}" y="{pad_top + plot_h:.1f}" '
        f'text-anchor="end" font-size="10" fill="currentColor" opacity="0.55">{_fmt_compact(vmin)}</text>'
    )

    # X-axis labels at bottom
    x_axis = (
        f'<text x="{pad_left:.1f}" y="{height - 8:.1f}" font-size="11" '
        f'fill="currentColor" opacity="0.65">{left_label}</text>'
        f'<text x="{pad_left + plot_w:.1f}" y="{height - 8:.1f}" '
        f'text-anchor="end" font-size="11" fill="currentColor" opacity="0.65">{right_label}</text>'
    )

    # Light baseline grid line at y=0 (anchor)
    grid_y = pad_top + plot_h
    grid = (
        f'<line x1="{pad_left}" y1="{grid_y:.1f}" x2="{pad_left + plot_w:.1f}" '
        f'y2="{grid_y:.1f}" stroke="currentColor" stroke-opacity="0.15" stroke-width="1" />'
    )

    return (
        f'<svg viewBox="0 0 {width} {height}" class="incident-volume-chart" '
        f'role="img" aria-label="Request volume over the incident window" '
        f'preserveAspectRatio="xMidYMid meet">'
        f"{grid}"
        f"{incident_window}"
        f"{secondary_window}"
        f"{baseline_polyline}"
        f'<polyline fill="none" stroke="{current_color}" stroke-width="2.2" '
        f'stroke-linejoin="round" stroke-linecap="round" '
        f'points="{current_path}" />'
        f"{peak_marker}"
        f"{y_axis}"
        f"{x_axis}"
        f"</svg>"
    )
