"""Sparkline chart helpers."""

from __future__ import annotations

from ..theme import PALETTE


def sparkline_svg(
    values: list[float],
    width: int = 120,
    height: int = 32,
    color: str = PALETTE["observe"],
) -> str:
    """Single-series sparkline. Empty values returns an empty string."""
    values = [v for v in values if v is not None]
    if len(values) < 2:
        return ""
    vmin, vmax = min(values), max(values)
    span = vmax - vmin or 1.0
    pad = 2
    plot_w, plot_h = width - 2 * pad, height - 2 * pad
    pts = []
    for i, v in enumerate(values):
        x = pad + (i / (len(values) - 1)) * plot_w
        y = pad + (1 - (v - vmin) / span) * plot_h
        pts.append(f"{x:.1f},{y:.1f}")
    return (
        f'<svg viewBox="0 0 {width} {height}" class="sparkline" '
        f'role="img" aria-label="Trend">'
        f'<polyline fill="none" stroke="{color}" stroke-width="1.5" '
        f'points="{" ".join(pts)}" />'
        "</svg>"
    )
