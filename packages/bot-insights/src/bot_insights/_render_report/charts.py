"""Shared legacy chart-rendering helpers (SVG)."""

from __future__ import annotations

import math
from typing import Any

from .errors import ReportContext
from .formatters import h_escape

__all__ = [
    '_chart_numeric',
    '_chart_skip',
    '_chart_open',
    '_horizontal_bars_svg',
    '_gauge_arc_path',
]


def _chart_numeric(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None


def _chart_skip(heading: str, reason: str, ctx: ReportContext) -> str:
    ctx.warn(f"Chart '{heading}' skipped because {reason}.")
    return (
        f'<div class="chart-skip" role="note" aria-label="{h_escape(heading)} skipped">'
        f"<strong>{h_escape(heading)}</strong>: chart skipped because "
        f"{h_escape(reason)}.</div>"
    )


def _chart_open(heading: str, width: int, height: int) -> str:
    return (
        f'<svg class="chart" viewBox="0 0 {width} {height}" role="img"'
        f' aria-label="{h_escape(heading)}">'
        f"<title>{h_escape(heading)}</title>"
        f'<text class="chart-title" x="0" y="16">{h_escape(heading)}</text>'
    )


def _horizontal_bars_svg(
    heading: str,
    rows: list[tuple[str, float, str]],
    *,
    width: int = 720,
    label_width: int = 220,
    row_height: int = 30,
) -> str:
    max_value = max((abs(value) for _, value, _ in rows), default=0.0) or 1.0
    bar_max = width - label_width - 120
    height = 40 + len(rows) * row_height
    parts = [_chart_open(heading, width, height)]
    for index, (label, value, display) in enumerate(rows):
        y = 32 + index * row_height
        scaled = max(1, int(abs(value) / max_value * bar_max))
        parts.append(
            f'<text class="chart-label" x="0" y="{y + 14}">{h_escape(label)}</text>'
        )
        parts.append(
            f'<rect class="chart-bar" x="{label_width}" y="{y}"'
            f' width="{scaled}" height="18" rx="2"></rect>'
        )
        parts.append(
            f'<text class="chart-value" x="{label_width + scaled + 8}"'
            f' y="{y + 14}">{h_escape(display)}</text>'
        )
    parts.append("</svg>")
    return "".join(parts)


def _gauge_arc_path(
    cx: float,
    cy: float,
    radius: float,
    start_degrees: float,
    end_degrees: float,
) -> str:
    start = math.radians(start_degrees)
    end = math.radians(end_degrees)
    start_x = cx + radius * math.cos(start)
    start_y = cy + radius * math.sin(start)
    end_x = cx + radius * math.cos(end)
    end_y = cy + radius * math.sin(end)
    large_arc = 1 if abs(end_degrees - start_degrees) > 180 else 0
    sweep = 1 if end_degrees > start_degrees else 0
    return (
        f"M {start_x:.1f} {start_y:.1f} "
        f"A {radius:.1f} {radius:.1f} 0 {large_arc} {sweep} {end_x:.1f} {end_y:.1f}"
    )
