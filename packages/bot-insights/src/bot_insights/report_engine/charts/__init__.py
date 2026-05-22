"""Chart helpers that emit inline SVG strings.

Kept in Python (not in templates) because the math is awkward in Jinja and
because they're worth unit-testing independently. Exposed to templates as
globals via `render.py`.
"""

from __future__ import annotations

from .comparison import bullet_chart_svg, slopegraph_svg
from .constants import CURRENT_SERIES_COLOR
from .incident import incident_volume_chart_svg
from .numbers import _fmt_compact
from .score import band_distribution_bar_svg, score_bar_svg, score_gauge_svg
from .score import score_histogram_svg
from .sparkline import sparkline_svg
from .triage import coverage_bar_svg, triage_histogram_svg

__all__ = [
    "CURRENT_SERIES_COLOR",
    "band_distribution_bar_svg",
    "bullet_chart_svg",
    "coverage_bar_svg",
    "incident_volume_chart_svg",
    "score_bar_svg",
    "score_gauge_svg",
    "score_histogram_svg",
    "slopegraph_svg",
    "sparkline_svg",
    "triage_histogram_svg",
]
