"""Public chart helper compatibility API.

The implementations live in :mod:`reportkit._charts`; this module preserves
the historical import surface used by report templates and package consumers.
"""

from __future__ import annotations

from ._charts import (
    CURRENT_SERIES_COLOR,
    _fmt_compact,
    band_distribution_bar_svg,
    bullet_chart_svg,
    coverage_bar_svg,
    incident_volume_chart_svg,
    score_bar_svg,
    score_gauge_svg,
    score_histogram_svg,
    slopegraph_svg,
    sparkline_svg,
    triage_histogram_svg,
)

__all__ = [
    "CURRENT_SERIES_COLOR",
    "_fmt_compact",
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
