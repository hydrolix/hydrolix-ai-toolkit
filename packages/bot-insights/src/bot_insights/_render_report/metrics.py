"""Per-metric label / sentence / executive-summary helpers."""

from __future__ import annotations

from typing import Any
from report_engine.humanize import human_metric_name
from report_engine.humanize import stringify

from .formatters import (
    human_delta,
    human_number,
    to_float,
)

__all__ = [
    'metric_by_name',
    'metric_sentence',
    'executive_summary_lines',
]


def metric_by_name(metrics: list[Any], name: str) -> dict[str, Any] | None:
    for metric in metrics:
        if isinstance(metric, dict) and metric.get("name") == name:
            return metric
    return None


def metric_sentence(metric: dict[str, Any]) -> str:
    label = human_metric_name(metric.get("name"))
    direction_text = {
        "increase": "increased",
        "decrease": "decreased",
        "flat": "was flat",
        "no_change": "did not change",
    }.get(stringify(metric.get("direction")), "changed")
    return (
        f"{label} {direction_text} by {human_delta(metric.get('absolute_delta'))} "
        f"({human_number(metric.get('pct_change'), percent=True)}), from "
        f"{human_number(metric.get('baseline'))} baseline to "
        f"{human_number(metric.get('current'))} current."
    )


def executive_summary_lines(metrics: list[Any]) -> list[str]:
    usable = [metric for metric in metrics if isinstance(metric, dict)]
    if not usable:
        return [
            "No posture metrics were available in the artifact; review the evidence limits before drawing conclusions.",
            "This is a movement report, not a root-cause analysis.",
        ]

    lines: list[str] = []
    total = metric_by_name(usable, "requests")
    if total:
        lines.append(metric_sentence(total))
    else:
        lines.append(
            "The artifact does not include total request volume, so the summary is limited to supplied metric deltas."
        )

    ranked = sorted(
        (
            metric
            for metric in usable
            if to_float(metric.get("pct_change")) is not None
            and metric.get("name") != "requests"
        ),
        key=lambda metric: abs(to_float(metric.get("pct_change")) or 0.0),
        reverse=True,
    )
    if ranked:
        leaders = ranked[:3]
        fragments = [
            f"{human_metric_name(metric.get('name'))} {human_number(metric.get('pct_change'), percent=True)}"
            for metric in leaders
        ]
        lines.append("Largest relative movements: " + ", ".join(fragments) + ".")

    review_metrics = [
        metric
        for name in ("cache_misses", "rate_limited_requests", "error_5xx_requests")
        if (metric := metric_by_name(usable, name)) is not None
    ]
    if review_metrics:
        fragments = [
            f"{human_metric_name(metric.get('name'))} {human_delta(metric.get('absolute_delta'))}"
            for metric in review_metrics
        ]
        lines.append("Operational signals to review: " + ", ".join(fragments) + ".")

    lines.append(
        "Treat these changes as evidence of movement only; this report does not identify root cause or malicious intent by itself."
    )
    return lines
