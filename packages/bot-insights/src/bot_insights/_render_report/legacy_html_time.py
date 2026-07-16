"""Legacy HTML trend-card and timeline builders."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from report_engine.humanize import human_metric_name

from .charts import (
    _chart_numeric,
    _chart_open,
)
from .constants import (
    CONTROL_SCHEMA,
    POSTURE_SCHEMA,
    SCORECARD_SCHEMA,
    TIMESERIES_SCHEMA,
)
from .errors import ReportContext
from .formatters import (
    h_escape,
    human_number,
    human_timestamp,
    parse_utc_timestamp,
)
from .scorecard_helpers import timeseries_artifacts
from .tables import artifact_display_name

__all__ = [
    'html_timeseries_cards',
    'html_window_timeline',
]


def html_timeseries_cards(
    artifacts: list[dict[str, Any]],
    limit: int,
    ctx: ReportContext,
    report_type: str,
) -> str:
    metrics = _timeseries_metrics(artifacts)
    if not metrics:
        return ""
    metrics = metrics[:limit] if limit else metrics
    card_w = 340
    card_h = 138
    gap = 16
    cols = 2
    rows = (len(metrics) + cols - 1) // cols
    width = cols * card_w + (cols - 1) * gap
    height = 40 + rows * card_h + (rows - 1) * gap
    is_control = report_type == "control_review"
    heading = "Control Review Trend Cards" if is_control else "Posture Trend Cards"
    current_label = "After" if is_control else "Current"
    baseline_label = "Expected" if is_control else "Prior"
    section_label = (
        "Control review trend cards" if is_control else "Posture trend cards"
    )
    parts = [_chart_open(heading, width, height)]
    for index, metric in enumerate(metrics):
        col = index % cols
        row = index // cols
        x = col * (card_w + gap)
        y = 34 + row * (card_h + gap)
        current_values, baseline_values = _timeseries_metric_values(metric, ctx)
        if current_values is None:
            continue
        if not current_values and not baseline_values:
            ctx.warn(
                "Trend card skipped a metric because no numeric values were available."
            )
            continue
        parts.extend(
            _timeseries_card_parts(
                metric,
                current_values,
                baseline_values,
                x=x,
                y=y,
                card_w=card_w,
                card_h=card_h,
                current_label=current_label,
                baseline_label=baseline_label,
            )
        )
    parts.append("</svg>")
    return (
        f'<section class="trend-cards" aria-label="{h_escape(section_label)}">'
        + "".join(parts)
        + "</section>"
    )


def _timeseries_metrics(artifacts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    metrics: list[dict[str, Any]] = []
    for artifact in timeseries_artifacts(artifacts):
        for metric in artifact.get("metrics", []):
            if isinstance(metric, dict):
                metrics.append(metric)
    return metrics


def _timeseries_metric_values(
    metric: dict[str, Any], ctx: ReportContext
) -> tuple[list[float], list[float]] | tuple[None, None]:
    points = metric.get("points")
    if not isinstance(points, list):
        ctx.warn("Trend card skipped a metric because points were unavailable.")
        return None, None
    current_values = [
        value
        for point in points
        if isinstance(point, dict)
        and (value := _chart_numeric(point.get("current"))) is not None
    ]
    baseline_values = [
        value
        for point in points
        if isinstance(point, dict)
        and (value := _chart_numeric(point.get("baseline"))) is not None
    ]
    return current_values, baseline_values


def _timeseries_card_parts(
    metric: dict[str, Any],
    current_values: list[float],
    baseline_values: list[float],
    *,
    x: int,
    y: int,
    card_w: int,
    card_h: int,
    current_label: str,
    baseline_label: str,
) -> list[str]:
    label = metric.get("label") or human_metric_name(metric.get("name"))
    spark = _sparkline_parts(current_values, baseline_values, x, y, card_w)
    return [
        f'<rect class="chart-card" x="{x}" y="{y}" width="{card_w}" height="{card_h}" rx="4"></rect>',
        f'<text class="chart-label" x="{x + 12}" y="{y + 22}">{h_escape(label)}</text>',
        f'<text class="chart-value" x="{x + 12}" y="{y + 44}">'
        f"{current_label} {h_escape(human_number(metric.get('current')))} vs "
        f"{baseline_label.lower()} {h_escape(human_number(metric.get('baseline')))}"
        "</text>",
        f'<text class="chart-value" x="{x + 12}" y="{y + 62}">'
        f"Delta vs {h_escape(baseline_label.lower())} "
        f"{h_escape(human_number(metric.get('pct_change'), percent=True))}</text>",
        *spark,
    ]


def _sparkline_parts(
    current_values: list[float], baseline_values: list[float], x: int, y: int, card_w: int
) -> list[str]:
    spark_x = x + 14
    spark_y = y + 78
    spark_w = card_w - 28
    spark_h = 42
    all_values = current_values + baseline_values
    min_value = min(all_values)
    span = max(max(all_values) - min_value, 1.0)
    return [
        f'<polyline points="{_scaled_sparkline(baseline_values, spark_x, spark_y, spark_w, spark_h, min_value, span)}" fill="none" stroke="#85c1e9" stroke-width="2"></polyline>',
        f'<polyline points="{_scaled_sparkline(current_values, spark_x, spark_y, spark_w, spark_h, min_value, span)}" fill="none" stroke="#2474a6" stroke-width="2.5"></polyline>',
    ]


def _scaled_sparkline(
    values: list[float],
    spark_x: int,
    spark_y: int,
    spark_w: int,
    spark_h: int,
    min_value: float,
    span: float,
) -> str:
    if not values:
        return ""
    if len(values) == 1:
        return f"{spark_x},{spark_y + spark_h / 2:.1f}"
    pts: list[str] = []
    for idx, value in enumerate(values):
        px = spark_x + (idx / (len(values) - 1)) * spark_w
        py = spark_y + spark_h - ((value - min_value) / span) * spark_h
        pts.append(f"{px:.1f},{py:.1f}")
    return " ".join(pts)


def html_window_timeline(artifacts: list[dict[str, Any]], report_type: str) -> str:
    rows: list[dict[str, Any]] = []
    is_control_report = report_type == "control_review"
    for artifact in artifacts:
        row = _timeline_row(artifact, is_control_report)
        if row:
            rows.append(row)
    if not rows:
        return ""
    rows = _collapse_timeline_rows(rows)
    min_start = min(row["baseline_start"] for row in rows)
    max_end = max(row["current_end"] for row in rows)
    total_seconds = max((max_end - min_start).total_seconds(), 1.0)
    width = 760
    label_w = 150
    plot_w = 560
    row_h = 50
    height = 54 + row_h * len(rows)

    def x_for(moment: datetime) -> int:
        return int(
            label_w + ((moment - min_start).total_seconds() / total_seconds) * plot_w
        )

    parts = [
        '<section class="window-timeline" aria-label="Evidence window timeline">',
        _chart_open("Evidence Window Timeline", width, height),
        f'<text class="chart-value" x="{label_w}" y="38">{h_escape(human_timestamp(min_start.isoformat().replace("+00:00", "Z")))}</text>',
        f'<text class="chart-value" x="{label_w + plot_w}" y="38" text-anchor="end">{h_escape(human_timestamp(max_end.isoformat().replace("+00:00", "Z")))}</text>',
    ]
    for index, row in enumerate(rows):
        y = 58 + index * row_h
        base_x = x_for(row["baseline_start"])
        base_w = max(2, x_for(row["baseline_end"]) - base_x)
        cur_x = x_for(row["current_start"])
        cur_w = max(2, x_for(row["current_end"]) - cur_x)
        parts.extend(
            [
                f'<text class="chart-label" x="0" y="{y + 17}">{h_escape(row["label"])}</text>',
                f'<line x1="{label_w}" y1="{y + 10}" x2="{label_w + plot_w}" y2="{y + 10}" stroke="#d8dee8" stroke-width="1"></line>',
                f'<rect class="timeline-baseline" x="{base_x}" y="{y}" width="{base_w}" height="20" rx="3"></rect>',
                f'<rect class="timeline-current" x="{cur_x}" y="{y}" width="{cur_w}" height="20" rx="3"></rect>',
                f'<text class="chart-value" x="{base_x + base_w / 2:.1f}" y="{y + 36}" text-anchor="middle">{h_escape(row.get("baseline_label", "Baseline"))}</text>',
                f'<text class="chart-value" x="{cur_x + cur_w / 2:.1f}" y="{y + 36}" text-anchor="middle">{h_escape(row.get("current_label", "Current"))}</text>',
            ]
        )
    parts.append("</svg></section>")
    return "".join(parts)


def _timeline_row(
    artifact: dict[str, Any], is_control_report: bool
) -> dict[str, Any] | None:
    schema = artifact.get("schema_version")
    if schema not in {POSTURE_SCHEMA, TIMESERIES_SCHEMA, CONTROL_SCHEMA, SCORECARD_SCHEMA}:
        return None
    current, baseline = _timeline_windows(artifact, schema)
    if not isinstance(current, dict) or not isinstance(baseline, dict):
        return None
    current_start = parse_utc_timestamp(current.get("start"))
    current_end = parse_utc_timestamp(current.get("end"))
    baseline_start = parse_utc_timestamp(baseline.get("start"))
    baseline_end = parse_utc_timestamp(baseline.get("end"))
    if not all((current_start, current_end, baseline_start, baseline_end)):
        return None
    is_control_row = schema == CONTROL_SCHEMA or (
        is_control_report and schema == TIMESERIES_SCHEMA
    )
    return {
        "label": artifact_display_name(artifact),
        "baseline_start": baseline_start,
        "baseline_end": baseline_end,
        "current_start": current_start,
        "current_end": current_end,
        "baseline_label": "Expected" if is_control_row else "Baseline",
        "current_label": "After" if is_control_row else "Current",
    }


def _timeline_windows(
    artifact: dict[str, Any], schema: Any
) -> tuple[Any, Any]:
    if schema == CONTROL_SCHEMA:
        return artifact.get("after_window"), artifact.get("before_window")
    baselines = artifact.get("baseline_windows")
    if not isinstance(baselines, list) or not baselines:
        return None, None
    return artifact.get("current_window"), baselines[0]


def _collapse_timeline_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if len(rows) <= 1:
        return rows
    endpoints = ("baseline_start", "baseline_end", "current_start", "current_end")
    first = rows[0]
    max_drift_seconds = max(
        abs((row[field] - first[field]).total_seconds())
        for row in rows[1:]
        for field in endpoints
    )
    if max_drift_seconds >= 3600:
        return rows
    return [
        {
            "label": "Report comparison window",
            "baseline_start": min(row["baseline_start"] for row in rows),
            "baseline_end": max(row["baseline_end"] for row in rows),
            "current_start": min(row["current_start"] for row in rows),
            "current_end": max(row["current_end"] for row in rows),
            "baseline_label": rows[0].get("baseline_label", "Baseline"),
            "current_label": rows[0].get("current_label", "Current"),
        }
    ]


