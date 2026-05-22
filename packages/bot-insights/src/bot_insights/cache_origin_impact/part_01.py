from __future__ import annotations

from ._shared import *

"""Build cache-busting origin-impact reports from aggregate inputs.

This module parses and validates aggregate rows, derives canonical current,
baseline, and delta metrics, then assembles scored detector candidates.

Note on inputs: the detector consumes pre-aggregated JSON rows from a caller
(e.g. ``bot_insights_report.py``'s opt-in path-grain capture), not a live
Hydrolix query. The path-grain summary tables (``bot_agg_path_minute``,
``bot_agg_path_hour``, ``bot_agg_path_day``) referenced in ``table_used``
metadata and the ``bot_agg_path_*`` guard below are **not currently deployed
on any production cluster**. The detector logic is wired and tested so that
when those aggregates are eventually installed the path-grain pipeline
works end to end; today, callers should pass pre-built aggregate JSON via
``--file``.
"""


import argparse

import json

import math

import sys

from datetime import datetime, timezone

from pathlib import Path

from typing import Any

REPORT_SCHEMA = "cache_origin_impact_report.v1"

ANALYSIS_TYPE = "cache_busting_origin_impact"

SUPPORTED_ROW_DIMENSION_SETS = (
    ("request_path_norm",),
    ("request_path_norm", "bot_class"),
    ("request_path_norm", "asn_type"),
    ("request_path_norm", "bot_class", "asn_type"),
)

ACCEPTED_HOST_CONTEXT_FORMS = (
    "scope.request_host",
    "row_level_request_host",
)

INTERPRETATION_CONSTRAINTS = [
    "mechanical_candidate_only",
    "no_causal_claim",
    "origin_pressure_score_is_proxy",
    "not_a_billing_or_capacity_unit",
    "llm_may_summarize_structured_evidence_only",
]

SUPPORTED_DIMENSIONS = {"request_host", "request_path_norm", "bot_class", "asn_type"}

SUPPORTED_DIMENSION_SET_KEYS = {
    frozenset(dimensions) for dimensions in SUPPORTED_ROW_DIMENSION_SETS
}

PERIOD_VALUES = {"current", "baseline", "after", "before"}

METADATA_KEYS = {
    "period",
    "timestamp",
    "time",
    "bucket",
    "window",
    "label",
}

DIMENSION_KEYS = {"request_host", "request_path_norm", "bot_class", "asn_type"}

CANONICAL_ALIASES = {
    "requests": ("requests", "total_requests", "cnt_all"),
    "cache_misses": ("cache_misses", "cnt_cache_miss"),
    "unique_query_strings": ("unique_query_strings", "uniq_qs"),
    "origin_p95_ms": (
        "origin_p95_ms",
        "p95_origin_ttfb",
        "p95_origin_ttfb_ms",
        "origin_ttfb_p95_ms",
    ),
    "origin_p99_ms": (
        "origin_p99_ms",
        "p99_origin_ttfb",
        "p99_origin_ttfb_ms",
        "origin_ttfb_p99_ms",
    ),
    "response_bytes": ("response_bytes", "response_total_bytes"),
}

ALIAS_TO_CANONICAL = {
    alias: canonical
    for canonical, aliases in CANONICAL_ALIASES.items()
    for alias in aliases
}

ADDITIVE_BASELINE_METRICS = {"requests", "cache_misses", "response_bytes"}

SUFFICIENT_REQUEST_COUNT = 1000

SUFFICIENT_CACHE_MISS_COUNT = 100

CONFIDENCE_ORDER = {"low": 0, "medium": 1, "high": 2}

LOW_CONFIDENCE_REASONS = {
    "sparse_counts",
    "missing_retained_dimension",
    "contribution_withheld_source_limited",
    "partial_current_bucket",
}

LOW_CONFIDENCE_LIMITATIONS = {
    "missing_baseline",
    "broad_request_level_query",
    "source_limited_rowset",
}

MEDIUM_ONLY_CONFIDENCE_REASONS = {
    "caller_supplied_json_confidence_cap",
    "query_string_cardinality_approximate",
    "origin_latency_worst_bucket",
}

PERIOD_ALIASES = {
    "current": "current",
    "after": "current",
    "baseline": "baseline",
    "before": "baseline",
}

DERIVED_METRIC_INPUTS = {
    "current_miss_rate_pct": ("current", ("requests", "cache_misses")),
    "baseline_miss_rate_pct": ("baseline", ("requests", "cache_misses")),
    "current_qs_diversity_ratio": (
        "current",
        ("requests", "unique_query_strings"),
    ),
    "baseline_qs_diversity_ratio": (
        "baseline",
        ("requests", "unique_query_strings"),
    ),
    "current_origin_pressure_score": (
        "current",
        ("cache_misses", "origin_p95_ms"),
    ),
    "baseline_origin_pressure_score": (
        "baseline",
        ("cache_misses", "origin_p95_ms"),
    ),
    "request_delta": ("delta", ("current.requests", "baseline.requests")),
    "cache_miss_delta": (
        "delta",
        ("current.cache_misses", "baseline.cache_misses"),
    ),
    "miss_rate_delta_pp": (
        "delta",
        ("current.miss_rate_pct", "baseline.miss_rate_pct"),
    ),
    "qs_diversity_delta": (
        "delta",
        ("current.qs_diversity_ratio", "baseline.qs_diversity_ratio"),
    ),
    "origin_p95_delta_ms": (
        "delta",
        ("current.origin_p95_ms", "baseline.origin_p95_ms"),
    ),
    "origin_p99_delta_ms": (
        "delta",
        ("current.origin_p99_ms", "baseline.origin_p99_ms"),
    ),
    "cache_miss_pct_change": (
        "delta",
        ("current.cache_misses", "baseline.cache_misses"),
    ),
    "origin_p95_pct_change": (
        "delta",
        ("current.origin_p95_ms", "baseline.origin_p95_ms"),
    ),
    "origin_pressure_delta": (
        "delta",
        (
            "current.origin_pressure_score",
            "baseline.origin_pressure_score",
        ),
    ),
}

COMPLETE_SCOPE_BASIS_VALUES = {
    "complete_scope",
    "complete_scope_pre_limit",
}

SOURCE_LIMITED_BASIS_VALUES = {
    "source_limited",
    "limited_source_rows",
    "post_limit",
}

SCORING_THRESHOLDS = {
    "high_query_string_diversity": 0.8,
    "moderate_query_string_diversity": 0.5,
    "query_string_diversity_increased": 0.25,
    "high_miss_rate": 80.0,
    "miss_rate_increased": 10.0,
    "origin_tail_latency_delta_ms": 100.0,
    "origin_tail_latency_pct_change": 50.0,
    "origin_pressure_contributor": 10.0,
    "bot_attributable_majority": 50.0,
    "large_current_volume": 10000.0,
}

SEMANTIC_REQUIREMENT_KEYS = {
    "unique_query_strings": (
        "unique_query_strings",
        "query_string_cardinality",
        "uniq_qs",
    ),
    "origin_p95_ms": (
        "origin_p95_ms",
        "origin_latency",
        "origin_percentiles",
        "p95_origin_ttfb",
    ),
    "origin_p99_ms": (
        "origin_p99_ms",
        "origin_latency",
        "origin_percentiles",
        "p99_origin_ttfb",
    ),
    "contribution_fields": (
        "contribution_fields",
        "cache_miss_contribution_pct",
        "origin_pressure_contribution_pct",
    ),
}

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compute cache-busting origin-impact reports from aggregate JSON."
    )
    parser.add_argument(
        "text",
        nargs="*",
        help="Aggregate JSON. If omitted, stdin is read.",
    )
    parser.add_argument(
        "-f",
        "--file",
        type=Path,
        help="Read aggregate JSON from a file instead of positional arguments/stdin.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        help="Optional maximum number of ranked candidates to emit.",
    )
    return parser.parse_args()

def read_input(args: argparse.Namespace) -> str:
    if args.file:
        return args.file.read_text(encoding="utf-8")
    if args.text:
        return " ".join(args.text)
    return sys.stdin.read()

def column_names(columns: list[Any]) -> list[str]:
    names: list[str] = []
    for column in columns:
        if isinstance(column, str):
            names.append(column)
        elif isinstance(column, dict):
            names.append(str(column.get("name") or column.get("column") or ""))
        else:
            names.append(str(column))
    return names

def result_rows(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [row for row in value if isinstance(row, dict)]

    if not isinstance(value, dict):
        return []

    rows = value.get("rows")
    if not isinstance(rows, list):
        rows = value.get("data")
    if not isinstance(rows, list):
        return []

    if not rows:
        return []
    if all(isinstance(row, dict) for row in rows):
        return rows

    columns = value.get("columns", [])
    if not isinstance(columns, list):
        return []
    names = column_names(columns)
    converted: list[dict[str, Any]] = []
    for row in rows:
        if isinstance(row, list):
            converted.append(
                {name: row[index] for index, name in enumerate(names) if index < len(row)}
            )
    return converted

def to_number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        number = float(value)
        return number if math.isfinite(number) else None
    if isinstance(value, str):
        try:
            number = float(value)
        except ValueError:
            return None
        return number if math.isfinite(number) else None
    return None

def clean_number(value: float | int | None) -> float | int | None:
    if value is None:
        return None
    rounded = round(float(value), 6)
    if rounded.is_integer():
        return int(rounded)
    return rounded

def pct_delta(current: float, baseline: float) -> float:
    return (current - baseline) / max(baseline, 1.0) * 100.0

def _require_mapping(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("Input must be a JSON object containing aggregate rows.")
    return value

def _validate_metric_or_analysis_type(value: dict[str, Any]) -> None:
    analysis_type = value.get("analysis_type")
    metric = value.get("metric")
    if not analysis_type and not metric:
        raise ValueError("Input must include metric or analysis_type.")
    if analysis_type and analysis_type != ANALYSIS_TYPE:
        raise ValueError(
            f"Unsupported analysis_type {analysis_type!r}; expected {ANALYSIS_TYPE!r}."
        )

def _validate_current_window(value: dict[str, Any]) -> dict[str, Any]:
    current_window = value.get("current_window")
    if not isinstance(current_window, dict):
        raise ValueError("current_window is required and must include start and end.")
    if not current_window.get("start") or not current_window.get("end"):
        raise ValueError("current_window is malformed; start and end are required.")
    if _window_duration_seconds(current_window) is None:
        raise ValueError(
            "current_window is malformed; start and end must be valid timestamps with end after start."
        )
    return current_window

def _validate_dimensions(value: dict[str, Any]) -> list[str]:
    dimensions = value.get("dimensions")
    if not isinstance(dimensions, list) or not dimensions:
        raise ValueError("dimensions is required and must be a non-empty list.")
    if not all(isinstance(dimension, str) and dimension for dimension in dimensions):
        raise ValueError("dimensions must contain non-empty string names.")

    unsupported = sorted(set(dimensions) - SUPPORTED_DIMENSIONS)
    if unsupported:
        raise ValueError(
            "Unsupported v1 dimension(s): "
            + ", ".join(unsupported)
            + ". Supported path-grain dimensions are request_path_norm, bot_class, and asn_type."
        )

    row_dimensions = [dimension for dimension in dimensions if dimension != "request_host"]
    if frozenset(row_dimensions) not in SUPPORTED_DIMENSION_SET_KEYS:
        supported = [
            " + ".join(dimensions)
            for dimensions in SUPPORTED_ROW_DIMENSION_SETS
        ]
        raise ValueError(
            "Unsupported dimensions for v1 path-grain detector; supported row-level "
            "dimension sets are: "
            + "; ".join(supported)
            + "."
        )
    return dimensions

def _validated_rows(value: dict[str, Any]) -> list[dict[str, Any]]:
    raw_rows = value.get("rows")
    if raw_rows is None:
        raw_rows = value.get("data")
    if not isinstance(raw_rows, list) or not raw_rows:
        raise ValueError("rows is required and must contain at least one row.")

    if all(isinstance(row, dict) for row in raw_rows):
        return list(raw_rows)

    if all(isinstance(row, list) for row in raw_rows):
        columns = value.get("columns")
        if not isinstance(columns, list) or not columns:
            raise ValueError("MCP-style list rows require a non-empty columns list.")
        names = column_names(columns)
        return [
            {name: row[index] for index, name in enumerate(names) if index < len(row)}
            for row in raw_rows
        ]

    raise ValueError(
        "rows must contain either dictionaries or lists with columns; mixed row containers are unsupported."
    )

def _is_blank(value: Any) -> bool:
    return value is None or value == ""

__all__ = [name for name in globals() if not name.startswith("__")]
