from __future__ import annotations

from typing import Any

from .constants import (
    ANALYSIS_TYPE,
    DIMENSION_KEYS,
    METADATA_KEYS,
    SEMANTIC_REQUIREMENT_KEYS,
    SUPPORTED_DIMENSIONS,
    SUPPORTED_DIMENSION_SET_KEYS,
    SUPPORTED_ROW_DIMENSION_SETS,
)
from .helpers import (
    _canonical_for_key,
    _is_blank,
    _row_has_combined_metrics,
    _row_has_period,
    _split_period_key,
    _window_duration_seconds,
    clean_number,
    column_names,
    to_number,
)


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


def _validate_host_context(
    value: dict[str, Any],
    dimensions: list[str],
    rows: list[dict[str, Any]],
) -> tuple[dict[str, Any], bool]:
    scope = value.get("scope") if isinstance(value.get("scope"), dict) else {}
    scoped_host = scope.get("request_host")
    if isinstance(scoped_host, str) and scoped_host:
        conflicting_host_rows = [
            index + 1
            for index, row in enumerate(rows)
            if not _is_blank(row.get("request_host"))
            and str(row.get("request_host")) != scoped_host
        ]
        if conflicting_host_rows:
            raise ValueError(
                "Row-level request_host values must match scope.request_host "
                "when scoped host context is supplied."
            )
        return scope, True

    missing_host_rows = [
        index + 1
        for index, row in enumerate(rows)
        if _is_blank(row.get("request_host"))
    ]
    if missing_host_rows:
        raise ValueError(
            "Host context is required: provide scope.request_host or request_host on every row."
        )
    return scope, False


def _validate_row_shape(rows: list[dict[str, Any]]) -> None:
    saw_period = any(_row_has_period(row) for row in rows)
    saw_combined_or_unlabeled = any(
        not _row_has_period(row) or _row_has_combined_metrics(row) for row in rows
    )
    if saw_period and saw_combined_or_unlabeled:
        raise ValueError(
            "Input rows must not mix period-split rows with already-combined candidate rows."
        )


def _validate_dimension_values(
    dimensions: list[str],
    rows: list[dict[str, Any]],
    *,
    scoped_host: bool,
) -> None:
    required_dimensions = set(dimensions)
    if scoped_host:
        required_dimensions.discard("request_host")

    for index, row in enumerate(rows, start=1):
        missing = sorted(
            dimension for dimension in required_dimensions if _is_blank(row.get(dimension))
        )
        if missing:
            raise ValueError(
                f"Row {index} is missing dimension value(s): " + ", ".join(missing) + "."
            )


def _is_numeric_field(key: str) -> bool:
    if key in METADATA_KEYS or key in DIMENSION_KEYS:
        return False
    canonical = _canonical_for_key(key)
    if canonical is not None:
        return True
    _, base_key = _split_period_key(key)
    if base_key in METADATA_KEYS or base_key in DIMENSION_KEYS:
        return False
    return (
        base_key.endswith("_pct")
        or base_key.endswith("_ratio")
        or base_key.endswith("_ms")
        or base_key.endswith("_bytes")
        or base_key.endswith("_count")
        or base_key.endswith("_requests")
        or base_key.endswith("_misses")
        or base_key.endswith("_score")
        or "_requests_for_" in base_key
        or "_misses_for_" in base_key
        or "origin_pressure" in base_key
        or "cache_miss" in base_key
        or base_key.startswith("cnt_")
        or base_key.startswith("uniq_")
    )


def _is_count_field(key: str) -> bool:
    canonical = _canonical_for_key(key)
    if canonical is not None and canonical[1] in {
        "requests",
        "cache_misses",
        "unique_query_strings",
        "response_bytes",
    }:
        return True
    _, base_key = _split_period_key(key)
    if _is_percentage_field(key):
        return False
    return (
        base_key.endswith("_count")
        or base_key.endswith("_requests")
        or base_key.endswith("_misses")
        or "_requests_for_" in base_key
        or "_misses_for_" in base_key
        or base_key.startswith("cnt_")
        or base_key.startswith("uniq_")
    )


def _is_percentage_field(key: str) -> bool:
    _, base_key = _split_period_key(key)
    return base_key.endswith("_pct")


def _validate_numeric_fields(rows: list[dict[str, Any]]) -> None:
    for row_index, row in enumerate(rows, start=1):
        for key, value in row.items():
            if not _is_numeric_field(key):
                continue
            number = to_number(value)
            if number is None:
                raise ValueError(f"Row {row_index} field {key!r} must be numeric.")
            if _is_count_field(key) and number < 0:
                raise ValueError(f"Row {row_index} field {key!r} must not be negative.")
            if _is_percentage_field(key) and not 0 <= number <= 100:
                raise ValueError(
                    f"Row {row_index} field {key!r} must be a percentage from 0 to 100."
                )


def _validate_alias_conflicts(rows: list[dict[str, Any]]) -> None:
    for row_index, row in enumerate(rows, start=1):
        grouped: dict[tuple[str, str], list[tuple[str, float]]] = {}
        for key, value in row.items():
            canonical = _canonical_for_key(key)
            if canonical is None:
                continue
            number = to_number(value)
            if number is None:
                continue
            grouped.setdefault(canonical, []).append((key, number))

        for (_period, canonical), values in grouped.items():
            if len(values) < 2:
                continue
            first_key, first_value = values[0]
            for key, value in values[1:]:
                if value != first_value:
                    raise ValueError(
                        f"Row {row_index} has conflicting aliases for {canonical}: "
                        f"{first_key}={clean_number(first_value)} and {key}={clean_number(value)}."
                    )


def _semantic_requirements_for_key(key: str) -> set[str]:
    requirements: set[str] = set()
    canonical = _canonical_for_key(key)
    if canonical is not None:
        _period, canonical_name = canonical
        if canonical_name == "unique_query_strings":
            requirements.add("unique_query_strings")
        elif canonical_name in {"origin_p95_ms", "origin_p99_ms"}:
            requirements.add(canonical_name)

    _, base_key = _split_period_key(key)
    if base_key.endswith("contribution_pct") or "_for_contribution" in base_key:
        requirements.add("contribution_fields")
    return requirements


def _semantics_satisfy(
    metric_semantics: dict[str, Any],
    requirement: str,
) -> bool:
    return any(
        key in metric_semantics
        for key in SEMANTIC_REQUIREMENT_KEYS.get(requirement, (requirement,))
    )


def _validate_metric_semantics(value: dict[str, Any], rows: list[dict[str, Any]]) -> dict[str, Any]:
    requirements: set[str] = set()
    for row in rows:
        for key in row:
            requirements.update(_semantic_requirements_for_key(key))

    metric_semantics = value.get("metric_semantics")
    if not requirements:
        return metric_semantics if isinstance(metric_semantics, dict) else {}

    if not isinstance(metric_semantics, dict) or not metric_semantics:
        raise ValueError(
            "metric_semantics is required when rows include query-string cardinality, "
            "origin percentile, or precomputed contribution fields."
        )

    missing = sorted(
        requirement
        for requirement in requirements
        if not _semantics_satisfy(metric_semantics, requirement)
    )
    if missing:
        raise ValueError(
            "metric_semantics is missing required entry for: "
            + ", ".join(missing)
            + "."
        )
    return metric_semantics


def _validate_rows(
    value: dict[str, Any],
    dimensions: list[str],
    rows: list[dict[str, Any]],
) -> dict[str, Any]:
    _validate_row_shape(rows)
    scope, scoped_host = _validate_host_context(value, dimensions, rows)
    _validate_dimension_values(dimensions, rows, scoped_host=scoped_host)
    _validate_numeric_fields(rows)
    _validate_alias_conflicts(rows)
    return scope
