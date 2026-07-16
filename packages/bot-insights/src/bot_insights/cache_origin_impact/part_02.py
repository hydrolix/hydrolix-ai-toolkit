from __future__ import annotations

from ._shared import *
from .part_01 import *

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

def _row_has_period(row: dict[str, Any]) -> bool:
    return str(row.get("period", "")).lower() in PERIOD_VALUES

def _row_has_combined_metrics(row: dict[str, Any]) -> bool:
    return any(
        key.startswith(("current_", "baseline_", "current.", "baseline."))
        or key.endswith(("_current", "_baseline"))
        for key in row
    )

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

def _split_period_key(key: str) -> tuple[str, str]:
    for prefix in ("current_", "baseline_"):
        if key.startswith(prefix):
            return prefix[:-1], key[len(prefix):]
    for prefix in ("current.", "baseline."):
        if key.startswith(prefix):
            return prefix[:-1], key[len(prefix):]
    for suffix in ("_current", "_baseline"):
        if key.endswith(suffix):
            return suffix[1:], key[: -len(suffix)]
    return "row", key

def _canonical_for_key(key: str) -> tuple[str, str] | None:
    period, base_key = _split_period_key(key)
    canonical = ALIAS_TO_CANONICAL.get(base_key)
    if canonical is None:
        return None
    return period, canonical

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

def _parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed

def _window_duration_seconds(window: Any) -> float | None:
    if not isinstance(window, dict):
        return None
    start = _parse_timestamp(window.get("start"))
    end = _parse_timestamp(window.get("end"))
    if start is None or end is None:
        return None
    duration = (end - start).total_seconds()
    if duration <= 0:
        return None
    return duration

def _baseline_duration_seconds(value: dict[str, Any]) -> float | None:
    baseline_windows = value.get("baseline_windows")
    if isinstance(baseline_windows, dict):
        baseline_windows = [baseline_windows]
    if not isinstance(baseline_windows, list) or not baseline_windows:
        return None

    total = 0.0
    for window in baseline_windows:
        duration = _window_duration_seconds(window)
        if duration is not None:
            total += duration
    return total if total > 0 else None

def _baseline_normalization(
    value: dict[str, Any],
    current_window: dict[str, Any],
    rows: list[dict[str, Any]],
) -> dict[str, Any]:
    current_duration = _window_duration_seconds(current_window)
    baseline_duration = _baseline_duration_seconds(value)
    if current_duration is None or baseline_duration is None:
        return {
            "method": "missing_or_current_only",
            "factor": None,
            "applies_to": [],
        }

    factor = current_duration / baseline_duration
    if abs(factor - 1.0) < 0.000001:
        return {
            "method": "none_equal_duration_windows",
            "factor": 1.0,
            "applies_to": [],
        }

    affected = sorted(_baseline_additive_metrics(rows))
    return {
        "method": "duration_normalized_additive_metrics",
        "factor": clean_number(factor),
        "applies_to": affected,
    }

def _baseline_additive_metrics(rows: list[dict[str, Any]]) -> set[str]:
    affected: set[str] = set()
    for row in rows:
        row_period = PERIOD_ALIASES.get(str(row.get("period", "")).lower())
        for key in row:
            canonical = _canonical_for_key(key)
            if canonical is None:
                continue
            period, canonical_name = canonical
            if canonical_name not in ADDITIVE_BASELINE_METRICS:
                continue
            if period == "baseline" or (period == "row" and row_period == "baseline"):
                affected.add(canonical_name)
    return affected

def _entity_from_row(
    row: dict[str, Any],
    dimensions: list[str],
    scope: dict[str, Any],
) -> dict[str, Any]:
    entity: dict[str, Any] = {}
    scoped_host = scope.get("request_host")
    if _is_blank(scoped_host) and not _is_blank(row.get("request_host")):
        entity["request_host"] = row["request_host"]

    for dimension in dimensions:
        if dimension == "request_host" and not _is_blank(scoped_host):
            continue
        value = row.get(dimension)
        if not _is_blank(value):
            entity[dimension] = value
    return entity

def _entity_key(entity: dict[str, Any], dimensions: list[str]) -> tuple[Any, ...]:
    key_dimensions = list(dimensions)
    if "request_host" in entity and "request_host" not in key_dimensions:
        key_dimensions = ["request_host", *key_dimensions]
    return tuple(entity.get(dimension) for dimension in key_dimensions)

def _collect_metrics(
    row: dict[str, Any],
    *,
    period_override: str | None = None,
) -> dict[str, dict[str, float]]:
    periods: dict[str, dict[str, float]] = {"current": {}, "baseline": {}}
    for key, value in row.items():
        canonical = _canonical_for_key(key)
        if canonical is None:
            continue
        period, canonical_name = canonical
        normalized_period = period_override or PERIOD_ALIASES.get(period)
        if normalized_period is None and period == "row":
            normalized_period = "current"
        if normalized_period not in periods:
            continue
        number = to_number(value)
        if number is not None:
            periods[normalized_period][canonical_name] = number
    return periods

__all__ = [name for name in globals() if not name.startswith("__")]
