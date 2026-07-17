from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Any

from .constants import ALIAS_TO_CANONICAL, PERIOD_VALUES


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


def _is_blank(value: Any) -> bool:
    return value is None or value == ""


def _row_has_period(row: dict[str, Any]) -> bool:
    return str(row.get("period", "")).lower() in PERIOD_VALUES


def _row_has_combined_metrics(row: dict[str, Any]) -> bool:
    return any(
        key.startswith(("current_", "baseline_", "current.", "baseline."))
        or key.endswith(("_current", "_baseline"))
        for key in row
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


def _ratio(numerator: float | None, denominator: float | None, multiplier: float = 1.0) -> float | None:
    if numerator is None or denominator is None or denominator <= 0:
        return None
    return numerator / denominator * multiplier


def _qs_ratio(
    metrics: dict[str, float],
    *,
    exact_period_unique: bool,
) -> float | None:
    ratio = _ratio(metrics.get("unique_query_strings"), metrics.get("requests"))
    if ratio is None:
        return None
    if exact_period_unique:
        return min(max(ratio, 0.0), 1.0)
    return ratio


def _value_at_path(
    current: dict[str, float],
    baseline: dict[str, float],
    path: str,
) -> float | None:
    container_name, metric = path.split(".", 1)
    container = current if container_name == "current" else baseline
    return container.get(metric)


def _clean_metric_map(metrics: dict[str, float]) -> dict[str, float | int]:
    return {
        key: clean_number(value)
        for key, value in metrics.items()
        if value is not None
    }


def _row_number(row: dict[str, Any], *keys: str) -> float | None:
    for key in keys:
        number = to_number(row.get(key))
        if number is not None:
            return number
    return None


def _pct_from_parts(numerator: float | None, denominator: float | None) -> float | None:
    return _ratio(numerator, denominator, 100.0)
