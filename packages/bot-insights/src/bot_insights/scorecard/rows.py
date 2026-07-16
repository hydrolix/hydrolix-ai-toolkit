from __future__ import annotations

from typing import Any

from .constants import ALLOWED_POPULATIONS, SUPPORTED_ENTITY_TYPES
from .numeric import json_safe, to_number


def validate_rowset_scope(scope: Any, context: str) -> dict[str, Any]:
    if not isinstance(scope, dict):
        raise ValueError(f"{context} must be a JSON object")
    if "population" in scope:
        population = scope["population"]
        if not isinstance(population, str) or population not in ALLOWED_POPULATIONS:
            raise ValueError(
                f"{context}.population must be one of " + ", ".join(ALLOWED_POPULATIONS)
            )
    return json_safe(scope)


def validate_feature_provenance(provenance: Any, context: str) -> dict[str, Any]:
    if not isinstance(provenance, dict):
        raise ValueError(f"{context} must be a JSON object keyed by feature name")
    for feature_name, entry in provenance.items():
        if not isinstance(feature_name, str) or not feature_name:
            raise ValueError(f"{context} keys must be non-empty feature name strings")
        entry_context = f"{context}.{feature_name}"
        if not isinstance(entry, dict):
            raise ValueError(f"{entry_context} must be a JSON object")
        if "rowset_scope" in entry:
            validate_rowset_scope(
                entry["rowset_scope"], f"{entry_context}.rowset_scope"
            )
        if "metric_inputs" in entry:
            metric_inputs = entry["metric_inputs"]
            if not isinstance(metric_inputs, list) or not all(
                isinstance(item, str) for item in metric_inputs
            ):
                raise ValueError(
                    f"{entry_context}.metric_inputs must be an array of strings"
                )
    return json_safe(provenance)


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
                {
                    name: row[index]
                    for index, name in enumerate(names)
                    if index < len(row)
                }
            )
    return converted


def infer_entity_type(row: dict[str, Any], requested: str | None = None) -> str:
    if requested:
        return requested
    for entity_type in SUPPORTED_ENTITY_TYPES:
        if entity_type in row:
            return entity_type
    if "entity_type" in row and str(row["entity_type"]) in SUPPORTED_ENTITY_TYPES:
        return str(row["entity_type"])
    if "dimension" in row and str(row["dimension"]) in SUPPORTED_ENTITY_TYPES:
        return str(row["dimension"])
    return "value"


def entity_value(row: dict[str, Any], entity_type: str) -> str:
    if entity_type in row:
        return str(row[entity_type])
    if "entity" in row:
        return str(row["entity"])
    if "value" in row:
        return str(row["value"])
    return ""


def prefixed_keys(prefix: str, names: tuple[str, ...]) -> tuple[str, ...]:
    keys: list[str] = []
    for name in names:
        keys.extend(
            [
                f"{prefix}_{name}",
                f"{name}_{prefix}",
                f"{prefix}.{name}",
            ]
        )
    return tuple(keys)


def first_number(row: dict[str, Any], keys: tuple[str, ...]) -> float | None:
    for key in keys:
        if key in row:
            value = to_number(row[key])
            if value is not None:
                return value
    return None


def merge_period_metadata(
    combined: dict[str, Any],
    field: str,
    value: Any,
    *,
    entity_type: str,
    entity: str,
) -> None:
    if field not in combined:
        combined[field] = value
        return
    if combined[field] != value:
        raise ValueError(
            f"Period-split rows for {entity_type}={entity} must not disagree on {field}"
        )


def current_number(row: dict[str, Any], *names: str) -> float | None:
    return first_number(row, prefixed_keys("current", names) + names)


def baseline_number(row: dict[str, Any], *names: str) -> float | None:
    return first_number(row, prefixed_keys("baseline", names))


def count_values(row: dict[str, Any]) -> tuple[float | None, float | None]:
    current = first_number(
        row,
        (
            "current_count",
            "current_requests",
            "requests_current",
            "current.cnt_all",
            "current_cnt_all",
            "cnt_all_current",
            "requests",
            "cnt_all",
            "current",
        ),
    )
    baseline = first_number(
        row,
        (
            "baseline_count",
            "baseline_requests",
            "requests_baseline",
            "baseline.cnt_all",
            "baseline_cnt_all",
            "cnt_all_baseline",
            "baseline",
        ),
    )
    return current, baseline
