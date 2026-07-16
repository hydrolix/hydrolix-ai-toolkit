from __future__ import annotations

from ._shared import *
from .part_01 import *
from .part_02 import *
from .part_03 import *
from .part_04 import *
from .part_05 import *

def merge_sql_predicate_maps(*values: Any) -> dict[str, Any]:
    predicates: dict[str, Any] = {}
    normalized_by_column: dict[str, Any] = {}
    for value in values:
        if value is None:
            continue
        if not isinstance(value, dict):
            raise_invalid(
                "scope_invalid",
                "SQL template scope and filter predicates must be objects of retained column predicates.",
            )
        for key in sorted(value):
            column = str(key).strip()
            if not column:
                raise_invalid(
                    "scope_invalid",
                    "SQL template scope and filter predicate columns must be non-blank.",
                )
            predicate_value = value[key]
            if isinstance(predicate_value, (list, tuple)) and not predicate_value:
                raise_invalid(
                    "scope_invalid",
                    "SQL template scope list predicates must not be empty.",
                    details={"column": key},
                )
            normalized = normalized_predicate_value(predicate_value)
            if column in normalized_by_column:
                if normalized_by_column[column] != normalized:
                    raise_invalid(
                        "scope_filter_conflict",
                        "SQL template scope and filters contain conflicting predicates for the same column.",
                        details={"column": column},
                    )
                continue
            normalized_by_column[column] = normalized
            predicates[column] = predicate_value
    return predicates

def sql_scope_predicates(scope: Any) -> list[str]:
    if scope is None:
        return []
    if not isinstance(scope, dict):
        raise_invalid(
            "scope_invalid",
            "SQL template scope must be an object of retained column predicates.",
        )
    predicates: list[str] = []
    for key in sorted(scope):
        value = scope[key]
        column = sql_identifier(str(key))
        if isinstance(value, (list, tuple)):
            if not value:
                raise_invalid(
                    "scope_invalid",
                    "SQL template scope list predicates must not be empty.",
                    details={"column": key},
                )
            predicates.append(f"{column} IN ({', '.join(sql_literal(item) for item in value)})")
        elif value is None:
            predicates.append(f"{column} IS NULL")
        else:
            predicates.append(f"{column} = {sql_literal(value)}")
    return predicates

def resolve_sql_predicates(
    table_metadata: dict[str, Any],
    predicates: dict[str, Any],
) -> dict[str, Any]:
    resolved: dict[str, Any] = {}
    normalized_by_physical_column: dict[str, Any] = {}
    for canonical_column in sorted(predicates):
        physical_column = resolved_column_name(
            table_metadata,
            canonical_column,
            purpose="scope/filter",
        )
        normalized = normalized_predicate_value(predicates[canonical_column])
        if physical_column in normalized_by_physical_column:
            if normalized_by_physical_column[physical_column] != normalized:
                raise_invalid(
                    "scope_filter_conflict",
                    "SQL template scope and filters contain conflicting predicates for the same physical column.",
                    details={"column": canonical_column, "physical_column": physical_column},
                )
            continue
        normalized_by_physical_column[physical_column] = normalized
        resolved[physical_column] = predicates[canonical_column]
    return resolved

def selected_sql_columns(
    *,
    time_column: str,
    dimensions: list[str],
    scope: Any,
    filters: Any,
    applied_scope_filters: Any,
    metric_column: dict[str, Any],
    support_column: dict[str, Any],
) -> list[str]:
    columns = [time_column, *dimensions]
    columns.extend(selected_filter_columns(scope, filters, applied_scope_filters))
    columns.append(str(metric_column["name"]))
    columns.append(str(support_column["name"]))
    return unique_strings(columns)

def selected_physical_sql_columns(
    table_metadata: dict[str, Any],
    selected_columns: Iterable[str],
) -> list[str]:
    return unique_strings(
        resolved_column_name(table_metadata, column, purpose="selected")
        for column in selected_columns
    )

def render_select_dimensions(alias: str, dimensions: list[str]) -> list[str]:
    return [f"{alias}.{sql_identifier(dimension)} AS {sql_identifier(dimension)}" for dimension in dimensions]

def render_group_by_dimensions(dimensions: list[str]) -> str:
    return ", ".join(sql_identifier(dimension) for dimension in dimensions)

def render_join_key(dimensions: list[str]) -> str:
    return ", ".join(sql_identifier(dimension) for dimension in dimensions)

def render_coalesced_dimensions(dimensions: list[str]) -> list[str]:
    return [
        f"coalesce(c.{sql_identifier(dimension)}, b.{sql_identifier(dimension)}) AS {sql_identifier(dimension)}"
        for dimension in dimensions
    ]

def render_source_dimension_selects(column_map: dict[str, str]) -> list[str]:
    lines: list[str] = []
    for canonical_name, physical_name in column_map.items():
        expression = sql_identifier(physical_name)
        if physical_name != canonical_name:
            expression += f" AS {sql_identifier(canonical_name)}"
        lines.append(expression)
    return lines

def render_source_group_by_dimensions(column_map: dict[str, str]) -> str:
    return ", ".join(sql_identifier(physical_name) for physical_name in column_map.values())

def baseline_reduction_expression(
    *,
    baseline_method: str,
    source_column: str,
    duration_column: str,
) -> str:
    if baseline_method == "mean_of_baseline_windows":
        return f"avg({source_column})"
    if baseline_method == "duration_weighted_mean_of_baseline_windows":
        return f"sum({source_column})"
    return f"sum({source_column})"

def query_fingerprint(payload: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(canonical_json_bytes(payload)).hexdigest()

__all__ = [name for name in globals() if not name.startswith("__")]
