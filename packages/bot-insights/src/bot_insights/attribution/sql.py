from __future__ import annotations

import hashlib
from typing import Any, Iterable

from .constants import FIELD_NAME_ALIASES
from .digest import normalize_digest_value
from .errors import raise_invalid
from .fingerprint import table_metadata_columns
from .metrics import metric_aliases, metric_entry, normalize_metric_name
from .normalize import metric_support_uses_metric_value
from .numeric import canonical_json_bytes, unique_strings
from .options import selected_filter_columns


def sql_identifier(name: str) -> str:
    return "`" + str(name).replace("`", "``") + "`"


def sql_string_literal(value: Any) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def sql_literal(value: Any) -> str:
    if value is None:
        return "NULL"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    return sql_string_literal(value)


def sql_table_name(table_metadata: dict[str, Any]) -> str:
    table = table_metadata.get("table") or table_metadata.get("table_name") or table_metadata.get("name")
    if not isinstance(table, str) or not table.strip():
        raise_invalid(
            "table_metadata_missing_table",
            "Selected table metadata must include a non-blank table name.",
        )
    database = table_metadata.get("database")
    if isinstance(database, str) and database.strip():
        return f"{sql_identifier(database.strip())}.{sql_identifier(table.strip())}"
    return sql_identifier(table.strip())


def table_metadata_table_name(table_metadata: dict[str, Any]) -> str:
    table = table_metadata.get("table") or table_metadata.get("table_name") or table_metadata.get("name")
    if not isinstance(table, str) or not table.strip():
        raise_invalid(
            "table_metadata_missing_table",
            "Selected table metadata must include a non-blank table name.",
        )
    return table.strip()


def column_lookup(table_metadata: dict[str, Any]) -> dict[str, dict[str, Any]]:
    lookup: dict[str, dict[str, Any]] = {}
    for column in table_metadata_columns(table_metadata):
        name = column.get("name")
        if not isinstance(name, str) or not name:
            continue
        lookup[name] = column
        lookup.setdefault(name.lower(), column)
    return lookup


def metric_column_candidates(metric_name: str) -> list[str]:
    candidates: list[str] = []
    for alias in metric_aliases(metric_name):
        candidates.extend(
            (
                alias,
                f"sum({alias})",
                f"sumIf({alias})",
                f"count({alias})",
            )
        )
    if normalize_metric_name(metric_name) == "requests":
        candidates.extend(("count()", "count"))
    return unique_strings(candidates)


def support_column_candidates(metric_name: str) -> list[str]:
    if metric_support_uses_metric_value(metric_entry(metric_name)["metric_kind"]):
        return metric_column_candidates(metric_name)
    return metric_column_candidates("requests")


def find_metadata_column(
    table_metadata: dict[str, Any],
    candidates: Iterable[str],
    *,
    purpose: str,
) -> dict[str, Any]:
    lookup = column_lookup(table_metadata)
    for candidate in candidates:
        column = lookup.get(candidate) or lookup.get(candidate.lower())
        if column is not None:
            return column
    raise_invalid(
        "metadata_column_missing",
        f"Hydrolix metadata does not expose a reviewed {purpose} column.",
        details={"purpose": purpose, "candidates": list(candidates)},
    )


def aggregate_sql_expression(column: dict[str, Any]) -> str:
    name = str(column.get("name", "")).strip()
    if not name:
        raise_invalid("metadata_column_missing", "Hydrolix metadata column name is blank.")
    category = column.get("column_category")
    if category == "AggregateColumn":
        merge_function = column.get("merge_function")
        if not isinstance(merge_function, str) or not merge_function.strip():
            raise_invalid(
                "metadata_merge_function_missing",
                f"Aggregate-state column '{name}' is missing merge_function metadata.",
                details={"column": name},
            )
        return f"{merge_function.strip()}({sql_identifier(name)})"
    if category == "SummaryColumn":
        return sql_identifier(name)
    return f"sum({sql_identifier(name)})"


def merge_expression_map(columns: Iterable[dict[str, Any]]) -> dict[str, str]:
    expressions: dict[str, str] = {}
    for column in columns:
        if column.get("column_category") != "AggregateColumn":
            continue
        name = str(column.get("name", "")).strip()
        if not name:
            continue
        expressions[name] = aggregate_sql_expression(column)
    return expressions


def required_metadata_column(
    table_metadata: dict[str, Any],
    column_name: str,
    *,
    purpose: str,
) -> dict[str, Any]:
    return find_metadata_column(table_metadata, [column_name], purpose=purpose)


def metadata_column_aliases(column_name: str) -> list[str]:
    aliases = FIELD_NAME_ALIASES.get(column_name, (column_name,))
    return unique_strings([column_name, *aliases])


def resolved_metadata_column(
    table_metadata: dict[str, Any],
    column_name: str,
    *,
    purpose: str,
) -> dict[str, Any]:
    return find_metadata_column(table_metadata, metadata_column_aliases(column_name), purpose=purpose)


def resolved_column_name(
    table_metadata: dict[str, Any],
    column_name: str,
    *,
    purpose: str,
) -> str:
    return str(resolved_metadata_column(table_metadata, column_name, purpose=purpose)["name"])


def normalize_window(window: Any, *, path: str) -> dict[str, Any]:
    if not isinstance(window, dict):
        raise_invalid(
            "window_invalid",
            "SQL template windows must be objects with start and end.",
            path=path,
        )
    start = window.get("start")
    end = window.get("end")
    if not isinstance(start, str) or not start.strip() or not isinstance(end, str) or not end.strip():
        raise_invalid(
            "window_invalid",
            "SQL template windows must include non-blank start and end strings.",
            path=path,
        )
    normalized = {"start": start.strip(), "end": end.strip()}
    if "label" in window and window["label"] is not None:
        normalized["label"] = str(window["label"])
    return normalized


def normalize_baseline_windows(windows: Any) -> list[dict[str, Any]]:
    if not isinstance(windows, list) or not windows:
        raise_invalid(
            "baseline_windows_invalid",
            "SQL template rendering requires at least one baseline window.",
            path="$.baseline_windows",
        )
    return [normalize_window(window, path=f"$.baseline_windows[{index}]") for index, window in enumerate(windows)]


def normalized_predicate_value(value: Any) -> Any:
    if isinstance(value, (list, tuple)):
        return sorted(
            (normalize_digest_value(item, path="$.predicate") for item in value),
            key=lambda item: canonical_json_bytes(item).decode("utf-8"),
        )
    return normalize_digest_value(value, path="$.predicate")


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
