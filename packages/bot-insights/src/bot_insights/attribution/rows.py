from __future__ import annotations

from typing import Any, Iterable

from .constants import (
    BASELINE_METHODS,
    BASELINE_VALUE_SEMANTICS,
    DIMENSION_INFERENCE_EXACT_EXCLUSIONS,
    METADATA_KEYS,
    METRIC_ALLOWLIST,
    REPORT_FIELDS,
    ROW_SHAPE_PERIOD_ALIASES,
    TRUST_METADATA_FIELDS,
    WRAPPER_KEYS,
)
from .errors import raise_invalid
from .metrics import (
    baseline_metric_keys,
    current_metric_keys,
    metric_aliases,
    metric_entry,
    normalize_metric_name,
    period_metric_keys,
)
from .numeric import resolve_value, to_number
from .options import parse_dimensions


def first_number(row: dict[str, Any], keys: Iterable[str]) -> float | None:
    for key in keys:
        if key not in row:
            continue
        value = to_number(row[key])
        if value is not None:
            return value
    return None


def normalize_period(value: Any) -> str | None:
    if value is None:
        return None
    return ROW_SHAPE_PERIOD_ALIASES.get(str(value).strip().lower())


def extract_metadata_layer(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    metadata: dict[str, Any] = {}
    sidecar = value.get("metadata")
    if isinstance(sidecar, dict):
        for key in REPORT_FIELDS:
            if key in sidecar:
                metadata[key] = sidecar[key]
        for key in TRUST_METADATA_FIELDS:
            if key in sidecar:
                metadata[key] = sidecar[key]
        for key in (
            "caller_metric_kind_assertion",
            "metric_kind",
            "complete_scope_total_abs_delta",
            "scorecard_export_safe",
        ):
            if key in sidecar:
                metadata[key] = sidecar[key]
    for key in REPORT_FIELDS:
        if key in value and key not in {"rows", "columns", "data"}:
            metadata[key] = value[key]
    for key in TRUST_METADATA_FIELDS:
        if key in value and key not in {"rows", "columns", "data"}:
            metadata[key] = value[key]
    for key in (
        "caller_metric_kind_assertion",
        "metric_kind",
        "complete_scope_total_abs_delta",
        "scorecard_export_safe",
    ):
        if key in value:
            metadata[key] = value[key]
    return metadata


def has_row_payload(value: dict[str, Any]) -> bool:
    return isinstance(value.get("rows"), list) or isinstance(value.get("data"), list)


def unwrap_input_doc(input_doc: Any) -> tuple[Any, dict[str, Any]]:
    if isinstance(input_doc, list):
        return input_doc, {}

    current = input_doc
    metadata_stack: list[dict[str, Any]] = []
    seen: set[int] = set()
    while isinstance(current, dict):
        metadata_stack.append(extract_metadata_layer(current))
        if has_row_payload(current):
            break
        next_value = None
        for key in WRAPPER_KEYS:
            nested = current.get(key)
            if isinstance(nested, (dict, list)) and id(nested) not in seen:
                seen.add(id(nested))
                next_value = nested
                break
        if next_value is None:
            break
        current = next_value

    metadata: dict[str, Any] = {}
    for layer in metadata_stack:
        metadata.update(layer)
    return current, metadata


def is_scalar_dimension_value(value: Any) -> bool:
    return value is None or isinstance(value, (str, int, float, bool))


def normalize_dimension_value(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)


def column_names(columns: list[Any]) -> list[str]:
    names: list[str] = []
    seen: set[str] = set()
    for index, column in enumerate(columns):
        if isinstance(column, str):
            name = column.strip()
        elif isinstance(column, dict):
            raw_name = column.get("name")
            if raw_name is None:
                raw_name = column.get("column")
            if not isinstance(raw_name, str):
                raise_invalid(
                    "invalid_mcp_column",
                    "MCP column names must be non-blank strings.",
                    path=f"$.columns[{index}]",
                )
            name = raw_name.strip()
        else:
            raise_invalid(
                "invalid_mcp_column",
                "MCP column names must be non-blank strings.",
                path=f"$.columns[{index}]",
            )
        if not name:
            raise_invalid(
                "blank_mcp_column",
                f"MCP column {index + 1} is blank.",
                path=f"$.columns[{index}]",
            )
        if name in seen:
            raise_invalid(
                "duplicate_mcp_column",
                f"MCP column '{name}' is duplicated.",
                path=f"$.columns[{index}]",
                details={"column": name},
            )
        seen.add(name)
        names.append(name)
    return names


def result_rows(payload: Any) -> tuple[list[dict[str, Any]], str]:
    if isinstance(payload, list):
        if not all(isinstance(row, dict) for row in payload):
            raise_invalid(
                "unmappable_mcp_row",
                "List input must contain row objects.",
                path="$",
            )
        return list(payload), "row_objects"

    if not isinstance(payload, dict):
        raise_invalid(
            "rows_missing",
            "Input must contain aggregate rows or MCP-style columns and rows.",
        )

    rows = payload.get("rows")
    if not isinstance(rows, list):
        rows = payload.get("data")
    if not isinstance(rows, list):
        raise_invalid(
            "rows_missing",
            "Input must contain aggregate rows or MCP-style columns and rows.",
        )
    if not rows:
        return [], "row_objects"
    if all(isinstance(row, dict) for row in rows):
        return list(rows), "row_objects"

    columns = payload.get("columns")
    if not isinstance(columns, list):
        raise_invalid(
            "unmappable_mcp_row",
            "List-style rows require MCP columns for deterministic mapping.",
            path="$.rows",
        )
    names = column_names(columns)
    converted: list[dict[str, Any]] = []
    for index, row in enumerate(rows):
        if not isinstance(row, (list, tuple)):
            raise_invalid(
                "unmappable_mcp_row",
                "MCP rows must be lists after columns are declared.",
                path=f"$.rows[{index}]",
            )
        if len(row) != len(names):
            raise_invalid(
                "mcp_row_length_mismatch",
                f"MCP row {index + 1} has {len(row)} values but {len(names)} columns were declared.",
                path=f"$.rows[{index}]",
            )
        converted.append(dict(zip(names, row)))
    return converted, "mcp_rows"


def resolve_requested_metric(
    options: dict[str, Any],
    payload: Any,
    metadata: dict[str, Any],
) -> str | None:
    cli_metric = options.get("metric")
    input_metric = resolve_value(payload, metadata, "metric")
    if cli_metric and input_metric:
        cli_canonical = normalize_metric_name(cli_metric)
        input_canonical = normalize_metric_name(str(input_metric))
        if cli_canonical and input_canonical and cli_canonical != input_canonical:
            raise_invalid(
                "metric_conflict",
                "CLI metric conflicts with the input metric.",
                details={"cli_metric": cli_metric, "input_metric": input_metric},
            )
    selected = cli_metric or input_metric
    if selected is None:
        return None
    entry = metric_entry(str(selected))
    return str(entry["name"])


def infer_metric(rows: list[dict[str, Any]]) -> str:
    candidates: set[str] = set()
    for metric_name in METRIC_ALLOWLIST:
        has_combined = any(
            first_number(row, current_metric_keys(metric_name)) is not None
            and first_number(row, baseline_metric_keys(metric_name)) is not None
            for row in rows
        )
        has_period_split = any(
            normalize_period(row.get("period")) is not None
            and first_number(row, period_metric_keys(metric_name)) is not None
            for row in rows
        )
        if has_combined or has_period_split:
            candidates.add(metric_name)

    if not candidates:
        raise_invalid(
            "metric_input_missing",
            "Specify --metric or include a single unambiguous reviewed metric in the rows.",
        )
    if len(candidates) > 1:
        raise_invalid(
            "ambiguous_metric_input",
            "Input contains multiple reviewed metric candidates; specify --metric.",
            details={"metric_candidates": sorted(candidates)},
        )
    return next(iter(candidates))


def resolve_metric(
    payload: Any,
    metadata: dict[str, Any],
    rows: list[dict[str, Any]],
    options: dict[str, Any],
) -> dict[str, Any]:
    metric_name = resolve_requested_metric(options, payload, metadata) or infer_metric(rows)
    entry = metric_entry(metric_name)
    return {
        "metric": str(entry["name"]),
        "metric_kind": str(entry["metric_kind"]),
    }


def infer_dimensions(rows: list[dict[str, Any]], metric_name: str) -> list[str]:
    if not rows:
        raise_invalid(
            "no_inferable_dimensions",
            "No rows are available for dimension inference.",
        )

    excluded = set(DIMENSION_INFERENCE_EXACT_EXCLUSIONS)
    excluded.update(metric_aliases(metric_name))
    excluded.update(current_metric_keys(metric_name))
    excluded.update(baseline_metric_keys(metric_name))

    inferred: list[str] = []
    for key in rows[0]:
        if key in excluded or key in METADATA_KEYS:
            continue
        if key.startswith(("current_", "baseline_")):
            continue
        if key.endswith(("_current", "_baseline")):
            continue
        if not is_scalar_dimension_value(rows[0].get(key)):
            continue
        inferred.append(key)

    if not inferred:
        raise_invalid(
            "no_inferable_dimensions",
            "Input does not contain deterministic dimension columns.",
        )

    expected = tuple(inferred)
    for index, row in enumerate(rows[1:], start=1):
        row_inferred = []
        for key in row:
            if key in excluded or key in METADATA_KEYS:
                continue
            if key.startswith(("current_", "baseline_")):
                continue
            if key.endswith(("_current", "_baseline")):
                continue
            if not is_scalar_dimension_value(row.get(key)):
                continue
            row_inferred.append(key)
        if tuple(row_inferred) != expected:
            raise_invalid(
                "dimension_inference_ambiguous",
                "Rows do not expose a stable inferred dimension set.",
                path=f"$.rows[{index}]",
            )
    return inferred


def resolve_dimensions(
    payload: Any,
    metadata: dict[str, Any],
    rows: list[dict[str, Any]],
    metric_name: str,
    options: dict[str, Any],
) -> tuple[list[str], bool]:
    cli_dimensions = parse_dimensions(options.get("dimensions"))
    input_dimensions = parse_dimensions(resolve_value(payload, metadata, "dimensions"))
    grouped_dimensions = parse_dimensions(resolve_value(payload, metadata, "grouped_dimensions"))
    if input_dimensions and grouped_dimensions and input_dimensions != grouped_dimensions:
        raise_invalid(
            "dimension_conflict",
            "Input dimensions conflict with grouped_dimensions.",
            details={
                "dimensions": input_dimensions,
                "grouped_dimensions": grouped_dimensions,
            },
        )
    if not input_dimensions:
        input_dimensions = grouped_dimensions
    if cli_dimensions and input_dimensions and cli_dimensions != input_dimensions:
        raise_invalid(
            "dimension_conflict",
            "CLI dimensions conflict with input dimensions.",
            details={
                "cli_dimensions": cli_dimensions,
                "input_dimensions": input_dimensions,
            },
        )
    if cli_dimensions:
        return cli_dimensions, False
    if input_dimensions:
        return input_dimensions, False
    return infer_dimensions(rows, metric_name), True


def validate_baseline_metadata(payload: Any, metadata: dict[str, Any]) -> dict[str, Any]:
    baseline_method = resolve_value(payload, metadata, "baseline_method")
    baseline_value_semantic = resolve_value(payload, metadata, "baseline_value_semantic")
    baseline_windows = resolve_value(payload, metadata, "baseline_windows")

    if baseline_method is not None:
        baseline_method_text = str(baseline_method).strip()
        if baseline_method_text not in BASELINE_METHODS:
            raise_invalid(
                "baseline_method_invalid",
                f"Unsupported baseline_method '{baseline_method}'.",
            )
        baseline_method = baseline_method_text

    if baseline_value_semantic is None:
        baseline_value_semantic = "raw_total_window"
    if baseline_value_semantic is not None:
        semantic_text = str(baseline_value_semantic).strip()
        if semantic_text not in BASELINE_VALUE_SEMANTICS:
            raise_invalid(
                "baseline_value_semantic_invalid",
                f"Unsupported baseline_value_semantic '{baseline_value_semantic}'.",
            )
        baseline_value_semantic = semantic_text

    if baseline_windows is not None and not isinstance(baseline_windows, list):
        raise_invalid(
            "baseline_windows_invalid",
            "baseline_windows must be a list when provided.",
        )
    if isinstance(baseline_windows, list) and len(baseline_windows) > 1 and baseline_method is None:
        raise_invalid(
            "baseline_method_missing",
            "Multiple baseline windows require baseline_method metadata.",
        )

    result: dict[str, Any] = {}
    if baseline_method is not None:
        result["baseline_method"] = baseline_method
    if baseline_value_semantic is not None:
        result["baseline_value_semantic"] = baseline_value_semantic
    if isinstance(baseline_windows, list):
        result["baseline_windows"] = baseline_windows
    return result


def detect_row_shape(row: dict[str, Any], metric_name: str) -> str | None:
    has_combined = (
        first_number(row, current_metric_keys(metric_name)) is not None
        and first_number(row, baseline_metric_keys(metric_name)) is not None
    )
    has_period_split = (
        normalize_period(row.get("period")) is not None
        and first_number(row, period_metric_keys(metric_name)) is not None
    )
    if has_combined and has_period_split:
        return "mixed"
    if has_combined:
        return "combined"
    if has_period_split:
        return "period_split"
    return None
