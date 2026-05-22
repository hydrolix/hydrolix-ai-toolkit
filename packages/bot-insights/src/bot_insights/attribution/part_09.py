from __future__ import annotations

from ._shared import *
from .part_01 import *
from .part_02 import *
from .part_03 import *
from .part_04 import *
from .part_05 import *
from .part_06 import *
from .part_07 import *
from .part_08 import *

def extract_dimension_values(
    row: dict[str, Any],
    dimensions: list[str],
    *,
    path: str,
) -> dict[str, str | None]:
    values: dict[str, str | None] = {}
    for dimension in dimensions:
        if dimension not in row:
            raise_invalid(
                "missing_requested_dimension",
                f"Row is missing requested dimension '{dimension}'.",
                path=path,
                details={"dimension": dimension},
            )
        if not is_scalar_dimension_value(row[dimension]):
            raise_invalid(
                "non_scalar_dimension_value",
                f"Row dimension '{dimension}' must be a scalar value.",
                path=f"{path}.{dimension}",
                details={"dimension": dimension},
            )
        values[dimension] = normalize_dimension_value(row[dimension])
    return values

def entity_key(dimension_values: dict[str, str | None], dimensions: list[str]) -> str:
    return json.dumps(
        [[dimension, dimension_values[dimension]] for dimension in dimensions],
        ensure_ascii=True,
        separators=(",", ":"),
    )

def metric_support_uses_metric_value(metric_kind: str) -> bool:
    return metric_kind == "additive_count"

def explicit_support_value(row: dict[str, Any], period: str) -> float | None:
    if period == "current":
        return first_number(row, CURRENT_SUPPORT_KEYS)
    return first_number(row, BASELINE_SUPPORT_KEYS)

def resolve_support_value(metric_kind: str, explicit_value: float | None, metric_value: float | None) -> float | None:
    if explicit_value is not None:
        return explicit_value
    if metric_support_uses_metric_value(metric_kind):
        return metric_value
    return None

def optional_row_number(row: dict[str, Any], key: str, *, path: str) -> tuple[bool, float | None]:
    if key not in row:
        return False, None
    if row[key] is None:
        return True, None
    value = to_number(row[key])
    if value is None:
        raise_invalid(
            "non_finite_digest_value",
            f"Digest-relevant row field '{key}' must be a finite numeric value or null.",
            path=f"{path}.{key}",
        )
    return True, value

def add_optional_digest_row_fields(
    canonical_row: dict[str, Any],
    source_row: dict[str, Any],
    metric_name: str,
    *,
    path: str,
) -> None:
    optional_keys = (
        f"baseline_raw_{metric_name}",
        "baseline_raw",
        "absolute_delta",
        "abs_delta",
        "pct_change",
        "complete_scope_total_abs_delta",
        "contribution_pct",
        "baseline_normalization_factor",
    )
    for key in optional_keys:
        present, value = optional_row_number(source_row, key, path=path)
        if not present:
            continue
        target_key = "baseline_raw" if key == f"baseline_raw_{metric_name}" else key
        if target_key not in canonical_row:
            canonical_row[target_key] = value

def normalize_combined_rows(
    rows: list[dict[str, Any]],
    metric_name: str,
    metric_kind: str,
    dimensions: list[str],
) -> list[dict[str, Any]]:
    seen: set[str] = set()
    canonical_rows: list[dict[str, Any]] = []
    for index, row in enumerate(rows):
        path = f"$.rows[{index}]"
        dimension_values = extract_dimension_values(row, dimensions, path=path)
        key = entity_key(dimension_values, dimensions)
        if key in seen:
            raise_invalid(
                "duplicate_entity_key",
                "Duplicate combined-row entity key.",
                path=path,
                details={"entity_key": key},
            )
        current = first_number(row, current_metric_keys(metric_name))
        baseline = first_number(row, baseline_metric_keys(metric_name))
        if current is None or baseline is None:
            raise_invalid(
                "no_usable_metric_values",
                f"Row does not contain comparable current/baseline values for metric '{metric_name}'.",
                path=path,
                details={"metric": metric_name},
            )
        seen.add(key)
        canonical_row = {
            "dimensions": dimension_values,
            "entity_key": key,
            "current": current,
            "baseline": baseline,
            "current_support_raw": resolve_support_value(
                metric_kind,
                explicit_support_value(row, "current"),
                current,
            ),
            "baseline_support_raw": resolve_support_value(
                metric_kind,
                explicit_support_value(row, "baseline"),
                baseline,
            ),
            "baseline_support_normalized": first_number(row, BASELINE_SUPPORT_NORMALIZED_KEYS),
            "input_index": index,
        }
        add_optional_digest_row_fields(canonical_row, row, metric_name, path=path)
        canonical_rows.append(canonical_row)
    return canonical_rows

def normalize_period_split_rows(
    rows: list[dict[str, Any]],
    metric_name: str,
    metric_kind: str,
    dimensions: list[str],
    baseline_metadata: dict[str, Any],
) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    seen_period_keys: set[tuple[str, str]] = set()
    baseline_windows = baseline_metadata.get("baseline_windows")
    multiple_baseline_windows = isinstance(baseline_windows, list) and len(baseline_windows) > 1

    for index, row in enumerate(rows):
        path = f"$.rows[{index}]"
        dimension_values = extract_dimension_values(row, dimensions, path=path)
        key = entity_key(dimension_values, dimensions)
        period = normalize_period(row.get("period"))
        if multiple_baseline_windows and period == "baseline" and "baseline_window_label" in row:
            raise_invalid(
                "baseline_windows_not_reduced",
                "Period-split rows must be pre-reduced to one value per entity and period.",
                path=path,
                details={"entity_key": key, "period": period},
            )
        metric_value = first_number(row, period_metric_keys(metric_name))
        if period is None or metric_value is None:
            raise_invalid(
                "no_usable_metric_values",
                f"Row does not contain a usable period-split value for metric '{metric_name}'.",
                path=path,
                details={"metric": metric_name},
            )
        period_key = (key, period)
        if period_key in seen_period_keys:
            code = "baseline_windows_not_reduced" if multiple_baseline_windows and period == "baseline" else "duplicate_entity_period_key"
            raise_invalid(
                code,
                "Period-split rows must be pre-reduced to one value per entity and period.",
                path=path,
                details={"entity_key": key, "period": period},
            )
        seen_period_keys.add(period_key)
        if key not in grouped:
            grouped[key] = {
                "dimensions": dimension_values,
                "entity_key": key,
                "current": None,
                "baseline": None,
                "current_support_raw": None,
                "baseline_support_raw": None,
                "baseline_support_normalized": None,
                "input_index": index,
            }
            order.append(key)
        grouped[key][period] = metric_value
        support_value = resolve_support_value(
            metric_kind,
            first_number(row, PERIOD_SUPPORT_KEYS),
            metric_value,
        )
        grouped[key][f"{period}_support_raw"] = support_value
        if period == "baseline":
            grouped[key]["baseline_support_normalized"] = first_number(
                row,
                BASELINE_SUPPORT_NORMALIZED_KEYS,
            )
        add_optional_digest_row_fields(grouped[key], row, metric_name, path=path)

    return [grouped[key] for key in order]

def heuristic_summary_table_used(table_used: Any) -> bool | None:
    if not isinstance(table_used, str) or not table_used.strip():
        return None
    return table_used not in {"bot_detection", "bot_detection_siem"}

def collect_report_metadata(payload: Any, metadata: dict[str, Any]) -> dict[str, Any]:
    report_metadata: dict[str, Any] = {}
    for key in (
        "analysis_type",
        "comparison_type",
        "granularity",
        "scope",
        "filters",
        "applied_scope_filters",
        "current_window",
        "policy_change",
        "policy_change_window",
        "reviewed_policy",
        "target_effect",
        "table_used",
    ):
        value = resolve_value(payload, metadata, key)
        if value is not None:
            report_metadata[key] = value
    summary_table_used = resolve_value(payload, metadata, "summary_table_used")
    summary_bool = to_bool(summary_table_used)
    if summary_bool is None:
        summary_bool = heuristic_summary_table_used(report_metadata.get("table_used"))
    if summary_bool is not None:
        report_metadata["summary_table_used"] = summary_bool
    source_limit_applied = to_bool(resolve_value(payload, metadata, "source_limit_applied"))
    if source_limit_applied is not None:
        report_metadata["source_limit_applied"] = source_limit_applied
    return report_metadata

def summary_validation_for_report(
    report_metadata: dict[str, Any],
    dimensions: list[str],
) -> dict[str, Any] | None:
    if report_metadata.get("summary_table_used") is not True:
        return None
    table_used = report_metadata.get("table_used")
    if not isinstance(table_used, str) or not table_used.strip():
        return None
    return validate_summary_table_support(
        table_used,
        dimensions,
        scope=report_metadata.get("scope"),
        filters=report_metadata.get("filters"),
        applied_scope_filters=report_metadata.get("applied_scope_filters"),
    )

def collect_input_assertions(payload: Any, metadata: dict[str, Any]) -> dict[str, Any]:
    input_assertions: dict[str, Any] = {}
    caller_metric_kind = resolve_value(payload, metadata, "caller_metric_kind_assertion")
    if caller_metric_kind is None:
        caller_metric_kind = resolve_value(payload, metadata, "metric_kind")
    if caller_metric_kind is not None:
        input_assertions["caller_metric_kind_assertion"] = caller_metric_kind
    for key in (
        "rowset_complete",
        "contribution_basis",
        "complete_scope_total_abs_delta",
        "scorecard_export_safe",
        "output_limit_applied",
        "output_limit",
        "source_limit_applied",
        "evidence_source",
        "period_value_trust",
        "query_fingerprint",
        "result_digest",
        "trusted_context",
        "trusted_evidence",
    ):
        value = resolve_value(payload, metadata, key)
        if value is not None:
            input_assertions[key] = value
    return input_assertions

def normalize_input_rows(input_doc: Any, *, options: Any = None) -> dict[str, Any]:
    opts = normalize_options(options)
    payload, metadata = unwrap_input_doc(input_doc)
    rows, row_source = result_rows(payload)
    if not rows:
        raise_invalid(
            "rows_missing",
            "Input must contain aggregate rows or MCP-style columns and rows.",
        )

    metric_info = resolve_metric(payload, metadata, rows, opts)
    dimensions, dimensions_inferred = resolve_dimensions(payload, metadata, rows, metric_info["metric"], opts)
    baseline_metadata = validate_baseline_metadata(payload, metadata)
    analysis_type = resolve_analysis_type(payload, metadata, opts)

    row_shapes: set[str] = set()
    unusable_rows: list[int] = []
    for index, row in enumerate(rows):
        shape = detect_row_shape(row, metric_info["metric"])
        if shape == "mixed":
            raise_invalid(
                "mixed_row_shapes",
                "Rows cannot mix combined and period-split fields.",
                path=f"$.rows[{index}]",
            )
        if shape is None:
            unusable_rows.append(index)
            continue
        row_shapes.add(shape)

    if not row_shapes:
        raise_invalid(
            "no_usable_metric_values",
            f"Rows do not contain usable values for metric '{metric_info['metric']}'.",
            details={"metric": metric_info["metric"]},
        )
    if len(row_shapes) > 1:
        raise_invalid(
            "mixed_row_shapes",
            "Input cannot mix combined rows and period-split rows.",
        )
    if unusable_rows:
        raise_invalid(
            "no_usable_metric_values",
            "Every row must map to the selected row shape.",
            path=f"$.rows[{unusable_rows[0]}]",
            details={"metric": metric_info["metric"]},
        )

    row_shape = next(iter(row_shapes))
    if row_shape == "combined":
        canonical_rows = normalize_combined_rows(
            rows,
            metric_info["metric"],
            metric_info["metric_kind"],
            dimensions,
        )
    else:
        canonical_rows = normalize_period_split_rows(
            rows,
            metric_info["metric"],
            metric_info["metric_kind"],
            dimensions,
            baseline_metadata,
        )

    limitations: list[str] = []
    if row_source == "mcp_rows" and not any(
        resolve_value(payload, metadata, field) is not None
        for field in ("metric", "dimensions", "baseline_method", "baseline_value_semantic")
    ):
        limitations.append("metadata_poor_input")
    if dimensions_inferred:
        limitations.append("dimensions_inferred")

    report_metadata = collect_report_metadata(payload, metadata)
    report_metadata["analysis_type"] = analysis_type
    summary_validation = summary_validation_for_report(report_metadata, dimensions)
    if summary_validation is not None:
        limitations.extend(summary_validation["limitations"])

    normalized = {
        "metric": metric_info["metric"],
        "metric_kind": metric_info["metric_kind"],
        "analysis_type": analysis_type,
        "dimensions": dimensions,
        "row_shape": row_shape,
        "canonical_rows": canonical_rows,
        "dimensions_inferred": dimensions_inferred,
        "limitations": limitations,
        "report_metadata": report_metadata,
        "trust_metadata": collect_trust_metadata(payload, metadata),
    }
    if summary_validation is not None:
        normalized["summary_validation"] = summary_validation
    normalized.update(baseline_metadata)
    input_assertions = collect_input_assertions(payload, metadata)
    if input_assertions:
        normalized["input_assertions"] = input_assertions
    return normalized

__all__ = [name for name in globals() if not name.startswith("__")]
