from __future__ import annotations

from ._shared import *
from .part_01 import *
from .part_02 import *
from .part_03 import *
from .part_04 import *
from .part_05 import *
from .part_06 import *

def render_attribution_sql_template(
    *,
    table_metadata: dict[str, Any],
    metric: str,
    dimensions: Any,
    scope: Any,
    current_window: Any,
    baseline_windows: Any,
    baseline_method: str,
    output_limit: int,
    source_limit_applied: bool = False,
    source_limit_stage: str = "none",
    filters: Any = None,
    applied_scope_filters: Any = None,
    metadata_origin: str = "direct_hydrolix_table_metadata",
    metadata_retrieval_identity: str | None = None,
    metadata_fixture_identity: str | None = None,
    time_column: str = "timestamp",
    baseline_value_semantic: str = "duration_normalized_to_current_window",
) -> dict[str, Any]:
    """Render reviewed summary-table attribution SQL and assertion provenance."""

    table_name = table_metadata_table_name(table_metadata)
    if table_metadata.get("is_summary_table") is not True:
        raise_invalid(
            "table_metadata_not_summary_table",
            "SQL template rendering requires Hydrolix metadata for a summary table.",
            details={"table": table_name},
        )
    requested_dimensions = parse_dimensions(dimensions)
    if not requested_dimensions:
        raise_invalid(
            "dimensions_missing",
            "SQL template rendering requires at least one grouped dimension.",
        )
    if baseline_method not in BASELINE_METHODS or baseline_method == "externally_precomputed_baseline":
        raise_invalid(
            "baseline_method_invalid",
            f"Unsupported SQL template baseline_method '{baseline_method}'.",
        )
    if baseline_value_semantic not in BASELINE_VALUE_SEMANTICS or baseline_value_semantic == "externally_precomputed_baseline":
        raise_invalid(
            "baseline_value_semantic_invalid",
            f"Unsupported SQL template baseline_value_semantic '{baseline_value_semantic}'.",
        )
    if source_limit_stage not in SQL_LIMIT_STAGES:
        raise_invalid(
            "limit_stage_invalid",
            f"Unsupported source_limit_stage '{source_limit_stage}'.",
        )
    try:
        limit = int(output_limit)
    except (TypeError, ValueError):
        raise_invalid("output_limit_invalid", "SQL template output_limit must be an integer.")
    if limit <= 0:
        raise_invalid("output_limit_invalid", "SQL template output_limit must be positive.")

    metric_info = metric_entry(metric)
    metric_column = find_metadata_column(
        table_metadata,
        metric_column_candidates(metric_info["name"]),
        purpose="metric",
    )
    support_column = find_metadata_column(
        table_metadata,
        support_column_candidates(metric_info["name"]),
        purpose="support",
    )
    resolved_time_column = resolved_column_name(table_metadata, time_column, purpose="time")
    dimension_column_map = {
        dimension: resolved_column_name(table_metadata, dimension, purpose="dimension")
        for dimension in requested_dimensions
    }
    for filter_column in selected_filter_columns(scope, filters, applied_scope_filters):
        resolved_column_name(table_metadata, filter_column, purpose="scope/filter")

    summary_validation = validate_summary_table_support(
        table_name,
        requested_dimensions,
        scope=scope,
        filters=filters,
        applied_scope_filters=applied_scope_filters,
    )
    metadata_supports_requested_columns = True
    if not summary_validation["supported"]:
        for column in [
            *requested_dimensions,
            *selected_filter_columns(scope, filters, applied_scope_filters),
        ]:
            try:
                resolved_column_name(table_metadata, column, purpose="summary selection")
            except InvalidInputError:
                metadata_supports_requested_columns = False
                break
    if not summary_validation["supported"] and not metadata_supports_requested_columns:
        raise_invalid(
            "unsupported_summary_selection",
            "Selected summary table does not retain the requested grouped dimensions or scope filters.",
            details=summary_validation,
        )

    current = normalize_window(current_window, path="$.current_window")
    baselines = normalize_baseline_windows(baseline_windows)
    selected_columns = selected_sql_columns(
        time_column=time_column,
        dimensions=requested_dimensions,
        scope=scope,
        filters=filters,
        applied_scope_filters=applied_scope_filters,
        metric_column=metric_column,
        support_column=support_column,
    )
    physical_selected_columns = selected_physical_sql_columns(table_metadata, selected_columns)
    selected_column_metadata = [
        required_metadata_column(table_metadata, column, purpose="selected")
        for column in physical_selected_columns
    ]
    merge_expressions = merge_expression_map((metric_column, support_column))
    metric_expression = aggregate_sql_expression(metric_column)
    support_expression = aggregate_sql_expression(support_column)
    metadata_hash = metadata_fingerprint(
        table_metadata,
        selected_columns=physical_selected_columns,
        metadata_retrieval_identity=metadata_retrieval_identity,
        metadata_fixture_identity=metadata_fixture_identity,
    )
    sql_predicates = merge_sql_predicate_maps(scope, filters, applied_scope_filters)
    physical_sql_predicates = resolve_sql_predicates(table_metadata, sql_predicates)

    metric_name = metric_info["name"]
    current_metric_alias = f"current_{metric_name}"
    baseline_raw_alias = f"baseline_raw_{metric_name}"
    baseline_metric_alias = f"baseline_{metric_name}"
    source_dimension_group_by = render_source_group_by_dimensions(dimension_column_map)
    dimension_join_key = render_join_key(requested_dimensions)
    dimension_order = ", ".join(f"toString({sql_identifier(dimension)}) ASC" for dimension in requested_dimensions)
    current_predicates = [
        f"{sql_identifier(resolved_time_column)} >= current_start",
        f"{sql_identifier(resolved_time_column)} < current_end",
        *sql_scope_predicates(physical_sql_predicates),
    ]

    with_lines = [
        f"  toDateTime({sql_string_literal(current['start'])}) AS current_start",
        f"  toDateTime({sql_string_literal(current['end'])}) AS current_end",
    ]
    baseline_ctes: list[str] = []
    baseline_union_parts: list[str] = []
    for index, baseline in enumerate(baselines, start=1):
        start_alias = f"baseline_start_{index}"
        end_alias = f"baseline_end_{index}"
        duration_alias = f"baseline_duration_seconds_{index}"
        with_lines.extend(
            (
                f"  toDateTime({sql_string_literal(baseline['start'])}) AS {start_alias}",
                f"  toDateTime({sql_string_literal(baseline['end'])}) AS {end_alias}",
                f"  dateDiff('second', {start_alias}, {end_alias}) AS {duration_alias}",
            )
        )
        baseline_predicates = [
            f"{sql_identifier(resolved_time_column)} >= {start_alias}",
            f"{sql_identifier(resolved_time_column)} < {end_alias}",
            *sql_scope_predicates(physical_sql_predicates),
        ]
        baseline_ctes.append(
            "\n".join(
                [
                    f"  baseline_window_{index}_by_entity AS (",
                    "    SELECT",
                    *[f"      {dimension}," for dimension in render_source_dimension_selects(dimension_column_map)],
                    f"      {metric_expression} AS baseline_window_{metric_name},",
                    f"      {support_expression} AS baseline_window_support_raw,",
                    f"      {duration_alias} AS baseline_window_duration_seconds",
                    f"    FROM {sql_table_name(table_metadata)}",
                    "    WHERE " + "\n      AND ".join(baseline_predicates),
                    f"    GROUP BY {source_dimension_group_by}",
                    "  )",
                ]
            )
        )
        baseline_union_parts.append(f"SELECT * FROM baseline_window_{index}_by_entity")

    baseline_duration_terms = " + ".join(f"baseline_duration_seconds_{index}" for index in range(1, len(baselines) + 1))
    with_lines.extend(
        (
            "  dateDiff('second', current_start, current_end) AS current_duration_seconds",
            f"  {len(baselines)} AS baseline_window_count",
            f"  ({baseline_duration_terms}) AS baseline_total_duration_seconds",
        )
    )
    if baseline_value_semantic == "duration_normalized_to_current_window":
        if baseline_method == "mean_of_baseline_windows":
            with_lines.extend(
                (
                    "  toFloat64(baseline_total_duration_seconds) / nullIf(baseline_window_count, 0) AS baseline_average_duration_seconds",
                    "  toFloat64(current_duration_seconds) / nullIf(baseline_average_duration_seconds, 0) AS baseline_normalization_factor",
                )
            )
        else:
            with_lines.append(
                "  toFloat64(current_duration_seconds) / nullIf(baseline_total_duration_seconds, 0) AS baseline_normalization_factor"
            )
    else:
        with_lines.append("  toFloat64(1) AS baseline_normalization_factor")

    baseline_metric_reducer = baseline_reduction_expression(
        baseline_method=baseline_method,
        source_column=f"baseline_window_{metric_name}",
        duration_column="baseline_window_duration_seconds",
    )
    baseline_support_reducer = baseline_reduction_expression(
        baseline_method=baseline_method,
        source_column="baseline_window_support_raw",
        duration_column="baseline_window_duration_seconds",
    )
    baseline_union_sql = "\n    UNION ALL\n    ".join(baseline_union_parts)
    sql_lines = [
        "WITH",
        ",\n".join(with_lines) + ",",
        "  current_by_entity AS (",
        "    SELECT",
        *[f"      {dimension}," for dimension in render_source_dimension_selects(dimension_column_map)],
        f"      {metric_expression} AS {current_metric_alias},",
        f"      {support_expression} AS current_support_raw",
        f"    FROM {sql_table_name(table_metadata)}",
        "    WHERE " + "\n      AND ".join(current_predicates),
        f"    GROUP BY {source_dimension_group_by}",
        "  ),",
        *[cte + "," for cte in baseline_ctes],
        "  baseline_windows_by_entity AS (",
        f"    {baseline_union_sql}",
        "  ),",
        "  baseline_by_entity AS (",
        "    SELECT",
        *[f"      {sql_identifier(dimension)}," for dimension in requested_dimensions],
        f"      {baseline_metric_reducer} AS {baseline_raw_alias},",
        f"      {baseline_support_reducer} AS baseline_support_raw",
        "    FROM baseline_windows_by_entity",
        f"    GROUP BY {render_group_by_dimensions(requested_dimensions)}",
        "  ),",
        "  by_entity AS (",
        "    SELECT",
        *[f"      {line}," for line in render_coalesced_dimensions(requested_dimensions)],
        f"      coalesce(c.{current_metric_alias}, 0) AS {current_metric_alias},",
        f"      coalesce(b.{baseline_raw_alias}, 0) AS {baseline_raw_alias},",
        f"      coalesce(b.{baseline_raw_alias}, 0) * baseline_normalization_factor AS {baseline_metric_alias},",
        "      coalesce(c.current_support_raw, 0) AS current_support_raw,",
        "      coalesce(b.baseline_support_raw, 0) AS baseline_support_raw",
        "    FROM current_by_entity AS c",
        f"    FULL OUTER JOIN baseline_by_entity AS b USING ({dimension_join_key})",
        "  ),",
        "  scored AS (",
        "    SELECT",
        "      *,",
        f"      {current_metric_alias} - {baseline_metric_alias} AS absolute_delta,",
        f"      abs({current_metric_alias} - {baseline_metric_alias}) AS abs_delta,",
        f"      sum(abs({current_metric_alias} - {baseline_metric_alias})) OVER () AS complete_scope_total_abs_delta",
        "    FROM by_entity",
        "  )",
        "SELECT",
        *[f"  {sql_identifier(dimension)}," for dimension in requested_dimensions],
        f"  {current_metric_alias},",
        f"  {baseline_raw_alias},",
        f"  {baseline_metric_alias},",
        "  current_support_raw,",
        "  baseline_support_raw,",
        f"  {sql_string_literal(baseline_value_semantic)} AS baseline_value_semantic,",
        "  baseline_normalization_factor,",
        "  absolute_delta,",
        "  complete_scope_total_abs_delta,",
        f"  round(({current_metric_alias} - {baseline_metric_alias}) / greatest(abs({baseline_metric_alias}), 1.0) * 100, 6) AS pct_change,",
        "  if(complete_scope_total_abs_delta = 0, NULL, round(abs_delta / complete_scope_total_abs_delta * 100, 2)) AS contribution_pct",
        "FROM scored",
        f"ORDER BY abs_delta DESC, {dimension_order}",
        f"LIMIT {limit}",
    ]
    sql = "\n".join(sql_lines) + "\n"

    baseline_normalization = {
        "method": (
            "scale_baseline_to_current_window_duration"
            if baseline_value_semantic == "duration_normalized_to_current_window"
            else "none"
        ),
        "current_duration_expression": "dateDiff('second', current_start, current_end)",
        "baseline_duration_expression": " + ".join(
            f"dateDiff('second', baseline_start_{index}, baseline_end_{index})"
            for index in range(1, len(baselines) + 1)
        ),
        "factor_expression": (
            "current_duration_seconds / baseline_average_duration_seconds"
            if baseline_value_semantic == "duration_normalized_to_current_window"
            and baseline_method == "mean_of_baseline_windows"
            else "current_duration_seconds / baseline_total_duration_seconds"
            if baseline_value_semantic == "duration_normalized_to_current_window"
            else "1"
        ),
        "applies_to": ["baseline"] if baseline_value_semantic == "duration_normalized_to_current_window" else [],
    }
    provenance_base = {
        "generator_name": SQL_GENERATOR_NAME,
        "generator_version": SQL_GENERATOR_VERSION,
        "template_id": SQL_TEMPLATE_ID,
        "selected_table": table_name,
        "selected_columns": physical_selected_columns,
        "requested_columns": selected_columns,
        "column_aliases": {
            canonical: physical
            for canonical, physical in {
                time_column: resolved_time_column,
                **dimension_column_map,
                **{
                    canonical: resolved_column_name(table_metadata, canonical, purpose="scope/filter")
                    for canonical in selected_filter_columns(scope, filters, applied_scope_filters)
                },
            }.items()
            if canonical != physical
        },
        "selected_column_metadata": selected_column_metadata,
        "metadata_origin": metadata_origin,
        "metadata_fingerprint": metadata_hash,
        "metadata_retrieval_identity": metadata_retrieval_identity,
        "metadata_fixture_identity": metadata_fixture_identity,
        "merge_expressions": merge_expressions,
        "metric": metric_name,
        "metric_kind": metric_info["metric_kind"],
        "metric_expression": metric_expression,
        "support_expression": support_expression,
        "metric_semantics_reviewed": True,
        "dimensions": requested_dimensions,
        "grouped_dimensions": requested_dimensions,
        "scope": scope or {},
        "filters": filters or {},
        "applied_scope_filters": applied_scope_filters or {},
        "sql_predicates": sql_predicates,
        "physical_sql_predicates": physical_sql_predicates,
        "current_window": current,
        "baseline_windows": baselines,
        "baseline_method": baseline_method,
        "baseline_value_semantic": baseline_value_semantic,
        "baseline_normalization": baseline_normalization,
        "limit_stage": "after_denominator",
        "output_limit": limit,
        "source_limit_applied": bool(source_limit_applied),
        "source_limit_stage": source_limit_stage,
    }
    fingerprint_payload = {
        **provenance_base,
        "sql": sql,
        "schema_version": SQL_TEMPLATE_SCHEMA,
    }
    fingerprint = query_fingerprint(fingerprint_payload)
    provenance = {
        **provenance_base,
        "query_fingerprint": fingerprint,
        "trust_state": "assertion_until_direct_mcp_wrapper_result_digest",
    }
    source_limit_before_denominator = bool(source_limit_applied and source_limit_stage == "before_denominator")
    complete_scope_evidence = {
        **provenance_base,
        "evidence_id": "complete-scope-pre-limit-v1",
        "evidence_type": "complete_scope_pre_limit_evidence",
        "applies_to": {"scope": "report"},
        "evidence_source": "trusted_template_generator",
        "query_fingerprint": fingerprint,
        "denominator_expression": f"sum(abs({current_metric_alias} - {baseline_metric_alias})) over ()",
        "computed_over_complete_grouped_scope": True,
        "computed_before_output_limit": True,
        "source_limit_applied_before_denominator": source_limit_before_denominator,
        "trust_state": "assertion_until_direct_mcp_wrapper_result_digest",
    }
    zero_fill_evidence = {
        **provenance_base,
        "evidence_id": "zero-fill-full-scope-join-v1",
        "evidence_type": "zero_fill_evidence",
        "applies_to": {"scope": "report"},
        "evidence_source": "trusted_template_generator",
        "query_fingerprint": fingerprint,
        "period_value_trust": {
            "current": "trusted_full_scope_join",
            "baseline": "trusted_full_scope_join",
        },
        "grouped_scope_complete": True,
        "full_scope_joined_grouped_rowset": True,
        "computed_before_output_limit": True,
        "source_limit_applied_before_zero_fill": source_limit_before_denominator,
        "trust_state": "assertion_until_direct_mcp_wrapper_result_digest",
    }
    return {
        "schema_version": SQL_TEMPLATE_SCHEMA,
        "sql": sql,
        "provenance": provenance,
        "evidence_assertions": [complete_scope_evidence, zero_fill_evidence],
        "summary_validation": summary_validation,
    }

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

__all__ = [name for name in globals() if not name.startswith("__")]
