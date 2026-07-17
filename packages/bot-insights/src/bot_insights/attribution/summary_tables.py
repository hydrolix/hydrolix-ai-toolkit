from __future__ import annotations

from typing import Any, Iterable

from .constants import (
    SQL_GENERATOR_NAME,
    SQL_GENERATOR_VERSION,
    SUMMARY_FILTER_ALWAYS_RETAINED,
)
from .options import parse_dimensions, selected_filter_columns


def table_family(
    prefix: str,
    granularities: Iterable[str],
    retained_dimensions: Iterable[str],
    *,
    parent: str,
) -> dict[str, dict[str, Any]]:
    return {
        f"{prefix}_{granularity}": {
            "table": f"{prefix}_{granularity}",
            "granularity": granularity,
            "parent": parent,
            "retained_dimensions": tuple(retained_dimensions),
        }
        for granularity in granularities
    }


SUMMARY_TABLE_CATALOG: dict[str, dict[str, Any]] = {}


SUMMARY_TABLE_CATALOG.update(
    table_family(
        "bi_summary",
        ("minute", "hour", "day", "month"),
        (
            "request_host",
            "client_asn",
            "user_agent_category",
            "is_bot_traffic",
            "ai_category",
            "ai_source",
            "traffic_cohort",
            "resource_category",
            "request_method",
            "cache_was_cached",
            "response_status_code",
            "request_path_pattern",
            "client_country_iso_code",
        ),
        parent="bot_detection",
    )
)


SUMMARY_TABLE_CATALOG.update(
    table_family(
        "bi_siem_policy_summary",
        ("minute", "hour", "day"),
        (
            "request_host",
            "client_asn",
            "user_agent_category",
            "is_bot_traffic",
            "ai_category",
            "ai_source",
            "resource_category",
            "request_method",
            "response_status_code",
            "client_country_iso_code",
            "policy_id",
            "action_class",
            "bot_type",
        ),
        parent="bot_detection_siem",
    )
)


SUMMARY_TABLE_CATALOG["bot_agg_hour"] = {
    "table": "bot_agg_hour",
    "granularity": "hour",
    "parent": "bot_detection",
    "retained_dimensions": ("request_host",),
}


SUMMARY_TABLE_CATALOG.update(
    table_family(
        "bot_agg_path",
        ("minute", "hour", "day"),
        ("request_host", "request_path_norm", "bot_class", "asn_type"),
        parent="bot_detection",
    )
)


SUMMARY_TABLE_CATALOG["bot_agg_asn_hour"] = {
    "table": "bot_agg_asn_hour",
    "granularity": "hour",
    "parent": "bot_detection",
    "retained_dimensions": ("request_host", "client_asn", "asn_type"),
}


SUMMARY_TABLE_CATALOG["bot_agg_traffic_hour"] = {
    "table": "bot_agg_traffic_hour",
    "granularity": "hour",
    "parent": "bot_detection",
    "retained_dimensions": ("request_host", "is_bot_traffic", "ai_category"),
}


SUMMARY_TABLE_CATALOG["bot_agg_ua_hour"] = {
    "table": "bot_agg_ua_hour",
    "granularity": "hour",
    "parent": "bot_detection",
    "retained_dimensions": ("request_host", "bot_class"),
}


SUMMARY_TABLE_CATALOG.update(
    table_family(
        "bot_agg_resource",
        ("minute", "hour", "day"),
        ("request_host", "resource_category"),
        parent="bot_detection",
    )
)


def summary_table_metadata(table_name: str) -> dict[str, Any] | None:
    table = SUMMARY_TABLE_CATALOG.get(str(table_name).strip())
    if table is None:
        return None
    return {
        "table": table["table"],
        "granularity": table["granularity"],
        "parent": table["parent"],
        "retained_dimensions": list(table["retained_dimensions"]),
    }


def validate_summary_table_support(
    table_name: str,
    grouped_dimensions: Any,
    *,
    scope: Any = None,
    filters: Any = None,
    applied_scope_filters: Any = None,
) -> dict[str, Any]:
    table_text = str(table_name).strip()
    requested_dimensions = parse_dimensions(grouped_dimensions)
    requested_filter_columns = selected_filter_columns(scope, filters, applied_scope_filters)
    table = SUMMARY_TABLE_CATALOG.get(table_text)
    retained_dimensions = set(table["retained_dimensions"]) if table else set()
    retained_filter_columns = retained_dimensions | SUMMARY_FILTER_ALWAYS_RETAINED

    unsupported_dimensions = [
        dimension for dimension in requested_dimensions if dimension not in retained_dimensions
    ]
    unsupported_filters = [
        column for column in requested_filter_columns if column not in retained_filter_columns
    ]
    limitations: list[str] = []
    if unsupported_dimensions:
        limitations.append("unsupported_summary_dimension_set")
    if unsupported_filters:
        limitations.append("unsupported_summary_filter")

    result = {
        "generator_name": SQL_GENERATOR_NAME,
        "generator_version": SQL_GENERATOR_VERSION,
        "selected_table": table_text,
        "summary_table_known": table is not None,
        "retained_dimensions": sorted(retained_dimensions),
        "grouped_dimensions": requested_dimensions,
        "scope_filter_columns": requested_filter_columns,
        "unsupported_grouped_dimensions": unsupported_dimensions,
        "unsupported_filter_columns": unsupported_filters,
        "limitations": limitations,
        "supported": table is not None and not limitations,
    }
    if table:
        result["granularity"] = table["granularity"]
        result["parent"] = table["parent"]
    elif requested_dimensions:
        result["unsupported_grouped_dimensions"] = requested_dimensions
    return result
