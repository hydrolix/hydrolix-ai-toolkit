from __future__ import annotations

from typing import Any

from .constants import (
    CONFIDENCE_ORDER,
    LOW_CONFIDENCE_LIMITATIONS,
    LOW_CONFIDENCE_REASONS,
    MEDIUM_ONLY_CONFIDENCE_REASONS,
    SUFFICIENT_CACHE_MISS_COUNT,
    SUFFICIENT_REQUEST_COUNT,
    SUPPORTED_DIMENSION_SET_KEYS,
)
from .helpers import clean_number


def _current_bucket_is_partial(data: dict[str, Any]) -> bool:
    current_window = data.get("current_window")
    return (
        data.get("partial_current_bucket") is True
        or data.get("current_bucket_partial") is True
        or (
            isinstance(current_window, dict)
            and (
                current_window.get("partial") is True
                or current_window.get("partial_bucket") is True
            )
        )
    )


def _table_confidence_reasons(
    data: dict[str, Any],
    dimensions: list[str],
    normalization: dict[str, Any],
) -> list[str]:
    reasons: list[str] = []
    table_used = str(data.get("table_used") or "")

    if "trusted_context" in data:
        reasons.append("caller_supplied_json_confidence_cap")
    if data.get("summary_table_used") is True:
        reasons.append("summary_table_used")
    if (
        data.get("summary_table_used") is False
        or data.get("request_level_query") is True
        or table_used in {"bot_detection", "bot_detection_siem"}
    ):
        reasons.append("request_level_query")

    if (
        table_used.startswith("bot_agg_path_")
        or data.get("path_summary_used") is True
    ):
        reasons.append("path_summary_used")

    missing_retained = data.get("missing_retained_dimensions")
    if missing_retained:
        reasons.append("missing_retained_dimension")
    else:
        row_dimensions = [
            dimension
            for dimension in dimensions
            if dimension != "request_host"
        ]
        if frozenset(row_dimensions) in SUPPORTED_DIMENSION_SET_KEYS:
            reasons.append("retained_dimensions_fit")

    if normalization.get("method") == "duration_normalized_additive_metrics":
        reasons.append("baseline_duration_normalized")
    if _current_bucket_is_partial(data):
        reasons.append("partial_current_bucket")
    return reasons


def _candidate_count_confidence_reasons(
    current: dict[str, float],
    baseline: dict[str, float],
) -> list[str]:
    reasons: list[str] = []
    current_requests = current.get("requests")
    baseline_requests = baseline.get("requests")
    current_cache_misses = current.get("cache_misses")

    if current_requests is not None and current_requests >= SUFFICIENT_REQUEST_COUNT:
        reasons.append("current_count_sufficient")
    if baseline_requests is not None and baseline_requests >= SUFFICIENT_REQUEST_COUNT:
        reasons.append("baseline_count_sufficient")

    sparse = False
    if current_requests is not None and current_requests < SUFFICIENT_REQUEST_COUNT:
        sparse = True
    if (
        current_cache_misses is not None
        and current_cache_misses < SUFFICIENT_CACHE_MISS_COUNT
    ):
        sparse = True
    if (
        baseline
        and baseline_requests is not None
        and baseline_requests < SUFFICIENT_REQUEST_COUNT
    ):
        sparse = True
    if sparse:
        reasons.append("sparse_counts")
    return reasons


def _response_bytes_optional_metadata(
    current: dict[str, float],
    baseline: dict[str, float],
) -> dict[str, Any]:
    current_bytes = current.get("response_bytes")
    baseline_bytes = baseline.get("response_bytes")
    if current_bytes is None and baseline_bytes is None:
        return {
            "available": False,
            "reason": "not_present_in_selected_path_summary",
        }

    metadata: dict[str, Any] = {"available": True}
    if current_bytes is not None:
        metadata["current"] = clean_number(current_bytes)
    if baseline_bytes is not None:
        metadata["baseline"] = clean_number(baseline_bytes)
    return metadata


def _summary_context_metadata(data: dict[str, Any]) -> dict[str, Any] | None:
    context = data.get("summary_context")
    if context is None:
        return None
    if not isinstance(context, dict):
        return {
            "available": False,
            "reason": "malformed_summary_context",
            "limitations": ["host_scope_context_not_path_level_evidence"],
        }

    metadata = dict(context)
    metadata["available"] = True
    limitations = list(metadata.get("limitations", []))
    if "host_scope_context_not_path_level_evidence" not in limitations:
        limitations.append("host_scope_context_not_path_level_evidence")
    metadata["limitations"] = limitations
    return metadata


def _candidate_limitations(
    confidence_reasons: list[str],
    not_evaluated: list[dict[str, Any]],
    optional_metadata: dict[str, Any],
    data: dict[str, Any],
) -> list[str]:
    limitations: set[str] = set()
    reason_set = set(confidence_reasons)
    limitations.update(
        reason
        for reason in (
            "query_string_cardinality_approximate",
            "request_level_query",
            "missing_retained_dimension",
            "contribution_withheld_source_limited",
            "partial_current_bucket",
        )
        if reason in reason_set
    )

    response_metadata = optional_metadata.get("response_bytes")
    if isinstance(response_metadata, dict) and not response_metadata.get("available"):
        limitations.add("response_byte_metadata_not_available")
    limitations.update(_summary_context_limitations(optional_metadata))
    limitations.update(_not_evaluated_limitations(not_evaluated))
    if data.get("source_limited") is True or data.get("rowset_complete") is False:
        limitations.add("source_limited_rowset")
    request_level_scope = str(data.get("request_level_scope") or "").lower()
    if request_level_scope == "broad" or data.get("broad_request_level_query") is True:
        limitations.add("broad_request_level_query")
    return sorted(limitations)


def _summary_context_limitations(optional_metadata: dict[str, Any]) -> set[str]:
    bot_context = optional_metadata.get("summary_context")
    if not isinstance(bot_context, dict):
        return set()
    return {
        limitation
        for limitation in bot_context.get("limitations", [])
        if isinstance(limitation, str)
    }


def _not_evaluated_limitations(not_evaluated: list[dict[str, Any]]) -> set[str]:
    limitations: set[str] = set()
    if any(entry.get("reason") == "baseline_absent" for entry in not_evaluated):
        limitations.add("missing_baseline")
    for entry in not_evaluated:
        if entry.get("name") not in {
            "cache_miss_contribution_pct",
            "origin_pressure_contribution_pct",
        }:
            continue
        if entry.get("reason") == "complete_scope_denominator_absent":
            limitations.add("contribution_denominator_absent")
        if entry.get("reason") == "contribution_withheld_source_limited":
            limitations.add("contribution_withheld_source_limited")
    return limitations


def _confidence_label(
    confidence_reasons: list[str],
    limitations: list[str],
    *,
    trusted_context_complete: bool,
) -> str:
    if (
        trusted_context_complete
        and "direct_mcp_trusted_context" in confidence_reasons
        and not (set(confidence_reasons) & LOW_CONFIDENCE_REASONS)
        and not (set(confidence_reasons) & MEDIUM_ONLY_CONFIDENCE_REASONS)
        and not (set(limitations) & LOW_CONFIDENCE_LIMITATIONS)
    ):
        return "high"
    if set(confidence_reasons) & LOW_CONFIDENCE_REASONS:
        return "low"
    if set(limitations) & LOW_CONFIDENCE_LIMITATIONS:
        return "low"
    return "medium"


def _lowest_confidence(labels: list[str]) -> str:
    if not labels:
        return "medium"
    return min(labels, key=lambda label: CONFIDENCE_ORDER.get(label, 1))


def _truthy_context_value(context: dict[str, Any], *keys: str) -> bool:
    return any(bool(context.get(key)) for key in keys)


def _trusted_context_complete(
    trusted_context: dict[str, Any] | None,
    dimensions: list[str],
) -> bool:
    if not isinstance(trusted_context, dict):
        return False

    retained_dimensions = trusted_context.get("retained_dimensions")
    retained_dimensions_fit = trusted_context.get("retained_dimensions_fit") is True
    if isinstance(retained_dimensions, list):
        retained = {str(dimension) for dimension in retained_dimensions}
        expected = {
            dimension
            for dimension in dimensions
            if dimension != "request_host"
        }
        retained_dimensions_fit = retained_dimensions_fit or expected.issubset(retained)

    digest_proven = bool(trusted_context.get("query_result_digest")) or (
        bool(trusted_context.get("query_digest"))
        and bool(trusted_context.get("result_digest"))
    )
    direct_mcp = (
        trusted_context.get("direct_mcp_trusted_context") is True
        or trusted_context.get("source") == "direct_mcp"
    )

    return all(
        (
            direct_mcp,
            _truthy_context_value(trusted_context, "table_metadata", "table_info"),
            retained_dimensions_fit,
            digest_proven,
            _truthy_context_value(trusted_context, "comparable_windows"),
            _truthy_context_value(trusted_context, "current_count_sufficient"),
            _truthy_context_value(trusted_context, "baseline_count_sufficient"),
            _truthy_context_value(trusted_context, "complete_scope_contribution"),
        )
    )
