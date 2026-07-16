from __future__ import annotations

from ._shared import *

"""Normalize Bot Insights attribution aggregates into a conservative report."""


import argparse

from datetime import datetime, timezone

from decimal import Decimal, InvalidOperation, ROUND_HALF_UP

import hashlib

import json

import math

import re

import sys

from pathlib import Path

from typing import Any, Iterable, Sequence

ATTRIBUTION_SCHEMA = "bot_attribution_report.v1"

ERROR_SCHEMA = "bot_attribution_error.v1"

SQL_GENERATOR_NAME = "bot-insights-attribution-sql"

SQL_GENERATOR_VERSION = "1.0.0"

SQL_TEMPLATE_SCHEMA = "bot_attribution_sql_template.v1"

SQL_TEMPLATE_ID = "full_scope_joined_pre_limit_v1"

TRUSTED_WRAPPER_NAME = "bot-insights-attribution-runner"

TRUSTED_WRAPPER_VERSION = "1.0.0"

TRUSTED_RESULT_ORIGIN = "direct_mcp_tool_output"

TRUSTED_METADATA_ORIGIN = "direct_hydrolix_table_metadata"

TRUSTED_EVIDENCE_SOURCE = "trusted_template_generator"

DIGEST_SCHEMA_VERSION = "digest_payload_v1"

TRUSTED_WRAPPER_AVAILABLE = False

PROVIDED_CONTRIBUTION_TOLERANCE_PP = Decimal("0.01")

SAMPLE_ENTITY_VALUES_LIMIT = 10

SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

ANALYSIS_TYPES = {
    "aggregate_delta_attribution",
    "policy_displacement",
}

INTERPRETATION_CONSTRAINTS = [
    "attribution_from_aggregate_deltas",
    "movement_only",
    "no_causal_claim",
    "llm_may_summarize_structured_evidence_only",
]

WRAPPER_KEYS = (
    "input_doc",
    "input",
    "payload",
    "mcp_result",
    "mcpResult",
    "result",
    "aggregate",
    "value",
)

REPORT_FIELDS = {
    "baseline_method",
    "baseline_value_semantic",
    "baseline_windows",
    "comparison_type",
    "contribution_basis",
    "current_window",
    "dimensions",
    "filters",
    "granularity",
    "grouped_dimensions",
    "metric",
    "metric_kind",
    "output_limit",
    "output_limit_applied",
    "row_shape",
    "rowset_complete",
    "scope",
    "source_limit_applied",
    "summary_table_used",
    "table_used",
    "applied_scope_filters",
    "analysis_type",
    "policy_change",
    "policy_change_window",
    "reviewed_policy",
    "target_effect",
}

TRUST_METADATA_FIELDS = {
    "baseline_normalization",
    "generator_name",
    "generator_version",
    "limit_stage",
    "metadata_fingerprint",
    "metadata_fixture_identity",
    "metadata_origin",
    "metadata_retrieval_identity",
    "merge_expressions",
    "query_fingerprint",
    "result_digest",
    "selected_columns",
    "selected_table",
    "source_limit_stage",
    "template_id",
    "trusted_context",
    "trusted_evidence",
}

METADATA_KEYS = {
    "absolute_delta",
    "abs_delta",
    "analysis_type",
    "baseline",
    "baseline_method",
    "baseline_normalization",
    "baseline_support_count",
    "baseline_support_normalized",
    "baseline_support_raw",
    "baseline_value_semantic",
    "baseline_windows",
    "bucket",
    "caller_metric_kind_assertion",
    "columns",
    "comparison_type",
    "complete_scope_total_abs_delta",
    "contribution_basis",
    "contribution_pct",
    "current",
    "current_support_count",
    "current_support_raw",
    "current_window",
    "data",
    "dimension",
    "dimensions",
    "entity",
    "evidence_source",
    "filters",
    "generator_name",
    "granularity",
    "grouped_dimensions",
    "input_assertions",
    "label",
    "limit",
    "metadata",
    "metric",
    "metric_kind",
    "output_limit",
    "output_limit_applied",
    "pct_change",
    "period",
    "policy_change",
    "policy_change_window",
    "query_fingerprint",
    "result_digest",
    "reviewed_policy",
    "row_shape",
    "rowset_complete",
    "rows",
    "schema_version",
    "scope",
    "scorecard_export_safe",
    "source_limit_applied",
    "summary_table_used",
    "support_count",
    "support_raw",
    "table_used",
    "target_effect",
    "template_id",
    "time",
    "timestamp",
    "value",
    "window",
    "window_end",
    "window_start",
} | TRUST_METADATA_FIELDS

DIMENSION_INFERENCE_EXACT_EXCLUSIONS = {
    "absolute_delta",
    "abs_delta",
    "baseline",
    "baseline_support_count",
    "baseline_support_normalized",
    "baseline_support_raw",
    "caller_metric_kind_assertion",
    "columns",
    "complete_scope_total_abs_delta",
    "contribution_pct",
    "current",
    "current_support_count",
    "current_support_raw",
    "data",
    "entity",
    "evidence_source",
    "generator_name",
    "label",
    "metadata",
    "pct_change",
    "period",
    "query_fingerprint",
    "result_digest",
    "rows",
    "scorecard_export_safe",
    "support_count",
    "support_raw",
    "template_id",
    "time",
    "timestamp",
    "value",
    "window",
    "window_end",
    "window_start",
}

ROW_SHAPE_PERIOD_ALIASES = {
    "after": "current",
    "baseline": "baseline",
    "before": "baseline",
    "current": "current",
}

BASELINE_METHODS = {
    "single_previous_window",
    "mean_of_baseline_windows",
    "duration_weighted_mean_of_baseline_windows",
    "externally_precomputed_baseline",
}

BASELINE_VALUE_SEMANTICS = {
    "raw_total_window",
    "duration_normalized_to_current_window",
    "externally_precomputed_baseline",
}

SQL_LIMIT_STAGES = {
    "none",
    "after_denominator",
    "before_denominator",
}

METRIC_ALLOWLIST = {
    "requests": {
        "metric_kind": "additive_count",
        "aliases": (
            "requests",
            "request_count",
            "total_requests",
            "cnt_all",
            "current_requests",
            "baseline_requests",
        ),
    },
    "blocked_requests": {
        "metric_kind": "additive_count",
        "aliases": (
            "blocked_requests",
            "siem_blocked_requests",
            "cnt_blocked",
        ),
    },
    "bot_share_pct": {
        "metric_kind": "ratio",
        "aliases": (
            "bot_share_pct",
            "bot_share_percentage",
        ),
    },
}

CURRENT_SUPPORT_KEYS = (
    "current_support_raw",
    "current_support_count",
    "current_count",
    "support_current",
    "support_raw_current",
    "current.support_raw",
)

BASELINE_SUPPORT_KEYS = (
    "baseline_support_raw",
    "baseline_support_count",
    "baseline_count",
    "support_baseline",
    "support_raw_baseline",
    "baseline.support_raw",
)

PERIOD_SUPPORT_KEYS = (
    "support_raw",
    "support_count",
    "count",
    "requests",
    "cnt_all",
)

BASELINE_SUPPORT_NORMALIZED_KEYS = (
    "baseline_support_normalized",
    "support_normalized_baseline",
    "baseline.support_normalized",
)

LIMITATION_MESSAGES: dict[str, tuple[str, str]] = {
    "aggregate_rows_only": (
        "info",
        "Attribution is based on pre-aggregated current and baseline rows, not raw request inspection.",
    ),
    "no_causal_claim": (
        "required",
        "Movers explain observed aggregate delta but do not prove cause.",
    ),
    "contribution_withheld": (
        "warning",
        "Contribution percentage was not computed from a limited or incomplete rowset.",
    ),
    "period_absence_not_trusted": (
        "warning",
        "One-sided rows were excluded because public JSON cannot prove trusted period absence or zero-fill.",
    ),
    "lifecycle_support_missing": (
        "warning",
        "Lifecycle labels were not evaluated for some rows because support fields were missing or unsupported.",
    ),
    "metadata_poor_input": (
        "warning",
        "Plain MCP-style rows lacked enough metadata for stronger confidence.",
    ),
    "dimensions_inferred": (
        "info",
        "Dimensions were inferred from row columns because none were explicitly provided.",
    ),
    "caller_assertion_not_trusted": (
        "warning",
        "Caller-supplied completeness, contribution, or scorecard metadata remained assertion-only.",
    ),
    "unsupported_summary_dimension_set": (
        "warning",
        "The selected summary table does not retain every requested grouped dimension.",
    ),
    "unsupported_summary_filter": (
        "warning",
        "The selected summary table does not retain every requested scope or filter column.",
    ),
    "trusted_context_missing": (
        "warning",
        "No in-process trusted context was supplied; public JSON remains assertion-only.",
    ),
    "trusted_context_invalid": (
        "warning",
        "The supplied trusted context did not match the reviewed v1 shape.",
    ),
    "trusted_context_digest_mismatch": (
        "warning",
        "The supplied trusted context result digest did not match the recomputed digest.",
    ),
    "trusted_evidence_missing": (
        "warning",
        "No typed trusted evidence list was supplied in trusted_context.",
    ),
    "trusted_evidence_mismatch": (
        "warning",
        "Trusted evidence did not match the normalized report contract.",
    ),
    "trusted_wrapper_unavailable": (
        "warning",
        "This package does not ship the reviewed direct-MCP wrapper needed to unlock trust.",
    ),
    "query_fingerprint_missing": (
        "warning",
        "Trusted context or evidence was missing query_fingerprint.",
    ),
    "result_digest_missing": (
        "warning",
        "Trusted context or evidence was missing result_digest.",
    ),
    "provided_contribution_inconsistent": (
        "warning",
        "Provided contribution evidence was missing required consistency guarantees.",
    ),
    "duplicate_aggregation_not_trusted": (
        "warning",
        "Duplicate aggregation evidence cannot be used without the reviewed direct-MCP wrapper.",
    ),
}

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

__all__ = [name for name in globals() if not name.startswith("__")]
