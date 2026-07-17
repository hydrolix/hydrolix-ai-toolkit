from __future__ import annotations


REPORT_SCHEMA = "cache_origin_impact_report.v1"


ANALYSIS_TYPE = "cache_busting_origin_impact"


SUPPORTED_ROW_DIMENSION_SETS = (
    ("request_path_norm",),
    ("request_path_norm", "bot_class"),
    ("request_path_norm", "asn_type"),
    ("request_path_norm", "bot_class", "asn_type"),
)


ACCEPTED_HOST_CONTEXT_FORMS = (
    "scope.request_host",
    "row_level_request_host",
)


INTERPRETATION_CONSTRAINTS = [
    "mechanical_candidate_only",
    "no_causal_claim",
    "origin_pressure_score_is_proxy",
    "not_a_billing_or_capacity_unit",
    "llm_may_summarize_structured_evidence_only",
]


SUPPORTED_DIMENSIONS = {"request_host", "request_path_norm", "bot_class", "asn_type"}


SUPPORTED_DIMENSION_SET_KEYS = {
    frozenset(dimensions) for dimensions in SUPPORTED_ROW_DIMENSION_SETS
}


PERIOD_VALUES = {"current", "baseline", "after", "before"}


METADATA_KEYS = {
    "period",
    "timestamp",
    "time",
    "bucket",
    "window",
    "label",
}


DIMENSION_KEYS = {"request_host", "request_path_norm", "bot_class", "asn_type"}


CANONICAL_ALIASES = {
    "requests": ("requests", "total_requests", "cnt_all"),
    "cache_misses": ("cache_misses", "cnt_cache_miss"),
    "unique_query_strings": ("unique_query_strings", "uniq_qs"),
    "origin_p95_ms": (
        "origin_p95_ms",
        "p95_origin_ttfb",
        "p95_origin_ttfb_ms",
        "origin_ttfb_p95_ms",
    ),
    "origin_p99_ms": (
        "origin_p99_ms",
        "p99_origin_ttfb",
        "p99_origin_ttfb_ms",
        "origin_ttfb_p99_ms",
    ),
    "response_bytes": ("response_bytes", "response_total_bytes"),
}


ALIAS_TO_CANONICAL = {
    alias: canonical
    for canonical, aliases in CANONICAL_ALIASES.items()
    for alias in aliases
}


ADDITIVE_BASELINE_METRICS = {"requests", "cache_misses", "response_bytes"}


SUFFICIENT_REQUEST_COUNT = 1000


SUFFICIENT_CACHE_MISS_COUNT = 100


CONFIDENCE_ORDER = {"low": 0, "medium": 1, "high": 2}


LOW_CONFIDENCE_REASONS = {
    "sparse_counts",
    "missing_retained_dimension",
    "contribution_withheld_source_limited",
    "partial_current_bucket",
}


LOW_CONFIDENCE_LIMITATIONS = {
    "missing_baseline",
    "broad_request_level_query",
    "source_limited_rowset",
}


MEDIUM_ONLY_CONFIDENCE_REASONS = {
    "caller_supplied_json_confidence_cap",
    "query_string_cardinality_approximate",
    "origin_latency_worst_bucket",
}


PERIOD_ALIASES = {
    "current": "current",
    "after": "current",
    "baseline": "baseline",
    "before": "baseline",
}


DERIVED_METRIC_INPUTS = {
    "current_miss_rate_pct": ("current", ("requests", "cache_misses")),
    "baseline_miss_rate_pct": ("baseline", ("requests", "cache_misses")),
    "current_qs_diversity_ratio": (
        "current",
        ("requests", "unique_query_strings"),
    ),
    "baseline_qs_diversity_ratio": (
        "baseline",
        ("requests", "unique_query_strings"),
    ),
    "current_origin_pressure_score": (
        "current",
        ("cache_misses", "origin_p95_ms"),
    ),
    "baseline_origin_pressure_score": (
        "baseline",
        ("cache_misses", "origin_p95_ms"),
    ),
    "request_delta": ("delta", ("current.requests", "baseline.requests")),
    "cache_miss_delta": (
        "delta",
        ("current.cache_misses", "baseline.cache_misses"),
    ),
    "miss_rate_delta_pp": (
        "delta",
        ("current.miss_rate_pct", "baseline.miss_rate_pct"),
    ),
    "qs_diversity_delta": (
        "delta",
        ("current.qs_diversity_ratio", "baseline.qs_diversity_ratio"),
    ),
    "origin_p95_delta_ms": (
        "delta",
        ("current.origin_p95_ms", "baseline.origin_p95_ms"),
    ),
    "origin_p99_delta_ms": (
        "delta",
        ("current.origin_p99_ms", "baseline.origin_p99_ms"),
    ),
    "cache_miss_pct_change": (
        "delta",
        ("current.cache_misses", "baseline.cache_misses"),
    ),
    "origin_p95_pct_change": (
        "delta",
        ("current.origin_p95_ms", "baseline.origin_p95_ms"),
    ),
    "origin_pressure_delta": (
        "delta",
        (
            "current.origin_pressure_score",
            "baseline.origin_pressure_score",
        ),
    ),
}


COMPLETE_SCOPE_BASIS_VALUES = {
    "complete_scope",
    "complete_scope_pre_limit",
}


SOURCE_LIMITED_BASIS_VALUES = {
    "source_limited",
    "limited_source_rows",
    "post_limit",
}


SCORING_THRESHOLDS = {
    "high_query_string_diversity": 0.8,
    "moderate_query_string_diversity": 0.5,
    "query_string_diversity_increased": 0.25,
    "high_miss_rate": 80.0,
    "miss_rate_increased": 10.0,
    "origin_tail_latency_delta_ms": 100.0,
    "origin_tail_latency_pct_change": 50.0,
    "origin_pressure_contributor": 10.0,
    "bot_attributable_majority": 50.0,
    "large_current_volume": 10000.0,
}


SEMANTIC_REQUIREMENT_KEYS = {
    "unique_query_strings": (
        "unique_query_strings",
        "query_string_cardinality",
        "uniq_qs",
    ),
    "origin_p95_ms": (
        "origin_p95_ms",
        "origin_latency",
        "origin_percentiles",
        "p95_origin_ttfb",
    ),
    "origin_p99_ms": (
        "origin_p99_ms",
        "origin_latency",
        "origin_percentiles",
        "p99_origin_ttfb",
    ),
    "contribution_fields": (
        "contribution_fields",
        "cache_miss_contribution_pct",
        "origin_pressure_contribution_pct",
    ),
}
