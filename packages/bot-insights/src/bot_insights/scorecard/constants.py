from __future__ import annotations


SCORECARD_SCHEMA = "bot_entity_scorecard.v1"


INDEX_SCHEMA = "bot_scorecard_index.v1"


ARTIFACT_SCHEMA = "bot_scorecard_artifacts.v1"


SCORECARD_ERROR_SCHEMA = "bot_scorecard_error.v1"


ADVANCED_ATTRIBUTION_SCHEMA = "bot_attribution_report.v1"


ADVANCED_SCORECARD_INPUT_SCHEMA = "bot_scorecard_input.v1"


SUPPORTED_ENTITY_TYPES = (
    "client_asn",
    "request_path_norm",
    "request_host",
    "bot_class",
    "ai_category",
)


DOMAINS = (
    "movement",
    "origin_impact",
    "cache_busting",
    "crawler_governance",
    "security_evidence",
    "signal_alignment",
    "policy_collateral",
)


INTERPRETATION_CONSTRAINTS = [
    "rule_based_scorecard",
    "mechanical_features_only",
    "no_causal_claim",
    "llm_may_summarize_structured_evidence_only",
]


METADATA_KEYS = {
    "period",
    "timestamp",
    "time",
    "bucket",
    "window",
    "label",
    "dimension",
    "value",
}


ALLOWED_POPULATIONS = ("crawler", "good_bot", "ai_crawler", "all_traffic", "unknown")


PROVENANCE_KEYS = ("rowset_scope", "feature_provenance")


SIEM_INPUTS = {
    "siem_blocked_requests",
    "cnt_blocked",
    "blocked_requests",
    "siem_auth_fail_requests",
    "cnt_auth_fail",
    "auth_fail_requests",
}
