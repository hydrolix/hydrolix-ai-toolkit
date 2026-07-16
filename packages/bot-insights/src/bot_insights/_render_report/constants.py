"""Schema constants + report-type / feature-set frozensets."""

from __future__ import annotations

import re

__all__ = [
    'WRAPPER_SCHEMA',
    'POSTURE_SCHEMA',
    'MOVER_SCHEMA',
    'CONTROL_SCHEMA',
    'SCORECARD_SCHEMA',
    'INDEX_SCHEMA',
    'SCORECARD_PACKET_SCHEMA',
    'TIMESERIES_SCHEMA',
    'CACHE_ORIGIN_SCHEMA',
    'CONTROL_EXPECTED_BASES',
    'INCIDENT_SCOPE_SCHEMA',
    'INCIDENT_ACTORS_SCHEMA',
    'INCIDENT_ACTION_TARGETS_SCHEMA',
    'THREAT_HUNT_SCHEMA',
    'SUPPORTED_SCHEMAS',
    'KNOWN_UNSUPPORTED_SCHEMAS',
    'REPORT_TYPES',
    'RESERVED_CHILD_ID',
    'CRAWLER_FEATURES',
    'GENERIC_CRAWLER_RATE_FEATURES',
    'EDGE_OPS_FEATURES',
    'EDGE_OPS_DOMAINS',
    'CONFIDENCE_ORDER',
]


WRAPPER_SCHEMA = "bot_report_input.v1"


POSTURE_SCHEMA = "bot_posture_movement.v1"


MOVER_SCHEMA = "bot_mover_attribution.v1"


CONTROL_SCHEMA = "bot_control_review.v1"


SCORECARD_SCHEMA = "bot_entity_scorecard.v1"


INDEX_SCHEMA = "bot_scorecard_index.v1"


SCORECARD_PACKET_SCHEMA = "bot_scorecard_artifacts.v1"


TIMESERIES_SCHEMA = "bot_timeseries.v1"


CACHE_ORIGIN_SCHEMA = "cache_origin_impact_report.v1"


CONTROL_EXPECTED_BASES = {"before_window", "explicit_target", "external_model"}


INCIDENT_SCOPE_SCHEMA = "bot_incident_scope.v1"


INCIDENT_ACTORS_SCHEMA = "bot_incident_actors.v1"


INCIDENT_ACTION_TARGETS_SCHEMA = "bot_incident_action_targets.v1"


THREAT_HUNT_SCHEMA = "bot_threat_hunt.v3"


SUPPORTED_SCHEMAS = {
    POSTURE_SCHEMA,
    MOVER_SCHEMA,
    CONTROL_SCHEMA,
    SCORECARD_SCHEMA,
    INDEX_SCHEMA,
    SCORECARD_PACKET_SCHEMA,
    TIMESERIES_SCHEMA,
    CACHE_ORIGIN_SCHEMA,
    INCIDENT_SCOPE_SCHEMA,
    INCIDENT_ACTORS_SCHEMA,
    INCIDENT_ACTION_TARGETS_SCHEMA,
    THREAT_HUNT_SCHEMA,
}


KNOWN_UNSUPPORTED_SCHEMAS: set[str] = set()


try:
    from report_engine.contexts import REPORT_TYPE_REGISTRY
except Exception:  # pragma: no cover - defensive fallback for legacy import mode
    REPORT_TYPES = {
        "executive_posture",
        "soc_triage",
        "control_review",
        "scorecard_brief",
        "crawler_governance",
        "edge_ops_impact",
        "incident_report",
        "incident_executive_view",
    }
else:
    REPORT_TYPES = set(REPORT_TYPE_REGISTRY)


RESERVED_CHILD_ID = re.compile(r"(#index|#scorecard-\d+)$")


CRAWLER_FEATURES = {
    "rate_429_delta_high",
    "rate_5xx_delta_high",
    "good_bot_429_present",
    "good_bot_error_rate_high",
    "policy_surface_failure_present",
    "ai_crawler_growth_high",
}


GENERIC_CRAWLER_RATE_FEATURES = {"rate_429_delta_high", "rate_5xx_delta_high"}


EDGE_OPS_FEATURES = {
    "cache_miss_rate_high",
    "cache_miss_delta_high",
    "querystring_diversity_high",
    "querystring_diversity_with_high_miss_rate",
    "origin_p95_delta_high",
    "origin_cost_contribution_high",
}


EDGE_OPS_DOMAINS = {"cache_busting", "origin_impact"}


CONFIDENCE_ORDER = {"low": 0, "medium": 1, "high": 2}
