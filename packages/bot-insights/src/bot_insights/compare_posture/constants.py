from __future__ import annotations


POSTURE_SCHEMA = "bot_posture_movement.v1"


MOVER_SCHEMA = "bot_mover_attribution.v1"


CONTROL_SCHEMA = "bot_control_review.v1"


POSTURE_CONSTRAINTS = [
    "movement_only",
    "no_causal_claim",
    "llm_may_summarize_structured_evidence_only",
]


MOVER_CONSTRAINTS = [
    "attribution_from_aggregate_deltas",
    "no_causal_claim",
    "llm_may_summarize_structured_evidence_only",
]


CONTROL_CONSTRAINTS = [
    "control_effectiveness_review",
    "no_causal_claim_without_external_change_evidence",
    "llm_may_summarize_structured_evidence_only",
]


VALID_EXPECTED_BASIS = {
    "before_window",
    "explicit_target",
    "external_model",
    "unknown",
}


ABSOLUTE_DELTA_DENOMINATOR_BASES = {
    "complete_scope_abs_delta",
    "complete_scope_total_abs_delta",
    "sum_abs_delta",
    "sum_abs_mover_delta",
}


METADATA_KEYS = {
    "period",
    "timestamp",
    "time",
    "bucket",
    "window",
    "label",
    "dimension",
    "value",
    "current_count",
    "baseline_count",
    "before",
    "after",
    "expected",
}
