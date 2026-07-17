from __future__ import annotations

from typing import Any, Callable

from .evaluators_governance import (
    eval_ai_crawler_growth_high,
    eval_bad_bot_share_high,
    eval_displacement_delta_high,
    eval_good_bot_429_present,
    eval_good_bot_error_rate_high,
    eval_good_bot_policy_collateral_present,
    eval_policy_collateral_error_rate_high,
    eval_policy_surface_failure_present,
    eval_rate_429_delta_high,
    eval_rate_5xx_delta_high,
    eval_siem_auth_fail_present,
    eval_siem_blocked_present,
)
from .evaluators_movement import (
    eval_bot_share_delta_high,
    eval_cache_miss_delta_high,
    eval_cache_miss_rate_high,
    eval_contribution_to_total_delta_high,
    eval_new_entity,
    eval_origin_cost_contribution_high,
    eval_origin_p95_delta_high,
    eval_querystring_diversity_high,
    eval_querystring_diversity_with_high_miss_rate,
    eval_volume_delta_high,
)


FeatureEvaluator = Callable[
    [dict[str, Any]], tuple[dict[str, Any] | None, dict[str, Any] | None]
]


FEATURE_EVALUATORS: tuple[FeatureEvaluator, ...] = (
    eval_new_entity,
    eval_volume_delta_high,
    eval_contribution_to_total_delta_high,
    eval_bot_share_delta_high,
    eval_cache_miss_rate_high,
    eval_cache_miss_delta_high,
    eval_origin_p95_delta_high,
    eval_origin_cost_contribution_high,
    eval_querystring_diversity_high,
    eval_querystring_diversity_with_high_miss_rate,
    eval_rate_429_delta_high,
    eval_rate_5xx_delta_high,
    eval_good_bot_429_present,
    eval_good_bot_error_rate_high,
    eval_policy_surface_failure_present,
    eval_ai_crawler_growth_high,
    eval_good_bot_policy_collateral_present,
    eval_policy_collateral_error_rate_high,
    eval_displacement_delta_high,
    eval_siem_blocked_present,
    eval_siem_auth_fail_present,
    eval_bad_bot_share_high,
)


BASELINE_POINT_IN_TIME_EVALUATORS: tuple[FeatureEvaluator, ...] = (
    eval_cache_miss_rate_high,
    eval_origin_cost_contribution_high,
    eval_querystring_diversity_high,
    eval_querystring_diversity_with_high_miss_rate,
    eval_good_bot_429_present,
    eval_good_bot_error_rate_high,
    eval_policy_surface_failure_present,
    eval_good_bot_policy_collateral_present,
    eval_policy_collateral_error_rate_high,
    eval_siem_blocked_present,
    eval_siem_auth_fail_present,
    eval_bad_bot_share_high,
)


BASELINE_SCORE_DELTA_BASIS = (
    "Baseline score is recomputed from baseline-period point-in-time rule inputs; "
    "rules requiring pre-baseline delta inputs are excluded."
)
