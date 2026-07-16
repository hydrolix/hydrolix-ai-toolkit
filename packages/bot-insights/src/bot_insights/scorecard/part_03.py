from __future__ import annotations

from ._shared import *
from .part_01 import *
from .part_02 import *

def eval_origin_p95_delta_high(
    row: dict[str, Any],
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    current, baseline = metric_values(
        row, ("origin_p95_ms", "p95_origin_ttfb", "origin_p95_ttfb_ms")
    )
    if current is None or baseline is None:
        return None, missing_feature(
            "origin_p95_delta_high",
            "origin_impact",
            ["current_origin_p95_ms", "baseline_origin_p95_ms"],
        )
    delta = current - baseline
    change = pct_delta(current, baseline)
    if delta >= 100 and change >= 25:
        return make_feature(
            "origin_p95_delta_high",
            "origin_impact",
            10,
            f"Origin p95 increased by {clean_number(delta)} ms ({clean_number(change)}%).",
            current=current,
            baseline=baseline,
            threshold=100,
            supporting_metrics={
                "absolute_delta_ms": clean_number(delta),
                "pct_change": clean_number(change),
            },
        ), None
    return evaluated_zero_feature(
        "origin_p95_delta_high",
        "origin_impact",
        current=current,
        baseline=baseline,
        threshold=100,
        supporting_metrics={
            "absolute_delta_ms": clean_number(delta),
            "pct_change": clean_number(change),
        },
    ), None

def eval_origin_cost_contribution_high(
    row: dict[str, Any],
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    contribution = current_number(
        row, "origin_cost_contribution_pct", "origin_cost_pct"
    )
    if contribution is None:
        return None, missing_feature(
            "origin_cost_contribution_high",
            "origin_impact",
            ["origin_cost_contribution_pct"],
        )
    if contribution >= 20:
        return make_feature(
            "origin_cost_contribution_high",
            "origin_impact",
            18,
            f"Entity contributes {clean_number(contribution)}% of origin cost proxy.",
            current=contribution,
            threshold=20,
        ), None
    return evaluated_zero_feature(
        "origin_cost_contribution_high",
        "origin_impact",
        current=contribution,
        threshold=20,
    ), None

def eval_querystring_diversity_high(
    row: dict[str, Any],
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    ratio = current_number(row, "qs_diversity_ratio", "querystring_diversity_ratio")
    if ratio is None:
        return None, missing_feature(
            "querystring_diversity_high", "cache_busting", ["qs_diversity_ratio"]
        )
    if ratio >= 0.5:
        return make_feature(
            "querystring_diversity_high",
            "cache_busting",
            16,
            f"Query-string diversity ratio is {clean_number(ratio)}.",
            current=ratio,
            threshold=0.5,
        ), None
    return evaluated_zero_feature(
        "querystring_diversity_high",
        "cache_busting",
        current=ratio,
        threshold=0.5,
    ), None

def eval_querystring_diversity_with_high_miss_rate(
    row: dict[str, Any],
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    ratio = current_number(row, "qs_diversity_ratio", "querystring_diversity_ratio")
    miss_rate = current_number(row, "cache_miss_pct", "miss_rate_pct")
    if ratio is None or miss_rate is None:
        missing = []
        if ratio is None:
            missing.append("qs_diversity_ratio")
        if miss_rate is None:
            missing.append("cache_miss_pct")
        return None, missing_feature(
            "querystring_diversity_with_high_miss_rate", "cache_busting", missing
        )
    if ratio >= 0.5 and miss_rate >= 50:
        return make_feature(
            "querystring_diversity_with_high_miss_rate",
            "cache_busting",
            18,
            f"High query-string diversity coincides with {clean_number(miss_rate)}% cache misses.",
            current=ratio,
            threshold=0.5,
            supporting_metrics={
                "cache_miss_pct": clean_number(miss_rate),
                "cache_miss_threshold": 50,
            },
        ), None
    return evaluated_zero_feature(
        "querystring_diversity_with_high_miss_rate",
        "cache_busting",
        current=ratio,
        threshold=0.5,
        supporting_metrics={
            "cache_miss_pct": clean_number(miss_rate),
            "cache_miss_threshold": 50,
        },
    ), None

def eval_rate_429_delta_high(
    row: dict[str, Any],
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    current, baseline = metric_values(row, ("rate_429_pct", "rate_limited_pct"))
    if current is None or baseline is None:
        return None, missing_feature(
            "rate_429_delta_high",
            "crawler_governance",
            ["current_rate_429_pct", "baseline_rate_429_pct"],
        )
    delta = current - baseline
    if delta >= 5:
        return make_feature(
            "rate_429_delta_high",
            "crawler_governance",
            8,
            f"429 rate increased by {clean_number(delta)} percentage points.",
            current=current,
            baseline=baseline,
            threshold=5,
            supporting_metrics={"absolute_delta_points": clean_number(delta)},
        ), None
    return evaluated_zero_feature(
        "rate_429_delta_high",
        "crawler_governance",
        current=current,
        baseline=baseline,
        threshold=5,
        supporting_metrics={"absolute_delta_points": clean_number(delta)},
    ), None

def eval_rate_5xx_delta_high(
    row: dict[str, Any],
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    current, baseline = metric_values(row, ("rate_5xx_pct", "error_5xx_pct"))
    if current is None or baseline is None:
        return None, missing_feature(
            "rate_5xx_delta_high",
            "crawler_governance",
            ["current_rate_5xx_pct", "baseline_rate_5xx_pct"],
        )
    delta = current - baseline
    if delta >= 5:
        return make_feature(
            "rate_5xx_delta_high",
            "crawler_governance",
            8,
            f"5xx rate increased by {clean_number(delta)} percentage points.",
            current=current,
            baseline=baseline,
            threshold=5,
            supporting_metrics={"absolute_delta_points": clean_number(delta)},
        ), None
    return evaluated_zero_feature(
        "rate_5xx_delta_high",
        "crawler_governance",
        current=current,
        baseline=baseline,
        threshold=5,
        supporting_metrics={"absolute_delta_points": clean_number(delta)},
    ), None

def eval_good_bot_429_present(
    row: dict[str, Any],
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    good_429 = current_number(
        row, "good_bot_429_requests", "good_bot_rate_limited_429", "good_bot_429"
    )
    if good_429 is None:
        return None, missing_feature(
            "good_bot_429_present", "crawler_governance", ["good_bot_429_requests"]
        )
    if good_429 > 0:
        return make_feature(
            "good_bot_429_present",
            "crawler_governance",
            14,
            f"Good bot traffic has {clean_number(good_429)} 429 responses.",
            current=good_429,
            threshold=0,
        ), None
    return evaluated_zero_feature(
        "good_bot_429_present",
        "crawler_governance",
        current=good_429,
        threshold=0,
    ), None

def eval_good_bot_error_rate_high(
    row: dict[str, Any],
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    rate = current_number(row, "good_bot_error_rate_pct", "good_bot_errors_pct")
    if rate is None:
        return None, missing_feature(
            "good_bot_error_rate_high",
            "crawler_governance",
            ["good_bot_error_rate_pct"],
        )
    if rate >= 5:
        return make_feature(
            "good_bot_error_rate_high",
            "crawler_governance",
            12,
            f"Good bot error rate is {clean_number(rate)}%.",
            current=rate,
            threshold=5,
        ), None
    return evaluated_zero_feature(
        "good_bot_error_rate_high",
        "crawler_governance",
        current=rate,
        threshold=5,
    ), None

def eval_policy_surface_failure_present(
    row: dict[str, Any],
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    failures = current_number(
        row,
        "policy_surface_failures",
        "governance_surface_failures",
        "robots_llms_failures",
    )
    if failures is None:
        return None, missing_feature(
            "policy_surface_failure_present",
            "crawler_governance",
            ["policy_surface_failures"],
        )
    if failures > 0:
        return make_feature(
            "policy_surface_failure_present",
            "crawler_governance",
            16,
            f"Governance surfaces have {clean_number(failures)} failed requests.",
            current=failures,
            threshold=0,
        ), None
    return evaluated_zero_feature(
        "policy_surface_failure_present",
        "crawler_governance",
        current=failures,
        threshold=0,
    ), None

def eval_ai_crawler_growth_high(
    row: dict[str, Any],
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    current, baseline = metric_values(
        row, ("ai_crawler_requests", "ai_requests", "ai_crawler_share_pct")
    )
    if current is None or baseline is None:
        return None, missing_feature(
            "ai_crawler_growth_high",
            "crawler_governance",
            ["current_ai_crawler_requests", "baseline_ai_crawler_requests"],
        )
    delta = current - baseline
    change = pct_delta(current, baseline)
    if delta > 0 and change >= 100:
        return make_feature(
            "ai_crawler_growth_high",
            "crawler_governance",
            10,
            f"AI crawler metric increased by {clean_number(change)}%.",
            current=current,
            baseline=baseline,
            threshold=100,
            supporting_metrics={
                "absolute_delta": clean_number(delta),
                "pct_change": clean_number(change),
            },
        ), None
    return evaluated_zero_feature(
        "ai_crawler_growth_high",
        "crawler_governance",
        current=current,
        baseline=baseline,
        threshold=100,
        supporting_metrics={
            "absolute_delta": clean_number(delta),
            "pct_change": clean_number(change),
        },
    ), None

def eval_good_bot_policy_collateral_present(
    row: dict[str, Any],
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    affected = current_number(
        row,
        "good_bot_collateral_429_requests",
        "collateral_good_bot_429_requests",
        "policy_collateral_good_bot_429_requests",
        "good_bot_429_requests",
        "good_bot_rate_limited_429",
    )
    if affected is None:
        return None, missing_feature(
            "good_bot_policy_collateral_present",
            "policy_collateral",
            ["good_bot_collateral_429_requests"],
        )
    if affected > 0:
        return make_feature(
            "good_bot_policy_collateral_present",
            "policy_collateral",
            16,
            f"Policy collateral check found {clean_number(affected)} good bot 429 responses.",
            current=affected,
            threshold=0,
        ), None
    return evaluated_zero_feature(
        "good_bot_policy_collateral_present",
        "policy_collateral",
        current=affected,
        threshold=0,
    ), None

def eval_policy_collateral_error_rate_high(
    row: dict[str, Any],
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    rate = current_number(
        row,
        "policy_collateral_error_rate_pct",
        "collateral_error_rate_pct",
        "good_bot_collateral_error_rate_pct",
        "good_bot_error_rate_pct",
        "good_bot_errors_pct",
    )
    if rate is None:
        return None, missing_feature(
            "policy_collateral_error_rate_high",
            "policy_collateral",
            ["policy_collateral_error_rate_pct"],
        )
    if rate >= 5:
        return make_feature(
            "policy_collateral_error_rate_high",
            "policy_collateral",
            12,
            f"Policy collateral error rate is {clean_number(rate)}%.",
            current=rate,
            threshold=5,
        ), None
    return evaluated_zero_feature(
        "policy_collateral_error_rate_high",
        "policy_collateral",
        current=rate,
        threshold=5,
    ), None

def displacement_inputs_present(row: dict[str, Any]) -> bool:
    names = (
        "displacement_requests",
        "other_scope_requests",
        "post_policy_displacement_requests",
    )
    keys = prefixed_keys("current", names) + prefixed_keys("baseline", names) + names
    return any(key in row for key in keys)

__all__ = [name for name in globals() if not name.startswith("__")]
