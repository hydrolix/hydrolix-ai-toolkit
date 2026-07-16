from __future__ import annotations

from typing import Any

from .features import (
    evaluated_zero_feature,
    make_feature,
    metric_values,
    missing_feature,
)
from .numeric import clean_number, pct_delta
from .rows import current_number, prefixed_keys


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


def eval_displacement_delta_high(
    row: dict[str, Any],
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    if not displacement_inputs_present(row):
        return None, missing_feature(
            "displacement_delta_high",
            "policy_collateral",
            ["current_displacement_requests", "baseline_displacement_requests"],
        )
    current, baseline = metric_values(
        row,
        (
            "displacement_requests",
            "other_scope_requests",
            "post_policy_displacement_requests",
        ),
    )
    if current is None or baseline is None:
        return None, missing_feature(
            "displacement_delta_high",
            "policy_collateral",
            ["current_displacement_requests", "baseline_displacement_requests"],
        )
    delta = current - baseline
    change = pct_delta(current, baseline)
    if delta >= 100 and change >= 50:
        return make_feature(
            "displacement_delta_high",
            "policy_collateral",
            12,
            f"Displacement metric increased by {clean_number(delta)} ({clean_number(change)}%).",
            current=current,
            baseline=baseline,
            threshold=100,
            supporting_metrics={
                "absolute_delta": clean_number(delta),
                "pct_change": clean_number(change),
            },
        ), None
    return evaluated_zero_feature(
        "displacement_delta_high",
        "policy_collateral",
        current=current,
        baseline=baseline,
        threshold=100,
        supporting_metrics={
            "absolute_delta": clean_number(delta),
            "pct_change": clean_number(change),
        },
    ), None


def eval_siem_blocked_present(
    row: dict[str, Any],
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    blocked = current_number(
        row, "siem_blocked_requests", "cnt_blocked", "blocked_requests"
    )
    if blocked is None:
        return None, missing_feature(
            "siem_blocked_present", "security_evidence", ["siem_blocked_requests"]
        )
    if blocked > 0:
        return make_feature(
            "siem_blocked_present",
            "security_evidence",
            12,
            f"SIEM summary reports {clean_number(blocked)} blocked requests.",
            current=blocked,
            threshold=0,
        ), None
    return evaluated_zero_feature(
        "siem_blocked_present",
        "security_evidence",
        current=blocked,
        threshold=0,
    ), None


def eval_siem_auth_fail_present(
    row: dict[str, Any],
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    failures = current_number(
        row, "siem_auth_fail_requests", "cnt_auth_fail", "auth_fail_requests"
    )
    if failures is None:
        return None, missing_feature(
            "siem_auth_fail_present", "security_evidence", ["siem_auth_fail_requests"]
        )
    if failures > 0:
        return make_feature(
            "siem_auth_fail_present",
            "security_evidence",
            12,
            f"SIEM summary reports {clean_number(failures)} auth failures.",
            current=failures,
            threshold=0,
        ), None
    return evaluated_zero_feature(
        "siem_auth_fail_present",
        "security_evidence",
        current=failures,
        threshold=0,
    ), None


def eval_bad_bot_share_high(
    row: dict[str, Any],
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    share = current_number(row, "bad_bot_share_pct", "bad_bot_pct")
    if share is None:
        return None, missing_feature(
            "bad_bot_share_high", "security_evidence", ["bad_bot_share_pct"]
        )
    if share >= 50:
        return make_feature(
            "bad_bot_share_high",
            "security_evidence",
            14,
            f"Bad bot share is {clean_number(share)}%.",
            current=share,
            threshold=50,
        ), None
    return evaluated_zero_feature(
        "bad_bot_share_high",
        "security_evidence",
        current=share,
        threshold=50,
    ), None
