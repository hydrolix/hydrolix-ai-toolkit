from __future__ import annotations

from typing import Any

from .features import (
    evaluated_zero_feature,
    make_feature,
    metric_values,
    missing_feature,
)
from .numeric import clean_number, pct_delta
from .rows import baseline_number, count_values, current_number, first_number


def eval_new_entity(
    row: dict[str, Any],
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    current, baseline = count_values(row)
    if current is None or baseline is None:
        return None, missing_feature(
            "new_entity", "movement", ["current_requests", "baseline_requests"]
        )
    if baseline < 1 and current > 0:
        return make_feature(
            "new_entity",
            "movement",
            12,
            f"Entity has {clean_number(current)} current requests and no baseline support.",
            current=current,
            baseline=baseline,
            threshold=1,
        ), None
    return evaluated_zero_feature(
        "new_entity",
        "movement",
        current=current,
        baseline=baseline,
        threshold=1,
    ), None


def eval_volume_delta_high(
    row: dict[str, Any],
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    current, baseline = count_values(row)
    if current is None or baseline is None:
        return None, missing_feature(
            "volume_delta_high", "movement", ["current_requests", "baseline_requests"]
        )
    delta = current - baseline
    change = pct_delta(current, baseline)
    if delta >= 100 and change >= 100:
        return make_feature(
            "volume_delta_high",
            "movement",
            12,
            f"Request volume increased by {clean_number(delta)} ({clean_number(change)}%).",
            current=current,
            baseline=baseline,
            threshold=100,
            supporting_metrics={
                "absolute_delta": clean_number(delta),
                "pct_change": clean_number(change),
            },
        ), None
    return evaluated_zero_feature(
        "volume_delta_high",
        "movement",
        current=current,
        baseline=baseline,
        threshold=100,
        supporting_metrics={
            "absolute_delta": clean_number(delta),
            "pct_change": clean_number(change),
        },
    ), None


def eval_contribution_to_total_delta_high(
    row: dict[str, Any],
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    contribution = first_number(
        row, ("contribution_pct", "contribution_to_total_delta_pct")
    )
    if contribution is None:
        return None, missing_feature(
            "contribution_to_total_delta_high",
            "movement",
            ["contribution_pct"],
        )
    if contribution >= 20:
        return make_feature(
            "contribution_to_total_delta_high",
            "movement",
            10,
            f"Entity contributes {clean_number(contribution)}% of the total absolute delta.",
            current=contribution,
            threshold=20,
        ), None
    return evaluated_zero_feature(
        "contribution_to_total_delta_high",
        "movement",
        current=contribution,
        threshold=20,
    ), None


def eval_bot_share_delta_high(
    row: dict[str, Any],
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    current, baseline = metric_values(row, ("bot_share_pct", "bot_pct"))
    if current is None or baseline is None:
        return None, missing_feature(
            "bot_share_delta_high",
            "movement",
            ["current_bot_share_pct", "baseline_bot_share_pct"],
        )
    delta = current - baseline
    if delta >= 10:
        return make_feature(
            "bot_share_delta_high",
            "movement",
            8,
            f"Bot share increased by {clean_number(delta)} percentage points.",
            current=current,
            baseline=baseline,
            threshold=10,
            supporting_metrics={"absolute_delta_points": clean_number(delta)},
        ), None
    return evaluated_zero_feature(
        "bot_share_delta_high",
        "movement",
        current=current,
        baseline=baseline,
        threshold=10,
        supporting_metrics={"absolute_delta_points": clean_number(delta)},
    ), None


def eval_cache_miss_rate_high(
    row: dict[str, Any],
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    current = current_number(row, "cache_miss_pct", "miss_rate_pct")
    baseline = baseline_number(row, "cache_miss_pct", "miss_rate_pct")
    if current is None:
        misses = current_number(row, "cache_misses", "cnt_cache_miss")
        requests, _ = count_values(row)
        if misses is not None and requests and requests > 0:
            current = misses / requests * 100.0
    if current is None:
        return None, missing_feature(
            "cache_miss_rate_high", "cache_busting", ["cache_miss_pct"]
        )
    if current >= 50:
        return make_feature(
            "cache_miss_rate_high",
            "cache_busting",
            10,
            f"Cache miss rate is {clean_number(current)}%.",
            current=current,
            baseline=baseline,
            threshold=50,
            supporting_metrics={
                "absolute_delta_points": clean_number(current - baseline)
            }
            if baseline is not None
            else None,
        ), None
    return evaluated_zero_feature(
        "cache_miss_rate_high",
        "cache_busting",
        current=current,
        baseline=baseline,
        threshold=50,
        supporting_metrics={"absolute_delta_points": clean_number(current - baseline)}
        if baseline is not None
        else None,
    ), None


def eval_cache_miss_delta_high(
    row: dict[str, Any],
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    current, baseline = metric_values(row, ("cache_miss_pct", "miss_rate_pct"))
    if current is None or baseline is None:
        return None, missing_feature(
            "cache_miss_delta_high",
            "cache_busting",
            ["current_cache_miss_pct", "baseline_cache_miss_pct"],
        )
    delta = current - baseline
    if delta >= 15:
        return make_feature(
            "cache_miss_delta_high",
            "cache_busting",
            8,
            f"Cache miss rate increased by {clean_number(delta)} percentage points.",
            current=current,
            baseline=baseline,
            threshold=15,
            supporting_metrics={"absolute_delta_points": clean_number(delta)},
        ), None
    return evaluated_zero_feature(
        "cache_miss_delta_high",
        "cache_busting",
        current=current,
        baseline=baseline,
        threshold=15,
        supporting_metrics={"absolute_delta_points": clean_number(delta)},
    ), None


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
