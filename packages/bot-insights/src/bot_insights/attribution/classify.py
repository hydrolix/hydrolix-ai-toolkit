from __future__ import annotations

from typing import Any

from .constants import LIMITATION_MESSAGES
from .numeric import clean_number


def classify_row(
    row: dict[str, Any],
    *,
    min_count: float,
) -> dict[str, Any]:
    current = row["current"]
    baseline = row["baseline"]
    current_support = row.get("current_support_raw")
    baseline_support = row.get("baseline_support_raw")

    if current is None or baseline is None:
        return {"emit": False, "skip_reason": "period_absence_not_trusted"}

    if current_support is None or baseline_support is None:
        return {
            "emit": True,
            "presence_lifecycle": "not_evaluated",
            "support_change_label": "not_evaluated",
            "candidate_flags": [],
            "confidence_reasons": ["lifecycle_not_evaluated", "lifecycle_support_missing"],
        }

    if current_support <= 0 and baseline_support <= 0:
        return {"emit": False, "skip_reason": "period_absence_not_trusted"}

    if current_support > 0 and baseline_support > 0:
        reasons: list[str] = []
        candidate_flags: list[str] = []
        if current_support < min_count and baseline_support < min_count:
            candidate_flags.append("below_support_threshold")
            reasons.append("sparse_counts")
        elif current_support < min_count:
            candidate_flags.append("sparse_current_support")
            reasons.append("sparse_counts")
        elif baseline_support < min_count:
            candidate_flags.append("sparse_baseline_support")
            reasons.append("sparse_counts")
        else:
            reasons.extend(["current_support_sufficient", "baseline_support_sufficient"])

        if current_support > baseline_support:
            support_change = "support_increase"
        elif current_support < baseline_support:
            support_change = "support_decrease"
        else:
            support_change = "support_unchanged"
        reasons.append(support_change)

        return {
            "emit": True,
            "presence_lifecycle": "existing",
            "support_change_label": support_change,
            "candidate_flags": candidate_flags,
            "confidence_reasons": reasons,
        }

    if baseline_support <= 0 < current_support:
        if current_support < min_count:
            return {
                "emit": True,
                "presence_lifecycle": "not_evaluated",
                "support_change_label": "not_evaluated",
                "candidate_flags": ["sparse_new_candidate"],
                "confidence_reasons": ["lifecycle_not_evaluated", "sparse_counts"],
            }
        return {"emit": False, "skip_reason": "period_absence_not_trusted"}

    if current_support <= 0 < baseline_support:
        if baseline_support < min_count:
            return {
                "emit": True,
                "presence_lifecycle": "not_evaluated",
                "support_change_label": "not_evaluated",
                "candidate_flags": ["sparse_disappeared_candidate"],
                "confidence_reasons": ["lifecycle_not_evaluated", "sparse_counts"],
            }
        return {"emit": False, "skip_reason": "period_absence_not_trusted"}

    return {
        "emit": True,
        "presence_lifecycle": "not_evaluated",
        "support_change_label": "not_evaluated",
        "candidate_flags": [],
        "confidence_reasons": ["lifecycle_not_evaluated"],
    }


def dimension_sort_key(values: dict[str, str | None], dimensions: list[str]) -> tuple[tuple[bool, str], ...]:
    return tuple(
        (values.get(dimension) is None, "" if values.get(dimension) is None else str(values.get(dimension)))
        for dimension in dimensions
    )


def limitation_doc(code: str) -> dict[str, Any]:
    severity, message = LIMITATION_MESSAGES[code]
    return {"code": code, "severity": severity, "message": message}


def build_buckets(movers: list[dict[str, Any]]) -> dict[str, Any]:
    buckets = {
        "basis": "returned_rows",
        "increasing_count": 0,
        "decreasing_count": 0,
        "existing_count": 0,
        "new_count": 0,
        "disappeared_count": 0,
        "absent_count": 0,
        "not_evaluated_count": 0,
        "support_increase_count": 0,
        "support_decrease_count": 0,
        "support_unchanged_count": 0,
        "support_zero_both_count": 0,
        "support_not_evaluated_count": 0,
    }
    for mover in movers:
        if mover["direction"] == "increase":
            buckets["increasing_count"] += 1
        elif mover["direction"] == "decrease":
            buckets["decreasing_count"] += 1

        lifecycle = mover["presence_lifecycle"]
        if lifecycle == "existing":
            buckets["existing_count"] += 1
        elif lifecycle == "new":
            buckets["new_count"] += 1
        elif lifecycle == "disappeared":
            buckets["disappeared_count"] += 1
        elif lifecycle == "not_evaluated":
            buckets["not_evaluated_count"] += 1

        support_change = mover["support_change_label"]
        if support_change == "support_increase":
            buckets["support_increase_count"] += 1
        elif support_change == "support_decrease":
            buckets["support_decrease_count"] += 1
        elif support_change == "support_unchanged":
            buckets["support_unchanged_count"] += 1
        elif support_change == "not_evaluated":
            buckets["support_not_evaluated_count"] += 1
    return buckets


def movement_extreme(
    movers: list[dict[str, Any]],
    *,
    direction_name: str,
) -> dict[str, Any] | None:
    selected = [
        mover
        for mover in movers
        if mover.get("direction") == direction_name
    ]
    if not selected:
        return None
    if direction_name == "increase":
        mover = max(selected, key=lambda item: float(item["absolute_delta"]))
    else:
        mover = min(selected, key=lambda item: float(item["absolute_delta"]))
    return {
        "rank": mover.get("rank"),
        "values": mover.get("values", {}),
        "absolute_delta": mover.get("absolute_delta"),
        "pct_change": mover.get("pct_change"),
        "confidence": mover.get("confidence"),
    }


def displacement_summary(movers: list[dict[str, Any]]) -> dict[str, Any]:
    positive_delta = sum(
        max(float(mover["absolute_delta"]), 0.0)
        for mover in movers
    )
    negative_delta = sum(
        min(float(mover["absolute_delta"]), 0.0)
        for mover in movers
    )
    summary = {
        "basis": "returned_rows",
        "increase_count": sum(1 for mover in movers if mover["direction"] == "increase"),
        "decrease_count": sum(1 for mover in movers if mover["direction"] == "decrease"),
        "total_positive_delta": clean_number(positive_delta),
        "total_negative_delta": clean_number(negative_delta),
        "net_delta": clean_number(positive_delta + negative_delta),
        "largest_increase": movement_extreme(movers, direction_name="increase"),
        "largest_decrease": movement_extreme(movers, direction_name="decrease"),
    }
    return summary
