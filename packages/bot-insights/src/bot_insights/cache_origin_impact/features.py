from __future__ import annotations

from typing import Any

from .constants import SCORING_THRESHOLDS
from .helpers import clean_number


def _detector_not_evaluated_entries(
    entity: dict[str, Any],
    current: dict[str, float],
    baseline: dict[str, float],
    deltas: dict[str, float],
) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    if "unique_query_strings" not in current:
        entries.append(
            {
                "entity": entity,
                "name": "query_string_diversity_detector",
                "reason": "query_string_cardinality_absent",
                "missing_inputs": ["current.unique_query_strings"],
            }
        )
    if "cache_misses" not in current:
        entries.append(
            {
                "entity": entity,
                "name": "cache_miss_movement_detector",
                "reason": "cache_miss_metric_absent",
                "missing_inputs": ["current.cache_misses"],
            }
        )
    if not baseline:
        entries.append(
            {
                "entity": entity,
                "name": "baseline_comparison",
                "reason": "baseline_absent",
            }
        )
    if current.get("origin_p95_ms") is None:
        entries.append(
            {
                "entity": entity,
                "name": "origin_pressure_detector",
                "reason": "origin_p95_absent",
                "missing_inputs": ["current.origin_p95_ms"],
            }
        )
    elif current.get("origin_p95_ms") == 0:
        entries.append(
            {
                "entity": entity,
                "name": "origin_pressure_detector",
                "reason": "origin_p95_zero",
            }
        )
    if (
        current.get("bot_miss_share_pct") is None
        and current.get("bot_origin_pressure_share_pct") is None
    ):
        entries.append(
            {
                "entity": entity,
                "name": "bot_attribution_detector",
                "reason": "bot_class_share_unavailable",
                "missing_inputs": [
                    "current.bot_miss_share_pct",
                    "current.bot_origin_pressure_share_pct",
                ],
            }
        )
    if "origin_pressure_contribution_pct" not in deltas:
        entries.append(
            {
                "entity": entity,
                "name": "origin_pressure_contribution_pct",
                "reason": "complete_scope_denominator_absent",
                "missing_inputs": ["current_total_origin_pressure_score"],
            }
        )
    return entries


def _query_string_guard(current: dict[str, float]) -> bool:
    return (
        current.get("requests", 0) >= 1000
        and current.get("unique_query_strings", 0) >= 100
        and current.get("qs_diversity_ratio", 0) >= 0.5
    )


def _cache_miss_guard(current: dict[str, float]) -> bool:
    return current.get("requests", 0) >= 1000 and current.get("cache_misses", 0) >= 100


def _origin_pressure_guard(current: dict[str, float]) -> bool:
    return current.get("cache_misses", 0) >= 100 and current.get("origin_p95_ms", 0) > 0


def _bot_attribution_guard(current: dict[str, float]) -> bool:
    return current.get("cache_misses", 0) >= 100 and (
        current.get("bot_miss_share_pct", 0) >= 25
        or current.get("bot_origin_pressure_share_pct", 0) >= 25
    )


def _finding_types(current: dict[str, float]) -> list[str]:
    finding_types: list[str] = []
    if _query_string_guard(current):
        finding_types.append("cache_busting_candidate")
    if _cache_miss_guard(current):
        finding_types.append("cache_miss_movement_candidate")
    if _origin_pressure_guard(current):
        finding_types.append("origin_impact_candidate")
    if _bot_attribution_guard(current):
        if current.get("bot_miss_share_pct", 0) >= 25:
            finding_types.append("bot_attributable_cache_misses")
        if current.get("bot_origin_pressure_share_pct", 0) >= 25:
            finding_types.append("bot_attributable_origin_pressure")
    return finding_types


def _feature(
    name: str,
    points: int,
    value: float,
    threshold: float | dict[str, float],
) -> dict[str, Any]:
    return {
        "name": name,
        "points": points,
        "value": clean_number(value),
        "threshold": threshold,
    }


def _score_features(
    current: dict[str, float],
    deltas: dict[str, float],
) -> tuple[list[dict[str, Any]], int, str]:
    features: list[dict[str, Any]] = []

    _append_query_string_features(features, current, deltas)
    _append_miss_rate_features(features, current, deltas)
    _append_origin_impact_features(features, current, deltas)
    _append_bot_and_volume_features(features, current)

    score = min(sum(feature["points"] for feature in features), 100)
    return features, score, _score_band(score)


def _append_query_string_features(
    features: list[dict[str, Any]],
    current: dict[str, float],
    deltas: dict[str, float],
) -> None:
    qs_ratio = current.get("qs_diversity_ratio")
    if qs_ratio is not None and qs_ratio >= SCORING_THRESHOLDS["high_query_string_diversity"]:
        features.append(
            _feature(
                "high_query_string_diversity",
                20,
                qs_ratio,
                SCORING_THRESHOLDS["high_query_string_diversity"],
            )
        )
    elif (
        qs_ratio is not None
        and SCORING_THRESHOLDS["moderate_query_string_diversity"]
        <= qs_ratio
        < SCORING_THRESHOLDS["high_query_string_diversity"]
    ):
        features.append(
            _feature(
                "moderate_query_string_diversity",
                10,
                qs_ratio,
                SCORING_THRESHOLDS["moderate_query_string_diversity"],
            )
        )

    qs_delta = deltas.get("qs_diversity_delta")
    if qs_delta is not None and qs_delta >= SCORING_THRESHOLDS["query_string_diversity_increased"]:
        features.append(
            _feature(
                "query_string_diversity_increased",
                10,
                qs_delta,
                SCORING_THRESHOLDS["query_string_diversity_increased"],
            )
        )


def _append_miss_rate_features(
    features: list[dict[str, Any]],
    current: dict[str, float],
    deltas: dict[str, float],
) -> None:
    miss_rate = current.get("miss_rate_pct")
    if miss_rate is not None and miss_rate >= SCORING_THRESHOLDS["high_miss_rate"]:
        features.append(
            _feature(
                "high_miss_rate",
                15,
                miss_rate,
                SCORING_THRESHOLDS["high_miss_rate"],
            )
        )

    miss_rate_delta = deltas.get("miss_rate_delta_pp")
    if miss_rate_delta is not None and miss_rate_delta >= SCORING_THRESHOLDS["miss_rate_increased"]:
        features.append(
            _feature(
                "miss_rate_increased",
                15,
                miss_rate_delta,
                SCORING_THRESHOLDS["miss_rate_increased"],
            )
        )


def _append_origin_impact_features(
    features: list[dict[str, Any]],
    current: dict[str, float],
    deltas: dict[str, float],
) -> None:
    origin_p95_delta = deltas.get("origin_p95_delta_ms")
    origin_p95_pct_change = deltas.get("origin_p95_pct_change")
    if (
        origin_p95_delta is not None
        and origin_p95_pct_change is not None
        and origin_p95_delta >= SCORING_THRESHOLDS["origin_tail_latency_delta_ms"]
        and origin_p95_pct_change >= SCORING_THRESHOLDS["origin_tail_latency_pct_change"]
    ):
        features.append(
            _feature(
                "origin_tail_latency_increased",
                15,
                origin_p95_delta,
                {
                    "origin_p95_delta_ms": SCORING_THRESHOLDS[
                        "origin_tail_latency_delta_ms"
                    ],
                    "origin_p95_pct_change": SCORING_THRESHOLDS[
                        "origin_tail_latency_pct_change"
                    ],
                },
            )
        )

    origin_contribution = deltas.get("origin_pressure_contribution_pct")
    if (
        origin_contribution is not None
        and origin_contribution >= SCORING_THRESHOLDS["origin_pressure_contributor"]
    ):
        features.append(
            _feature(
                "origin_pressure_contributor",
                15,
                origin_contribution,
                SCORING_THRESHOLDS["origin_pressure_contributor"],
            )
        )


def _append_bot_and_volume_features(
    features: list[dict[str, Any]], current: dict[str, float]
) -> None:
    bot_share = max(
        current.get("bot_miss_share_pct", 0),
        current.get("bot_origin_pressure_share_pct", 0),
    )
    if bot_share >= SCORING_THRESHOLDS["bot_attributable_majority"]:
        features.append(
            _feature(
                "bot_attributable_majority",
                10,
                bot_share,
                SCORING_THRESHOLDS["bot_attributable_majority"],
            )
        )

    current_requests = current.get("requests")
    if (
        current_requests is not None
        and current_requests >= SCORING_THRESHOLDS["large_current_volume"]
    ):
        features.append(
            _feature(
                "large_current_volume",
                5,
                current_requests,
                SCORING_THRESHOLDS["large_current_volume"],
            )
        )


def _score_band(score: int) -> str:
    if score >= 70:
        return "high"
    if score >= 45:
        return "medium"
    if score >= 20:
        return "low"
    return "informational"


def _volume_sufficient(candidate: dict[str, Any]) -> bool:
    current = candidate.get("current", {})
    return current.get("requests", 0) >= 1000 or current.get("cache_misses", 0) >= 100


def _candidate_sort_key(candidate: dict[str, Any]) -> tuple[Any, ...]:
    current = candidate.get("current", {})
    deltas = candidate.get("deltas", {})
    return (
        0 if _volume_sufficient(candidate) else 1,
        -candidate.get("candidate_score", 0),
        -deltas.get("origin_pressure_delta", 0),
        -deltas.get("cache_misses", 0),
        -current.get("cache_misses", 0),
        -current.get("requests", 0),
    )
