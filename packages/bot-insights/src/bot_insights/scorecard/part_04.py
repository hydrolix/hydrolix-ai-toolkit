from __future__ import annotations

from ._shared import *
from .part_01 import *
from .part_02 import *
from .part_03 import *

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

def score_band(score: int) -> str:
    if score <= 20:
        return "urgent_review"
    if score <= 40:
        return "high_review"
    if score <= 60:
        return "medium_review"
    if score <= 80:
        return "low_review"
    return "observe"

def baseline_period_row(row: dict[str, Any]) -> dict[str, Any]:
    baseline: dict[str, Any] = {}
    for key, value in row.items():
        if key == "baseline":
            baseline["current"] = value
        elif key.startswith("baseline_"):
            baseline[f"current_{key.removeprefix('baseline_')}"] = value
        elif key.endswith("_baseline"):
            baseline[f"{key.removesuffix('_baseline')}_current"] = value
        elif key.startswith("baseline."):
            baseline[f"current.{key.removeprefix('baseline.')}"] = value
    return baseline

def baseline_score(row: dict[str, Any], active_domains: tuple[str, ...]) -> int:
    features: list[dict[str, Any]] = []
    baseline_row = baseline_period_row(row)
    for evaluator in BASELINE_POINT_IN_TIME_EVALUATORS:
        feature, _missing = evaluator(baseline_row)
        if (
            feature is not None
            and feature.get("domain") in active_domains
            and int(feature.get("points") or 0) > 0
        ):
            features.append(feature)
    risk_points = min(100, sum(int(feature["points"]) for feature in features))
    return 100 - risk_points

def siem_inputs_available(row: dict[str, Any]) -> bool:
    return current_number(row, *tuple(SIEM_INPUTS)) is not None

def confidence(
    row: dict[str, Any],
    metadata: dict[str, Any],
    not_evaluated: list[dict[str, Any]],
    min_count: float,
    analysis_domains: tuple[str, ...],
) -> tuple[str, list[str]]:
    reasons: list[str] = []
    table_used = metadata_text(metadata.get("table_used", ""))
    _append_scorecard_table_reasons(reasons, table_used, metadata)
    current_count, baseline_count = count_values(row)
    _append_scorecard_count_reasons(
        reasons, current_count, baseline_count, min_count
    )
    _append_scorecard_caveat_reasons(
        reasons, row, metadata, not_evaluated, analysis_domains
    )

    return _scorecard_confidence_label(reasons), reasons

def _append_scorecard_table_reasons(
    reasons: list[str], table_used: str, metadata: dict[str, Any]
) -> None:
    summary_table_used = metadata.get("summary_table_used")
    if summary_table_used is None:
        summary_table_used = bool(
            table_used and table_used not in {"bot_detection", "bot_detection_siem"}
        )
    if summary_table_used:
        reasons.append("summary_table_used")
        reasons.append("retained_dimensions_fit")
    else:
        reasons.append("request_level_query")

def _append_scorecard_count_reasons(
    reasons: list[str],
    current_count: float | None,
    baseline_count: float | None,
    min_count: float,
) -> None:
    sparse = False
    if current_count is not None:
        if current_count >= min_count:
            reasons.append("current_count_sufficient")
        else:
            sparse = True
    if baseline_count is not None:
        if baseline_count >= min_count:
            reasons.append("baseline_count_sufficient")
        else:
            sparse = True
    if sparse:
        reasons.append("sparse_counts")
    if baseline_count is not None and baseline_count < 1:
        reasons.append("zero_baseline_guard")

def _append_scorecard_caveat_reasons(
    reasons: list[str],
    row: dict[str, Any],
    metadata: dict[str, Any],
    not_evaluated: list[dict[str, Any]],
    analysis_domains: tuple[str, ...],
) -> None:
    if metadata.get("source_coverage_caveat") or metadata.get("source_caveats"):
        reasons.append("source_coverage_caveat")
    if "security_evidence" in analysis_domains and not siem_inputs_available(row):
        reasons.append("siem_unavailable")
    if not_evaluated:
        reasons.append("feature_input_missing")

def _scorecard_confidence_label(reasons: list[str]) -> str:
    low_reasons = {"request_level_query", "sparse_counts"}
    if any(reason in reasons for reason in low_reasons):
        return "low"
    if (
        "source_coverage_caveat" in reasons
        or "siem_unavailable" in reasons
        or "feature_input_missing" in reasons
    ):
        return "medium"
    return "high"

def evidence_summary(
    features: list[dict[str, Any]], not_evaluated: list[dict[str, Any]]
) -> list[str]:
    if not features:
        summary = ["No evaluated scorecard rules crossed their thresholds."]
    else:
        ordered = sorted(
            features, key=lambda item: (-int(item["points"]), item["name"])
        )
        summary = [str(feature["evidence"]) for feature in ordered[:5]]
    if not_evaluated:
        summary.append(
            f"{len(not_evaluated)} feature inputs were missing and were not scored as safe."
        )
    return summary

def recommended_next_steps(
    features: list[dict[str, Any]], not_evaluated: list[dict[str, Any]]
) -> list[dict[str, str]]:
    """Recommended next steps as ``{"summary", "detail"}`` pairs.

    ``summary`` is a director-readable imperative (~10 words); ``detail`` is
    the analyst-grade text. Consumers pick the form that fits their lens —
    executive summaries pull ``summary``, full action sections render
    ``detail``.
    """
    domains = {str(feature["domain"]) for feature in features}
    steps: list[dict[str, str]] = []
    if "movement" in domains:
        steps.append(
            {
                "summary": "Investigate the mover attribution.",
                "detail": (
                    "Review mover attribution for the same scope and confirm "
                    "comparable current/baseline windows."
                ),
            }
        )
    if "cache_busting" in domains:
        steps.append(
            {
                "summary": "Audit query-string and cache-key behavior.",
                "detail": (
                    "Inspect query-string diversity, cache-key behavior, and "
                    "cache miss concentration by host and path."
                ),
            }
        )
    if "origin_impact" in domains:
        steps.append(
            {
                "summary": "Break down origin cost by path and host.",
                "detail": (
                    "Break down origin cost proxy by path, host, ASN, and bot "
                    "class before changing origin-facing controls."
                ),
            }
        )
    if "crawler_governance" in domains:
        steps.append(
            {
                "summary": "Check good-crawler limits and policy surfaces.",
                "detail": (
                    "Check good crawler rate limits, 5xx exposure, robots.txt, "
                    "llms.txt, and sitemap availability."
                ),
            }
        )
    if "security_evidence" in domains:
        steps.append(
            {
                "summary": "Pull SIEM action and policy summaries for the entity.",
                "detail": (
                    "Enrich with SIEM action, policy, auth-failure, and "
                    "blocked-request summaries for the same entity."
                ),
            }
        )
    if "policy_collateral" in domains:
        steps.append(
            {
                "summary": "Check for policy displacement and collateral.",
                "detail": (
                    "Review collateral and displacement checks before declaring "
                    "the policy change successful."
                ),
            }
        )
    if not steps and not_evaluated:
        steps.append(
            {
                "summary": "Regenerate with the missing feature inputs.",
                "detail": (
                    "Regenerate aggregate rows with the missing scorecard "
                    "feature inputs listed in not_evaluated_features."
                ),
            }
        )
    if not steps:
        steps.append(
            {
                "summary": "Continue observing.",
                "detail": (
                    "Continue observing with summary-table aggregates and "
                    "compare against the next baseline window."
                ),
            }
        )
    return steps

__all__ = [name for name in globals() if not name.startswith("__")]
