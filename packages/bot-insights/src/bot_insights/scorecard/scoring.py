from __future__ import annotations

from typing import Any

from .constants import DOMAINS, SIEM_INPUTS
from .features import metric_values
from .numeric import clean_number, metadata_text
from .rows import count_values, current_number
from .rules import BASELINE_POINT_IN_TIME_EVALUATORS, FEATURE_EVALUATORS


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


def _entity_metrics(row: dict[str, Any]) -> dict[str, Any]:
    """Project request volume and origin-impact signals from a row.

    Pure projection — no recomputation. Every field is ``None`` when the
    corresponding key is absent from the source row, so downstream views
    can render "missing" rather than fabricating zeros.
    """
    current_requests, baseline_requests = count_values(row)
    current_cache_misses = current_number(row, "cache_misses", "cnt_cache_miss")
    current_cache_miss_pct, baseline_cache_miss_pct = metric_values(
        row, ("cache_miss_pct", "miss_rate_pct")
    )
    if (
        current_cache_miss_pct is None
        and current_cache_misses is not None
        and current_requests
    ):
        current_cache_miss_pct = current_cache_misses / current_requests * 100.0
    current_origin_p95_ms, baseline_origin_p95_ms = metric_values(
        row, ("origin_p95_ms", "p95_origin_ttfb", "origin_p95_ttfb_ms")
    )
    current_5xx_pct, baseline_5xx_pct = metric_values(
        row, ("rate_5xx_pct", "error_5xx_pct")
    )
    return {
        "current_requests": clean_number(current_requests),
        "baseline_requests": clean_number(baseline_requests),
        "current_cache_misses": clean_number(current_cache_misses),
        "current_cache_miss_pct": clean_number(current_cache_miss_pct),
        "baseline_cache_miss_pct": clean_number(baseline_cache_miss_pct),
        "current_origin_p95_ms": clean_number(current_origin_p95_ms),
        "baseline_origin_p95_ms": clean_number(baseline_origin_p95_ms),
        "current_5xx_pct": clean_number(current_5xx_pct),
        "baseline_5xx_pct": clean_number(baseline_5xx_pct),
    }


def _evaluate_scorecard_rules(
    row: dict[str, Any], active_domains: tuple[str, ...]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    features: list[dict[str, Any]] = []
    not_evaluated: list[dict[str, Any]] = []
    rule_results: list[dict[str, Any]] = []
    for evaluator in FEATURE_EVALUATORS:
        feature, missing = evaluator(row)
        _append_evaluated_feature(feature, active_domains, features, rule_results)
        _append_missing_feature(missing, active_domains, not_evaluated, rule_results)
    return features, not_evaluated, rule_results


def _append_evaluated_feature(
    feature: dict[str, Any] | None,
    active_domains: tuple[str, ...],
    features: list[dict[str, Any]],
    rule_results: list[dict[str, Any]],
) -> None:
    if feature is None or feature.get("domain") not in active_domains:
        return
    result = dict(feature)
    if int(result.get("points") or 0) > 0:
        result["status"] = "triggered"
        features.append(feature)
    else:
        result["status"] = "evaluated_zero"
    rule_results.append(result)


def _append_missing_feature(
    missing: dict[str, Any] | None,
    active_domains: tuple[str, ...],
    not_evaluated: list[dict[str, Any]],
    rule_results: list[dict[str, Any]],
) -> None:
    if missing is None or missing.get("domain") not in active_domains:
        return
    not_evaluated.append(missing)
    result = dict(missing)
    result["points"] = 0
    result["status"] = "missing_input"
    rule_results.append(result)


def _domain_scores(
    features: list[dict[str, Any]], rule_results: list[dict[str, Any]]
) -> dict[str, int]:
    evaluated_domains = {
        str(rule["domain"])
        for rule in rule_results
        if rule.get("status") in {"triggered", "evaluated_zero"}
    }
    domain_scores = {domain: 0 for domain in DOMAINS if domain in evaluated_domains}
    for feature in features:
        domain = str(feature["domain"])
        domain_scores[domain] = domain_scores.get(domain, 0) + int(feature["points"])
    return domain_scores


def _primary_domain(domain_scores: dict[str, int]) -> str:
    nonzero_domains = [
        (domain, points) for domain, points in domain_scores.items() if points > 0
    ]
    if not nonzero_domains:
        return "none"
    return sorted(nonzero_domains, key=lambda item: (-item[1], item[0]))[0][0]
