from __future__ import annotations

from ._shared import *

def _consistency_checks(flags: set[str]) -> list[dict[str, Any]]:
    checks = [
        (
            "temporal_regularity_plus_ua_anomaly",
            {"temporal_regularity", "ua_anomaly"},
            "Timing regularity reinforces a UA plausibility anomaly.",
        ),
        (
            "ua_anomaly_plus_coordinated_activity",
            {"ua_anomaly", "coordinated_activity"},
            "UA anomaly appears inside a coordinated multi-lead pattern.",
        ),
        (
            "endpoint_targeting_plus_rate_limit_or_error_pressure",
            {"endpoint_targeting", "rate_limit_or_error_pressure"},
            "Endpoint targeting coincides with 429 or 5xx pressure.",
        ),
    ]
    return [
        {
            "check": name,
            "status": "present" if required <= flags else "incomplete",
            "required_families": sorted(required),
            "missing_families": sorted(required - flags),
            "summary": summary,
        }
        for name, required, summary in checks
    ]

def _evidence_shelf_life(case: dict[str, Any]) -> list[dict[str, Any]]:
    flags = set(str(flag) for flag in case.get("evidence_flags") or [])
    notes = []
    if "ua_ip_fanout" in flags:
        notes.append(
            {
                "evidence": "ua_ip_fanout",
                "shelf_life": "next_hunt_window",
                "guidance": (
                    "Fan-out counts are hunt-window specific; re-query them in the next hunt window "
                    "because proxy pools, app releases, and device populations change."
                ),
            }
        )
    plausibility = case.get("ua_plausibility") if isinstance(case.get("ua_plausibility"), dict) else {}
    version_signal = (plausibility.get("signals") or {}).get("version_currency") if isinstance(plausibility.get("signals"), dict) else None
    if "ua_anomaly" in flags or version_signal:
        notes.append(
            {
                "evidence": "ua_version_currency",
                "shelf_life": "8_weeks",
                "guidance": "Re-validate browser version currency after 8 weeks or before enforcement changes.",
            }
        )
    if "coordinated_activity" in flags or "infrastructure_topology" in flags:
        notes.append(
            {
                "evidence": "shared_ip_or_infrastructure_linking",
                "shelf_life": "proxy_pool_rotation_risk",
                "guidance": "Re-check shared IP, ASN, and country links because proxy pools can rotate between hunt windows.",
            }
        )
    if "temporal_regularity" in flags:
        notes.append(
            {
                "evidence": "timing_regularity",
                "shelf_life": "next_observation_window",
                "guidance": "Re-sample timing in the next observation window; cadence can change after throttling or operator changes.",
            }
        )
    return notes

def _confidence_assessment(
    case: dict[str, Any],
    background: dict[str, Any],
    baseline_significance: dict[str, Any],
) -> dict[str, Any]:
    flags = set(str(flag) for flag in case.get("evidence_flags") or [])
    checks = _consistency_checks(flags)
    present_checks = [check for check in checks if check["status"] == "present"]
    background_families = background.get("families") if isinstance(background, dict) else {}
    high_background = [
        family
        for family in flags
        if isinstance(background_families, dict)
        and isinstance(background_families.get(family), dict)
        and background_families[family].get("concern") == "high"
    ]
    score = _confidence_score(flags, present_checks, high_background, baseline_significance)
    qualifier = _confidence_qualifier(flags, score, present_checks, high_background)
    reasons = _confidence_reasons(present_checks, high_background, baseline_significance)
    return {
        "qualifier": qualifier,
        "score": round(score, 3),
        "reasons": reasons,
        "background_rates": {
            family: background_families.get(family)
            for family in sorted(flags)
            if isinstance(background_families, dict)
        },
        "consistency_checks": checks,
        "baseline_significance": baseline_significance,
        "evidence_shelf_life": _evidence_shelf_life(case),
    }

def _confidence_score(
    flags: set[str],
    present_checks: list[dict[str, Any]],
    high_background: list[str],
    baseline_significance: dict[str, Any],
) -> float:
    score = min(0.92, len(flags) * 0.16 + len(present_checks) * 0.13)
    if baseline_significance.get("status") == "available":
        z = _num(baseline_significance.get("z_score"))
        if z >= 5:
            score += 0.10
        elif z >= 3:
            score += 0.06
    if high_background:
        score -= 0.18
    if not flags:
        score = 0.0
    return max(0.0, min(score, 1.0))

def _confidence_qualifier(
    flags: set[str],
    score: float,
    present_checks: list[dict[str, Any]],
    high_background: list[str],
) -> str:
    if not flags:
        return "unavailable"
    if score >= 0.70 and present_checks and not high_background:
        return "high"
    if score >= 0.40 or flags == {"automation_signature"}:
        return "partial"
    return "low"

def _confidence_reasons(
    present_checks: list[dict[str, Any]],
    high_background: list[str],
    baseline_significance: dict[str, Any],
) -> list[str]:
    reasons = [check["summary"] for check in present_checks]
    if high_background:
        reasons.append(
            "Some evidence families also fire in the organic background sample: "
            + ", ".join(sorted(high_background))
            + "."
        )
    if baseline_significance.get("status") == "available":
        reasons.append(
            f"Per-UA baseline bucket z-score is {baseline_significance.get('z_score'):.2f}."
        )
    elif baseline_significance.get("status") == "unavailable":
        reasons.append("Per-UA baseline bucket distribution was unavailable; ratio-based baseline growth is preserved.")
    if not reasons:
        reasons.append("Confidence is bounded by the available evidence families and missing corroboration.")
    return reasons

def _attach_confidence_assessments(
    scraper_cases: list[dict[str, Any]],
    campaigns: list[dict[str, Any]],
    *,
    background: dict[str, Any],
    baseline_by_ua: dict[str, dict[str, Any]],
) -> None:
    case_by_ua = {str(case.get("user_agent")): case for case in scraper_cases if case.get("user_agent")}
    for case in scraper_cases:
        _attach_case_confidence(case, background, baseline_by_ua)
    for campaign in campaigns:
        campaign["confidence_summary"] = _campaign_confidence_summary(campaign, case_by_ua)

def _attach_case_confidence(
    case: dict[str, Any],
    background: dict[str, Any],
    baseline_by_ua: dict[str, dict[str, Any]],
) -> None:
    baseline_significance = _baseline_significance_for_case(case, baseline_by_ua)
    case["confidence_assessment"] = _confidence_assessment(
        case, background, baseline_significance
    )
    if case["confidence_assessment"]["qualifier"] in {"partial", "low"}:
        _append_background_case_against(case)

def _append_background_case_against(case: dict[str, Any]) -> None:
    for family, rate in (case["confidence_assessment"].get("background_rates") or {}).items():
        if isinstance(rate, dict) and rate.get("concern") == "high":
            case.setdefault("case_against", []).append(
                f"{family.replace('_', ' ').title()} fired, but the organic background rate is high ({_num(rate.get('rate_pct')):.1f}%)."
            )

def _campaign_member_assessments(
    campaign: dict[str, Any], case_by_ua: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    return [
        case_by_ua[ua].get("confidence_assessment")
        for ua in campaign.get("leads") or []
        if ua in case_by_ua and isinstance(case_by_ua[ua].get("confidence_assessment"), dict)
    ]

def _campaign_confidence_summary(
    campaign: dict[str, Any], case_by_ua: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    member_assessments = _campaign_member_assessments(campaign, case_by_ua)
    qualifiers = Counter(str(item.get("qualifier") or "unavailable") for item in member_assessments)
    reinforcing, max_background, baseline_available = _campaign_confidence_counters(member_assessments)
    member_count = len(member_assessments)
    confirmed_ua, elevated_ua = _campaign_ua_counts(campaign)
    confirmed_or_elevated_share = (confirmed_ua + elevated_ua) / member_count if member_count else 0.0
    confirmed_share = confirmed_ua / member_count if member_count else 0.0
    dominant = qualifiers.most_common(1)[0][0] if qualifiers else "unavailable"
    evidence_weighted = _campaign_weighted_qualifier(
        member_count, confirmed_share, confirmed_or_elevated_share, reinforcing, dominant
    )
    return {
        "member_count": member_count,
        "qualifier_counts": dict(sorted(qualifiers.items())),
        "dominant_qualifier": evidence_weighted,
        "raw_dominant_qualifier": dominant,
        "aggregate_support": {
            "confirmed_or_elevated_ua_members": int(confirmed_ua + elevated_ua),
            "confirmed_ua_members": int(confirmed_ua),
            "confirmed_or_elevated_share": round(confirmed_or_elevated_share, 3),
        },
        "strongest_reinforcing_combinations": [
            {"check": name, "member_count": count}
            for name, count in reinforcing.most_common(3)
        ],
        "max_background_rate_concern": max_background,
        "baseline_significance_available_count": baseline_available,
    }

def _campaign_confidence_counters(
    member_assessments: list[dict[str, Any]],
) -> tuple[Counter[str], dict[str, Any], int]:
    reinforcing: Counter[str] = Counter()
    max_background: dict[str, Any] = {"family": None, "rate_pct": None, "concern": "unavailable"}
    baseline_available = 0
    for item in member_assessments:
        for check in item.get("consistency_checks") or []:
            if isinstance(check, dict) and check.get("status") == "present":
                reinforcing[str(check.get("check"))] += 1
        max_background = _max_background_rate(item, max_background)
        baseline = item.get("baseline_significance") if isinstance(item.get("baseline_significance"), dict) else {}
        if baseline.get("status") == "available":
            baseline_available += 1
    return reinforcing, max_background, baseline_available

def _max_background_rate(
    item: dict[str, Any], current: dict[str, Any]
) -> dict[str, Any]:
    for family, rate in (item.get("background_rates") or {}).items():
        if isinstance(rate, dict) and rate.get("rate_pct") is not None:
            if current["rate_pct"] is None or _num(rate.get("rate_pct")) > _num(current["rate_pct"]):
                current = {"family": family, "rate_pct": rate.get("rate_pct"), "concern": rate.get("concern")}
    return current

def _campaign_ua_counts(campaign: dict[str, Any]) -> tuple[float, float]:
    ua_summary = campaign.get("ua_plausibility_summary") if isinstance(campaign.get("ua_plausibility_summary"), dict) else {}
    return _num(ua_summary.get("anomalous_member_count")), _num(ua_summary.get("weak_member_count"))

def _campaign_weighted_qualifier(
    member_count: int,
    confirmed_share: float,
    confirmed_or_elevated_share: float,
    reinforcing: Counter[str],
    dominant: str,
) -> str:
    if member_count and confirmed_share >= 0.50:
        return "high"
    if member_count and confirmed_or_elevated_share >= 0.50:
        return "partial"
    if reinforcing and sum(reinforcing.values()) / member_count >= 0.50 and dominant == "low":
        return "partial"
    return dominant

def _future_dated_ua(case: dict[str, Any]) -> bool:
    plausibility = case.get("ua_plausibility") if isinstance(case.get("ua_plausibility"), dict) else {}
    signals = plausibility.get("signals") if isinstance(plausibility.get("signals"), dict) else {}
    version = signals.get("version_currency") if isinstance(signals.get("version_currency"), dict) else {}
    return str(version.get("status") or "") == "future_dated"

def _stale_ua(case: dict[str, Any]) -> bool:
    plausibility = case.get("ua_plausibility") if isinstance(case.get("ua_plausibility"), dict) else {}
    signals = plausibility.get("signals") if isinstance(plausibility.get("signals"), dict) else {}
    version = signals.get("version_currency") if isinstance(signals.get("version_currency"), dict) else {}
    return str(version.get("status") or "") in {"stale", "very_stale", "outdated"}

def _action_tier(case: dict[str, Any], *, campaign: bool = False) -> tuple[str, str]:
    flags = set(str(flag) for flag in case.get("evidence_flags") or [])
    plausibility = case.get("ua_plausibility") if isinstance(case.get("ua_plausibility"), dict) else {}
    parsed = plausibility.get("parsed") if isinstance(plausibility.get("parsed"), dict) else {}
    ua_class = str(parsed.get("ua_class") or "")
    native_app_distribution_evidence = {
        "ua_ip_fanout",
        "baseline_novelty_or_growth",
        "infrastructure_topology",
        "temporal_regularity",
        "rate_limit_or_error_pressure",
    }
    abnormal_native_evidence = {
        "automation_signature",
        "endpoint_targeting",
        "ua_anomaly",
        "coordinated_activity",
    }
    if ua_class == "first_party_native_app" and flags and flags <= native_app_distribution_evidence:
        return "tier_4", "monitor_and_revalidate"
    if _future_dated_ua(case) or "automation_signature" in flags:
        return "tier_1", "challenge_or_block_ua"
    if ua_class == "first_party_native_app" and not (flags & abnormal_native_evidence):
        return "tier_4", "monitor_and_revalidate"
    if ua_class == "browser" and {"ua_ip_fanout", "ua_anomaly", "temporal_regularity"} <= flags:
        return "tier_2", "challenge_and_rate_limit"
    if (
        _num(case.get("unique_client_ips")) >= 20
        or "endpoint_targeting" in flags
        or {"temporal_regularity", "rate_limit_or_error_pressure"} <= flags
    ):
        return "tier_2", "challenge_and_rate_limit"
    if campaign or _stale_ua(case) or "coordinated_activity" in flags:
        return "tier_3", "campaign_watchlist_or_challenge"
    return "tier_4", "monitor_and_revalidate"

__all__ = [name for name in globals() if not name.startswith("__")]
