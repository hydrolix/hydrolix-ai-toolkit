from __future__ import annotations

from ._shared import *

_IMPACT_INTERPRETIVE_FRAGMENTS = {
    ("dominant", "new_entrant"): "Dominant current-window share with no comparable baseline footprint.",
    ("dominant", "accelerating"): "Dominant traffic share that expanded sharply from baseline.",
    ("dominant", "growing"): "Dominant traffic share that is still growing versus baseline.",
    ("significant", "new_entrant"): "Significant current-window share from a baseline-new lead.",
    ("significant", "accelerating"): "Significant traffic share with a sharp share increase versus baseline.",
    ("significant", "growing"): "Significant traffic share that increased versus baseline.",
    ("moderate", "new_entrant"): "Moderate current-window share that was absent from baseline.",
    ("moderate", "accelerating"): "Moderate traffic share with sharp relative growth versus baseline.",
    ("moderate", "growing"): "Moderate traffic share that grew versus baseline.",
    ("minor", "new_entrant"): "Small current-window share, but newly visible versus baseline.",
}

def _impact_for_totals(
    *,
    scope: str,
    requests: float,
    baseline_requests: float,
    bytes_value: float,
    baseline_bytes: float,
    hydrolix_log_ingest_bytes: float | None,
    baseline_hydrolix_log_ingest_bytes: float | None,
    response_body_bytes: float | None,
    baseline_response_body_bytes: float | None,
    akamai_billed_bytes: float | None,
    baseline_akamai_billed_bytes: float | None,
    current_totals: dict[str, float],
    baseline_totals: dict[str, float],
    cost_config: dict[str, Any] | None,
    user_agents: Iterable[str] | None = None,
) -> dict[str, Any]:
    current_requests_total = _num(current_totals.get("requests"))
    baseline_requests_total = _num(baseline_totals.get("requests"))
    current_bytes_total = _num(current_totals.get("bytes"))
    baseline_bytes_total = _num(baseline_totals.get("bytes"))
    current_hydrolix_total = (
        _num(current_totals.get("hydrolix_log_ingest_bytes"))
        if current_totals.get("hydrolix_log_ingest_bytes") not in (None, "")
        else None
    )
    baseline_hydrolix_total = (
        _num(baseline_totals.get("hydrolix_log_ingest_bytes"))
        if baseline_totals.get("hydrolix_log_ingest_bytes") not in (None, "")
        else None
    )
    current_response_total = _num(current_totals.get("response_body_bytes"))
    baseline_response_total = _num(baseline_totals.get("response_body_bytes"))
    current_akamai_total = _num(current_totals.get("akamai_billed_bytes"))
    baseline_akamai_total = _num(baseline_totals.get("akamai_billed_bytes"))
    request_share = _share_fraction(requests, current_requests_total)
    baseline_request_share = _share_fraction(baseline_requests, baseline_requests_total)
    byte_share = _share_fraction(bytes_value, current_bytes_total)
    baseline_byte_share = _share_fraction(baseline_bytes, baseline_bytes_total)
    trend = _trend_severity(request_share, baseline_request_share)
    severity = _share_severity(request_share)
    impact = {
        "scope": scope,
        "user_agents": sorted({str(ua) for ua in (user_agents or []) if str(ua)}),
        "requests": requests,
        "baseline_requests": baseline_requests,
        "request_delta": requests - baseline_requests,
        "request_share": request_share,
        "baseline_request_share": baseline_request_share,
        "request_share_delta": (
            request_share - baseline_request_share
            if request_share is not None and baseline_request_share is not None
            else None
        ),
        "request_share_ratio": (
            request_share / baseline_request_share
            if request_share is not None and baseline_request_share not in (None, 0)
            else None
        ),
        "bytes": bytes_value,
        "baseline_bytes": baseline_bytes,
        "byte_share": byte_share,
        "baseline_byte_share": baseline_byte_share,
        "hydrolix_log_ingest_bytes": hydrolix_log_ingest_bytes,
        "baseline_hydrolix_log_ingest_bytes": baseline_hydrolix_log_ingest_bytes,
        "hydrolix_log_ingest_byte_share": _lane_share(hydrolix_log_ingest_bytes, current_hydrolix_total),
        "baseline_hydrolix_log_ingest_byte_share": _lane_share(
            baseline_hydrolix_log_ingest_bytes, baseline_hydrolix_total
        ),
        "response_body_bytes": response_body_bytes,
        "baseline_response_body_bytes": baseline_response_body_bytes,
        "response_body_byte_share": _lane_share(response_body_bytes, current_response_total),
        "baseline_response_body_byte_share": _lane_share(
            baseline_response_body_bytes, baseline_response_total
        ),
        "akamai_billed_bytes": akamai_billed_bytes,
        "baseline_akamai_billed_bytes": baseline_akamai_billed_bytes,
        "akamai_billed_byte_share": _lane_share(akamai_billed_bytes, current_akamai_total),
        "baseline_akamai_billed_byte_share": _lane_share(
            baseline_akamai_billed_bytes, baseline_akamai_total
        ),
        "share_severity": severity,
        "trend_severity": trend,
        "share_direction": _share_direction(request_share, baseline_request_share),
    }
    fragment = _IMPACT_INTERPRETIVE_FRAGMENTS.get((severity, trend))
    if fragment:
        impact["interpretation"] = fragment
    if cost_config:
        gb = bytes_value / 1_000_000_000
        impact["cost_estimate"] = {
            "egress_gb_decimal": gb,
            "low": gb * _num(cost_config.get("egress_rate_low_per_gb")),
            "high": gb * _num(cost_config.get("egress_rate_high_per_gb")),
            "basis_label": cost_config.get("basis_label"),
            "disclaimer": cost_config.get("disclaimer"),
        }
    return impact

def _impact_for_uas(
    *,
    scope: str,
    user_agents: Iterable[str],
    case_by_ua: dict[str, dict[str, Any]],
    current_totals: dict[str, float],
    baseline_totals: dict[str, float],
    cost_config: dict[str, Any] | None,
) -> dict[str, Any]:
    uas = sorted({str(ua) for ua in user_agents if str(ua) in case_by_ua})
    return _impact_for_totals(
        scope=scope,
        requests=sum(_num(case_by_ua[ua].get("requests")) for ua in uas),
        baseline_requests=sum(_num(case_by_ua[ua].get("baseline_requests")) for ua in uas),
        bytes_value=sum(_num(case_by_ua[ua].get("bytes")) for ua in uas),
        baseline_bytes=sum(_num(case_by_ua[ua].get("baseline_bytes")) for ua in uas),
        hydrolix_log_ingest_bytes=_sum_optional_lane(
            (case_by_ua[ua] for ua in uas), "hydrolix_log_ingest_bytes"
        ),
        baseline_hydrolix_log_ingest_bytes=_sum_optional_lane(
            (case_by_ua[ua] for ua in uas), "baseline_hydrolix_log_ingest_bytes"
        ),
        response_body_bytes=_sum_optional_lane(
            (case_by_ua[ua] for ua in uas), "response_body_bytes"
        ),
        baseline_response_body_bytes=_sum_optional_lane(
            (case_by_ua[ua] for ua in uas), "baseline_response_body_bytes"
        ),
        akamai_billed_bytes=_sum_optional_lane(
            (case_by_ua[ua] for ua in uas), "akamai_billed_bytes"
        ),
        baseline_akamai_billed_bytes=_sum_optional_lane(
            (case_by_ua[ua] for ua in uas), "baseline_akamai_billed_bytes"
        ),
        current_totals=current_totals,
        baseline_totals=baseline_totals,
        cost_config=cost_config,
        user_agents=uas,
    )

def _attach_impact_assessments(
    *,
    current_totals: dict[str, float],
    baseline_totals: dict[str, float],
    scraper_cases: list[dict[str, Any]],
    campaigns: list[dict[str, Any]],
    ua_families: list[dict[str, Any]],
    recommended_actions: list[dict[str, Any]],
    cost_config: dict[str, Any] | None,
) -> dict[str, Any]:
    case_by_ua = {str(case.get("user_agent")): case for case in scraper_cases if case.get("user_agent")}
    for case in scraper_cases:
        ua = str(case.get("user_agent") or "")
        case["impact_assessment"] = _impact_for_uas(
            scope="scraper_case",
            user_agents=[ua],
            case_by_ua=case_by_ua,
            current_totals=current_totals,
            baseline_totals=baseline_totals,
            cost_config=cost_config,
        )
    for campaign in campaigns:
        impact = _impact_for_uas(
            scope="campaign",
            user_agents=campaign.get("leads") or [],
            case_by_ua=case_by_ua,
            current_totals=current_totals,
            baseline_totals=baseline_totals,
            cost_config=cost_config,
        )
        campaign["impact_assessment"] = impact
        campaign["bytes"] = impact["bytes"]
        campaign["baseline_bytes"] = impact["baseline_bytes"]
        for field in BYTE_LANE_FIELDS:
            campaign[field] = impact[field]
            campaign[f"baseline_{field}"] = impact[f"baseline_{field}"]
    for family in ua_families:
        impact = _impact_for_uas(
            scope="ua_family",
            user_agents=family.get("members") or [],
            case_by_ua=case_by_ua,
            current_totals=current_totals,
            baseline_totals=baseline_totals,
            cost_config=cost_config,
        )
        family["impact_assessment"] = impact
        family["bytes"] = impact["bytes"]
        family["baseline_bytes"] = impact["baseline_bytes"]
        for field in BYTE_LANE_FIELDS:
            family[field] = impact[field]
            family[f"baseline_{field}"] = impact[f"baseline_{field}"]

    action_tiers: dict[str, set[str]] = defaultdict(set)
    for action in recommended_actions:
        targets = action.get("target_values") if isinstance(action.get("target_values"), dict) else {}
        uas = sorted({str(ua) for ua in (targets.get("user_agents") or []) if str(ua) in case_by_ua})
        impact = _impact_for_uas(
            scope=str(action.get("scope") or "action"),
            user_agents=uas,
            case_by_ua=case_by_ua,
            current_totals=current_totals,
            baseline_totals=baseline_totals,
            cost_config=cost_config,
        )
        action["impact_assessment"] = impact
        action["estimated_observed_window_impact"] = {
            "requests": impact["requests"],
            "bytes": impact["bytes"],
            "request_share": impact["request_share"],
            "byte_share": impact["byte_share"],
            "hydrolix_log_ingest_bytes": impact["hydrolix_log_ingest_bytes"],
            "hydrolix_log_ingest_byte_share": impact["hydrolix_log_ingest_byte_share"],
            "response_body_bytes": impact["response_body_bytes"],
            "response_body_byte_share": impact["response_body_byte_share"],
            "akamai_billed_bytes": impact["akamai_billed_bytes"],
            "akamai_billed_byte_share": impact["akamai_billed_byte_share"],
        }
        action_tiers[str(action.get("tier") or "tier_4")].update(uas)

    scoped_uas = {
        ua
        for case in scraper_cases
        if (ua := str(case.get("user_agent") or ""))
        and str(((case.get("confidence_assessment") or {}).get("qualifier") or "unavailable")).lower()
        in HUNT_IMPACT_INCLUDED_CONFIDENCE_QUALIFIERS
    }
    tiers = {
        tier: _impact_for_uas(
            scope=tier,
            user_agents=uas,
            case_by_ua=case_by_ua,
            current_totals=current_totals,
            baseline_totals=baseline_totals,
            cost_config=cost_config,
        )
        for tier, uas in sorted(action_tiers.items())
    }
    assessment = {
        "totals": {
            "current": {
                "requests": _num(current_totals.get("requests")),
                "bytes": _num(current_totals.get("bytes")),
                "hydrolix_log_ingest_bytes": current_totals.get("hydrolix_log_ingest_bytes"),
                "response_body_bytes": _num(current_totals.get("response_body_bytes")),
                "akamai_billed_bytes": _num(current_totals.get("akamai_billed_bytes")),
            },
            "baseline": {
                "requests": _num(baseline_totals.get("requests")),
                "bytes": _num(baseline_totals.get("bytes")),
                "hydrolix_log_ingest_bytes": baseline_totals.get("hydrolix_log_ingest_bytes"),
                "response_body_bytes": _num(baseline_totals.get("response_body_bytes")),
                "akamai_billed_bytes": _num(baseline_totals.get("akamai_billed_bytes")),
            },
        },
        "impact_scope": {
            "included_confidence_qualifiers": list(HUNT_IMPACT_INCLUDED_CONFIDENCE_QUALIFIERS),
            "excluded_confidence_qualifiers": list(HUNT_IMPACT_EXCLUDED_CONFIDENCE_QUALIFIERS),
            "included_user_agent_count": len(scoped_uas),
            "note": HUNT_IMPACT_SCOPE_NOTE,
        },
        "hunt": _impact_for_uas(
            scope="hunt",
            user_agents=scoped_uas,
            case_by_ua=case_by_ua,
            current_totals=current_totals,
            baseline_totals=baseline_totals,
            cost_config=cost_config,
        ),
        "tiers": tiers,
    }
    assessment["hunt"]["impact_scope_note"] = HUNT_IMPACT_SCOPE_NOTE
    if cost_config:
        assessment["cost_config"] = cost_config
    return assessment

__all__ = [name for name in globals() if not name.startswith("__")]
