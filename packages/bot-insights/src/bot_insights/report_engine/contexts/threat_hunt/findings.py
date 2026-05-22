from __future__ import annotations

from ._shared import *

def _build_impact_tiles(
    artifact: dict[str, Any], campaigns: list[dict[str, Any]], cases: list[dict[str, Any]]
) -> list[dict[str, str]]:
    request_total = _request_total(campaigns, cases, artifact)
    timing_count = sum(1 for case in cases if isinstance(case, dict) and case.get("temporal_regularity"))
    drilldown_count = sum(
        1
        for case in cases
        if isinstance(case, dict)
        and (case.get("drilldown_coverage") or {}).get("status", "unavailable") != "unavailable"
    )
    return [
        {
            "label": "Request volume",
            "value": _fmt_num(request_total),
            "delta": "campaign requests" if campaigns else "lead requests",
        },
        {
            "label": "Campaigns",
            "value": str(len(campaigns)),
            "delta": "linked lead groups",
        },
        {
            "label": "Scraper leads",
            "value": str(len(cases)),
            "delta": "behavioral cases",
        },
        {
            "label": "Top endpoint",
            "value": _first_endpoint_label(artifact, campaigns, cases).split(" (", 1)[0],
            "delta": _first_endpoint_label(artifact, campaigns, cases).split("(", 1)[1].rstrip(")")
            if "(" in _first_endpoint_label(artifact, campaigns, cases)
            else "not supplied",
        },
        {
            "label": "Evidence coverage",
            "value": f"{timing_count}/{len(cases)}",
            "delta": f"timing; {drilldown_count}/{len(cases)} drilldown",
        },
    ]

def _build_threat_findings(
    artifact: dict[str, Any], campaigns: list[dict[str, Any]], cases: list[dict[str, Any]]
) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    if campaigns:
        top = campaigns[0]
        pattern = _label(str(top.get("temporal_pattern") or "not_established"))
        ua_summary = top.get("ua_plausibility_summary") or {}
        forged_text = (
            " It is a forged-UA residential proxy operation candidate based on repeated UA plausibility anomalies."
            if ua_summary.get("forged_ua_candidate")
            else ""
        )
        findings.append(
            {
                "label": "Finding 1",
                "lead": f"{top.get('campaign_id')} is the strongest coordinated lead.",
                "body": (
                    f"It links {_count_label(len(top.get('leads') or []), 'user-agent fingerprint')} "
                    f"across {_fmt_num(top.get('total_requests'))} requests with {len(top.get('link_narratives') or [])} "
                    f"link evidence row(s); timing pattern is {pattern}.{forged_text}"
                ),
            }
        )
    else:
        findings.append(
            {
                "label": "Finding 1",
                "lead": "No coordinated scraper campaign cleared the linking threshold.",
                "body": "The report preserves singleton scraper leads as independent cases instead of inferring coordination.",
            }
        )
    if cases:
        top_case = next(
            (case for case in cases if not _is_weak_first_party_app_lead(case)),
            cases[0],
        )
        ua_view = top_case.get("ua_plausibility") or {}
        ua_text = (
            f" UA plausibility: {ua_view.get('trigger_reason')}."
            if ua_view.get("verdict") in {"confirmed", "elevated"}
            else ""
        )
        if _is_weak_first_party_app_lead(top_case):
            lead = f"{_parsed_ua_label(top_case)} is the highest-volume evidence-bounded lead."
            body = (
                f"It accounts for {_fmt_num(top_case.get('requests'))} requests, but the first-party "
                "app user-agent shape and current evidence do not support stronger scraper wording."
            )
        else:
            lead = f"{_parsed_ua_label(top_case)} is the strongest non-campaign lead."
            body = (
                f"It accounts for {_fmt_num(top_case.get('requests'))} requests with "
                f"{', '.join(top_case.get('evidence_flag_labels') or []) or 'no named evidence flags'}.{ua_text}"
            )
        findings.append(
            {
                "label": "Finding 2",
                "lead": lead,
                "body": body,
            }
        )
    else:
        findings.append(
            {
                "label": "Finding 2",
                "lead": "No scraper leads could be assembled from the supplied actor evidence.",
                "body": "The report remains an evidence availability review until actor or drilldown inputs are supplied.",
            }
        )
    missing_drilldown = not any(
        isinstance(c, dict) and (c.get("endpoint_targets") or c.get("hourly_bursts"))
        for c in cases
    )
    missing_timing = not any(isinstance(c, dict) and c.get("temporal_regularity") for c in cases)
    gap = "timing and drilldown" if missing_timing and missing_drilldown else "timing" if missing_timing else "drilldown" if missing_drilldown else "operator attribution"
    findings.append(
        {
            "label": "Finding 3",
            "lead": "Evidence boundaries remain explicit.",
            "body": f"The hunt does not establish intent, operator identity, or cross-customer reuse; the main unresolved area is {gap}.",
        }
    )
    return findings[:3]

def _is_weak_first_party_app_lead(case: dict[str, Any]) -> bool:
    ua = str(case.get("user_agent") or "")
    parsed = ((case.get("ua_plausibility") or {}).get("parsed") or {})
    first_party = ua.lower().startswith(("expedia/", "vrbo/", "hotels.com/"))
    app_like = parsed.get("ua_class") in {"native_app", "mobile_app", "first_party_app"}
    weak = str(case.get("verdict") or "").lower() in {"weak_lead", "not_enough_data", "possible"}
    confidence = ((case.get("confidence_assessment") or {}).get("qualifier") or "").lower()
    return first_party and (app_like or weak or confidence in {"weak", "low", "partial"})

def _build_evidence_boundaries(
    campaigns: list[dict[str, Any]], cases: list[dict[str, Any]]
) -> dict[str, list[str]]:
    return {
        "observed": _observed_boundaries(campaigns, cases),
        "not_established": _not_established_boundaries(cases),
    }

def _observed_boundaries(
    campaigns: list[dict[str, Any]], cases: list[dict[str, Any]]
) -> list[str]:
    observed = [
        "Current-window scraper leads were derived from the supplied Bot Insights artifacts.",
    ]
    if campaigns:
        observed.append("At least one multi-lead campaign met conservative linking thresholds.")
    if any(isinstance(c, dict) and c.get("temporal_regularity") for c in cases):
        observed.append("Timing regularity is available for at least one scraper lead.")
    confirmed_ua = _cases_with_ua(cases, counts_for_verdict=True)
    elevated_ua = _cases_with_ua(cases, verdict="elevated")
    if confirmed_ua:
        observed.append("UA plausibility anomaly confirmed for at least one scraper lead.")
    if elevated_ua:
        observed.append("UA plausibility elevated but not verdict-driving for at least one scraper lead.")
    if any(isinstance(c, dict) and c.get("temporal_pattern") == "parallel_independent" for c in campaigns):
        observed.append("A campaign shows parallel independent worker timing: regular hourly cadence without synchronized timing.")
    characterized_cases = _cases_with_drilldown(cases, {"partial", "substantial", "focused"})
    thin_cases = _cases_with_drilldown(cases, {"uncharacterized", "thin_slice"})
    exact_drilldown_cases = _cases_with_drilldown_not(cases, "unavailable")
    confirmed_endpoint_cases = _cases_with_endpoint(cases, counts_for_verdict=True)
    inferred_endpoint_cases = _cases_with_endpoint(cases, tier="inferred_site_context")
    unconfirmed_endpoint_cases = _cases_with_endpoint(cases, tier="unconfirmed_scoped")
    if confirmed_endpoint_cases:
        observed.append("Scoped endpoint targeting confirmed for at least one scraper lead.")
    if inferred_endpoint_cases:
        observed.append("Endpoint context inferred from site-level summary rows is visible but not lead-specific evidence.")
    if characterized_cases:
        observed.append("At least one lead has partial-or-better scoped endpoint surface coverage.")
    return observed

def _not_established_boundaries(cases: list[dict[str, Any]]) -> list[str]:
    confirmed_ua = _cases_with_ua(cases, counts_for_verdict=True)
    elevated_ua = _cases_with_ua(cases, verdict="elevated")
    thin_cases = _cases_with_drilldown(cases, {"uncharacterized", "thin_slice"})
    exact_drilldown_cases = _cases_with_drilldown_not(cases, "unavailable")
    unconfirmed_endpoint_cases = _cases_with_endpoint(cases, tier="unconfirmed_scoped")
    not_established = [
        "Operator identity is not established.",
        "Malicious intent is not established by this artifact.",
        "Cross-customer reuse is not established.",
    ]
    if not any(isinstance(c, dict) and c.get("temporal_regularity") for c in cases):
        not_established.append("timing regularity is not established for the visible leads.")
    if thin_cases:
        not_established.append("Primary request surface characterized is not established for leads with near-zero or thin drilldown coverage.")
    if unconfirmed_endpoint_cases:
        not_established.append("Primary request surface remains uncharacterized or non-targeted for at least one scoped lead.")
    if not exact_drilldown_cases:
        not_established.append("Scoped drilldown behavior is not established for the visible leads.")
    if not confirmed_ua and not elevated_ua:
        not_established.append("UA plausibility unavailable or inconclusive for the visible leads.")
    return not_established

def _cases_with_ua(
    cases: list[dict[str, Any]],
    *,
    counts_for_verdict: bool | None = None,
    verdict: str | None = None,
) -> list[dict[str, Any]]:
    matches = []
    for case in cases:
        ua = case.get("ua_plausibility") if isinstance(case, dict) else None
        if not isinstance(ua, dict):
            continue
        if counts_for_verdict is not None and bool(ua.get("counts_for_verdict")) != counts_for_verdict:
            continue
        if verdict is not None and ua.get("verdict") != verdict:
            continue
        matches.append(case)
    return matches

def _cases_with_drilldown(
    cases: list[dict[str, Any]], statuses: set[str]
) -> list[dict[str, Any]]:
    return [
        case
        for case in cases
        if isinstance(case, dict)
        and (case.get("drilldown_coverage") or {}).get("status") in statuses
    ]

def _cases_with_drilldown_not(
    cases: list[dict[str, Any]], status: str
) -> list[dict[str, Any]]:
    return [
        case
        for case in cases
        if isinstance(case, dict)
        and (case.get("drilldown_coverage") or {}).get("status") != status
    ]

def _cases_with_endpoint(
    cases: list[dict[str, Any]],
    *,
    counts_for_verdict: bool | None = None,
    tier: str | None = None,
) -> list[dict[str, Any]]:
    matches = []
    for case in cases:
        evidence = case.get("endpoint_evidence") if isinstance(case, dict) else None
        if not isinstance(evidence, dict):
            continue
        if counts_for_verdict is not None and bool(evidence.get("counts_for_verdict")) != counts_for_verdict:
            continue
        if tier is not None and evidence.get("tier") != tier:
            continue
        matches.append(case)
    return matches

def _build_analyst_assessment(summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "conclusion": summary["summary"],
        "pillars": summary["reasons"],
        "boundary": (
            "This readout is deterministic and scoped to the supplied threat-hunt artifact; "
            "it reports observed scraper evidence, not operator identity, intent, or reuse."
        ),
    }

__all__ = [name for name in globals() if not name.startswith("__")]
