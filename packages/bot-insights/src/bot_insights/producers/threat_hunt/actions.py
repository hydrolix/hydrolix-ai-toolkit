from __future__ import annotations

from ._shared import *

def _action_for_case(case: dict[str, Any], *, scope: str = "lead", covered_by_campaign: bool = False) -> dict[str, Any]:
    if scope == "ua_family":
        tier, action_type = "tier_3", "campaign_watchlist_or_challenge"
        block_allowed = False
        target_values = {
            "ua_family_id": case.get("family_id"),
            "ua_family_template": case.get("template"),
            "user_agents": case.get("members") or [],
        }
    else:
        tier, action_type = _action_tier(case, campaign=scope == "campaign")
        block_allowed = _future_dated_ua(case) or "automation_signature" in set(case.get("evidence_flags") or [])
        target_values = {"user_agents": [case.get("user_agent")]} if scope == "lead" else {
            "campaign_id": case.get("campaign_id"),
            "user_agents": case.get("leads") or [],
        }
    if case.get("endpoint_targets"):
        target_values["endpoint_prefixes"] = [
            str(row.get("endpoint_prefix") or row.get("request_path") or row.get("value"))
            for row in (case.get("endpoint_targets") or [])[:5]
            if isinstance(row, dict)
        ]
    action = {
        "tier": tier,
        "scope": scope,
        "action_type": action_type,
        "target_values": target_values,
        "supporting_evidence": list(case.get("evidence_flags") or [])[:6],
        "estimated_observed_window_impact": {
            "requests": case.get("total_requests") if scope in {"campaign", "ua_family"} else case.get("requests"),
            "bytes": case.get("bytes"),
        },
        "validation_notes": [
            "Verify current Bot Manager, SIEM, and edge policy coverage before enforcement.",
            "Re-check the target values in a fresh observation window because scraper operators can rotate UA strings, IPs, and endpoints.",
        ],
        "false_positive_caveat": (
            "Challenge-first handling is recommended unless the UA is future-dated or has explicit automation tooling markers."
        ),
        "rollback_monitoring": [
            "Track requests, 429s, 5xxs, and conversion/business-safe traffic for the target scope after deployment.",
            "Remove or relax the rule if protected traffic appears in the validation sample.",
        ],
        "enforcement_wording": "block_candidate" if block_allowed else "challenge_first",
        "covered_by_campaign": covered_by_campaign,
    }
    classification = case.get("threat_classification") if isinstance(case.get("threat_classification"), dict) else {}
    primary = classification.get("primary") if isinstance(classification.get("primary"), dict) else {}
    modifier = conservative_modifier(classification) if classification else None
    if primary:
        action["threat_category"] = primary.get("category")
        action["threat_confidence"] = primary.get("confidence")
    if modifier:
        action["threat_action_modifier"] = modifier
        action["false_positive_caveat"] = modifier
        action["validation_notes"] = [*action["validation_notes"], modifier]
    if classification.get("ambiguity_note"):
        action["classification_ambiguity_note"] = classification.get("ambiguity_note")
    return action

_BROWSER_VERSION_TOKEN_RE = re.compile(
    r"\b(Chrome|CriOS|Chromium|Firefox|Edg|EdgA|EdgiOS|Edge|Version)/(\d+)((?:\.\d+){0,3})",
    re.I,
)

def _ua_family_template(user_agent: str, parsed: dict[str, Any]) -> str | None:
    if parsed.get("ua_class") != "browser" or parsed.get("browser_major") is None:
        return None

    def repl(match: re.Match[str]) -> str:
        return f"{match.group(1)}/{{ver}}{match.group(3)}"

    template = _BROWSER_VERSION_TOKEN_RE.sub(repl, user_agent)
    return template if template != user_agent else None

def _population_cv(values: list[float]) -> float | None:
    if not values:
        return None
    mean = sum(values) / len(values)
    if mean <= 0:
        return None
    variance = sum((value - mean) ** 2 for value in values) / len(values)
    return math.sqrt(variance) / mean

def _campaign_overlaps(members: list[str], campaigns: list[dict[str, Any]]) -> list[dict[str, Any]]:
    member_set = set(members)
    overlaps: list[dict[str, Any]] = []
    for campaign in campaigns:
        campaign_members = [
            str(ua) for ua in campaign.get("leads") or [] if str(ua) in member_set
        ]
        if not campaign_members:
            continue
        overlaps.append(
            {
                "campaign_id": campaign.get("campaign_id"),
                "member_count": len(campaign_members),
                "members": campaign_members,
            }
        )
    return overlaps

def _build_ua_families(
    scraper_cases: list[dict[str, Any]], campaigns: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for case in scraper_cases:
        ua = str(case.get("user_agent") or "")
        parsed = ((case.get("ua_plausibility") or {}).get("parsed") or {})
        template = _ua_family_template(ua, parsed)
        if template:
            grouped[template].append(case)

    candidates: list[dict[str, Any]] = []
    for template, members in grouped.items():
        versions = sorted(
            {
                int(((case.get("ua_plausibility") or {}).get("parsed") or {}).get("browser_major"))
                for case in members
                if ((case.get("ua_plausibility") or {}).get("parsed") or {}).get("browser_major") is not None
            }
        )
        if len(members) < 3 or len(versions) < 3:
            continue
        request_counts = [_num(case.get("requests")) for case in members]
        request_cv = _population_cv(request_counts)
        if request_cv is None or request_cv >= 0.5:
            continue
        member_uas = [str(case.get("user_agent")) for case in members if case.get("user_agent")]
        total_requests = sum(request_counts)
        total_baseline = sum(_num(case.get("baseline_requests")) for case in members)
        total_bytes = sum(_num(case.get("bytes")) for case in members)
        total_baseline_bytes = sum(_num(case.get("baseline_bytes")) for case in members)
        total_hydrolix_log_ingest_bytes = _sum_optional_lane(members, "hydrolix_log_ingest_bytes")
        total_baseline_hydrolix_log_ingest_bytes = _sum_optional_lane(
            members, "baseline_hydrolix_log_ingest_bytes"
        )
        total_response_body_bytes = _sum_optional_lane(members, "response_body_bytes")
        total_baseline_response_body_bytes = _sum_optional_lane(members, "baseline_response_body_bytes")
        total_akamai_billed_bytes = _sum_optional_lane(members, "akamai_billed_bytes")
        total_baseline_akamai_billed_bytes = _sum_optional_lane(members, "baseline_akamai_billed_bytes")
        common_flags = sorted(
            set.intersection(
                *[set(str(flag) for flag in case.get("evidence_flags") or []) for case in members]
            )
        ) if members else []
        structural_checks = sorted(
            {
                str(check)
                for case in members
                for check in ((case.get("ua_plausibility") or {}).get("fired_structural_checks") or [])
            }
        )
        candidates.append(
            {
                "template": template,
                "members": member_uas,
                "member_count": len(member_uas),
                "version_range": {
                    "min": min(versions),
                    "max": max(versions),
                },
                "version_count": len(versions),
                "versions": versions,
                "total_requests": total_requests,
                "total_baseline": total_baseline,
                "bytes": total_bytes,
                "baseline_bytes": total_baseline_bytes,
                "hydrolix_log_ingest_bytes": total_hydrolix_log_ingest_bytes,
                "baseline_hydrolix_log_ingest_bytes": total_baseline_hydrolix_log_ingest_bytes,
                "response_body_bytes": total_response_body_bytes,
                "baseline_response_body_bytes": total_baseline_response_body_bytes,
                "akamai_billed_bytes": total_akamai_billed_bytes,
                "baseline_akamai_billed_bytes": total_baseline_akamai_billed_bytes,
                "request_volume_cv": round(request_cv, 4),
                "common_evidence": [
                    "Browser user-agent strings share the same template after replacing browser major versions.",
                    "Request volumes are uniform enough to suggest parameterized UA-version rotation.",
                    *common_flags,
                ],
                "structural_checks": structural_checks,
                "campaign_overlaps": _campaign_overlaps(member_uas, campaigns),
                "evidence_flags": ["ua_family_version_rotation"],
            }
        )
    candidates.sort(key=lambda family: (-_num(family.get("total_requests")), str(family.get("template"))))
    for idx, family in enumerate(candidates, start=1):
        family["family_id"] = f"ua-family-{idx}"
        family["recommended_actions"] = [_action_for_case(family, scope="ua_family")]
        for case in scraper_cases:
            if case.get("user_agent") not in set(family["members"]):
                continue
            case["ua_family_id"] = family["family_id"]
            case["ua_family_template"] = family["template"]
            case["nested_under_family"] = not bool(case.get("campaign_id"))
    return candidates

def _attach_recommended_actions(
    campaigns: list[dict[str, Any]],
    ua_families: list[dict[str, Any]],
    scraper_cases: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    case_by_ua = {str(case.get("user_agent")): case for case in scraper_cases if case.get("user_agent")}
    covered_leads: set[str] = set()
    actions: list[dict[str, Any]] = []
    for campaign in campaigns:
        member_cases = [case_by_ua[ua] for ua in campaign.get("leads") or [] if ua in case_by_ua]
        if not member_cases:
            continue
        prototype = {
            **campaign,
            "campaign_id": campaign.get("campaign_id"),
            "evidence_flags": campaign.get("evidence_flags") or sorted({flag for case in member_cases for flag in case.get("evidence_flags", [])}),
            "endpoint_targets": campaign.get("endpoint_targets") or [],
            "bytes": sum(_num(case.get("bytes")) for case in member_cases) or None,
        }
        action = _action_for_case(prototype, scope="campaign")
        campaign["recommended_actions"] = [action]
        covered_leads.update(str(ua) for ua in campaign.get("leads") or [])
        actions.append(action)
    family_leads: set[str] = set()
    for family in ua_families:
        family_action = _action_for_case(family, scope="ua_family")
        family["recommended_actions"] = [family_action]
        family_leads.update(str(ua) for ua in family.get("members") or [])
        actions.append(family_action)
    for case in scraper_cases:
        ua = str(case.get("user_agent") or "")
        if ua in covered_leads or ua in family_leads:
            case["recommended_actions"] = []
            continue
        flags = [str(flag) for flag in case.get("evidence_flags") or [] if str(flag)]
        if case.get("known_traffic") or not flags:
            case["recommended_actions"] = []
            continue
        if str(case.get("verdict") or "") == "not_enough_data" and not flags:
            case["recommended_actions"] = []
            continue
        action = _action_for_case(case, scope="lead")
        case["recommended_actions"] = [action]
        actions.append(action)
    order = {"tier_1": 0, "tier_2": 1, "tier_3": 2, "tier_4": 3}
    actions.sort(
        key=lambda action: (
            {"campaign": 0, "ua_family": 1}.get(str(action.get("scope")), 2),
            order.get(str(action.get("tier")), 9),
            -_num((action.get("estimated_observed_window_impact") or {}).get("requests")),
        )
    )
    return actions

__all__ = [name for name in globals() if not name.startswith("__")]
