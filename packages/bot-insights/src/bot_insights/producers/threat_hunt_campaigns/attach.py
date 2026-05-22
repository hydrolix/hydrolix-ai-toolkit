"""Top-level campaign attachment entrypoint."""

from __future__ import annotations

from typing import Any

from .compose import _compose_campaign
from .constants import VERDICT_ORDER
from .features import _feature_vectors
from .linking import _connected_components, _link_edge
from .numbers import _num
from .verdicts import _verdict_for_family_count


def attach_campaigns(
    *,
    scraper_cases: list[dict[str, Any]],
    cooccurrence_rows: list[dict[str, Any]],
    drilldown_rows: list[dict[str, Any]],
    geo: dict[str, dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Return ``(campaigns, scraper_cases)`` with campaign membership added."""

    if len(scraper_cases) < 2:
        return [], scraper_cases

    cases = [{**case} for case in scraper_cases]
    case_by_ua = {str(case.get("user_agent")): case for case in cases if case.get("user_agent")}
    features = _feature_vectors(cases, cooccurrence_rows, drilldown_rows, geo)
    uas = sorted(case_by_ua)
    edges = []
    for index, left_ua in enumerate(uas):
        for right_ua in uas[index + 1 :]:
            edge = _link_edge(features[left_ua], features[right_ua])
            if edge:
                edges.append(edge)

    campaigns = []
    for ordinal, members in enumerate(_connected_components(uas, edges), start=1):
        member_set = set(members)
        member_edges = [
            edge
            for edge in edges
            if edge["left_user_agent"] in member_set and edge["right_user_agent"] in member_set
        ]
        campaigns.append(
            _compose_campaign(
                f"campaign-{ordinal}",
                members,
                member_edges,
                case_by_ua,
                features,
            )
        )

    campaigns.sort(
        key=lambda row: (
            VERDICT_ORDER.get(str(row.get("verdict")), 9),
            -_num(row.get("total_requests")),
            str(row.get("campaign_id")),
        )
    )
    campaign_for_ua = {
        ua: campaign
        for campaign in campaigns
        for ua in campaign.get("leads", [])
    }
    for case in cases:
        ua = str(case.get("user_agent") or "")
        campaign = campaign_for_ua.get(ua)
        if not campaign:
            continue
        flags = [str(flag) for flag in case.get("evidence_flags") or []]
        if "coordinated_activity" not in flags:
            flags.append("coordinated_activity")
        case["evidence_flags"] = flags
        family = {
            "family": "coordinated_activity",
            "label": f"Part of {campaign['campaign_id']} with explainable shared infrastructure, targeting, or timing evidence.",
            "rows": [
                {
                    "campaign_id": campaign["campaign_id"],
                    "member_count": len(campaign.get("leads") or []),
                    "edge_count": len(campaign.get("linking_evidence") or []),
                }
            ],
        }
        families = [row for row in case.get("evidence_families") or [] if isinstance(row, dict)]
        if not any(row.get("family") == "coordinated_activity" for row in families):
            families.append(family)
        case["evidence_families"] = families
        case["campaign_id"] = campaign["campaign_id"]
        case["campaign_verdict"] = campaign["verdict"]
        case["verdict"] = _verdict_for_family_count(len(set(flags)))
        case["case_for"] = [
            *(case.get("case_for") or []),
            family["label"],
        ]
        case["missing_evidence"] = [
            flag for flag in (case.get("missing_evidence") or []) if flag != "coordinated_activity"
        ]
        case["case_against"] = [
            item
            for item in (case.get("case_against") or [])
            if "coordinated activity" not in str(item).lower()
        ]

    cases.sort(
        key=lambda row: (
            VERDICT_ORDER.get(str(row.get("verdict")), 9),
            -_num(row.get("requests")),
            str(row.get("user_agent")),
        )
    )
    return campaigns, cases
