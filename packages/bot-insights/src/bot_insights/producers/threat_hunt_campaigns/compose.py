"""Campaign record assembly."""

from __future__ import annotations

from collections import Counter
from typing import Any

from .endpoints import _campaign_endpoint_evidence_summary, _endpoint_category
from .linking import _campaign_sophistication, _temporal_pattern
from .numbers import _num, _pct
from .summaries import (
    _campaign_drilldown_coverage_summary,
    _campaign_fanout_summary,
    _campaign_timing_summary,
    _campaign_ua_plausibility_summary,
)
from .verdicts import _verdict_for_family_count


def _compose_campaign(
    campaign_id: str,
    members: list[str],
    edges: list[dict[str, Any]],
    case_by_ua: dict[str, dict[str, Any]],
    features: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    families = set()
    for ua in members:
        case = case_by_ua.get(ua, {})
        temporal = case.get("temporal_regularity") if isinstance(case, dict) else None
        for flag in case.get("evidence_flags", []):
            flag_name = str(flag)
            if (
                flag_name == "temporal_regularity"
                and isinstance(temporal, dict)
                and temporal.get("resolution") != "request_iat"
            ):
                continue
            if flag_name:
                families.add(flag_name)
    families.add("coordinated_activity")
    total_requests = sum(_num(case_by_ua.get(ua, {}).get("requests")) for ua in members)
    baseline_requests = sum(_num(case_by_ua.get(ua, {}).get("baseline_requests")) for ua in members)
    ips = set().union(*(features[ua]["client_ips"] for ua in members))
    asns = Counter()
    countries = Counter()
    paths = Counter()
    hours = Counter()
    for ua in members:
        asns.update(features[ua]["asns"])
        countries.update(features[ua]["countries"])
        paths.update(features[ua]["paths"])
        hours.update(features[ua]["hours"])
    coverage_summary = _campaign_drilldown_coverage_summary(members, case_by_ua)
    endpoint_evidence_summary = _campaign_endpoint_evidence_summary(
        members, case_by_ua, paths, coverage_summary
    )
    if endpoint_evidence_summary.get("counts_for_verdict"):
        families.add("endpoint_targeting")
    else:
        families.discard("endpoint_targeting")
    timing_summary = _campaign_timing_summary(members, case_by_ua, features)
    ua_plausibility_summary = _campaign_ua_plausibility_summary(members, case_by_ua)
    fanout_summary = _campaign_fanout_summary(members, case_by_ua)
    temporal_pattern = _temporal_pattern(edges)
    if temporal_pattern == "not_established" and timing_summary.get("parallel_independent"):
        temporal_pattern = "parallel_independent"
        families.add("temporal_regularity")

    endpoint_targets = [
        {
            "endpoint_prefix": path,
            "requests": requests,
            "share_pct": _pct(requests, sum(paths.values())),
            "endpoint_category": _endpoint_category(path),
        }
        for path, requests in paths.most_common(10)
    ]
    hourly_profile = [
        {"hour": hour, "requests": requests, "share_pct": _pct(requests, sum(hours.values()))}
        for hour, requests in hours.most_common(10)
    ]
    return {
        "campaign_id": campaign_id,
        "verdict": _verdict_for_family_count(len(families)),
        "sophistication": _campaign_sophistication(edges, len(asns), len(countries)),
        "temporal_pattern": temporal_pattern,
        "timing_summary": timing_summary,
        "leads": members,
        "linking_evidence": edges,
        "evidence_flags": sorted(families),
        "total_requests": total_requests,
        "baseline_requests": baseline_requests,
        "unique_client_ips": len(ips),
        "unique_asns": len(asns),
        "unique_countries": len(countries),
        "endpoint_targets": endpoint_targets,
        "endpoint_evidence_summary": endpoint_evidence_summary,
        "ua_plausibility_summary": ua_plausibility_summary,
        "fanout_summary": fanout_summary,
        "hourly_profile": hourly_profile,
        "drilldown_coverage_summary": coverage_summary,
        "sample_asns": [asn for asn, _ in asns.most_common(5)],
        "sample_countries": [country for country, _ in countries.most_common(5)],
    }
