"""Second-pass campaign detector for ``bot_threat_hunt.v3`` scraper leads."""

from __future__ import annotations

import math
import ipaddress
from collections import Counter, defaultdict, deque
from typing import Any, Iterable
from urllib.parse import urlsplit


VERDICT_ORDER = {
    "strong_lead": 0,
    "lead": 1,
    "weak_lead": 2,
    "not_enough_data": 3,
}

_TRACKING_STATIC_PATHS = (
    "/cl/2x2.json",
    "/travel-pixel-js",
    "/egds/fonts",
    "/favicon.ico",
    "/landing-pwa/css",
)

_TARGET_ENDPOINT_CATEGORIES = {"api", "graphql", "catalog_search_product_content", "auth"}


def _num(value: Any, default: float = 0.0) -> float:
    if value is None or value == "":
        return default
    try:
        n = float(value)
    except (TypeError, ValueError):
        return default
    if math.isnan(n) or math.isinf(n):
        return default
    return n


def _pct(part: float, whole: float) -> float | None:
    if whole <= 0:
        return None
    return part / whole * 100.0


def _coverage_label(status_counts: Counter[str], weighted_pct: float | None, member_count: int) -> str:
    if weighted_pct is not None and weighted_pct >= 75.0:
        return "focused_api_surface"
    low_count = status_counts.get("unavailable", 0) + status_counts.get("uncharacterized", 0)
    if member_count and low_count > member_count / 2:
        return "diffuse_surface"
    return "mixed_surface"


def _campaign_drilldown_coverage_summary(members: list[str], case_by_ua: dict[str, dict[str, Any]]) -> dict[str, Any]:
    status_counts: Counter[str] = Counter()
    drilldown_requests = 0.0
    total_requests = 0.0
    for ua in members:
        coverage = case_by_ua.get(ua, {}).get("drilldown_coverage")
        if not isinstance(coverage, dict):
            coverage = {
                "status": "unavailable",
                "drilldown_requests": 0.0,
                "total_requests": _num(case_by_ua.get(ua, {}).get("requests")),
            }
        status_counts[str(coverage.get("status") or "unavailable")] += 1
        drilldown_requests += _num(coverage.get("drilldown_requests"))
        total_requests += _num(coverage.get("total_requests"))
    weighted_pct = _pct(drilldown_requests, total_requests)
    return {
        "member_count": len(members),
        "status_counts": dict(sorted(status_counts.items())),
        "drilldown_requests": drilldown_requests,
        "total_requests": total_requests,
        "weighted_coverage_pct": weighted_pct,
        "surface_label": _coverage_label(status_counts, weighted_pct, len(members)),
    }


def _geo_for_ip(ip: str, geo: dict[str, dict[str, Any]]) -> dict[str, Any]:
    if ip in geo:
        return geo[ip]
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return {}
    for key, value in geo.items():
        try:
            network = ipaddress.ip_network(key, strict=False)
        except ValueError:
            continue
        if address in network:
            return value
    return {}


def endpoint_prefix(path: str) -> str:
    """Collapse a request path to the first two stable path segments."""

    raw = str(path or "").strip()
    if not raw:
        return ""
    parsed = urlsplit(raw if "://" in raw else f"https://example.invalid{raw if raw.startswith('/') else '/' + raw}")
    segments = [segment for segment in parsed.path.split("/") if segment]
    if not segments:
        return "/"
    return "/" + "/".join(segments[:2])


def _endpoint_category(path: str) -> str:
    lowered = str(path or "").lower()
    if any(lowered.startswith(prefix) for prefix in _TRACKING_STATIC_PATHS):
        return "tracking_static_asset"
    if "graphql" in lowered or "gql" in lowered:
        return "graphql"
    if any(token in lowered for token in ("login", "auth", "token", "session", "oauth")):
        return "auth"
    if any(token in lowered for token in ("checkout", "book", "booking", "reserve", "reservation", "cart", "hold", "purchase", "payment", "order")):
        return "transaction"
    if any(token in lowered for token in ("catalog", "product", "inventory", "search", "listing")):
        return "catalog_search_product_content"
    if any(token in lowered for token in ("/api", "/v1", "/v2", "/v3")):
        return "api"
    if lowered.endswith((".css", ".js", ".ico", ".woff", ".woff2", ".ttf", ".png", ".jpg", ".jpeg", ".gif", ".svg")):
        return "static_asset"
    return "general_site"


def _campaign_endpoint_evidence_summary(
    members: list[str],
    case_by_ua: dict[str, dict[str, Any]],
    paths: Counter[str],
    coverage_summary: dict[str, Any],
) -> dict[str, Any]:
    tier_counts: Counter[str] = Counter()
    source_counts: Counter[str] = Counter()
    category_counts: Counter[str] = Counter()
    confirmed_member_count = 0
    for ua in members:
        evidence = case_by_ua.get(ua, {}).get("endpoint_evidence")
        if not isinstance(evidence, dict):
            evidence = {"tier": "not_available", "source": None, "counts_for_verdict": False}
        tier = str(evidence.get("tier") or "not_available")
        tier_counts[tier] += 1
        source = evidence.get("source")
        if source:
            source_counts[str(source)] += 1
        if evidence.get("counts_for_verdict"):
            confirmed_member_count += 1
        for category in evidence.get("categories") or []:
            if category:
                category_counts[str(category)] += 1
    for path, requests in paths.items():
        category_counts[_endpoint_category(path)] += _num(requests)
    dominant_categories = [
        {"category": category, "weight": weight}
        for category, weight in category_counts.most_common(5)
    ]
    confirmed_campaign_scoped = bool(
        _num(coverage_summary.get("weighted_coverage_pct")) >= 1.0
        and any(category in _TARGET_ENDPOINT_CATEGORIES for category in category_counts)
    )
    counts_for_verdict = confirmed_member_count > 0 or confirmed_campaign_scoped
    if counts_for_verdict:
        reason = "confirmed_member_endpoint_evidence" if confirmed_member_count else "campaign_scoped_ge_1pct_target_categories"
    elif tier_counts.get("inferred_site_context"):
        reason = "members_inferred_from_site_context"
    elif tier_counts.get("unconfirmed_scoped"):
        reason = "members_unconfirmed_scoped"
    else:
        reason = "no_endpoint_evidence"
    return {
        "member_count": len(members),
        "confirmed_member_count": confirmed_member_count,
        "inferred_member_count": tier_counts.get("inferred_site_context", 0),
        "unconfirmed_member_count": tier_counts.get("unconfirmed_scoped", 0),
        "not_available_member_count": tier_counts.get("not_available", 0),
        "tier_counts": dict(sorted(tier_counts.items())),
        "source_counts": dict(sorted(source_counts.items())),
        "dominant_categories": dominant_categories,
        "counts_for_verdict": counts_for_verdict,
        "reason": reason,
    }


def _cosine(left: Counter[str], right: Counter[str]) -> float | None:
    if not left or not right:
        return None
    shared = set(left) & set(right)
    numerator = sum(left[key] * right[key] for key in shared)
    left_mag = math.sqrt(sum(value * value for value in left.values()))
    right_mag = math.sqrt(sum(value * value for value in right.values()))
    if left_mag <= 0 or right_mag <= 0:
        return None
    return numerator / (left_mag * right_mag)


def _pearson(left: Counter[str], right: Counter[str]) -> float | None:
    keys = sorted(set(left) | set(right))
    if len(keys) < 2:
        return None
    left_values = [_num(left.get(key)) for key in keys]
    right_values = [_num(right.get(key)) for key in keys]
    left_mean = sum(left_values) / len(left_values)
    right_mean = sum(right_values) / len(right_values)
    numerator = sum((a - left_mean) * (b - right_mean) for a, b in zip(left_values, right_values))
    left_den = math.sqrt(sum((a - left_mean) ** 2 for a in left_values))
    right_den = math.sqrt(sum((b - right_mean) ** 2 for b in right_values))
    if left_den <= 0 or right_den <= 0:
        return None
    return numerator / (left_den * right_den)


def _verdict_for_family_count(count: int) -> str:
    if count >= 3:
        return "strong_lead"
    if count >= 2:
        return "lead"
    if count == 1:
        return "weak_lead"
    return "not_enough_data"


def _feature_vectors(
    scraper_cases: list[dict[str, Any]],
    cooccurrence_rows: list[dict[str, Any]],
    drilldown_rows: list[dict[str, Any]],
    geo: dict[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    uas = {str(case.get("user_agent") or "") for case in scraper_cases if case.get("user_agent")}
    features: dict[str, dict[str, Any]] = {
        ua: {
            "user_agent": ua,
            "client_ips": set(),
            "countries": Counter(),
            "asns": Counter(),
            "paths": Counter(),
            "hours": Counter(),
        }
        for ua in uas
    }

    for row in cooccurrence_rows:
        ua = str(row.get("user_agent") or "")
        ip = str(row.get("client_ip") or "")
        if ua not in features or not ip:
            continue
        requests = _num(row.get("requests"), 1.0) or 1.0
        item = features[ua]
        item["client_ips"].add(ip)
        geo_row = _geo_for_ip(ip, geo)
        country = str(row.get("country") or geo_row.get("country") or "").strip()
        if country:
            item["countries"][country] += requests
        asn = str(geo_row.get("asn") or "").strip()
        if asn:
            item["asns"][asn] += requests

    for row in drilldown_rows:
        ua = str(row.get("user_agent") or "")
        if ua not in features:
            continue
        requests = _num(row.get("requests"), 1.0) or 1.0
        item = features[ua]
        ip = str(row.get("client_ip") or "")
        if ip:
            item["client_ips"].add(ip)
            geo_row = _geo_for_ip(ip, geo)
            asn = str(geo_row.get("asn") or "").strip()
            if asn:
                item["asns"][asn] += requests
            country = str(row.get("country") or geo_row.get("country") or "").strip()
            if country:
                item["countries"][country] += requests
        prefix = endpoint_prefix(str(row.get("request_path") or ""))
        if prefix:
            item["paths"][prefix] += requests
        hour = str(row.get("hour") or "").strip()
        if hour:
            item["hours"][hour] += requests

    for case in scraper_cases:
        ua = str(case.get("user_agent") or "")
        if ua not in features:
            continue
        item = features[ua]
        timing = case.get("temporal_regularity")
        if isinstance(timing, dict):
            for row in timing.get("hourly_profile") or []:
                if not isinstance(row, dict):
                    continue
                hour = str(row.get("hour") or "").strip()
                if hour:
                    item["hours"][hour] += _num(row.get("requests"), 1.0) or 1.0
        if not case.get("drilldown_available"):
            continue
        for row in case.get("endpoint_targets") or []:
            if not isinstance(row, dict):
                continue
            prefix = endpoint_prefix(str(row.get("request_path") or row.get("value") or ""))
            if prefix:
                item["paths"][prefix] += _num(row.get("requests"), 1.0) or 1.0
        for row in case.get("hourly_bursts") or []:
            if not isinstance(row, dict):
                continue
            hour = str(row.get("hour") or "").strip()
            if hour:
                item["hours"][hour] += _num(row.get("requests"), 1.0) or 1.0
        for country in case.get("countries") or []:
            if isinstance(country, str) and country:
                item["countries"][country] += 1.0
        for asn in case.get("asns") or []:
            if isinstance(asn, str) and asn:
                item["asns"][asn] += 1.0
        for row in case.get("client_ips") or []:
            if isinstance(row, dict) and row.get("client_ip"):
                item["client_ips"].add(str(row["client_ip"]))

    return features


def _link_edge(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any] | None:
    shared_ips = sorted(left["client_ips"] & right["client_ips"])
    path_cosine = _cosine(left["paths"], right["paths"])
    asn_cosine = _cosine(left["asns"], right["asns"])
    country_cosine = _cosine(left["countries"], right["countries"])
    temporal_correlation = _pearson(left["hours"], right["hours"])
    shared_paths = sorted(set(left["paths"]) & set(right["paths"]))
    link_types = []

    if len(shared_ips) >= 3:
        link_types.append("shared_ips")
    if path_cosine is not None and path_cosine >= 0.85 and len(shared_paths) >= 3:
        link_types.append("shared_endpoint_profile")
    if (
        temporal_correlation is not None
        and temporal_correlation <= -0.6
        and asn_cosine is not None
        and asn_cosine >= 0.7
    ):
        link_types.append("temporal_rotation_asn_similarity")
    if (
        temporal_correlation is not None
        and temporal_correlation >= 0.75
        and path_cosine is not None
        and path_cosine >= 0.7
    ):
        link_types.append("synchronized_timing_endpoint_similarity")

    if not link_types:
        return None

    return {
        "left_user_agent": left["user_agent"],
        "right_user_agent": right["user_agent"],
        "link_types": link_types,
        "shared_ip_count": len(shared_ips),
        "shared_ip_samples": shared_ips[:5],
        "path_cosine": path_cosine,
        "asn_cosine": asn_cosine,
        "country_cosine": country_cosine,
        "temporal_correlation": temporal_correlation,
        "shared_path_count": len(shared_paths),
        "shared_path_samples": shared_paths[:5],
        "path_similarity_available": path_cosine is not None,
        "temporal_similarity_available": temporal_correlation is not None,
        "asn_similarity_available": asn_cosine is not None,
    }


def _connected_components(nodes: Iterable[str], edges: list[dict[str, Any]]) -> list[list[str]]:
    graph: dict[str, set[str]] = {node: set() for node in nodes}
    for edge in edges:
        left = str(edge["left_user_agent"])
        right = str(edge["right_user_agent"])
        graph.setdefault(left, set()).add(right)
        graph.setdefault(right, set()).add(left)
    seen: set[str] = set()
    components = []
    for node in sorted(graph):
        if node in seen:
            continue
        queue: deque[str] = deque([node])
        seen.add(node)
        component = []
        while queue:
            current = queue.popleft()
            component.append(current)
            for neighbor in sorted(graph[current]):
                if neighbor not in seen:
                    seen.add(neighbor)
                    queue.append(neighbor)
        if len(component) >= 2:
            components.append(sorted(component))
    return components


def _campaign_sophistication(edges: list[dict[str, Any]], unique_asns: int, unique_countries: int) -> str:
    link_types = {link_type for edge in edges for link_type in edge.get("link_types", [])}
    if len(link_types) >= 3 or (unique_asns >= 3 and unique_countries >= 3):
        return "high"
    if len(link_types) >= 2 or unique_asns >= 2:
        return "moderate"
    return "basic"


def _temporal_pattern(edges: list[dict[str, Any]]) -> str:
    link_types = {link_type for edge in edges for link_type in edge.get("link_types", [])}
    if "temporal_rotation_asn_similarity" in link_types:
        return "rotating"
    if "synchronized_timing_endpoint_similarity" in link_types:
        return "synchronized"
    return "not_established"


def _campaign_timing_summary(
    members: list[str],
    case_by_ua: dict[str, dict[str, Any]],
    features: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    regular_members = []
    correlations = []
    for ua in members:
        timing = case_by_ua.get(ua, {}).get("temporal_regularity")
        if isinstance(timing, dict) and timing.get("archetype") == "hourly_regular":
            regular_members.append(ua)
    for index, left_ua in enumerate(members):
        for right_ua in members[index + 1 :]:
            corr = _pearson(features[left_ua]["hours"], features[right_ua]["hours"])
            if corr is not None:
                correlations.append(corr)
    mean_abs = (
        sum(abs(value) for value in correlations) / len(correlations)
        if correlations
        else None
    )
    max_abs = max((abs(value) for value in correlations), default=None)
    member_count = len(members)
    regular_pct = _pct(len(regular_members), member_count)
    parallel = bool(
        member_count >= 4
        and regular_pct is not None
        and regular_pct >= 50.0
        and correlations
        and _num(mean_abs, 999.0) <= 0.25
        and _num(max_abs, 999.0) <= 0.50
    )
    return {
        "member_count": member_count,
        "regular_member_count": len(regular_members),
        "regular_member_pct": regular_pct,
        "regular_members": regular_members,
        "pairwise_correlation_count": len(correlations),
        "mean_abs_pairwise_temporal_correlation": mean_abs,
        "max_abs_pairwise_temporal_correlation": max_abs,
        "parallel_independent": parallel,
        "evidence_text": (
            "linked leads independently exhibit regular hourly cadence without synchronized timing, "
            "consistent with parallel scraper workers."
        )
        if parallel
        else None,
    }


def _campaign_ua_plausibility_summary(
    members: list[str], case_by_ua: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    trigger_counts: Counter[str] = Counter()
    status_counts: Counter[str] = Counter()
    anomaly_counts: Counter[str] = Counter()
    anomalous = 0
    weak = 0
    max_score = 0.0
    for ua in members:
        plausibility = case_by_ua.get(ua, {}).get("ua_plausibility")
        if not isinstance(plausibility, dict):
            status_counts["unavailable"] += 1
            continue
        verdict = str(plausibility.get("verdict") or "unavailable")
        status_counts[verdict] += 1
        score = _num(plausibility.get("composite_score"))
        max_score = max(max_score, score)
        if plausibility.get("counts_for_verdict"):
            anomalous += 1
        elif verdict == "elevated":
            weak += 1
        trigger = str(plausibility.get("trigger_reason") or "")
        if trigger:
            trigger_counts[trigger] += 1
        signals = plausibility.get("signals") if isinstance(plausibility.get("signals"), dict) else {}
        for name, signal in signals.items():
            if isinstance(signal, dict) and _num(signal.get("score")) > 0:
                anomaly_counts[str(name)] += 1
    forged = bool(
        anomalous >= 2
        or (
            len(members) >= 3
            and status_counts.get("elevated", 0) + anomalous >= 2
            and max_score >= 0.6
        )
    )
    return {
        "member_count": len(members),
        "anomalous_member_count": anomalous,
        "weak_member_count": weak,
        "status_counts": dict(sorted(status_counts.items())),
        "top_triggers": [
            {"trigger": trigger, "count": count}
            for trigger, count in trigger_counts.most_common(5)
        ],
        "dominant_anomaly_types": [
            {"type": name, "count": count}
            for name, count in anomaly_counts.most_common(5)
        ],
        "max_score": max_score,
        "forged_ua_candidate": forged,
    }


def _campaign_fanout_summary(
    members: list[str], case_by_ua: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    source_counts: Counter[str] = Counter()
    unique_total = 0.0
    effective_total = 0.0
    available = 0
    threshold_counts: Counter[str] = Counter()
    for ua in members:
        fanout = case_by_ua.get(ua, {}).get("fanout_enrichment")
        if not isinstance(fanout, dict) or str(fanout.get("source") or "unavailable") == "unavailable":
            continue
        available += 1
        source = str(fanout.get("source") or "unknown")
        source_counts[source] += 1
        threshold_counts[str(fanout.get("threshold_class") or "unknown")] += 1
        unique_total += _num(fanout.get("unique_ips") if fanout.get("unique_ips") is not None else fanout.get("unique_client_ips"))
        effective_total += _num(fanout.get("effective_ips") or fanout.get("unique_ips") or fanout.get("unique_client_ips"))
    source = source_counts.most_common(1)[0][0] if source_counts else "unavailable"
    return {
        "member_count": len(members),
        "available_member_count": available,
        "source": source,
        "source_counts": dict(sorted(source_counts.items())),
        "threshold_counts": dict(sorted(threshold_counts.items())),
        "unique_ips_lower_bound": int(unique_total),
        "effective_ips_composite": int(effective_total),
        "line": (
            f"Composite member fan-out lower bound sums {int(unique_total):,} per-UA unique-IP observations "
            f"({int(effective_total):,} effective IPs); this is not an exact deduplicated campaign union."
        )
        if available
        else "Campaign fan-out enrichment unavailable; no exact member-union IP count is claimed.",
    }


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
