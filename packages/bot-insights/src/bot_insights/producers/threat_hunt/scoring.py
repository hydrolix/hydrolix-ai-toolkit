from __future__ import annotations

from ._shared import *

def _fanout_limit_detail(fanout: list[dict[str, Any]]) -> str:
    if not fanout:
        return "source-aware UA fan-out enrichment"
    sources = sorted({str(row.get("source") or "unknown") for row in fanout})
    if sources == ["summary_hour"]:
        return "full-window source-aware UA fan-out enrichment from summary_hour"
    if sources == ["logs_probe"]:
        return "peak-hour logs_probe fan-out enrichment; effective counts are conservative bounded lower-bound estimates"
    if sources == ["cooccurrence_lower_bound"]:
        return "cooccurrence-derived lower-bound UA fan-out enrichment; true full-window fan-out is unknown"
    return "mixed-source UA fan-out enrichment; campaign totals are composite lower-bound estimates"

def _score_baseline(current: dict[str, float], baseline: dict[str, float]) -> dict[str, Any]:
    req_delta_pct = _pct(current.get("requests", 0) - baseline.get("requests", 0), baseline.get("requests", 0))
    strong = req_delta_pct is not None and abs(req_delta_pct) >= 50 and current.get("requests", 0) >= 1000
    return {
        "module": "baseline_movement",
        "verdict": "likely" if strong else "possible" if current.get("requests", 0) else "not_enough_data",
        "rationale": "Current-vs-baseline request movement is large." if strong else "Baseline movement is present but not independently conclusive.",
        "metrics": [_metric_delta(name, current, baseline) for name in ("requests", "bytes", "status_429", "status_5xx", "bot_requests", "human_requests")],
    }

def _score_ua(
    fingerprints: list[dict[str, Any]],
    cooccurrence_available: bool,
    fanout: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    top = fingerprints[0] if fingerprints else {}
    top_fanout = (fanout or [None])[0] if fanout else None
    top_fanout_ips = _fanout_effective_ips(top_fanout or {}) if top_fanout else 0.0
    if not top and not top_fanout:
        verdict = "not_enough_data"
    elif top_fanout_ips >= 50_000:
        verdict = "confirmed"
    elif top_fanout_ips >= 10_000:
        verdict = "likely"
    elif cooccurrence_available and _int(top.get("unique_client_ips")) >= 20 and _int(top.get("unique_asns")) >= 3 and _int(top.get("unique_countries")) >= 3:
        verdict = "confirmed"
    elif cooccurrence_available and (_int(top.get("unique_client_ips")) >= 10 or _int(top.get("unique_asns")) >= 2):
        verdict = "likely"
    else:
        verdict = "possible"
    return {
        "module": "ua_fanout",
        "verdict": verdict,
        "rationale": "UA fanout is scored from source-aware enrichment when available, otherwise from cooccurrence IP/ASN/country spread.",
        "top_user_agent": (top_fanout or top).get("user_agent"),
        "top_fanout_source": (top_fanout or {}).get("source"),
    }

def _score_endpoint(endpoints: list[dict[str, Any]]) -> dict[str, Any]:
    marker_rows = [row for row in endpoints if row.get("markers")]
    if not endpoints:
        verdict = "not_enough_data"
    elif marker_rows and _num(endpoints[0].get("request_share_pct")) >= 50:
        verdict = "likely"
    elif marker_rows or _num(endpoints[0].get("requests")) > 0:
        verdict = "possible"
    else:
        verdict = "not_enough_data"
    return {
        "module": "endpoint_harvest",
        "verdict": verdict,
        "rationale": "Endpoint-harvest scoring looks for concentrated paths plus API/catalog/GraphQL/auth markers.",
        "marker_count": len(marker_rows),
    }

def _score_infra(infra: dict[str, Any]) -> dict[str, Any]:
    hints = infra.get("topology_hints") or []
    if infra.get("availability") == "not_available":
        verdict = "not_enough_data"
    elif {"concentrated_asn", "multi_ip_asn_cluster"} <= set(hints):
        verdict = "likely"
    elif hints:
        verdict = "possible"
    else:
        verdict = "possible"
    return {
        "module": "infrastructure",
        "verdict": verdict,
        "rationale": "Infrastructure scoring reports concentration or distributed-pool hints without inferring operator identity.",
        "topology_hints": hints,
    }

def _score_bhu(fingerprints: list[dict[str, Any]], endpoints: list[dict[str, Any]], infra: dict[str, Any]) -> dict[str, Any]:
    signals = 0
    if fingerprints and _int(fingerprints[0].get("unique_client_ips")) >= 10:
        signals += 1
    if endpoints and endpoints[0].get("markers"):
        signals += 1
    if infra.get("topology_hints"):
        signals += 1
    verdict = "confirmed" if signals == 3 else "likely" if signals == 2 else "possible" if signals == 1 else "not_enough_data"
    return {
        "module": "bhu_style_scraper_indicators",
        "verdict": verdict,
        "rationale": "BHU-style indicators combine exact-UA fanout, endpoint harvesting, and infrastructure topology as a module, not as attribution.",
        "signals_present": signals,
    }

def _ua_actor_row(actor_rows: list[dict[str, Any]], user_agent: str) -> dict[str, Any]:
    for row in actor_rows:
        if (
            row.get("period") == "current"
            and row.get("actor_type") == "user_agent"
            and str(row.get("value")) == user_agent
        ):
            return row
    return {}

def _drilldown_profile(
    user_agent: str,
    drilldown_rows: list[dict[str, Any]],
    geo: dict[str, dict[str, Any]],
    top_n: int,
) -> dict[str, Any]:
    rows = [row for row in drilldown_rows if row.get("user_agent") == user_agent]
    if not rows:
        return {"available": False, "rows": [], "endpoint_targets": [], "hourly_bursts": []}
    endpoint_counter: Counter[str] = Counter()
    hourly_counter: Counter[str] = Counter()
    ip_counter: Counter[str] = Counter()
    country_counter: Counter[str] = Counter()
    asn_counter: Counter[str] = Counter()
    status_429 = 0.0
    status_5xx = 0.0
    total = 0.0
    for row in rows:
        requests = _num(row.get("requests"))
        total += requests
        status_429 += _num(row.get("status_429"))
        status_5xx += _num(row.get("status_5xx"))
        path = str(row.get("request_path") or "")
        if path:
            endpoint_counter[path] += requests
        hour = str(row.get("hour") or "")
        if hour:
            hourly_counter[hour] += requests
        ip = str(row.get("client_ip") or "")
        if ip:
            ip_counter[ip] += requests
            geo_row = _geo_for_ip(ip, geo)
            if geo_row.get("asn"):
                asn_counter[str(geo_row["asn"])] += requests
            if geo_row.get("country"):
                country_counter[str(geo_row["country"])] += requests
        if row.get("country"):
            country_counter[str(row["country"])] += requests
    endpoint_targets = [
        {
            "request_path": path,
            "requests": requests,
            "share_pct": _pct(requests, total),
            "markers": _path_markers(path),
            "endpoint_category": _endpoint_category(path),
        }
        for path, requests in endpoint_counter.most_common(top_n)
    ]
    hourly = [
        {"hour": hour, "requests": requests, "share_pct": _pct(requests, total)}
        for hour, requests in hourly_counter.most_common(top_n)
    ]
    return {
        "available": True,
        "rows": rows[: min(len(rows), 50)],
        "endpoint_targets": endpoint_targets,
        "hourly_bursts": hourly,
        "top_client_ips": [
            {"client_ip": ip, "requests": requests} for ip, requests in ip_counter.most_common(top_n)
        ],
        "countries": [country for country, _ in country_counter.most_common(top_n)],
        "asns": [asn for asn, _ in asn_counter.most_common(top_n)],
        "requests": total,
        "rate_429_pct": _pct(status_429, total),
        "rate_5xx_pct": _pct(status_5xx, total),
    }

def _coverage_status(coverage_pct: float | None, *, has_rows: bool) -> str:
    if not has_rows:
        return "unavailable"
    if coverage_pct is None or coverage_pct < 0.01:
        return "uncharacterized"
    if coverage_pct < 1.0:
        return "thin_slice"
    if coverage_pct < 25.0:
        return "partial"
    if coverage_pct < 75.0:
        return "substantial"
    return "focused"

def _drilldown_coverage(total_requests: float, drilldown_requests: float, has_rows: bool) -> dict[str, Any]:
    coverage_pct = _pct(drilldown_requests, total_requests)
    status = _coverage_status(coverage_pct, has_rows=has_rows)
    return {
        "drilldown_requests": drilldown_requests,
        "total_requests": total_requests,
        "coverage_pct": coverage_pct,
        "status": status,
    }

def _add_family(
    families: dict[str, dict[str, Any]],
    name: str,
    *,
    label: str,
    rows: list[dict[str, Any]] | None = None,
) -> None:
    families[name] = {"family": name, "label": label, "rows": rows or []}

def _automation_signature(user_agent: str) -> bool:
    lowered = user_agent.lower()
    return any(marker in lowered for marker in _AUTOMATION_UA_MARKERS)

def _known_traffic_disposition(user_agent: str) -> dict[str, Any] | None:
    lowered = user_agent.lower()
    if any(pattern in lowered for pattern in _KNOWN_INFRASTRUCTURE_UA_PATTERNS):
        return {
            "disposition": "known_infrastructure",
            "reason": "Akamai image infrastructure user-agent pattern; informational traffic, not a threat-hunt finding.",
        }
    if any(pattern in lowered for pattern in _KNOWN_CRAWLER_UA_PATTERNS):
        return {
            "disposition": "known_crawler",
            "reason": "Major search or app crawler user-agent pattern; informational traffic unless crawler-specific analysis is requested.",
        }
    return None

def _mark_known_traffic(scraper_cases: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    active_cases: list[dict[str, Any]] = []
    known_rows: list[dict[str, Any]] = []
    for case in scraper_cases:
        ua = str(case.get("user_agent") or "")
        disposition = _known_traffic_disposition(ua)
        if not disposition:
            active_cases.append(case)
            continue
        case["known_traffic"] = True
        case["known_traffic_disposition"] = disposition["disposition"]
        case["known_traffic_reason"] = disposition["reason"]
        case["threat_classification"] = {"primary": None, "secondary": [], "ambiguity_note": None}
        case["recommended_actions"] = []
        known_rows.append(
            {
                "user_agent": ua,
                "disposition": disposition["disposition"],
                "reason": disposition["reason"],
                "requests": case.get("requests"),
                "baseline_requests": case.get("baseline_requests"),
                "evidence_flags": case.get("evidence_flags") or [],
            }
        )
    return active_cases, known_rows

def _scraper_case_verdict(families: dict[str, dict[str, Any]]) -> str:
    count = len(families)
    if count >= 3:
        return "strong_lead"
    if count >= 2:
        return "lead"
    if count == 1:
        return "weak_lead"
    return "not_enough_data"

def _case_for_against(
    families: dict[str, dict[str, Any]],
    drilldown_coverage: dict[str, Any],
    endpoint_evidence: dict[str, Any],
) -> tuple[list[str], list[str]]:
    case_for = [families[name]["label"] for name in SCRAPER_EVIDENCE_FAMILIES if name in families]
    missing = [
        name
        for name in SCRAPER_EVIDENCE_FAMILIES
        if name not in families
    ]
    case_against = [f"No {name.replace('_', ' ')} evidence in supplied artifacts." for name in missing]
    status = str(drilldown_coverage.get("status") or "unavailable")
    coverage_pct = drilldown_coverage.get("coverage_pct")
    if status == "unavailable":
        case_against.append(
            "Scoped raw scraper drilldown was unavailable, so endpoint targeting is inferred only from site-level patterns when shown."
        )
    elif status == "uncharacterized":
        case_against.append(
            "Scoped endpoint drilldown captures <0.01% of this lead's traffic; primary request surface remains uncharacterized."
        )
    elif status == "thin_slice":
        case_against.append(
            f"Scoped endpoint drilldown captures {_num(coverage_pct):.2f}% of this lead's traffic; primary request surface remains only thinly characterized."
        )
    elif status == "partial":
        case_against.append(
            f"Scoped endpoint drilldown captures {_num(coverage_pct):.1f}% of this lead's traffic; endpoint targeting requires scoped category rows to count for the verdict."
        )
    elif "endpoint_targeting" in families:
        case_for.append(
            f"Scoped endpoint drilldown covers {_num(coverage_pct):.1f}% of this lead's traffic; scoped endpoint targeting is confirmed."
        )
    if not endpoint_evidence.get("counts_for_verdict"):
        tier = str(endpoint_evidence.get("tier") or "not_available")
        if tier == "inferred_site_context":
            case_against.append(
                "Endpoint context is inferred from site-level summary rows and is not confirmed for this UA."
            )
        elif tier == "unconfirmed_scoped":
            case_against.append(
                "Scoped endpoint rows are unavailable, too thinly sampled, or outside scoring categories, so endpoint targeting is not verdict-driving."
            )
        elif tier == "not_available":
            case_against.append("No scoped or site-level endpoint context was supplied for this lead.")
    return case_for, case_against

def _global_endpoint_evidence(endpoints: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        row
        for row in endpoints
        if row.get("markers") and (_num(row.get("request_share_pct")) >= 10 or _num(row.get("requests")) > 0)
    ][:5]

def _endpoint_evidence_qualification(
    *,
    scoped_rows: list[dict[str, Any]],
    fallback_rows: list[dict[str, Any]],
    drilldown_coverage: dict[str, Any],
) -> dict[str, Any]:
    scoped_targeting_rows = _endpoint_targeting_rows(scoped_rows)
    coverage_pct = _num(drilldown_coverage.get("coverage_pct"))
    status = str(drilldown_coverage.get("status") or "unavailable")
    if (
        scoped_targeting_rows
        and status not in {"unavailable", "uncharacterized", "thin_slice"}
        and coverage_pct >= _CONFIRMED_ENDPOINT_COVERAGE_PCT
    ):
        return {
            "tier": "confirmed",
            "source": "scoped_drilldown",
            "counts_for_verdict": True,
            "reason": "scoped_drilldown_ge_1pct_with_target_categories",
            "categories": sorted(
                {
                    str(row.get("endpoint_category") or _endpoint_category(str(row.get("request_path") or row.get("value") or ""), row.get("markers")))
                    for row in scoped_targeting_rows
                }
            ),
        }
    if scoped_rows:
        if not scoped_targeting_rows:
            reason = "scoped_rows_without_target_categories"
        elif status in {"uncharacterized", "thin_slice"} or coverage_pct < _CONFIRMED_ENDPOINT_COVERAGE_PCT:
            reason = "scoped_coverage_below_1pct"
        else:
            reason = "scoped_endpoint_unconfirmed"
        return {
            "tier": "unconfirmed_scoped",
            "source": "scoped_drilldown",
            "counts_for_verdict": False,
            "reason": reason,
            "categories": sorted(
                {
                    str(row.get("endpoint_category") or _endpoint_category(str(row.get("request_path") or row.get("value") or ""), row.get("markers")))
                    for row in scoped_rows
                }
            ),
        }
    if fallback_rows:
        return {
            "tier": "inferred_site_context",
            "source": "site_summary_fallback",
            "counts_for_verdict": False,
            "reason": "no_scoped_endpoint_rows_site_summary_available",
            "categories": sorted(
                {
                    str(row.get("endpoint_category") or _endpoint_category(str(row.get("request_path") or row.get("value") or ""), row.get("markers")))
                    for row in fallback_rows
                }
            ),
        }
    return {
        "tier": "not_available",
        "source": None,
        "counts_for_verdict": False,
        "reason": "no_endpoint_rows",
        "categories": [],
    }

__all__ = [name for name in globals() if not name.startswith("__")]
