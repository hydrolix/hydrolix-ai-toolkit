from __future__ import annotations

from ._shared import *

def _timing_analysis(
    user_agent: str,
    iat_rows: list[dict[str, Any]],
    drilldown_rows: list[dict[str, Any]],
    hourly_rows: list[dict[str, Any]],
    *,
    window_hour_count: int,
) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    temporal = _temporal_regularity(user_agent, iat_rows, drilldown_rows)
    if temporal and temporal.get("resolution") == "request_iat":
        return temporal, {
            "status": "regular",
            "source": "iat_samples",
            "resolution": "request_iat",
            "archetype": temporal.get("archetype"),
            "sample_size": temporal.get("sample_size"),
        }
    if iat_rows:
        return None, {
            "status": "irregular",
            "source": "iat_samples",
            "resolution": "request_iat",
            "sample_size": 0,
        }
    source = "scraper_hourly" if hourly_rows else "scraper_drilldown"
    profile = _hourly_timing_profile(
        user_agent,
        hourly_rows or drilldown_rows,
        window_hour_count=window_hour_count,
        source=source,
    )
    return profile.get("temporal"), {key: value for key, value in profile.items() if key != "temporal"}

def _fingerprints(
    actor_rows: list[dict[str, Any]],
    cooccurrence: list[dict[str, Any]],
    geo: dict[str, dict[str, Any]],
    top_n: int,
) -> list[dict[str, Any]]:
    baseline = _baseline_actor_map(actor_rows, "user_agent")
    ip_by_ua: dict[str, set[str]] = defaultdict(set)
    countries_by_ua: dict[str, set[str]] = defaultdict(set)
    asn_by_ua: dict[str, set[str]] = defaultdict(set)
    for row in cooccurrence:
        ua = row.get("user_agent")
        ip = row.get("client_ip")
        if not ua:
            continue
        if ip:
            ip_by_ua[ua].add(ip)
            geo_row = _geo_for_ip(ip, geo)
            if geo_row.get("asn"):
                asn_by_ua[ua].add(str(geo_row["asn"]))
            if geo_row.get("country"):
                countries_by_ua[ua].add(str(geo_row["country"]))
        if row.get("country"):
            countries_by_ua[ua].add(str(row["country"]))

    current = [
        row
        for row in actor_rows
        if row.get("period") == "current" and row.get("actor_type") == "user_agent"
    ]
    current.sort(key=lambda row: (-_num(row.get("requests")), str(row.get("value"))))
    out = []
    for rank, row in enumerate(current[:top_n], start=1):
        value = str(row.get("value"))
        base = baseline.get(value, {})
        out.append(
            {
                "rank": rank,
                "user_agent": value,
                "requests": _num(row.get("requests")),
                "bytes": _num(row.get("bytes")),
                "hydrolix_log_ingest_bytes": row.get("hydrolix_log_ingest_bytes"),
                "response_body_bytes": _num(row.get("response_body_bytes")),
                "akamai_billed_bytes": _num(row.get("akamai_billed_bytes")),
                "baseline_requests": _num(base.get("requests")),
                "baseline_bytes": _num(base.get("bytes")),
                "baseline_hydrolix_log_ingest_bytes": base.get("hydrolix_log_ingest_bytes"),
                "baseline_response_body_bytes": _num(base.get("response_body_bytes")),
                "baseline_akamai_billed_bytes": _num(base.get("akamai_billed_bytes")),
                "request_delta": _num(row.get("requests")) - _num(base.get("requests")),
                "unique_client_ips": len(ip_by_ua[value]) if cooccurrence else None,
                "unique_asns": len(asn_by_ua[value]) if cooccurrence else None,
                "unique_countries": len(countries_by_ua[value]) if cooccurrence else None,
                "sample_asns": sorted(asn_by_ua[value])[:5],
                "sample_countries": sorted(countries_by_ua[value])[:5],
            }
        )
    return out

def _infrastructure(
    actor_rows: list[dict[str, Any]],
    cooccurrence: list[dict[str, Any]],
    geo: dict[str, dict[str, Any]],
    top_n: int,
) -> dict[str, Any]:
    ip_requests = Counter()
    for row in actor_rows:
        if row.get("period") == "current" and row.get("actor_type") == "client_ip":
            ip_requests[str(row.get("value"))] += _num(row.get("requests"))
    for row in cooccurrence:
        ip = row.get("client_ip")
        if ip:
            ip_requests[str(ip)] += _num(row.get("requests"))
    asn_rollup: dict[str, dict[str, Any]] = defaultdict(lambda: {"requests": 0.0, "client_ips": set(), "asn_org": None, "countries": set()})
    for ip, requests in ip_requests.items():
        geo_row = _geo_for_ip(ip, geo)
        asn = str(geo_row.get("asn") or "unknown")
        item = asn_rollup[asn]
        item["requests"] += requests
        item["client_ips"].add(ip)
        if geo_row.get("asn_org"):
            item["asn_org"] = geo_row.get("asn_org")
        if geo_row.get("country"):
            item["countries"].add(str(geo_row["country"]))
    rows = []
    for rank, (asn, item) in enumerate(
        sorted(asn_rollup.items(), key=lambda pair: (-pair[1]["requests"], pair[0]))[:top_n],
        start=1,
    ):
        rows.append(
            {
                "rank": rank,
                "asn": asn,
                "asn_org": item["asn_org"],
                "requests": item["requests"],
                "client_ip_count": len(item["client_ips"]),
                "country_count": len(item["countries"]),
                "sample_countries": sorted(item["countries"])[:5],
            }
        )
    return {
        "asn_rollups": rows,
        "topology_hints": _topology_hints(rows),
        "availability": "evidence_backed" if rows and geo else "partial" if rows else "not_available",
    }

def _topology_hints(asn_rows: list[dict[str, Any]]) -> list[str]:
    known_rows = [row for row in asn_rows if row.get("asn") not in {None, "", "unknown"}]
    if not known_rows:
        return []
    total_requests = sum(_num(row.get("requests")) for row in known_rows)
    top = known_rows[0]
    hints = []
    if _pct(_num(top.get("requests")), total_requests) and _pct(_num(top.get("requests")), total_requests) >= 70:
        hints.append("concentrated_asn")
    if len(known_rows) >= 5:
        hints.append("distributed_pool")
    if any(_int(row.get("client_ip_count")) >= 10 for row in known_rows):
        hints.append("multi_ip_asn_cluster")
    return hints

def _classification_gap(edge_rows: list[dict[str, Any]], siem_rows: list[dict[str, Any]]) -> dict[str, Any]:
    if not edge_rows and not siem_rows:
        return {
            "module": "classification_gap",
            "availability": "not_available",
            "verdict": "not_enough_data",
            "summary": "Bot/SIEM/edge classification artifacts were not supplied.",
            "rows": [],
        }
    rows = edge_rows or siem_rows
    total = sum(_num(_first(row, ("requests", "count", "hits"))) for row in rows)
    covered = sum(
        _num(_first(row, ("classified_requests", "bot_requests", "blocked_requests", "edge_action_requests")))
        for row in rows
    )
    return {
        "module": "classification_gap",
        "availability": "evidence_backed",
        "verdict": "possible" if total and covered < total else "likely",
        "summary": "Classification coverage supplied by optional local artifacts.",
        "coverage_pct": _pct(covered, total),
        "rows": rows[:20],
    }

def _classification_gap_is_signal(classification: dict[str, Any]) -> bool:
    if classification.get("availability") == "not_available":
        return False
    coverage = classification.get("coverage_pct")
    return coverage is not None and _num(coverage) < 90

def _bot_manager_value(row: dict[str, Any], names: Iterable[str]) -> str:
    value = _first(row, names)
    if value in (None, ""):
        return "unknown"
    return str(value).strip() or "unknown"

def _bot_manager_requests(row: dict[str, Any]) -> float:
    return _num(
        _first(
            row,
            (
                "requests",
                "request_count",
                "count",
                "hits",
                "cnt_all",
                "total_requests",
                "edge_action_requests",
            ),
        )
    )

def _bot_manager_mix(
    rows: list[dict[str, Any]],
    names: Iterable[str],
    *,
    top_n: int,
) -> list[dict[str, Any]]:
    totals: dict[str, float] = defaultdict(float)
    total_requests = 0.0
    for row in rows:
        requests = _bot_manager_requests(row)
        if requests <= 0:
            continue
        total_requests += requests
        totals[_bot_manager_value(row, names)] += requests
    ranked = sorted(totals.items(), key=lambda item: (-item[1], item[0]))
    return [
        {
            "rank": rank,
            "value": value,
            "requests": requests,
            "share_pct": _pct(requests, total_requests),
        }
        for rank, (value, requests) in enumerate(ranked[:top_n], start=1)
    ]

def _bot_manager_average_score(rows: list[dict[str, Any]]) -> float | None:
    weighted_score = 0.0
    weight_total = 0.0
    for row in rows:
        score = _first(row, ("avg_bot_score", "average_bot_score", "botScore", "bot_score", "score"))
        if score in (None, ""):
            continue
        weight = _bot_manager_requests(row) or 1.0
        weighted_score += _num(score) * weight
        weight_total += weight
    if weight_total <= 0:
        return None
    return weighted_score / weight_total

def _normalize_bot_manager_rows(
    rows: list[dict[str, Any]],
    *,
    source: str,
    source_table: str | None,
    start: str,
    end: str,
    top_n: int,
) -> dict[str, Any]:
    total_requests = sum(_bot_manager_requests(row) for row in rows)
    if not rows:
        return {
            "availability": "not_available",
            "source": source,
            "source_table": source_table,
            "window": {"start": start, "end": end},
            "row_count": 0,
            "total_requests": 0,
            "action_class_mix": [],
            "bot_type_mix": [],
            "policy_mix": [],
            "average_bot_score": None,
        }
    tables = sorted(
        {
            str(_first(row, ("source_table", "table", "_table"), source_table) or "")
            for row in rows
            if _first(row, ("source_table", "table", "_table"), source_table)
        }
    )
    return {
        "availability": "evidence_backed",
        "source": source,
        "source_table": source_table,
        "source_tables": tables,
        "window": {"start": start, "end": end},
        "row_count": len(rows),
        "total_requests": total_requests,
        "action_class_mix": _bot_manager_mix(
            rows, ("actionClass", "action_class", "action", "edge_action"), top_n=top_n
        ),
        "bot_type_mix": _bot_manager_mix(
            rows, ("botType", "bot_type", "botCategory", "bot_category"), top_n=top_n
        ),
        "policy_mix": _bot_manager_mix(
            rows, ("policyId", "policy_id", "policyName", "policy_name", "policy"), top_n=top_n
        ),
        "average_bot_score": _bot_manager_average_score(rows),
    }

def _bot_manager_context(
    aggregate_rows: list[dict[str, Any]],
    exact_ua_rows: list[dict[str, Any]],
    *,
    start: str,
    end: str,
    top_n: int,
) -> dict[str, Any]:
    aggregate = _normalize_bot_manager_rows(
        aggregate_rows,
        source="aggregate_siem_policy_summary",
        source_table="bi_siem_policy_summary_*",
        start=start,
        end=end,
        top_n=top_n,
    )
    exact = _normalize_bot_manager_rows(
        exact_ua_rows,
        source="exact_ua_export",
        source_table=None,
        start=start,
        end=end,
        top_n=top_n,
    )
    availability = (
        "evidence_backed"
        if aggregate["availability"] == "evidence_backed" or exact["availability"] == "evidence_backed"
        else "not_available"
    )
    context = {
        "module": "bot_manager_context",
        "availability": availability,
        "summary": (
            "Bot Manager operational context is supplied for display only."
            if availability == "evidence_backed"
            else "Bot Manager operational context was not supplied."
        ),
        "caveat": (
            "Bot Manager context is operational enrichment, not threat-hunt attribution "
            "or independent evidence for classification."
        ),
        "aggregate": aggregate,
        "exact_ua": exact,
        "lead_context_available": exact["availability"] == "evidence_backed",
    }
    return context

def _attach_bot_manager_lead_context(
    scraper_cases: list[dict[str, Any]],
    exact_ua_rows: list[dict[str, Any]],
    *,
    start: str,
    end: str,
    top_n: int,
) -> None:
    rows_by_ua: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in exact_ua_rows:
        ua = _first(row, ("user_agent", "userAgent", "ua", "request_user_agent"))
        if ua:
            rows_by_ua[str(ua)].append(row)
    for case in scraper_cases:
        ua = str(case.get("user_agent") or "")
        rows = rows_by_ua.get(ua, [])
        case["bot_manager_context"] = _normalize_bot_manager_rows(
            rows,
            source="exact_ua_export",
            source_table=None,
            start=start,
            end=end,
            top_n=top_n,
        )

def _data_limits(
    summary_rows: list[dict[str, Any]],
    actor_rows: list[dict[str, Any]],
    cooccurrence: list[dict[str, Any]],
    fanout: list[dict[str, Any]],
    drilldown: list[dict[str, Any]],
    hourly: list[dict[str, Any]],
    iat_samples: list[dict[str, Any]],
    geo: dict[str, dict[str, Any]],
    classification: dict[str, Any],
    bot_manager_context: dict[str, Any] | None = None,
) -> list[dict[str, str]]:
    bot_manager_context = bot_manager_context or {}
    checks = [
        ("summary_parquet", bool(summary_rows), "baseline movement and endpoint rankings"),
        ("raw_actor_exports", bool(actor_rows), "exact client IP and user-agent evidence"),
        ("cooccurrence", bool(cooccurrence), "UA fanout, unique-IP, country, and ASN spread"),
        (
            "fanout_enrichment",
            bool(fanout),
            _fanout_limit_detail(fanout),
        ),
        ("scraper_drilldown", bool(drilldown), "UA x endpoint, client IP x endpoint, and hourly burst detail"),
        ("scraper_hourly", bool(hourly), "complete UA x hour request profiles for coarse timing regularity"),
        ("iat_samples", bool(iat_samples), "request-level sampled timestamp evidence for inter-arrival timing"),
        ("geoip_asn", bool(geo), "ASN organization and topology enrichment"),
        ("classification_gap", classification.get("availability") != "not_available", "SIEM/Bot/edge coverage"),
        (
            "bot_manager_context",
            bot_manager_context.get("availability") != "not_available",
            "Bot Manager operational enrichment; informational only and not classification evidence",
        ),
    ]
    return [
        {
            "module": name,
            "availability": "evidence_backed" if available else "not_available",
            "detail": detail if available else f"{detail} not supplied",
        }
        for name, available, detail in checks
    ]

__all__ = [name for name in globals() if not name.startswith("__")]
