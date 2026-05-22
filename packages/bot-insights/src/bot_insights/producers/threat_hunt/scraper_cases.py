from __future__ import annotations

from ._shared import *

def _scraper_cases(
    *,
    fingerprints: list[dict[str, Any]],
    actor_rows: list[dict[str, Any]],
    endpoints: list[dict[str, Any]],
    drilldown_rows: list[dict[str, Any]],
    iat_rows: list[dict[str, Any]],
    hourly_rows: list[dict[str, Any]],
    ua_fanout_rows: list[dict[str, Any]],
    ua_fanout_source: str,
    window_hour_count: int,
    window_end: datetime,
    geo: dict[str, dict[str, Any]],
    classification: dict[str, Any],
    top_n: int,
) -> list[dict[str, Any]]:
    cases = []
    global_endpoint_rows = _global_endpoint_evidence(endpoints)
    fanout_by_ua = {str(row.get("user_agent")): row for row in ua_fanout_rows if row.get("user_agent")}
    parsed_by_ua = {
        str(fp.get("user_agent")): parse_user_agent(str(fp.get("user_agent") or ""))
        for fp in fingerprints
        if fp.get("user_agent")
    }
    family_request_totals, total_family_requests, browser_fingerprint_count = (
        _family_request_context(fingerprints, parsed_by_ua)
    )
    for fp in fingerprints[:top_n]:
        user_agent = str(fp.get("user_agent") or "")
        if not user_agent:
            continue
        actor = _ua_actor_row(actor_rows, user_agent)
        drilldown = _drilldown_profile(user_agent, drilldown_rows, geo, top_n)
        drilldown_coverage = _drilldown_coverage(
            _num(fp.get("requests")),
            _num(drilldown.get("requests")),
            bool(drilldown.get("available")),
        )
        temporal, timing_status = _timing_analysis(
            user_agent,
            iat_rows,
            drilldown_rows,
            hourly_rows,
            window_hour_count=window_hour_count,
        )
        families: dict[str, dict[str, Any]] = {}

        if _int(fp.get("unique_client_ips")) >= 10 or _int(fp.get("unique_asns")) >= 2:
            _add_family(
                families,
                "ua_ip_fanout",
                label=(
                    f"Exact UA/IP cooccurrence observed {_int(fp.get('unique_client_ips'))} "
                    f"client IPs across {_int(fp.get('unique_asns'))} ASNs."
                ),
                rows=[
                    {
                        "unique_client_ips": fp.get("unique_client_ips"),
                        "unique_asns": fp.get("unique_asns"),
                        "unique_countries": fp.get("unique_countries"),
                        "sample_asns": fp.get("sample_asns") or [],
                        "sample_countries": fp.get("sample_countries") or [],
                    }
                ],
            )

        scoped_endpoint_rows = [
            row for row in drilldown.get("endpoint_targets", []) if isinstance(row, dict)
        ]
        endpoint_rows = _endpoint_targeting_rows(scoped_endpoint_rows)
        endpoint_evidence = _endpoint_evidence_qualification(
            scoped_rows=scoped_endpoint_rows,
            fallback_rows=global_endpoint_rows,
            drilldown_coverage=drilldown_coverage,
        )
        display_endpoint_rows = scoped_endpoint_rows or global_endpoint_rows
        if endpoint_evidence.get("counts_for_verdict"):
            _add_family(
                families,
                "endpoint_targeting",
                label="Scoped endpoint targeting confirmed from per-UA drilldown.",
                rows=endpoint_rows,
            )

        _add_temporal_family(families, temporal)

        baseline_requests = _num(fp.get("baseline_requests"))
        requests = _num(fp.get("requests"))
        baseline_growth = _baseline_growth_family(
            requests, baseline_requests, fp.get("request_delta")
        )
        _add_baseline_family(families, baseline_growth)

        if _automation_signature(user_agent):
            _add_family(
                families,
                "automation_signature",
                label="The user-agent string has automation/crawler tooling markers.",
                rows=[{"user_agent": user_agent}],
            )

        _add_rate_pressure_family(families, actor, drilldown, requests)

        _add_infrastructure_family(families, fp)

        _add_classification_family(families, classification)

        ua_plausibility = score_ua_plausibility(
            user_agent=user_agent,
            window_end=window_end,
            fanout_by_ua=fanout_by_ua,
            fallback_unique_ips=fp.get("unique_client_ips"),
            family_request_totals=family_request_totals,
            total_family_requests=total_family_requests,
            browser_fingerprint_count=browser_fingerprint_count,
            source=ua_fanout_source,
        )
        fanout_signal = (ua_plausibility.get("signals") or {}).get("fanout")
        _add_ua_plausibility_families(families, ua_plausibility, fanout_signal)

        case_for, case_against = _case_for_against(families, drilldown_coverage, endpoint_evidence)
        if ua_plausibility.get("verdict") == "elevated":
            case_for.append(
                "UA plausibility elevated but not verdict-driving: "
                + str(ua_plausibility.get("trigger_reason") or "weak browser-token anomaly")
            )
        cases.append(
            {
                "user_agent": user_agent,
                "verdict": _scraper_case_verdict(families),
                "requests": requests,
                "bytes": fp.get("bytes"),
                "hydrolix_log_ingest_bytes": fp.get("hydrolix_log_ingest_bytes"),
                "response_body_bytes": fp.get("response_body_bytes"),
                "akamai_billed_bytes": fp.get("akamai_billed_bytes"),
                "baseline_bytes": fp.get("baseline_bytes"),
                "baseline_hydrolix_log_ingest_bytes": fp.get("baseline_hydrolix_log_ingest_bytes"),
                "baseline_response_body_bytes": fp.get("baseline_response_body_bytes"),
                "baseline_akamai_billed_bytes": fp.get("baseline_akamai_billed_bytes"),
                "baseline_requests": baseline_requests,
                "request_delta": fp.get("request_delta"),
                "unique_client_ips": fp.get("unique_client_ips"),
                "unique_asns": fp.get("unique_asns"),
                "unique_countries": fp.get("unique_countries"),
                "client_ips": drilldown.get("top_client_ips", []),
                "countries": drilldown.get("countries") or fp.get("sample_countries") or [],
                "asns": drilldown.get("asns") or fp.get("sample_asns") or [],
                "endpoint_targets": display_endpoint_rows,
                "endpoint_evidence": endpoint_evidence,
                "ua_plausibility": ua_plausibility,
                "fanout_enrichment": fanout_signal if isinstance(fanout_signal, dict) else {},
                "hourly_bursts": drilldown.get("hourly_bursts", []),
                "temporal_regularity": temporal,
                "timing_status": timing_status,
                "evidence_flags": [name for name in SCRAPER_EVIDENCE_FAMILIES if name in families],
                "evidence_families": [families[name] for name in SCRAPER_EVIDENCE_FAMILIES if name in families],
                "case_for": case_for,
                "case_against": case_against,
                "missing_evidence": [
                    name for name in SCRAPER_EVIDENCE_FAMILIES if name not in families
                ],
                "drilldown_available": bool(drilldown.get("available")),
                "drilldown_coverage": drilldown_coverage,
            }
        )
    return sorted(
        cases,
        key=lambda row: (
            {"strong_lead": 0, "lead": 1, "weak_lead": 2, "not_enough_data": 3}.get(
                str(row.get("verdict")), 9
            ),
            -_num(row.get("requests")),
            str(row.get("user_agent")),
        ),
    )

def _family_request_context(
    fingerprints: list[dict[str, Any]], parsed_by_ua: dict[str, dict[str, Any]]
) -> tuple[Counter[str], float, int]:
    family_request_totals: Counter[str] = Counter()
    total_family_requests = 0.0
    browser_fingerprint_count = 0
    for fp in fingerprints:
        ua = str(fp.get("user_agent") or "")
        family = str((parsed_by_ua.get(ua) or {}).get("browser_family") or "Unknown")
        requests = _num(fp.get("requests"))
        if family != "Unknown" and requests > 0:
            family_request_totals[family] += requests
            total_family_requests += requests
            browser_fingerprint_count += 1
    return family_request_totals, total_family_requests, browser_fingerprint_count

def _add_temporal_family(
    families: dict[str, dict[str, Any]], temporal: dict[str, Any] | None
) -> None:
    if not temporal:
        return
    if temporal.get("resolution") == "hourly_coarse":
        label = "Hourly drilldown shows coarse timing regularity; request-level timestamp samples were not supplied."
    else:
        label = f"Request-level timing sample shows {str(temporal.get('archetype')).replace('_', ' ')} regularity."
    _add_family(families, "temporal_regularity", label=label, rows=[temporal])

def _add_baseline_family(
    families: dict[str, dict[str, Any]], baseline_growth: dict[str, Any] | None
) -> None:
    if not baseline_growth:
        return
    _add_family(
        families,
        "baseline_novelty_or_growth",
        label=str(baseline_growth["label"]),
        rows=[{key: value for key, value in baseline_growth.items() if key != "label"}],
    )

def _add_rate_pressure_family(
    families: dict[str, dict[str, Any]],
    actor: dict[str, Any],
    drilldown: dict[str, Any],
    requests: float,
) -> None:
    ua_requests = _num(actor.get("requests")) or requests
    ua_429 = _pct(_num(actor.get("status_429")), ua_requests)
    ua_5xx = _pct(_num(actor.get("status_5xx")), ua_requests)
    drill_429 = drilldown.get("rate_429_pct")
    drill_5xx = drilldown.get("rate_5xx_pct")
    if not any(_num(value) >= 2 for value in (ua_429, ua_5xx, drill_429, drill_5xx)):
        return
    _add_family(
        families,
        "rate_limit_or_error_pressure",
        label="The UA carried elevated 429 or 5xx pressure in supplied rows.",
        rows=[{
            "actor_rate_429_pct": ua_429,
            "actor_rate_5xx_pct": ua_5xx,
            "drilldown_rate_429_pct": drill_429,
            "drilldown_rate_5xx_pct": drill_5xx,
        }],
    )

def _add_infrastructure_family(
    families: dict[str, dict[str, Any]], fp: dict[str, Any]
) -> None:
    if _int(fp.get("unique_asns")) < 3 and _int(fp.get("unique_countries")) < 3:
        return
    _add_family(
        families,
        "infrastructure_topology",
        label="The UA spans multiple ASNs or countries in the exact cooccurrence evidence.",
        rows=[{
            "unique_asns": fp.get("unique_asns"),
            "unique_countries": fp.get("unique_countries"),
            "sample_asns": fp.get("sample_asns") or [],
            "sample_countries": fp.get("sample_countries") or [],
        }],
    )

def _add_classification_family(
    families: dict[str, dict[str, Any]], classification: dict[str, Any]
) -> None:
    if not _classification_gap_is_signal(classification):
        return
    _add_family(
        families,
        "classification_gap",
        label="Optional classification artifacts show incomplete bot/edge coverage.",
        rows=[{
            "coverage_pct": classification.get("coverage_pct"),
            "verdict": classification.get("verdict"),
        }],
    )

def _add_ua_plausibility_families(
    families: dict[str, dict[str, Any]],
    ua_plausibility: dict[str, Any],
    fanout_signal: Any,
) -> None:
    if isinstance(fanout_signal, dict) and fanout_signal.get("threshold_class") in {"strong", "elevated"}:
        _add_family(
            families,
            "ua_ip_fanout",
            label=str(fanout_signal.get("caveat") or "Source-aware UA fan-out enrichment crossed the suspicious threshold."),
            rows=[{
                "unique_ips": fanout_signal.get("unique_ips"),
                "effective_ips": fanout_signal.get("effective_ips"),
                "source": fanout_signal.get("source"),
                "threshold_class": fanout_signal.get("threshold_class"),
                "probe_window_hours": fanout_signal.get("probe_window_hours"),
                "caveat": fanout_signal.get("caveat"),
            }],
        )
    if ua_plausibility.get("counts_for_verdict"):
        _add_family(
            families,
            "ua_anomaly",
            label=str(ua_plausibility.get("trigger_reason") or "UA plausibility anomaly confirmed."),
            rows=[ua_plausibility],
        )

__all__ = [name for name in globals() if not name.startswith("__")]
