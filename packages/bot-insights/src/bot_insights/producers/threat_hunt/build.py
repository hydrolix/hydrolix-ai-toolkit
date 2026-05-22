from __future__ import annotations

from ._shared import *

def _validate_threat_hunt_windows(
    current_start: datetime,
    current_end: datetime,
    base_start: datetime,
    base_end: datetime,
) -> None:
    if current_end - current_start != base_end - base_start:
        raise SystemExit("--baseline window must match the current window duration")

def _resolve_fanout_strategy(
    *,
    ua_fanout_query: str,
    fanout_strategy: str,
    fanout: list[dict[str, Any]],
) -> str:
    if ua_fanout_query not in {"auto", "off", "required", "summary_hour", "logs_probe", "skip"}:
        raise SystemExit("--ua-fanout-query must be one of auto, off, required")
    if fanout_strategy not in {"auto", "summary_hour", "logs_probe", "skip"}:
        raise SystemExit("--fanout-strategy must be one of auto, summary_hour, logs_probe, skip")
    if ua_fanout_query in {"summary_hour", "logs_probe", "skip"} and fanout_strategy == "auto":
        fanout_strategy = ua_fanout_query
    if ua_fanout_query == "off":
        fanout_strategy = "skip"
    if ua_fanout_query == "required" and not fanout:
        raise SystemExit("--ua-fanout-query required needs --ua-fanout-in or a producer-side export step.")
    return fanout_strategy

def _validate_required_rows(
    *,
    mode: str,
    rows: list[dict[str, Any]],
    option_name: str,
    input_name: str,
) -> None:
    if mode not in {"auto", "off", "required"}:
        raise SystemExit(f"--{option_name} must be one of auto, off, required")
    if mode == "required" and not rows:
        raise SystemExit(f"--{option_name} required needs --{input_name} or a producer-side export step.")

def build_threat_hunt_artifact(
    *,
    cluster: str,
    database: str,
    summary_parquet_glob: str,
    start: str,
    end: str,
    baseline_start: str,
    baseline_end: str,
    raw_actor_dir: str | None = None,
    top_n: int = 10,
    geoip_asn_v4: str | None = None,
    geoip_asn_v6: str | None = None,
    cooccurrence_in: str | None = None,
    cooccurrence_path_in: str | None = None,
    scraper_drilldown_in: str | None = None,
    scraper_hourly_in: str | None = None,
    fanout_in: str | None = None,
    fanout_strategy: str = "auto",
    ua_fanout_in: str | None = None,
    ua_fanout_query: str = "off",
    iat_sample_in: str | None = None,
    background_ua_sample_in: str | None = None,
    background_query: str = "auto",
    baseline_ua_timeseries_in: str | None = None,
    baseline_significance_query: str = "auto",
    edge_response_in: str | None = None,
    bot_manager_context_in: str | None = None,
    bot_manager_exact_ua_in: str | None = None,
    cost_estimate_config: str | None = None,
    hydrolix_log_ingest_usagemeter_in: str | None = None,
    hydrolix_log_ingest_project_deployment_id: str | None = None,
    hydrolix_log_ingest_table_name: str = "logs",
) -> dict[str, Any]:
    current_start = parse_time(start, "start")
    current_end = parse_time(end, "end")
    base_start = parse_time(baseline_start, "baseline-start")
    base_end = parse_time(baseline_end, "baseline-end")
    _validate_threat_hunt_windows(current_start, current_end, base_start, base_end)
    rows = [_normalize_summary_row(row) for row in read_rows_from_glob(summary_parquet_glob)]
    actor_rows = load_raw_actor_rows(raw_actor_dir)
    geo = _geoip_map((geoip_asn_v4, geoip_asn_v6))
    cooccurrence = _cooccurrence_rows(cooccurrence_in, "ua") + _cooccurrence_rows(cooccurrence_path_in, "path")
    drilldown = _drilldown_rows(scraper_drilldown_in)
    hourly = _scraper_hourly_rows(scraper_hourly_in)
    if fanout_in is None:
        fanout_in = ua_fanout_in
    fanout = _ua_fanout_rows(fanout_in)
    iat_samples = _iat_sample_rows(iat_sample_in)
    background_rows = _read_optional_rows(background_ua_sample_in)
    baseline_timeseries_rows = _read_optional_rows(baseline_ua_timeseries_in)
    edge_rows = _read_optional_rows(edge_response_in)
    bot_manager_rows = _read_optional_rows(bot_manager_context_in)
    bot_manager_exact_rows = _read_optional_rows(bot_manager_exact_ua_in)
    cost_config = _load_cost_estimate_config(cost_estimate_config)
    hydrolix_ingest_metadata = _load_hydrolix_usagemeter_estimate(
        hydrolix_log_ingest_usagemeter_in,
        project_deployment_id=hydrolix_log_ingest_project_deployment_id,
        table_name=hydrolix_log_ingest_table_name,
        metadata_window={"start": start, "end": end} if hydrolix_log_ingest_usagemeter_in else None,
    )
    _apply_hydrolix_ingest_estimate(rows, actor_rows, hydrolix_ingest_metadata)
    siem_rows: list[dict[str, Any]] = []
    fanout_strategy = _resolve_fanout_strategy(
        ua_fanout_query=ua_fanout_query,
        fanout_strategy=fanout_strategy,
        fanout=fanout,
    )
    _validate_required_rows(
        mode=background_query,
        rows=background_rows,
        option_name="background-query",
        input_name="background-ua-sample-in",
    )
    _validate_required_rows(
        mode=baseline_significance_query,
        rows=baseline_timeseries_rows,
        option_name="baseline-significance-query",
        input_name="baseline-ua-timeseries-in",
    )

    current = _sum_period(rows, "current")
    baseline = _sum_period(rows, "baseline")
    endpoints = _endpoint_rows(rows, top_n)
    fingerprints = _fingerprints(actor_rows, cooccurrence, geo, top_n)
    countries = _rank_dimension(rows, "country", top_n)
    cohorts = _rank_dimension(rows, "traffic_cohort", top_n)
    infra = _infrastructure(actor_rows, cooccurrence, geo, top_n)
    classification = _classification_gap(edge_rows, siem_rows)
    bot_manager = _bot_manager_context(
        bot_manager_rows,
        bot_manager_exact_rows,
        start=start,
        end=end,
        top_n=top_n,
    )
    scraper_cases = _scraper_cases(
        fingerprints=fingerprints,
        actor_rows=actor_rows,
        endpoints=endpoints,
        drilldown_rows=drilldown,
        iat_rows=iat_samples,
        hourly_rows=hourly,
        ua_fanout_rows=fanout,
        ua_fanout_source="fanout_enrichment" if fanout else "cooccurrence_lower_bound" if cooccurrence else "unavailable",
        window_hour_count=_window_hour_count(current_start, current_end),
        window_end=current_end,
        geo=geo,
        classification=classification,
        top_n=top_n,
    )
    _attach_bot_manager_lead_context(
        scraper_cases,
        bot_manager_exact_rows,
        start=start,
        end=end,
        top_n=top_n,
    )
    scraper_cases, known_traffic = _mark_known_traffic(scraper_cases)
    campaigns, scraper_cases = attach_campaigns(
        scraper_cases=scraper_cases,
        cooccurrence_rows=cooccurrence,
        drilldown_rows=drilldown,
        geo=geo,
    )
    background_rates = _background_rates(background_rows, window_end=current_end)
    baseline_by_ua = _baseline_significance_by_ua(baseline_timeseries_rows)
    _attach_confidence_assessments(
        scraper_cases,
        campaigns,
        background=background_rates,
        baseline_by_ua=baseline_by_ua,
    )
    ua_families = _build_ua_families(scraper_cases, campaigns)
    attach_classifications(
        scraper_cases=scraper_cases,
        campaigns=campaigns,
        ua_families=ua_families,
    )
    recommended_actions = _attach_recommended_actions(campaigns, ua_families, scraper_cases)
    impact_assessment = _attach_impact_assessments(
        current_totals=current,
        baseline_totals=baseline,
        scraper_cases=scraper_cases,
        campaigns=campaigns,
        ua_families=ua_families,
        recommended_actions=recommended_actions,
        cost_config=cost_config,
    )
    if hydrolix_ingest_metadata:
        impact_assessment["hydrolix_log_ingest_metadata"] = hydrolix_ingest_metadata

    scorecards = [
        _score_baseline(current, baseline),
        _score_ua(fingerprints, bool(cooccurrence), fanout),
        _score_endpoint(endpoints),
        _score_infra(infra),
        classification,
        _score_bhu(fingerprints, endpoints, infra),
    ]

    return {
        "schema_version": SCHEMA,
        "artifact_id": "bot_threat_hunt",
        "scope": {
            "cluster": cluster,
            "database": database,
            "current_window": {"start": start, "end": end},
            "baseline_window": {"start": baseline_start, "end": baseline_end},
            "analysis_mode": "single_customer_single_window",
        },
        "module_scorecards": scorecards,
        "baseline_movement": {
            "current": current,
            "baseline": baseline,
            "metric_deltas": [_metric_delta(name, current, baseline) for name in ("requests", "bytes", "status_429", "status_5xx", "bot_requests", "human_requests")],
            "countries": countries,
            "traffic_cohorts": cohorts,
        },
        "fingerprints": fingerprints,
        "campaigns": campaigns,
        "ua_families": ua_families,
        "scraper_cases": scraper_cases,
        "known_traffic": known_traffic,
        "confidence_metadata": {
            "background_rates": background_rates,
            "baseline_significance": {
                "status": "available" if baseline_by_ua else "unavailable",
                "user_agent_count": len(baseline_by_ua),
            },
        },
        "impact_assessment": impact_assessment,
        "recommended_actions": recommended_actions,
        "endpoints": endpoints,
        "infrastructure": infra,
        "classification_gap": classification,
        "bot_manager_context": bot_manager,
        "fanout_enrichment": {
            "strategy": fanout_strategy,
            "rows": fanout,
            "availability": "evidence_backed" if fanout else "not_available",
            "sources": sorted({str(row.get("source") or "unknown") for row in fanout}),
            "caveat": _fanout_limit_detail(fanout),
        },
        "limitations": _data_limits(
            rows,
            actor_rows,
            cooccurrence,
            fanout,
            drilldown,
            hourly,
            iat_samples,
            geo,
            classification,
            bot_manager,
        ),
        "interpretation_constraints": [
            "single_customer_single_window_only",
            "scraper_means_behavioral_repeated_automated_access",
            "no_operator_identity_claim",
            "no_malicious_intent_claim",
            "no_cross_customer_exact_ua_reuse_claim",
        ],
    }

__all__ = [name for name in globals() if not name.startswith("__")]
