from __future__ import annotations

from ._shared import *

def _normalize_fanout_source(value: Any) -> str:
    source = str(value or "").strip() or "summary_hour"
    aliases = {
        "ua_fanout": "summary_hour",
        "exact_ua": "summary_hour",
        "scoped_fallback": "cooccurrence_lower_bound",
        "cooccurrence": "cooccurrence_lower_bound",
    }
    return aliases.get(source, source)

def _fanout_caveat(source: str, probe_window_hours: float | None = None) -> str:
    if source == "summary_hour":
        return "Full-window summary-hour unique-IP count for this byte-identical UA."
    if source == "logs_probe":
        hours = probe_window_hours or 1.0
        return (
            f"Peak-hour raw-log probe over {hours:g} hour(s); effective IPs use a conservative bounded "
            "24h lower-bound estimate, not a full-window exact union."
        )
    if source == "cooccurrence_lower_bound":
        return "Lower bound from existing UA/IP cooccurrence evidence; true full-window fan-out is unknown."
    return "Fan-out enrichment source is not available."

def _fanout_effective_ips(row: dict[str, Any]) -> float:
    unique_ips = _num(row.get("effective_ips") or row.get("unique_ips") or row.get("unique_client_ips"))
    if str(row.get("source") or "") == "logs_probe":
        hours = _num(row.get("probe_window_hours"), 1.0) or 1.0
        return unique_ips * min(hours * 3.0, 24.0)
    return unique_ips

def merge_fanout_rows(rows: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for row in rows:
        user_agent = str(_first(row, ("user_agent", "userAgent", "UA", "ua"), "")).strip()
        if not user_agent:
            continue
        source = _normalize_fanout_source(_first(row, ("source", "fanout_source"), "summary_hour"))
        probe_window_hours = _num(_first(row, ("probe_window_hours", "probe_hours", "window_hours")), 0.0) or None
        cell = merged.setdefault(
            user_agent,
            {
                "user_agent": user_agent,
                "unique_ips": 0.0,
                "hits": 0.0,
                "bytes": 0.0,
                "source": source,
                "probe_window_hours": probe_window_hours,
            },
        )
        source_rank = {"summary_hour": 3, "logs_probe": 2, "cooccurrence_lower_bound": 1}
        if source_rank.get(source, 0) > source_rank.get(str(cell.get("source")), 0):
            cell["source"] = source
        if probe_window_hours is not None:
            cell["probe_window_hours"] = min(
                probe_window_hours,
                _num(cell.get("probe_window_hours"), probe_window_hours) or probe_window_hours,
            )
        cell["unique_ips"] = max(
            _num(cell.get("unique_ips")),
            _num(_first(row, ("unique_ips", "unique_client_ips", "distinct_client_ips", "client_ip_count", "ips"))),
        )
        cell["hits"] += _num(_first(row, ("hits", "requests", "request_count", "count")))
        cell["bytes"] += _num(_first(row, ("bytes", "total_bytes", "sum_totalBytes")))
    out = []
    for row in merged.values():
        unique_ips = int(row["unique_ips"])
        hits = int(row["hits"]) if float(row["hits"]).is_integer() else row["hits"]
        bytes_value = int(row["bytes"]) if float(row["bytes"]).is_integer() else row["bytes"]
        source = str(row.get("source") or "summary_hour")
        out.append(
            {
                "user_agent": row["user_agent"],
                "unique_ips": unique_ips,
                "effective_ips": int(_fanout_effective_ips({**row, "unique_ips": unique_ips})),
                "hits": hits,
                "bytes": bytes_value,
                "source": source,
                "probe_window_hours": row.get("probe_window_hours"),
                "caveat": _fanout_caveat(source, row.get("probe_window_hours")),
                # Backward-compatible field names for older callers/tests.
                "unique_client_ips": unique_ips,
                "requests": hits,
            }
        )
    return sorted(out, key=lambda row: (-_num(row.get("unique_ips")), -_num(row.get("hits")), str(row.get("user_agent"))))

def merge_ua_fanout_rows(rows: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    return merge_fanout_rows(rows)

def cooccurrence_fanout_lower_bound_rows(rows: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    ips_by_ua: dict[str, set[str]] = defaultdict(set)
    hits_by_ua: Counter[str] = Counter()
    bytes_by_ua: Counter[str] = Counter()
    for row in rows:
        user_agent = str(_first(row, ("user_agent", "userAgent", "UA", "ua"), "")).strip()
        client_ip = str(_first(row, ("client_ip", "clientIp", "cliIP", "ip"), "")).strip()
        if not user_agent:
            continue
        if client_ip:
            ips_by_ua[user_agent].add(client_ip)
        hits_by_ua[user_agent] += _num(_first(row, ("hits", "requests", "request_count", "count")))
        bytes_by_ua[user_agent] += _num(_first(row, ("bytes", "total_bytes", "sum_totalBytes")))
    return merge_fanout_rows(
        {
            "user_agent": ua,
            "unique_ips": len(ips),
            "hits": hits_by_ua.get(ua, 0),
            "bytes": bytes_by_ua.get(ua, 0),
            "source": "cooccurrence_lower_bound",
        }
        for ua, ips in ips_by_ua.items()
    )

def export_ua_fanout(
    *,
    actor_dir: str,
    start: str,
    end: str,
    cluster: str,
    database: str = "akamai",
    top_leads: int = 25,
    output: str,
    run_summary: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    actor_rows = load_raw_actor_rows(actor_dir)
    user_agents = _top_actor_values(actor_rows, "user_agent", top_leads)
    if not user_agents:
        raise SystemExit("--raw-actor-dir has no current user_agent actors")
    output_path = Path(output).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    raw_output = output_path.with_suffix(output_path.suffix + ".raw")
    _run_mux_export(
        cluster,
        _raw_ua_fanout_sql(
            database=database,
            start=parse_time(start, "start"),
            end=parse_time(end, "end"),
            user_agents=user_agents,
        ),
        raw_output,
    )
    merged = merge_ua_fanout_rows(_read_json_rows(raw_output))
    raw_output.unlink(missing_ok=True)
    output_path.write_text(json.dumps(merged, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if run_summary is not None:
        run_summary.clear()
        run_summary.update({"rows": len(merged), "selected_user_agents": user_agents})
    return merged

def _summary_hour_supports_ua(*, cluster: str, database: str) -> bool:
    with tempfile.TemporaryDirectory(prefix="threat-hunt-summary-hour-probe-") as tmpdir:
        output = Path(tmpdir) / "summary-hour-support.json"
        try:
            _run_mux_export(cluster, _summary_hour_ua_support_sql(database=database), output)
            rows = _read_json_rows(output)
        except SystemExit:
            return False
    for row in rows:
        if _num(_first(row, ("matching_columns", "count", "count()"))) > 0:
            return True
    return False

def _hour_start(value: Any) -> datetime | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).replace(minute=0, second=0, microsecond=0)

def _peak_hours_by_ua(hourly_rows: list[dict[str, Any]]) -> dict[str, datetime]:
    peaks: dict[str, tuple[float, datetime]] = {}
    for row in hourly_rows:
        user_agent = str(_first(row, ("user_agent", "userAgent", "UA", "ua"), "")).strip()
        hour = _hour_start(_first(row, ("hour", "bucket", "timestamp")))
        if not user_agent or hour is None:
            continue
        requests = _num(_first(row, ("requests", "request_count", "count", "hits")))
        if user_agent not in peaks or requests > peaks[user_agent][0]:
            peaks[user_agent] = (requests, hour)
    return {ua: hour for ua, (_requests, hour) in peaks.items()}

def _export_fanout_query_rows(
    *,
    cluster: str,
    sql_rows: list[tuple[str, str]],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="threat-hunt-fanout-") as tmpdir:
        tmp = Path(tmpdir)
        for index, (source, sql) in enumerate(sql_rows, start=1):
            output = tmp / f"fanout-{index}.json"
            _run_mux_export(cluster, sql, output)
            for row in _read_json_rows(output):
                if isinstance(row, dict):
                    rows.append({**row, "source": source})
    return rows

def export_fanout_enrichment(
    *,
    actor_dir: str,
    start: str,
    end: str,
    cluster: str,
    database: str = "akamai",
    top_leads: int = 25,
    output: str,
    strategy: str = "auto",
    scraper_hourly_in: str | None = None,
    cooccurrence_in: str | None = None,
    run_summary: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    if strategy not in {"auto", "summary_hour", "logs_probe", "skip"}:
        raise SystemExit("--fanout-strategy must be one of auto, summary_hour, logs_probe, skip")
    actor_rows = load_raw_actor_rows(actor_dir)
    user_agents = _top_actor_values(actor_rows, "user_agent", top_leads)
    if not user_agents:
        raise SystemExit("--raw-actor-dir has no current user_agent actors")
    start_dt = parse_time(start, "start")
    end_dt = parse_time(end, "end")
    output_path = Path(output).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    errors: list[str] = []
    selected_strategy = strategy
    rows: list[dict[str, Any]] = []

    if strategy in {"auto", "summary_hour"}:
        rows, selected_strategy = _try_summary_hour_fanout(
            cluster, database, start_dt, end_dt, user_agents, strategy, errors
        )

    if strategy in {"auto", "logs_probe"} and not rows:
        rows, selected_strategy = _try_logs_probe_fanout(
            cluster, database, end_dt, user_agents, strategy, scraper_hourly_in, errors
        )

    if strategy in {"auto", "skip"} and not rows:
        rows = cooccurrence_fanout_lower_bound_rows(_cooccurrence_rows(cooccurrence_in, "ua"))
        selected_strategy = "cooccurrence_lower_bound" if rows else "skip"
        if strategy == "skip" and not rows:
            selected_strategy = "skip"

    merged = merge_fanout_rows(rows)
    output_path.write_text(json.dumps(merged, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if run_summary is not None:
        run_summary.clear()
        run_summary.update(
            {
                "rows": len(merged),
                "selected_user_agents": user_agents,
                "strategy": selected_strategy,
                "fallback_errors": errors,
            }
        )
    return merged

def _try_summary_hour_fanout(
    cluster: str,
    database: str,
    start_dt: datetime,
    end_dt: datetime,
    user_agents: list[str],
    strategy: str,
    errors: list[str],
) -> tuple[list[dict[str, Any]], str]:
    rows: list[dict[str, Any]] = []
    selected_strategy = strategy
    if _summary_hour_supports_ua(cluster=cluster, database=database):
        try:
            rows = _export_fanout_query_rows(
                cluster=cluster,
                sql_rows=[
                    ("summary_hour", _summary_hour_fanout_sql(database=database, start=start_dt, end=end_dt, user_agent=user_agent))
                    for user_agent in user_agents
                ],
            )
            selected_strategy = "summary_hour"
        except SystemExit as exc:
            errors.append(str(exc))
    elif strategy == "summary_hour":
        errors.append(f"{database}.summary_hour does not expose UA in system.columns")
    if strategy == "summary_hour" and not rows:
        raise SystemExit("--fanout-strategy summary_hour could not produce usable fan-out rows: " + "; ".join(errors))
    return rows, selected_strategy

def _try_logs_probe_fanout(
    cluster: str,
    database: str,
    end_dt: datetime,
    user_agents: list[str],
    strategy: str,
    scraper_hourly_in: str | None,
    errors: list[str],
) -> tuple[list[dict[str, Any]], str]:
    rows: list[dict[str, Any]] = []
    selected_strategy = strategy
    peak_hours = _peak_hours_by_ua(_scraper_hourly_rows(scraper_hourly_in))
    missing = [ua for ua in user_agents if ua not in peak_hours]
    if peak_hours:
        try:
            rows = _export_fanout_query_rows(
                cluster=cluster,
                sql_rows=[
                    ("logs_probe", _logs_probe_fanout_sql(database=database, start=hour, end=min(hour + timedelta(hours=1), end_dt), user_agent=user_agent))
                    for user_agent, hour in peak_hours.items()
                    if user_agent in user_agents
                ],
            )
            rows = [{**row, "probe_window_hours": 1} for row in rows]
            selected_strategy = "logs_probe"
        except SystemExit as exc:
            errors.append(str(exc))
    elif strategy == "logs_probe":
        errors.append("--fanout-strategy logs_probe requires --scraper-hourly-in peak-hour rows")
    if strategy == "logs_probe" and (not rows or missing):
        raise SystemExit(
            "--fanout-strategy logs_probe could not produce usable fan-out rows"
            + (f"; missing peak-hour rows for {len(missing)} lead UA(s)" if missing else "")
            + ("; " + "; ".join(errors) if errors else "")
        )
    return rows, selected_strategy

def export_background_ua_sample(
    *,
    start: str,
    end: str,
    cluster: str,
    database: str = "akamai",
    excluded_user_agents: list[str] | None = None,
    output: str,
    sample_limit: int = 200,
    run_summary: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    output_path = Path(output).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    raw_output = output_path.with_suffix(output_path.suffix + ".raw")
    _run_mux_export(
        cluster,
        _raw_background_ua_sample_sql(
            database=database,
            start=parse_time(start, "start"),
            end=parse_time(end, "end"),
            excluded_user_agents=excluded_user_agents or [],
            sample_limit=sample_limit,
        ),
        raw_output,
    )
    rows = _read_json_rows(raw_output)
    raw_output.unlink(missing_ok=True)
    output_path.write_text(json.dumps(rows, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if run_summary is not None:
        run_summary.clear()
        run_summary.update({"rows": len(rows), "sample_limit": sample_limit})
    return rows

def export_baseline_ua_timeseries(
    *,
    baseline_start: str,
    baseline_end: str,
    user_agents: list[str],
    cluster: str,
    database: str = "akamai",
    output: str,
    granularity: str = "day",
    run_summary: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    if not user_agents:
        raise SystemExit("baseline significance export requires selected user agents")
    output_path = Path(output).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    raw_output = output_path.with_suffix(output_path.suffix + ".raw")
    _run_mux_export(
        cluster,
        _raw_baseline_ua_timeseries_sql(
            database=database,
            baseline_start=parse_time(baseline_start, "baseline-start"),
            baseline_end=parse_time(baseline_end, "baseline-end"),
            user_agents=user_agents,
            granularity=granularity,
        ),
        raw_output,
    )
    rows = _read_json_rows(raw_output)
    raw_output.unlink(missing_ok=True)
    output_path.write_text(json.dumps(rows, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if run_summary is not None:
        run_summary.clear()
        run_summary.update(
            {"rows": len(rows), "selected_user_agents": user_agents, "granularity": granularity}
        )
    return rows

def export_iat_samples(
    *,
    actor_dir: str,
    cooccurrence_in: str,
    start: str,
    end: str,
    cluster: str,
    database: str = "akamai",
    top_leads: int = 25,
    sample_limit_per_ua: int = 5_000,
    output: str,
    include_non_public_ips: bool = False,
    run_summary: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    scope = iat_sample_scope(
        actor_dir=actor_dir,
        cooccurrence_in=cooccurrence_in,
        start=start,
        end=end,
        database=database,
        top_leads=top_leads,
        sample_limit_per_ua=sample_limit_per_ua,
        include_non_public_ips=include_non_public_ips,
    )
    output_path = Path(output).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="threat-hunt-iat-samples-") as tmpdir:
        raw_output = Path(tmpdir) / "iat-samples.json"
        _run_mux_export(cluster, str(scope["sample_sql"]), raw_output)
        merged = merge_iat_sample_rows(_read_json_rows(raw_output))
    output_path.write_text(json.dumps(merged, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if run_summary is not None:
        run_summary.clear()
        run_summary.update(
            {
                "rows": len(merged),
                "selected_user_agents": scope["selected_user_agents"],
                "selected_client_ips": scope["selected_client_ips"],
                "excluded_non_public_client_ips": scope["excluded_non_public_client_ips"],
                "sample_limit_per_ua": sample_limit_per_ua,
            }
        )
    return merged

__all__ = [name for name in globals() if not name.startswith("__")]
