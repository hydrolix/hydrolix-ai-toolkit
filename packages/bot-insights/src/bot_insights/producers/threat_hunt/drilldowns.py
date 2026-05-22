from __future__ import annotations

from ._shared import *

def _top_scraper_user_agents(
    actor_rows: list[dict[str, Any]],
    cooccurrence_rows: list[dict[str, Any]],
    top_leads: int,
) -> list[str]:
    requests_by_ua: Counter[str] = Counter()
    for row in actor_rows:
        if row.get("period") == "current" and row.get("actor_type") == "user_agent":
            value = str(row.get("value") or "").strip()
            if value:
                requests_by_ua[value] += _num(row.get("requests"))
    for row in cooccurrence_rows:
        value = str(row.get("user_agent") or "").strip()
        if value and value not in requests_by_ua:
            requests_by_ua[value] += _num(row.get("requests"))
    return [
        ua
        for ua, _requests in sorted(
            requests_by_ua.items(), key=lambda item: (-item[1], item[0])
        )[:top_leads]
    ]

def _is_public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False

def scraper_drilldown_scope(
    *,
    actor_dir: str,
    cooccurrence_in: str,
    start: str,
    end: str,
    database: str = "akamai",
    top_leads: int = 5,
    chunk_seconds: int = 3_600,
    row_limit_per_chunk: int | None = None,
    include_non_public_ips: bool = False,
) -> dict[str, Any]:
    actor_rows = load_raw_actor_rows(actor_dir)
    cooccurrence = _cooccurrence_rows(cooccurrence_in, "ua")
    user_agents = _top_scraper_user_agents(actor_rows, cooccurrence, top_leads)
    if not user_agents:
        raise SystemExit("--cooccurrence-in or --actor-dir has no current user_agent rows")

    selected_user_agents = set(user_agents)
    all_scoped_ips = sorted(
        {
            str(row.get("client_ip")).strip()
            for row in cooccurrence
            if row.get("user_agent") in selected_user_agents and row.get("client_ip")
        }
    )
    client_ips = [
        ip
        for ip in all_scoped_ips
        if include_non_public_ips or _is_public_ip(ip)
    ]
    if not client_ips:
        raise SystemExit("--cooccurrence-in has no public client_ip rows for selected user agents")

    start_dt = parse_time(start, "start")
    end_dt = parse_time(end, "end")
    chunks = split_raw_cooccurrence_window(
        start_dt, end_dt, max_seconds=chunk_seconds
    )
    first_start, first_end = chunks[0]
    return {
        "selected_user_agents": user_agents,
        "selected_client_ips": client_ips,
        "excluded_non_public_client_ips": [
            ip for ip in all_scoped_ips if ip not in set(client_ips)
        ],
        "chunks": [
            {
                "start": chunk_start.isoformat().replace("+00:00", "Z"),
                "end": chunk_end.isoformat().replace("+00:00", "Z"),
            }
            for chunk_start, chunk_end in chunks
        ],
        "first_sql": _raw_scraper_drilldown_sql(
            database=database,
            start=first_start,
            end=first_end,
            client_ips=client_ips,
            user_agents=user_agents,
            row_limit=row_limit_per_chunk,
        ),
    }

def iat_sample_scope(
    *,
    actor_dir: str,
    cooccurrence_in: str,
    start: str,
    end: str,
    database: str = "akamai",
    top_leads: int = 25,
    sample_limit_per_ua: int = 5_000,
    include_non_public_ips: bool = False,
) -> dict[str, Any]:
    actor_rows = load_raw_actor_rows(actor_dir)
    cooccurrence = _cooccurrence_rows(cooccurrence_in, "ua")
    user_agents = _top_scraper_user_agents(actor_rows, cooccurrence, top_leads)
    if not user_agents:
        raise SystemExit("--cooccurrence-in or --actor-dir has no current user_agent rows")

    selected_user_agents = set(user_agents)
    all_scoped_ips = sorted(
        {
            str(row.get("client_ip")).strip()
            for row in cooccurrence
            if row.get("user_agent") in selected_user_agents and row.get("client_ip")
        }
    )
    client_ips = [
        ip
        for ip in all_scoped_ips
        if include_non_public_ips or _is_public_ip(ip)
    ]
    if not client_ips:
        raise SystemExit("--cooccurrence-in has no public client_ip rows for selected user agents")

    start_dt = parse_time(start, "start")
    end_dt = parse_time(end, "end")
    return {
        "selected_user_agents": user_agents,
        "selected_client_ips": client_ips,
        "excluded_non_public_client_ips": [
            ip for ip in all_scoped_ips if ip not in set(client_ips)
        ],
        "sample_limit_per_ua": sample_limit_per_ua,
        "sample_sql": _raw_iat_sample_sql(
            database=database,
            start=start_dt,
            end=end_dt,
            client_ips=client_ips,
            user_agents=user_agents,
            sample_limit_per_ua=sample_limit_per_ua,
        ),
    }

def export_scraper_drilldowns(
    *,
    actor_dir: str,
    cooccurrence_in: str,
    start: str,
    end: str,
    cluster: str,
    database: str = "akamai",
    top_leads: int = 5,
    output: str,
    chunk_seconds: int = 3_600,
    row_limit_per_chunk: int | None = 100_000,
    include_non_public_ips: bool = False,
    run_summary: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    scope = scraper_drilldown_scope(
        actor_dir=actor_dir,
        cooccurrence_in=cooccurrence_in,
        start=start,
        end=end,
        database=database,
        top_leads=top_leads,
        chunk_seconds=chunk_seconds,
        row_limit_per_chunk=row_limit_per_chunk,
        include_non_public_ips=include_non_public_ips,
    )
    start_dt = parse_time(start, "start")
    end_dt = parse_time(end, "end")
    user_agents = scope["selected_user_agents"]
    client_ips = scope["selected_client_ips"]
    output_path = Path(output).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    chunk_rows: list[dict[str, Any]] = []
    chunk_row_counts: list[int] = []
    with tempfile.TemporaryDirectory(prefix="threat-hunt-scraper-drilldown-") as tmpdir:
        tmp = Path(tmpdir)
        for index, (chunk_start, chunk_end) in enumerate(
            split_raw_cooccurrence_window(start_dt, end_dt, max_seconds=chunk_seconds),
            start=1,
        ):
            chunk_output = tmp / f"chunk-{index}.json"
            _run_mux_export(
                cluster,
                _raw_scraper_drilldown_sql(
                    database=database,
                    start=chunk_start,
                    end=chunk_end,
                    client_ips=client_ips,
                    user_agents=user_agents,
                    row_limit=row_limit_per_chunk,
                ),
                chunk_output,
            )
            rows = _read_json_rows(chunk_output)
            chunk_row_counts.append(len(rows))
            chunk_rows.extend(rows)

    merged = merge_scraper_drilldown_rows(chunk_rows)
    output_path.write_text(json.dumps(merged, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if run_summary is not None:
        run_summary.clear()
        run_summary.update(
            {
                "rows": len(merged),
                "selected_user_agents": user_agents,
                "selected_client_ips": client_ips,
                "excluded_non_public_client_ips": scope["excluded_non_public_client_ips"],
                "chunks": len(scope["chunks"]),
                "chunk_row_counts": chunk_row_counts,
            }
        )
    return merged

def export_scraper_hourly_profiles(
    *,
    actor_dir: str,
    cooccurrence_in: str | None,
    start: str,
    end: str,
    cluster: str,
    database: str = "akamai",
    top_leads: int = 25,
    output: str,
    chunk_seconds: int = RAW_COOCCURRENCE_MAX_SECONDS,
    run_summary: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    if chunk_seconds <= 0:
        raise SystemExit("chunk_seconds must be positive")
    actor_rows = load_raw_actor_rows(actor_dir)
    cooccurrence = _cooccurrence_rows(cooccurrence_in, "ua") if cooccurrence_in else []
    user_agents = _top_scraper_user_agents(actor_rows, cooccurrence, top_leads)
    if not user_agents:
        raise SystemExit("--actor-dir or --cooccurrence-in has no current user_agent rows")
    output_path = Path(output).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    start_dt = parse_time(start, "start")
    end_dt = parse_time(end, "end")
    chunk_rows: list[dict[str, Any]] = []
    chunk_row_counts: list[int] = []
    with tempfile.TemporaryDirectory(prefix="threat-hunt-scraper-hourly-") as tmpdir:
        tmp = Path(tmpdir)
        chunks = split_raw_cooccurrence_window(start_dt, end_dt, max_seconds=chunk_seconds)
        for index, (chunk_start, chunk_end) in enumerate(chunks, start=1):
            raw_output = tmp / f"scraper-hourly-{index}.json"
            _run_mux_export(
                cluster,
                _raw_scraper_hourly_sql(
                    database=database,
                    start=chunk_start,
                    end=chunk_end,
                    user_agents=user_agents,
                ),
                raw_output,
            )
            rows = _read_json_rows(raw_output)
            chunk_row_counts.append(len(rows))
            chunk_rows.extend(rows)
    merged = merge_scraper_hourly_rows(chunk_rows)
    output_path.write_text(json.dumps(merged, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if run_summary is not None:
        run_summary.clear()
        run_summary.update(
            {
                "rows": len(merged),
                "selected_user_agents": user_agents,
                "chunks": len(chunk_row_counts),
                "chunk_row_counts": chunk_row_counts,
            }
        )
    return merged

__all__ = [name for name in globals() if not name.startswith("__")]
