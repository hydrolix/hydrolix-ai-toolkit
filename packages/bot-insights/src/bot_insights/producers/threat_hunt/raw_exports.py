from __future__ import annotations

from ._shared import *

def export_raw_actor_fixtures(
    *,
    actor_dir: str,
    start: str,
    end: str,
    baseline_start: str,
    baseline_end: str,
    cluster: str,
    database: str = "akamai",
    top_n: int = DEFAULT_COOCCURRENCE_TOP_N,
    hydrolix_log_ingest_bytes_column: str | None = None,
    chunk_seconds: int = RAW_ACTOR_MAX_SECONDS,
    extraction_mode: str = "topk",
    hash_buckets: int = RAW_ACTOR_HASH_BUCKETS,
    topk_candidate_multiplier: int = RAW_ACTOR_TOPK_CANDIDATE_MULTIPLIER,
) -> Path:
    if chunk_seconds <= 0:
        raise SystemExit("chunk_seconds must be positive")
    if hash_buckets <= 0:
        raise SystemExit("hash_buckets must be positive")
    if topk_candidate_multiplier <= 0:
        raise SystemExit("topk_candidate_multiplier must be positive")
    if extraction_mode not in {"topk", "hash"}:
        raise SystemExit("extraction_mode must be one of topk, hash")
    output_dir = Path(actor_dir).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    windows = {
        "current": (parse_time(start, "start"), parse_time(end, "end")),
        "baseline": (
            parse_time(baseline_start, "baseline-start"),
            parse_time(baseline_end, "baseline-end"),
        ),
    }
    with tempfile.TemporaryDirectory(prefix="threat-hunt-actors-") as tmpdir:
        tmp = Path(tmpdir)
        for period, (window_start, window_end) in windows.items():
            for actor_type in ("client_ip", "user_agent"):
                chunk_rows: list[dict[str, Any]] = []
                actor_hash_buckets = (
                    hash_buckets
                    if extraction_mode == "hash" and actor_type == "client_ip"
                    else 1
                )
                topk_candidate_count = (
                    max(int(top_n) * int(topk_candidate_multiplier), int(top_n))
                    if extraction_mode == "topk"
                    else None
                )
                for index, (chunk_start, chunk_end) in enumerate(
                    split_raw_cooccurrence_window(
                        window_start,
                        window_end,
                        max_seconds=chunk_seconds,
                    ),
                    start=1,
                ):
                    for bucket_index in range(actor_hash_buckets):
                        chunk_output = (
                            tmp / f"{period}-{actor_type}-{index}-bucket-{bucket_index}.json"
                        )
                        _run_mux_export(
                            cluster,
                            _raw_actor_sql(
                                database=database,
                                actor_type=actor_type,
                                start=chunk_start,
                                end=chunk_end,
                                top_n=top_n,
                                hydrolix_log_ingest_bytes_column=hydrolix_log_ingest_bytes_column,
                                hash_bucket_count=actor_hash_buckets
                                if actor_hash_buckets > 1
                                else None,
                                hash_bucket_index=bucket_index
                                if actor_hash_buckets > 1
                                else None,
                                topk_candidate_count=topk_candidate_count,
                            ),
                            chunk_output,
                        )
                        chunk_rows.extend(_read_json_rows(chunk_output))
                merged = _merge_actor_rows(chunk_rows, actor_type, top_n, period)
                output_path = output_dir / f"expedia-actors-{period}-{actor_type}.json"
                output_path.write_text(
                    json.dumps(merged, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
    return output_dir

def export_hydrolix_usagemeter_ingest_estimate(
    *,
    output: str,
    start: str,
    end: str,
    cluster: str,
    project_deployment_id: str,
    table_name: str = "logs",
) -> Path:
    output_path = Path(output).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    _run_mux_export(
        cluster,
        _hydrolix_usagemeter_sql(
            start=parse_time(start, "start"),
            end=parse_time(end, "end"),
            project_deployment_id=project_deployment_id,
            table_name=table_name,
        ),
        output_path,
    )
    return output_path

def _mux_export_command() -> list[str]:
    mux_project = Path(
        os.environ.get("HYDROLIX_MUX_PROJECT") or DEFAULT_MUX_PROJECT
    ).expanduser()
    if (mux_project / "pyproject.toml").exists():
        uv = shutil.which("uv")
        if uv:
            return [
                uv,
                "run",
                "--project",
                str(mux_project),
                "mcp-hydrolix-mux",
                "export-select-query",
            ]
    binary = shutil.which("mcp-hydrolix-mux")
    if binary:
        return [binary, "export-select-query"]
    raise SystemExit(
        "Could not find mcp-hydrolix-mux. Set HYDROLIX_MUX_PROJECT to the standalone "
        "mcp-hydrolix-mux checkout, or install the mcp-hydrolix-mux console script."
    )

def _run_mux_export(cluster: str, sql: str, output: Path) -> None:
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".sql", delete=False) as handle:
        sql_file = Path(handle.name)
        handle.write(sql)
        handle.write("\n")
    command = [
        *_mux_export_command(),
        "--cluster",
        cluster,
        "--query-file",
        str(sql_file),
        "--output",
        str(output),
    ]
    try:
        result = subprocess.run(command, text=True, capture_output=True, check=False)
    finally:
        sql_file.unlink(missing_ok=True)
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise SystemExit(f"mcp-hydrolix-mux export-select-query failed: {detail}")

def merge_cooccurrence_rows(rows: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    cells: dict[tuple[str, str], dict[str, Any]] = {}
    countries: dict[tuple[str, str], set[str]] = defaultdict(set)
    for row in rows:
        client_ip = str(_first(row, ("client_ip", "clientIp", "cliIP", "ip", "value_a"), "")).strip()
        user_agent = str(_first(row, ("user_agent", "userAgent", "UA", "ua", "value_b"), "")).strip()
        if not client_ip or not user_agent:
            continue
        key = (client_ip, user_agent)
        cell = cells.setdefault(
            key,
            {"client_ip": client_ip, "user_agent": user_agent, "country": "", "requests": 0.0},
        )
        cell["requests"] += _num(_first(row, ("requests", "request_count", "count", "hits")))
        country = str(_first(row, ("country", "country_code"), "")).strip()
        if country:
            countries[key].add(country)
    for key, cell in cells.items():
        if countries[key]:
            cell["country"] = sorted(countries[key])[0]
        if float(cell["requests"]).is_integer():
            cell["requests"] = int(cell["requests"])
    return sorted(
        cells.values(),
        key=lambda row: (-_num(row.get("requests")), str(row.get("client_ip")), str(row.get("user_agent"))),
    )

def merge_scraper_drilldown_rows(rows: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    cells: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    countries: dict[tuple[str, str, str, str], set[str]] = defaultdict(set)
    for row in rows:
        user_agent = str(_first(row, ("user_agent", "userAgent", "UA", "ua"), "")).strip()
        client_ip = str(_first(row, ("client_ip", "clientIp", "cliIP", "ip"), "")).strip()
        request_path = str(_first(row, ("request_path", "requestPath", "path", "reqPath"), "")).strip()
        hour = str(_first(row, ("hour", "bucket", "timestamp"), "")).strip()
        if not user_agent or not client_ip:
            continue
        key = (user_agent, client_ip, request_path, hour)
        cell = cells.setdefault(
            key,
            {
                "user_agent": user_agent,
                "client_ip": client_ip,
                "request_path": request_path,
                "hour": hour,
                "country": "",
                "status_429": 0.0,
                "status_5xx": 0.0,
                "requests": 0.0,
            },
        )
        cell["status_429"] += _num(_first(row, ("status_429", "requests_429", "429", "req_429")))
        cell["status_5xx"] += _num(_first(row, ("status_5xx", "requests_5xx", "5xx", "req_5xx")))
        cell["requests"] += _num(_first(row, ("requests", "request_count", "count", "hits")))
        country = str(_first(row, ("country", "country_code"), "")).strip()
        if country:
            countries[key].add(country)
    for key, cell in cells.items():
        if countries[key]:
            cell["country"] = sorted(countries[key])[0]
        for numeric in ("status_429", "status_5xx", "requests"):
            if float(cell[numeric]).is_integer():
                cell[numeric] = int(cell[numeric])
    return sorted(
        cells.values(),
        key=lambda row: (
            -_num(row.get("requests")),
            str(row.get("user_agent")),
            str(row.get("client_ip")),
            str(row.get("request_path")),
            str(row.get("hour")),
        ),
    )

def merge_iat_sample_rows(rows: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized = []
    seen: set[tuple[str, str, str, str, str]] = set()
    for row in rows:
        user_agent = str(_first(row, ("user_agent", "userAgent", "UA", "ua"), "")).strip()
        client_ip = str(_first(row, ("client_ip", "clientIp", "cliIP", "ip"), "")).strip()
        timestamp = _first(row, ("timestamp", "reqTimeSec", "request_time", "time"))
        if not user_agent or not client_ip or timestamp in (None, ""):
            continue
        request_path = str(_first(row, ("request_path", "requestPath", "path", "reqPath"), "")).strip()
        status_code = str(_first(row, ("status_code", "statusCode"), "")).strip()
        key = (user_agent, client_ip, str(timestamp), request_path, status_code)
        if key in seen:
            continue
        seen.add(key)
        cell = {
            "user_agent": user_agent,
            "client_ip": client_ip,
            "timestamp": timestamp,
            "request_path": request_path,
            "status_code": status_code,
        }
        response_time = _first(row, ("response_time_ms", "responseTimeMs", "responseTime", "duration_ms"))
        if response_time not in (None, ""):
            cell["response_time_ms"] = _num(response_time)
        normalized.append(cell)
    return sorted(
        normalized,
        key=lambda row: (
            str(row.get("user_agent")),
            str(row.get("client_ip")),
            _timestamp_seconds(row.get("timestamp")) or 0.0,
            str(row.get("request_path")),
        ),
    )

def export_raw_ua_cooccurrence(
    *,
    actor_dir: str,
    start: str,
    end: str,
    cluster: str,
    database: str = "akamai",
    top_n: int = DEFAULT_COOCCURRENCE_TOP_N,
    output: str,
) -> list[dict[str, Any]]:
    actor_rows = load_raw_actor_rows(actor_dir)
    client_ips = _top_actor_values(actor_rows, "client_ip", top_n)
    user_agents = _top_actor_values(actor_rows, "user_agent", top_n)
    if not client_ips:
        raise SystemExit("--raw-actor-dir has no current client_ip actors")
    if not user_agents:
        raise SystemExit("--raw-actor-dir has no current user_agent actors")

    start_dt = parse_time(start, "start")
    end_dt = parse_time(end, "end")
    output_path = Path(output).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    chunk_rows: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="threat-hunt-cooccurrence-") as tmpdir:
        tmp = Path(tmpdir)
        for index, (chunk_start, chunk_end) in enumerate(
            split_raw_cooccurrence_window(start_dt, end_dt), start=1
        ):
            chunk_output = tmp / f"chunk-{index}.json"
            _run_mux_export(
                cluster,
                _raw_cooccurrence_sql(
                    database=database,
                    start=chunk_start,
                    end=chunk_end,
                    client_ips=client_ips,
                    user_agents=user_agents,
                ),
                chunk_output,
            )
            chunk_rows.extend(_read_json_rows(chunk_output))

    merged = merge_cooccurrence_rows(chunk_rows)
    output_path.write_text(json.dumps(merged, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return merged

__all__ = [name for name in globals() if not name.startswith("__")]
