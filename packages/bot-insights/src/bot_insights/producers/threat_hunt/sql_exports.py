from __future__ import annotations

from ._shared import *

def split_raw_cooccurrence_window(
    start: datetime,
    end: datetime,
    *,
    max_seconds: int = RAW_COOCCURRENCE_MAX_SECONDS,
) -> list[tuple[datetime, datetime]]:
    if end <= start:
        raise SystemExit("--end must be later than --start")
    if max_seconds <= 0:
        raise SystemExit("max_seconds must be positive")
    chunks = []
    cursor = start
    delta = timedelta(seconds=max_seconds)
    while cursor < end:
        chunk_end = min(cursor + delta, end)
        chunks.append((cursor, chunk_end))
        cursor = chunk_end
    return chunks

def _top_actor_values(
    actor_rows: list[dict[str, Any]], actor_type: str, top_n: int
) -> list[str]:
    values = [
        (str(row.get("value")), _num(row.get("requests")))
        for row in actor_rows
        if row.get("period") == "current"
        and row.get("actor_type") == actor_type
        and str(row.get("value") or "").strip()
    ]
    values.sort(key=lambda item: (-item[1], item[0]))
    return [value for value, _requests in values[:top_n]]

def _actor_value_field(actor_type: str) -> str:
    if actor_type == "client_ip":
        return "client_ip"
    if actor_type == "user_agent":
        return "user_agent"
    raise AssertionError(actor_type)

def _sql_in(values: list[str]) -> str:
    if not values:
        return "NULL"
    return ", ".join(sql_literal(value) for value in values)

def _raw_actor_sql(
    *,
    database: str,
    actor_type: str,
    start: datetime,
    end: datetime,
    top_n: int,
    response_body_bytes_column: str = "bytes",
    akamai_billed_bytes_column: str = "totalBytes",
    hydrolix_log_ingest_bytes_column: str | None = None,
    path_column: str = "reqPath",
    hash_bucket_count: int | None = None,
    hash_bucket_index: int | None = None,
    topk_candidate_count: int | None = None,
) -> str:
    if actor_type == "client_ip":
        value_expr = "toString(cliIP)"
    elif actor_type == "user_agent":
        value_expr = "toString(UA)"
    else:
        raise AssertionError(actor_type)
    value_field = _actor_value_field(actor_type)
    hydrolix_expr = (
        f"sum({hydrolix_log_ingest_bytes_column})"
        if hydrolix_log_ingest_bytes_column
        else "CAST(NULL, 'Nullable(Float64)')"
    )
    bucket_clause = ""
    prefix = ""
    actor_filter = f"AND nullIf({value_expr}, '') IS NOT NULL"
    if topk_candidate_count is not None and hash_bucket_count is not None:
        raise SystemExit("topk candidate selection and hash buckets are mutually exclusive")
    if topk_candidate_count is not None:
        if topk_candidate_count <= 0:
            raise SystemExit("topk_candidate_count must be positive")
        prefix = f"""
WITH (
  SELECT topK({int(topk_candidate_count)})({value_expr})
  FROM {database}.logs
  WHERE reqTimeSec >= toDateTime('{sql_ts(start)}', 'UTC')
    AND reqTimeSec < toDateTime('{sql_ts(end)}', 'UTC')
    AND nullIf({value_expr}, '') IS NOT NULL
) AS top_values
""".strip() + "\n"
        actor_filter = f"AND has(top_values, {value_expr})"
    if hash_bucket_count is not None:
        if hash_bucket_count <= 0:
            raise SystemExit("hash_bucket_count must be positive")
        if hash_bucket_index is None or not 0 <= hash_bucket_index < hash_bucket_count:
            raise SystemExit("hash_bucket_index must be between 0 and hash_bucket_count - 1")
        bucket_clause = (
            f"\n    AND modulo(cityHash64({value_expr}), {int(hash_bucket_count)}) = "
            f"{int(hash_bucket_index)}"
        )
    return f"""{prefix}\
SELECT
  {value_field},
  requests,
  response_body_bytes,
  response_body_bytes AS bytes,
  akamai_billed_bytes,
  hydrolix_log_ingest_bytes,
  status_429,
  status_5xx,
  country,
  request_path
FROM (
  SELECT
    {value_expr} AS {value_field},
    count() AS requests,
    sum({response_body_bytes_column}) AS response_body_bytes,
    sum({akamai_billed_bytes_column}) AS akamai_billed_bytes,
    {hydrolix_expr} AS hydrolix_log_ingest_bytes,
    countIf(statusCode = 429) AS status_429,
    countIf(statusCode BETWEEN 500 AND 599) AS status_5xx,
    any(country) AS country,
    any({path_column}) AS request_path
  FROM {database}.logs
  WHERE reqTimeSec >= toDateTime('{sql_ts(start)}', 'UTC')
    AND reqTimeSec < toDateTime('{sql_ts(end)}', 'UTC')
    {actor_filter}{bucket_clause}
  GROUP BY {value_field}
)
ORDER BY requests DESC
LIMIT {int(top_n)}
""".strip()

def _hydrolix_usagemeter_sql(
    *,
    start: datetime,
    end: datetime,
    project_deployment_id: str,
    table_name: str,
) -> str:
    return f"""
SELECT
  'hydro.logs usagemeter' AS source,
  {sql_literal(project_deployment_id)} AS project_deployment_id,
  {sql_literal(table_name)} AS table_name,
  min(timestamp) AS metadata_window_start,
  max(timestamp) AS metadata_window_end,
  sum(toUInt64OrZero(toString(rows))) AS rows,
  sum(toUInt64OrZero(catchall['billing_bytes'])) AS billing_bytes,
  sum(toUInt64OrZero(toString(bytes))) AS raw_usage_bytes,
  billing_bytes / nullIf(rows, 0) AS billing_bytes_per_row,
  raw_usage_bytes / nullIf(rows, 0) AS raw_usage_bytes_per_row
FROM hydro.logs
WHERE timestamp >= toDateTime('{sql_ts(start)}', 'UTC')
  AND timestamp < toDateTime('{sql_ts(end)}', 'UTC')
  AND message = 'Reported usage.'
  AND table_name = {sql_literal(table_name)}
  AND catchall['project_deployment_id'] = {sql_literal(project_deployment_id)}
""".strip()

def _raw_impact_lane_sql(
    *,
    database: str,
    start: datetime,
    end: datetime,
    scope: str,
    user_agents: list[str] | None = None,
) -> str:
    ua_clause = ""
    if user_agents is not None:
        if not user_agents:
            raise SystemExit("impact lane scoped export requires at least one user agent")
        ua_clause = f"\n    AND UA IN ({_sql_in(user_agents)})"
    return f"""
SELECT
  {sql_literal(scope)} AS scope,
  count() AS requests,
  sum(bytes) AS response_body_bytes,
  sum(totalBytes) AS akamai_billed_bytes
FROM {database}.logs
WHERE reqTimeSec >= toDateTime('{sql_ts(start)}', 'UTC')
  AND reqTimeSec < toDateTime('{sql_ts(end)}', 'UTC'){ua_clause}
""".strip()

def _normalize_impact_lane_row(row: dict[str, Any]) -> dict[str, Any]:
    scope = str(_first(row, ("scope",), "")).strip()
    if scope not in {*IMPACT_LANE_TOTAL_SCOPES, *IMPACT_LANE_SCOPED_HUNT_SCOPES}:
        raise SystemExit(f"impact lane row has unsupported scope: {scope or '<missing>'}")
    missing = [
        field
        for field in IMPACT_LANE_REQUIRED_FIELDS
        if field not in row or row.get(field) in (None, "")
    ]
    if missing:
        raise SystemExit(
            "impact lane row is missing required field(s): " + ", ".join(missing)
        )
    normalized = {
        "scope": scope,
        "requests": _num(row.get("requests")),
        "response_body_bytes": _num(row.get("response_body_bytes")),
        "akamai_billed_bytes": _num(row.get("akamai_billed_bytes")),
    }
    for field in ("requests", "response_body_bytes", "akamai_billed_bytes"):
        if float(normalized[field]).is_integer():
            normalized[field] = int(normalized[field])
    return normalized

def read_impact_lane_rows(path_value: str | None) -> list[dict[str, Any]]:
    """Read and aggregate raw-log impact lane rows from JSON/CSV/parquet input."""
    if not path_value:
        return []
    rows = [_normalize_impact_lane_row(row) for row in _read_optional_rows(path_value)]
    return merge_impact_lane_rows(rows)

def merge_impact_lane_rows(rows: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    cells: dict[str, dict[str, Any]] = {}
    for raw in rows:
        row = _normalize_impact_lane_row(raw)
        scope = row["scope"]
        cell = cells.setdefault(
            scope,
            {
                "scope": scope,
                "requests": 0.0,
                "response_body_bytes": 0.0,
                "akamai_billed_bytes": 0.0,
            },
        )
        cell["requests"] += _num(row.get("requests"))
        cell["response_body_bytes"] += _num(row.get("response_body_bytes"))
        cell["akamai_billed_bytes"] += _num(row.get("akamai_billed_bytes"))
    ordered_scopes = (*IMPACT_LANE_TOTAL_SCOPES, *IMPACT_LANE_SCOPED_HUNT_SCOPES)
    merged = [cells[scope] for scope in ordered_scopes if scope in cells]
    for cell in merged:
        for field in ("requests", "response_body_bytes", "akamai_billed_bytes"):
            if float(cell[field]).is_integer():
                cell[field] = int(cell[field])
    return merged

def _impact_lane_rows_by_scope(rows: Iterable[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {str(row["scope"]): row for row in merge_impact_lane_rows(rows)}

def export_impact_lane_totals(
    *,
    output: str,
    start: str,
    end: str,
    baseline_start: str,
    baseline_end: str,
    cluster: str,
    database: str = "akamai",
    chunk_seconds: int = RAW_COOCCURRENCE_MAX_SECONDS,
) -> list[dict[str, Any]]:
    output_path = Path(output).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    windows = {
        "current_total": (parse_time(start, "start"), parse_time(end, "end")),
        "baseline_total": (
            parse_time(baseline_start, "baseline-start"),
            parse_time(baseline_end, "baseline-end"),
        ),
    }
    rows = _export_impact_lane_windows(
        cluster=cluster,
        database=database,
        windows=windows,
        user_agents=None,
        chunk_seconds=chunk_seconds,
    )
    output_path.write_text(json.dumps(rows, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return rows

def export_impact_lane_scoped_hunt(
    *,
    output: str,
    start: str,
    end: str,
    baseline_start: str,
    baseline_end: str,
    cluster: str,
    user_agents: list[str],
    database: str = "akamai",
    chunk_seconds: int = RAW_COOCCURRENCE_MAX_SECONDS,
) -> list[dict[str, Any]]:
    if not user_agents:
        raise SystemExit("scoped Hunt impact lane export requires high/partial user agents")
    output_path = Path(output).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    windows = {
        "current_high_partial": (parse_time(start, "start"), parse_time(end, "end")),
        "baseline_high_partial": (
            parse_time(baseline_start, "baseline-start"),
            parse_time(baseline_end, "baseline-end"),
        ),
    }
    rows = _export_impact_lane_windows(
        cluster=cluster,
        database=database,
        windows=windows,
        user_agents=user_agents,
        chunk_seconds=chunk_seconds,
    )
    output_path.write_text(json.dumps(rows, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return rows

def _export_impact_lane_windows(
    *,
    cluster: str,
    database: str,
    windows: dict[str, tuple[datetime, datetime]],
    user_agents: list[str] | None,
    chunk_seconds: int,
) -> list[dict[str, Any]]:
    if chunk_seconds <= 0:
        raise SystemExit("chunk_seconds must be positive")
    chunk_rows: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="threat-hunt-impact-lanes-") as tmpdir:
        tmp = Path(tmpdir)
        for scope, (window_start, window_end) in windows.items():
            for index, (chunk_start, chunk_end) in enumerate(
                split_raw_cooccurrence_window(
                    window_start,
                    window_end,
                    max_seconds=chunk_seconds,
                ),
                start=1,
            ):
                chunk_output = tmp / f"{scope}-{index}.json"
                _run_mux_export(
                    cluster,
                    _raw_impact_lane_sql(
                        database=database,
                        start=chunk_start,
                        end=chunk_end,
                        scope=scope,
                        user_agents=user_agents,
                    ),
                    chunk_output,
                )
                chunk_rows.extend(_read_json_rows(chunk_output))
    return merge_impact_lane_rows(chunk_rows)

__all__ = [name for name in globals() if not name.startswith("__")]
