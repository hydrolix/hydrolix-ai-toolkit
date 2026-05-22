from __future__ import annotations

from ._shared import *

def _merge_actor_rows(
    rows: Iterable[dict[str, Any]], actor_type: str, top_n: int, period: str
) -> list[dict[str, Any]]:
    value_field = _actor_value_field(actor_type)
    cells: dict[str, dict[str, Any]] = {}
    countries: dict[str, set[str]] = defaultdict(set)
    paths: dict[str, set[str]] = defaultdict(set)
    for row in rows:
        value = str(_first(row, (value_field, "actor", "value", "entity"), "")).strip()
        if not value:
            continue
        cell = cells.setdefault(
            value,
            {
                "period": period,
                actor_type: value,
                "actor_type": actor_type,
                "value": value,
                "requests": 0.0,
                "bytes": 0.0,
                "response_body_bytes": 0.0,
                "akamai_billed_bytes": 0.0,
                "hydrolix_log_ingest_bytes": None,
                "status_429": 0.0,
                "status_5xx": 0.0,
                "country": "",
                "request_path": "",
            },
        )
        cell["requests"] += _num(_first(row, ("requests", "request_count", "count", "hits")))
        response_body_bytes = _num(_first(row, ("response_body_bytes", "response_bytes", "bytes")))
        cell["response_body_bytes"] += response_body_bytes
        cell["bytes"] += _num(_first(row, ("bytes", "response_body_bytes", "response_bytes"), response_body_bytes))
        cell["akamai_billed_bytes"] += _num(_first(row, ("akamai_billed_bytes", "totalBytes", "sum_totalBytes")))
        hydrolix_value = _first(row, ("hydrolix_log_ingest_bytes",))
        if hydrolix_value not in (None, ""):
            cell["hydrolix_log_ingest_bytes"] = (
                _num(cell["hydrolix_log_ingest_bytes"]) + _num(hydrolix_value)
            )
        cell["status_429"] += _num(_first(row, ("status_429", "requests_429", "429", "req_429")))
        cell["status_5xx"] += _num(_first(row, ("status_5xx", "requests_5xx", "5xx", "req_5xx")))
        _merge_actor_dimension(row, value, countries, paths)
    for value, cell in cells.items():
        _finalize_actor_cell(cell, value, countries, paths)
    return sorted(
        cells.values(),
        key=lambda row: (-_num(row.get("requests")), str(row.get("value"))),
    )[:top_n]

def _merge_actor_dimension(
    row: dict[str, Any],
    value: str,
    countries: dict[str, set[str]],
    paths: dict[str, set[str]],
) -> None:
    country = str(_first(row, ("country", "country_code"), "")).strip()
    if country:
        countries[value].add(country)
    request_path = str(_first(row, ("request_path", "requestPath", "path"), "")).strip()
    if request_path:
        paths[value].add(request_path)

def _finalize_actor_cell(
    cell: dict[str, Any],
    value: str,
    countries: dict[str, set[str]],
    paths: dict[str, set[str]],
) -> None:
    if countries[value]:
        cell["country"] = sorted(countries[value])[0]
    if paths[value]:
        cell["request_path"] = sorted(paths[value])[0]
    for key in (
        "requests",
        "bytes",
        "response_body_bytes",
        "akamai_billed_bytes",
        "hydrolix_log_ingest_bytes",
        "status_429",
        "status_5xx",
    ):
        if cell[key] is not None and float(cell[key]).is_integer():
            cell[key] = int(cell[key])

def _raw_cooccurrence_sql(
    *,
    database: str,
    start: datetime,
    end: datetime,
    client_ips: list[str],
    user_agents: list[str],
    client_ip_column: str = "cliIP",
    user_agent_column: str = "UA",
    country_column: str = "country",
) -> str:
    return f"""
SELECT
  toString({client_ip_column}) AS client_ip,
  toString({user_agent_column}) AS user_agent,
  any({country_column}) AS country,
  count() AS requests
FROM {database}.logs
WHERE reqTimeSec >= toDateTime('{sql_ts(start)}', 'UTC')
  AND reqTimeSec < toDateTime('{sql_ts(end)}', 'UTC')
  AND {client_ip_column} IN ({_sql_in(client_ips)})
  AND {user_agent_column} IN ({_sql_in(user_agents)})
GROUP BY client_ip, user_agent
ORDER BY requests DESC
""".strip()

def _raw_scraper_drilldown_sql(
    *,
    database: str,
    start: datetime,
    end: datetime,
    client_ips: list[str],
    user_agents: list[str],
    client_ip_column: str = "cliIP",
    user_agent_column: str = "UA",
    country_column: str = "country",
    path_column: str = "reqPath",
    row_limit: int | None = None,
) -> str:
    limit_clause = ""
    if row_limit is not None:
        if row_limit <= 0:
            raise SystemExit("row_limit must be positive")
        limit_clause = f"\nLIMIT {row_limit}"
    return f"""
SELECT
  toString({user_agent_column}) AS user_agent,
  toString({client_ip_column}) AS client_ip,
  toString({path_column}) AS request_path,
  toStartOfHour(reqTimeSec) AS hour,
  any({country_column}) AS country,
  countIf(statusCode = 429) AS status_429,
  countIf(statusCode BETWEEN 500 AND 599) AS status_5xx,
  count() AS requests
FROM {database}.logs
WHERE reqTimeSec >= toDateTime('{sql_ts(start)}', 'UTC')
  AND reqTimeSec < toDateTime('{sql_ts(end)}', 'UTC')
  AND {client_ip_column} IN ({_sql_in(client_ips)})
  AND {user_agent_column} IN ({_sql_in(user_agents)})
GROUP BY user_agent, client_ip, request_path, hour
ORDER BY requests DESC{limit_clause}
""".strip()

def _raw_scraper_hourly_sql(
    *,
    database: str,
    start: datetime,
    end: datetime,
    user_agents: list[str],
    user_agent_column: str = "UA",
) -> str:
    return f"""
SELECT
  toString({user_agent_column}) AS user_agent,
  toStartOfHour(reqTimeSec) AS hour,
  count() AS requests
FROM {database}.logs
WHERE reqTimeSec >= toDateTime('{sql_ts(start)}', 'UTC')
  AND reqTimeSec < toDateTime('{sql_ts(end)}', 'UTC')
  AND {user_agent_column} IN ({_sql_in(user_agents)})
GROUP BY user_agent, hour
ORDER BY user_agent, hour
""".strip()

def _raw_ua_fanout_sql(
    *,
    database: str,
    start: datetime,
    end: datetime,
    user_agents: list[str],
    client_ip_column: str = "cliIP",
    user_agent_column: str = "UA",
) -> str:
    return f"""
SELECT
  toString({user_agent_column}) AS user_agent,
  uniqExact(toString({client_ip_column})) AS unique_ips,
  count() AS hits,
  sum(totalBytes) AS bytes
FROM {database}.logs
WHERE reqTimeSec >= toDateTime('{sql_ts(start)}', 'UTC')
  AND reqTimeSec < toDateTime('{sql_ts(end)}', 'UTC')
  AND {user_agent_column} IN ({_sql_in(user_agents)})
GROUP BY user_agent
ORDER BY unique_ips DESC, hits DESC
""".strip()

def _summary_hour_ua_support_sql(*, database: str) -> str:
    return f"""
SELECT count() AS matching_columns
FROM system.columns
WHERE database = {sql_literal(database)}
  AND table = 'summary_hour'
  AND name = 'UA'
""".strip()

def _summary_hour_fanout_sql(
    *,
    database: str,
    start: datetime,
    end: datetime,
    user_agent: str,
) -> str:
    return f"""
SELECT
  toString(UA) AS user_agent,
  uniqMerge(`uniq(cliIP)`) AS unique_ips,
  countMerge(`count()`) AS hits,
  sumMerge(`sum(totalBytes)`) AS bytes
FROM {database}.summary_hour
WHERE reqTimeSec >= toDateTime('{sql_ts(start)}', 'UTC')
  AND reqTimeSec < toDateTime('{sql_ts(end)}', 'UTC')
  AND UA = {sql_literal(user_agent)}
GROUP BY user_agent
ORDER BY unique_ips DESC, hits DESC
""".strip()

def _logs_probe_fanout_sql(
    *,
    database: str,
    start: datetime,
    end: datetime,
    user_agent: str,
) -> str:
    return f"""
SELECT
  toString(UA) AS user_agent,
  uniqExact(toString(cliIP)) AS unique_ips,
  count() AS hits,
  sum(totalBytes) AS bytes
FROM {database}.logs
WHERE reqTimeSec >= toDateTime('{sql_ts(start)}', 'UTC')
  AND reqTimeSec < toDateTime('{sql_ts(end)}', 'UTC')
  AND UA = {sql_literal(user_agent)}
GROUP BY user_agent
ORDER BY unique_ips DESC, hits DESC
""".strip()

def _raw_background_ua_sample_sql(
    *,
    database: str,
    start: datetime,
    end: datetime,
    excluded_user_agents: list[str],
    min_requests: int = 100,
    max_requests: int = 10_000,
    sample_limit: int = 200,
    client_ip_column: str = "cliIP",
    user_agent_column: str = "UA",
    path_column: str = "reqPath",
) -> str:
    excluded_clause = ""
    if excluded_user_agents:
        excluded_clause = f"\n  AND user_agent NOT IN ({_sql_in(excluded_user_agents)})"
    return f"""
SELECT
  user_agent,
  requests,
  unique_client_ips,
  targeted_endpoint_requests,
  status_429,
  status_5xx,
  any_path
FROM (
  SELECT
    toString({user_agent_column}) AS user_agent,
    count() AS requests,
    uniqExact(toString({client_ip_column})) AS unique_client_ips,
    countIf(
      positionCaseInsensitive(toString({path_column}), '/api') > 0
      OR positionCaseInsensitive(toString({path_column}), 'catalog') > 0
      OR positionCaseInsensitive(toString({path_column}), 'product') > 0
      OR positionCaseInsensitive(toString({path_column}), 'search') > 0
      OR positionCaseInsensitive(toString({path_column}), 'graphql') > 0
      OR positionCaseInsensitive(toString({path_column}), 'auth') > 0
    ) AS targeted_endpoint_requests,
    countIf(statusCode = 429) AS status_429,
    countIf(statusCode BETWEEN 500 AND 599) AS status_5xx,
    any(toString({path_column})) AS any_path
  FROM {database}.logs
  WHERE reqTimeSec >= toDateTime('{sql_ts(start)}', 'UTC')
    AND reqTimeSec < toDateTime('{sql_ts(end)}', 'UTC')
    AND nullIf(toString({user_agent_column}), '') IS NOT NULL
  GROUP BY user_agent
)
WHERE requests BETWEEN {int(min_requests)} AND {int(max_requests)}{excluded_clause}
ORDER BY cityHash64(user_agent)
LIMIT {int(sample_limit)}
""".strip()

def _raw_baseline_ua_timeseries_sql(
    *,
    database: str,
    baseline_start: datetime,
    baseline_end: datetime,
    user_agents: list[str],
    granularity: str = "day",
    user_agent_column: str = "UA",
) -> str:
    if granularity not in {"hour", "day"}:
        raise SystemExit("baseline UA timeseries granularity must be hour or day")
    bucket_expr = "toStartOfHour(reqTimeSec)" if granularity == "hour" else "toDate(reqTimeSec)"
    return f"""
SELECT
  toString({user_agent_column}) AS user_agent,
  {bucket_expr} AS bucket,
  count() AS requests
FROM {database}.logs
WHERE reqTimeSec >= toDateTime('{sql_ts(baseline_start)}', 'UTC')
  AND reqTimeSec < toDateTime('{sql_ts(baseline_end)}', 'UTC')
  AND {user_agent_column} IN ({_sql_in(user_agents)})
GROUP BY user_agent, bucket
ORDER BY user_agent, bucket
""".strip()

def _raw_iat_sample_sql(
    *,
    database: str,
    start: datetime,
    end: datetime,
    client_ips: list[str],
    user_agents: list[str],
    sample_limit_per_ua: int = 5_000,
    client_ip_column: str = "cliIP",
    user_agent_column: str = "UA",
    path_column: str = "reqPath",
) -> str:
    if sample_limit_per_ua <= 0:
        raise SystemExit("sample_limit_per_ua must be positive")
    return f"""
SELECT
  user_agent,
  client_ip,
  reqTimeSec,
  request_path,
  status_code
FROM (
  SELECT
    toString({user_agent_column}) AS user_agent,
    toString({client_ip_column}) AS client_ip,
    reqTimeSec,
    toString({path_column}) AS request_path,
    statusCode AS status_code,
    row_number() OVER (PARTITION BY toString({user_agent_column}) ORDER BY reqTimeSec, toString({client_ip_column})) AS ua_sample_rank
  FROM {database}.logs
  WHERE reqTimeSec >= toDateTime('{sql_ts(start)}', 'UTC')
    AND reqTimeSec < toDateTime('{sql_ts(end)}', 'UTC')
    AND {client_ip_column} IN ({_sql_in(client_ips)})
    AND {user_agent_column} IN ({_sql_in(user_agents)})
)
WHERE ua_sample_rank <= {int(sample_limit_per_ua)}
ORDER BY user_agent, client_ip, reqTimeSec
""".strip()

__all__ = [name for name in globals() if not name.startswith("__")]
