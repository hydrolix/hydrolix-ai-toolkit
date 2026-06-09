"""Discovery SQL builders for host-scoped bot-incident candidates."""

from __future__ import annotations

from datetime import datetime

from producers.formatting import sql_literal, sql_ts

from .shared import (
    _incident_identifier,
    _incident_raw_scope_predicate,
    _incident_summary_count_expr,
    _incident_summary_count_if_expr,
)


def _incident_discovery_hourly_candidates_sql(
    summary_table: str,
    start: datetime,
    end: datetime,
    baseline_start: datetime,
    baseline_end: datetime,
    *,
    top_n: int = 50,
    min_requests: int = 100_000,
    summary_time_column: str = "reqTimeSec",
    summary_count_column: str = "count()",
    summary_host_column: str = "reqHost",
    summary_asn_column: str = "asn",
    summary_country_column: str = "country",
    summary_user_agent_category_column: str = "userAgentCategory",
    summary_bot_column: str = "isBotTraffic",
    summary_status_column: str = "statusCode",
    summary_cache_column: str = "cacheStatus",
    summary_path_pattern_column: str = "reqPathPatternCoarse",
    summary_cohort_column: str = "trafficCohort",
    origin_sum_column: str = (
        "sumIf(Origin_TurnAroundTime, and(isNotNull(Origin_TurnAroundTime), "
        "greaterOrEquals(Origin_TurnAroundTime, 0)))"
    ),
    origin_count_column: str = (
        "countIf(and(isNotNull(Origin_TurnAroundTime), "
        "greaterOrEquals(Origin_TurnAroundTime, 0)))"
    ),
) -> str:
    """Rank host-hour candidate incidents from Expedia-style summary data.

    The query intentionally scans only summary rows. It compares current
    host-hours with baseline rows for the same host and hour-of-week, then
    requires at least two independent evidence families before ranking.
    """
    time_col = _incident_identifier(summary_time_column)
    host_col = _incident_identifier(summary_host_column)
    ua_col = _incident_identifier(summary_user_agent_category_column)
    bot_col = _incident_identifier(summary_bot_column)
    status_col = _incident_identifier(summary_status_column)
    cache_col = _incident_identifier(summary_cache_column)
    cohort_col = _incident_identifier(summary_cohort_column)
    requests_expr = _incident_summary_count_expr(summary_count_column)
    count_if = lambda condition: _incident_summary_count_if_expr(  # noqa: E731
        condition, summary_count_column
    )
    origin_sum_expr = f"sumIfMerge({_incident_identifier(origin_sum_column)})"
    origin_count_expr = f"countIfMerge({_incident_identifier(origin_count_column)})"
    bot_condition = (
        f"{bot_col} = 1 OR {cohort_col} IN ('Bot', 'AI') OR "
        f"{ua_col} IN ('Bot', 'AI', 'Crawler', 'Automation', 'Script')"
    )
    return f"""
WITH
host_hour AS (
  SELECT
    if({time_col} >= toDateTime('{sql_ts(start)}', 'UTC'), 'current', 'baseline') AS period,
    toStartOfHour({time_col}) AS hour,
    ((toDayOfWeek({time_col}) - 1) * 24 + toHour({time_col})) AS hour_of_week,
    toString({host_col}) AS host,
    {requests_expr} AS requests,
    {count_if(bot_condition)} AS bot_like_requests,
    {count_if(f"{status_col} = 429")} AS req_429,
    {count_if(f"{status_col} BETWEEN 500 AND 599")} AS req_5xx,
    {count_if(f"{cache_col} = 0")} AS cache_miss_requests,
    {origin_sum_expr} AS origin_turnaround_ms,
    {origin_count_expr} AS origin_turnaround_count
  FROM {summary_table}
  WHERE {time_col} >= toDateTime('{sql_ts(baseline_start)}', 'UTC')
    AND {time_col} < toDateTime('{sql_ts(end)}', 'UTC')
    AND ({time_col} < toDateTime('{sql_ts(baseline_end)}', 'UTC')
         OR {time_col} >= toDateTime('{sql_ts(start)}', 'UTC'))
  GROUP BY period, hour, hour_of_week, host
),
baseline_hour_of_week AS (
  SELECT
    host,
    hour_of_week,
    avg(requests) AS baseline_requests,
    avg(bot_like_requests / nullIf(requests, 0)) AS baseline_bot_share,
    avg(req_429 / nullIf(requests, 0)) AS baseline_429_rate,
    avg(req_5xx / nullIf(requests, 0)) AS baseline_5xx_rate,
    avg(cache_miss_requests / nullIf(requests, 0)) AS baseline_cache_miss_rate,
    avg(origin_turnaround_ms / nullIf(origin_turnaround_count, 0)) AS baseline_origin_ms,
    count() AS baseline_hours
  FROM host_hour
  WHERE period = 'baseline'
  GROUP BY host, hour_of_week
),
baseline_host AS (
  SELECT
    host,
    avg(requests) AS baseline_requests,
    avg(bot_like_requests / nullIf(requests, 0)) AS baseline_bot_share,
    avg(req_429 / nullIf(requests, 0)) AS baseline_429_rate,
    avg(req_5xx / nullIf(requests, 0)) AS baseline_5xx_rate,
    avg(cache_miss_requests / nullIf(requests, 0)) AS baseline_cache_miss_rate,
    avg(origin_turnaround_ms / nullIf(origin_turnaround_count, 0)) AS baseline_origin_ms,
    count() AS baseline_hours
  FROM host_hour
  WHERE period = 'baseline'
  GROUP BY host
),
baseline AS (
  SELECT
    keys.host,
    keys.hour_of_week,
    coalesce(how.baseline_requests, host.baseline_requests) AS baseline_requests,
    coalesce(how.baseline_bot_share, host.baseline_bot_share) AS baseline_bot_share,
    coalesce(how.baseline_429_rate, host.baseline_429_rate) AS baseline_429_rate,
    coalesce(how.baseline_5xx_rate, host.baseline_5xx_rate) AS baseline_5xx_rate,
    coalesce(how.baseline_cache_miss_rate, host.baseline_cache_miss_rate) AS baseline_cache_miss_rate,
    coalesce(how.baseline_origin_ms, host.baseline_origin_ms) AS baseline_origin_ms,
    coalesce(how.baseline_hours, host.baseline_hours, 0) AS baseline_hours,
    if(how.baseline_hours > 0, 'same_host_hour_of_week', 'same_host') AS baseline_method
  FROM (
    SELECT DISTINCT host, hour_of_week
    FROM host_hour
    WHERE period = 'current'
  ) AS keys
  LEFT JOIN baseline_hour_of_week AS how
    ON keys.host = how.host AND keys.hour_of_week = how.hour_of_week
  LEFT JOIN baseline_host AS host
    ON keys.host = host.host
)
SELECT
  c.hour,
  c.host,
  c.requests,
  c.bot_like_requests,
  round(c.bot_like_requests / nullIf(c.requests, 0), 4) AS bot_share,
  c.req_429,
  round(c.req_429 / nullIf(c.requests, 0), 4) AS rate_429,
  c.req_5xx,
  round(c.req_5xx / nullIf(c.requests, 0), 4) AS rate_5xx,
  c.cache_miss_requests,
  round(c.cache_miss_requests / nullIf(c.requests, 0), 4) AS cache_miss_rate,
  round(c.origin_turnaround_ms / nullIf(c.origin_turnaround_count, 0), 2) AS origin_ms,
  b.baseline_requests,
  b.baseline_bot_share,
  b.baseline_429_rate,
  b.baseline_5xx_rate,
  b.baseline_cache_miss_rate,
  b.baseline_origin_ms,
  b.baseline_hours,
  b.baseline_method,
  if(b.baseline_requests > 0, c.requests / b.baseline_requests, 0) AS request_ratio,
  if(b.baseline_bot_share > 0,
     (c.bot_like_requests / nullIf(c.requests, 0)) / b.baseline_bot_share,
     if(c.bot_like_requests > 0, 99, 0)) AS bot_share_ratio,
  if(b.baseline_429_rate > 0,
     (c.req_429 / nullIf(c.requests, 0)) / b.baseline_429_rate,
     if(c.req_429 > 0, 99, 0)) AS rate_429_ratio,
  if(b.baseline_5xx_rate > 0,
     (c.req_5xx / nullIf(c.requests, 0)) / b.baseline_5xx_rate,
     if(c.req_5xx > 0, 99, 0)) AS rate_5xx_ratio,
  if(b.baseline_cache_miss_rate > 0,
     (c.cache_miss_requests / nullIf(c.requests, 0)) / b.baseline_cache_miss_rate,
     if(c.cache_miss_requests > 0, 99, 0)) AS cache_miss_ratio,
  if(b.baseline_origin_ms > 0,
     (c.origin_turnaround_ms / nullIf(c.origin_turnaround_count, 0)) / b.baseline_origin_ms,
     0) AS origin_latency_ratio,
  (
    if(c.requests >= {int(min_requests)} AND request_ratio >= 3, 1, 0) +
    if(c.requests >= {int(min_requests)} AND bot_share_ratio >= 3
       AND c.bot_like_requests / nullIf(c.requests, 0) >= 0.05, 1, 0) +
    if(c.requests >= {int(min_requests)} AND (rate_429_ratio >= 3 OR rate_5xx_ratio >= 3)
       AND (c.req_429 + c.req_5xx) / nullIf(c.requests, 0) >= 0.01, 1, 0) +
    if(c.requests >= {int(min_requests)} AND cache_miss_ratio >= 2
       AND c.cache_miss_requests / nullIf(c.requests, 0) >= 0.10, 1, 0) +
    if(c.requests >= {int(min_requests)} AND origin_latency_ratio >= 2, 1, 0)
  ) AS evidence_families,
  round(
    least(request_ratio, 20) * 10 +
    least(bot_share_ratio, 20) * 8 +
    least(greatest(rate_429_ratio, rate_5xx_ratio), 20) * 8 +
    least(cache_miss_ratio, 20) * 5 +
    least(origin_latency_ratio, 20) * 5 +
    evidence_families * 20,
    2
  ) AS candidate_score
FROM host_hour c
INNER JOIN baseline b
  ON c.host = b.host AND c.hour_of_week = b.hour_of_week
WHERE c.period = 'current'
  AND c.requests >= {int(min_requests)}
  AND evidence_families >= 2
ORDER BY candidate_score DESC, c.requests DESC
LIMIT {int(top_n)}
""".strip()


def _incident_discovery_minute_tightening_sql(
    summary_table: str,
    start: datetime,
    end: datetime,
    host: str,
    *,
    summary_time_column: str = "reqTimeSec",
    summary_count_column: str = "count()",
    summary_host_column: str = "reqHost",
    summary_status_column: str = "statusCode",
    summary_cache_column: str = "cacheStatus",
    summary_bot_column: str = "isBotTraffic",
    summary_cohort_column: str = "trafficCohort",
) -> str:
    """Return minute-grain metrics for one host-scoped candidate window."""
    time_col = _incident_identifier(summary_time_column)
    host_col = _incident_identifier(summary_host_column)
    status_col = _incident_identifier(summary_status_column)
    cache_col = _incident_identifier(summary_cache_column)
    bot_col = _incident_identifier(summary_bot_column)
    cohort_col = _incident_identifier(summary_cohort_column)
    requests_expr = _incident_summary_count_expr(summary_count_column)
    count_if = lambda condition: _incident_summary_count_if_expr(  # noqa: E731
        condition, summary_count_column
    )
    return f"""
SELECT
  toStartOfMinute({time_col}) AS minute,
  {requests_expr} AS requests,
  {count_if(f"{bot_col} = 1 OR {cohort_col} IN ('Bot', 'AI')")} AS bot_like_requests,
  {count_if(f"{status_col} = 429")} AS req_429,
  {count_if(f"{status_col} BETWEEN 500 AND 599")} AS req_5xx,
  {count_if(f"{cache_col} = 0")} AS cache_miss_requests
FROM {summary_table}
WHERE {time_col} >= toDateTime('{sql_ts(start)}', 'UTC')
  AND {time_col} < toDateTime('{sql_ts(end)}', 'UTC')
  AND {host_col} = {sql_literal(host)}
GROUP BY minute
ORDER BY minute
""".strip()


def _incident_discovery_raw_drilldown_sql(
    start: datetime,
    end: datetime,
    host: str,
    *,
    top_n: int = 20,
    raw_time_column: str = "reqTimeSec",
    raw_host_column: str = "reqHost",
    raw_ip_column: str = "cliIP",
    raw_asn_column: str = "asn",
    raw_user_agent_column: str = "UA",
    raw_path_column: str = "reqPath",
    raw_query_column: str = "queryStr",
    raw_status_column: str = "statusCode",
    raw_cache_column: str = "cacheStatus",
    raw_bot_column: str = "isBotTraffic",
    raw_latency_column: str = "Origin_TurnAroundTime",
    raw_token_columns: tuple[str, ...] = ("botnet_id", "bot_category", "bot_type"),
) -> str:
    """Top actors and request shapes for one narrowed Expedia incident window."""
    time_col = _incident_identifier(raw_time_column)
    host_col = _incident_identifier(raw_host_column)
    status_col = _incident_identifier(raw_status_column)
    cache_col = _incident_identifier(raw_cache_column)
    bot_col = _incident_identifier(raw_bot_column)
    latency_col = _incident_identifier(raw_latency_column)
    token_select = ", ".join(
        f"any({_incident_identifier(column)}) AS sample_{column}"
        for column in raw_token_columns
    )
    token_projection = f",\n  {token_select}" if token_select else ""
    return f"""
SELECT * FROM (
SELECT * FROM (
  SELECT
    'client_ip' AS dimension,
    toString({_incident_identifier(raw_ip_column)}) AS value,
    count() AS requests,
    countIf({status_col} = 429) AS req_429,
    countIf({status_col} BETWEEN 500 AND 599) AS req_5xx,
    countIf({cache_col} = 0) AS cache_miss_requests,
    countIf({bot_col} = 1) AS bot_requests,
    avg({latency_col}) AS avg_origin_ms,
    min({time_col}) AS first_seen,
    max({time_col}) AS last_seen{token_projection}
  FROM akamai.logs
  WHERE {time_col} >= toDateTime('{sql_ts(start)}', 'UTC')
    AND {time_col} < toDateTime('{sql_ts(end)}', 'UTC')
    AND {host_col} = {sql_literal(host)}
  GROUP BY value
  ORDER BY requests DESC
  LIMIT {int(top_n)}
)
UNION ALL
SELECT * FROM (
  SELECT
    'client_asn' AS dimension,
    toString({_incident_identifier(raw_asn_column)}) AS value,
    count() AS requests,
    countIf({status_col} = 429) AS req_429,
    countIf({status_col} BETWEEN 500 AND 599) AS req_5xx,
    countIf({cache_col} = 0) AS cache_miss_requests,
    countIf({bot_col} = 1) AS bot_requests,
    avg({latency_col}) AS avg_origin_ms,
    min({time_col}) AS first_seen,
    max({time_col}) AS last_seen{token_projection}
  FROM akamai.logs
  WHERE {time_col} >= toDateTime('{sql_ts(start)}', 'UTC')
    AND {time_col} < toDateTime('{sql_ts(end)}', 'UTC')
    AND {host_col} = {sql_literal(host)}
  GROUP BY value
  ORDER BY requests DESC
  LIMIT {int(top_n)}
)
UNION ALL
SELECT * FROM (
  SELECT
    'user_agent' AS dimension,
    toString({_incident_identifier(raw_user_agent_column)}) AS value,
    count() AS requests,
    countIf({status_col} = 429) AS req_429,
    countIf({status_col} BETWEEN 500 AND 599) AS req_5xx,
    countIf({cache_col} = 0) AS cache_miss_requests,
    countIf({bot_col} = 1) AS bot_requests,
    avg({latency_col}) AS avg_origin_ms,
    min({time_col}) AS first_seen,
    max({time_col}) AS last_seen{token_projection}
  FROM akamai.logs
  WHERE {time_col} >= toDateTime('{sql_ts(start)}', 'UTC')
    AND {time_col} < toDateTime('{sql_ts(end)}', 'UTC')
    AND {host_col} = {sql_literal(host)}
  GROUP BY value
  ORDER BY requests DESC
  LIMIT {int(top_n)}
)
UNION ALL
SELECT * FROM (
  SELECT
    'request_path' AS dimension,
    toString({_incident_identifier(raw_path_column)}) AS value,
    count() AS requests,
    countIf({status_col} = 429) AS req_429,
    countIf({status_col} BETWEEN 500 AND 599) AS req_5xx,
    countIf({cache_col} = 0) AS cache_miss_requests,
    countIf({bot_col} = 1) AS bot_requests,
    avg({latency_col}) AS avg_origin_ms,
    min({time_col}) AS first_seen,
    max({time_col}) AS last_seen{token_projection}
  FROM akamai.logs
  WHERE {time_col} >= toDateTime('{sql_ts(start)}', 'UTC')
    AND {time_col} < toDateTime('{sql_ts(end)}', 'UTC')
    AND {host_col} = {sql_literal(host)}
  GROUP BY value
  ORDER BY requests DESC
  LIMIT {int(top_n)}
)
UNION ALL
SELECT * FROM (
  SELECT
    'query_string' AS dimension,
    toString({_incident_identifier(raw_query_column)}) AS value,
    count() AS requests,
    countIf({status_col} = 429) AS req_429,
    countIf({status_col} BETWEEN 500 AND 599) AS req_5xx,
    countIf({cache_col} = 0) AS cache_miss_requests,
    countIf({bot_col} = 1) AS bot_requests,
    avg({latency_col}) AS avg_origin_ms,
    min({time_col}) AS first_seen,
    max({time_col}) AS last_seen{token_projection}
  FROM akamai.logs
  WHERE {time_col} >= toDateTime('{sql_ts(start)}', 'UTC')
    AND {time_col} < toDateTime('{sql_ts(end)}', 'UTC')
    AND {host_col} = {sql_literal(host)}
    AND nullIf({_incident_identifier(raw_query_column)}, '') IS NOT NULL
  GROUP BY value
  ORDER BY requests DESC
  LIMIT {int(top_n)}
)
ORDER BY dimension, requests DESC
) AS drilldown
ORDER BY dimension, requests DESC
""".strip()
