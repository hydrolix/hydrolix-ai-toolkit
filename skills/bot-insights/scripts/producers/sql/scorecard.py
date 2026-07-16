"""SQL builders for the scorecard-family reports.

Four entity-keyed scorecards (``scorecard_brief``, ``soc_triage``,
``crawler_governance``, ``edge_ops_impact``) plus the optional
``cache_origin_path_sql`` path-grain drill-down used by
``edge_ops_impact``. The entity-type → ClickHouse-expression
mappings live alongside the builders so the orchestrator can both
emit SQL and validate ``--entity-type`` against the same table.
"""

from __future__ import annotations

from datetime import datetime

from producers.formatting import choose_granularity, sql_literal, sql_ts


SCORECARD_ENTITY_SQL = {
    "client_asn": "toString(asn)",
    "request_path_norm": "toString(requestPathPattern)",
    "request_host": "toString(reqHost)",
    "bot_class": "toString(userAgentCategory)",
    "ai_category": "toString(aiCategory)",
}

SOC_ENTITY_SQL = {
    "client_asn": "toString(asn)",
    "request_host": "toString(reqHost)",
    "bot_class": "toString(userAgentCategory)",
    "ai_category": "toString(aiCategory)",
}

CRAWLER_ENTITY_SQL = {
    "ai_category": "toString(aiCategory)",
    "bot_class": "toString(userAgentCategory)",
    "request_host": "toString(reqHost)",
}

CRAWLER_POPULATION_BY_ENTITY = {
    "ai_category": "ai_crawler",
    "bot_class": "crawler",
    "request_host": "crawler",
}

EDGE_OPS_ENTITY_SQL = {
    "client_asn": "toString(asn)",
    "request_host": "toString(reqHost)",
    "bot_class": "toString(userAgentCategory)",
}


def scorecard_sql(
    database: str,
    start: datetime,
    end: datetime,
    baseline_start: datetime,
    entity_type: str,
    producer_limit: int,
) -> str:
    granularity = choose_granularity(start, end)
    table = f"{database}.bi_summary_{granularity}"
    entity_expr = SCORECARD_ENTITY_SQL[entity_type]
    limit_clause = f"\nLIMIT {producer_limit}" if producer_limit > 0 else ""
    return f"""
WITH
  toDateTime('{sql_ts(start)}', 'UTC') AS current_start,
  toDateTime('{sql_ts(end)}', 'UTC') AS current_end,
  toDateTime('{sql_ts(baseline_start)}', 'UTC') AS baseline_start
SELECT
  {entity_expr} AS {entity_type},
  countMergeIf(`count()`, reqTimeSec >= current_start) AS current_requests,
  countMergeIf(`count()`, reqTimeSec < current_start) AS baseline_requests,
  if(current_requests > 0, countMergeIf(`count()`, reqTimeSec >= current_start AND trafficCohort IN ('Bot', 'AI')) / current_requests * 100, 0) AS current_bot_share_pct,
  if(baseline_requests > 0, countMergeIf(`count()`, reqTimeSec < current_start AND trafficCohort IN ('Bot', 'AI')) / baseline_requests * 100, 0) AS baseline_bot_share_pct,
  if(current_requests > 0, countMergeIf(`count()`, reqTimeSec >= current_start AND cacheStatus = false) / current_requests * 100, 0) AS current_cache_miss_pct,
  if(baseline_requests > 0, countMergeIf(`count()`, reqTimeSec < current_start AND cacheStatus = false) / baseline_requests * 100, 0) AS baseline_cache_miss_pct,
  if(current_requests > 0, countMergeIf(`count()`, reqTimeSec >= current_start AND statusCode = 429) / current_requests * 100, 0) AS current_rate_429_pct,
  if(baseline_requests > 0, countMergeIf(`count()`, reqTimeSec < current_start AND statusCode = 429) / baseline_requests * 100, 0) AS baseline_rate_429_pct,
  if(current_requests > 0, countMergeIf(`count()`, reqTimeSec >= current_start AND statusCode >= 500) / current_requests * 100, 0) AS current_rate_5xx_pct,
  if(baseline_requests > 0, countMergeIf(`count()`, reqTimeSec < current_start AND statusCode >= 500) / baseline_requests * 100, 0) AS baseline_rate_5xx_pct
FROM {table}
WHERE reqTimeSec >= baseline_start
  AND reqTimeSec < current_end
  AND {entity_expr} != ''
GROUP BY {entity_type}
ORDER BY current_requests DESC
{limit_clause}
""".strip()


def scorecard_soc_sql(
    database: str,
    start: datetime,
    end: datetime,
    baseline_start: datetime,
    entity_type: str,
    producer_limit: int,
) -> str:
    granularity = choose_granularity(start, end)
    table = f"{database}.bi_siem_policy_summary_{granularity}"
    if entity_type not in SOC_ENTITY_SQL:
        raise SystemExit(
            "--entity-type "
            + entity_type
            + " is not supported for soc_triage; use one of "
            + ", ".join(sorted(SOC_ENTITY_SQL))
        )
    entity_expr = SOC_ENTITY_SQL[entity_type]
    limit_clause = f"\nLIMIT {producer_limit}" if producer_limit > 0 else ""
    return f"""
WITH
  toDateTime('{sql_ts(start)}', 'UTC') AS current_start,
  toDateTime('{sql_ts(end)}', 'UTC') AS current_end,
  toDateTime('{sql_ts(baseline_start)}', 'UTC') AS baseline_start
SELECT
  {entity_expr} AS {entity_type},
  countMergeIf(`count()`, timestamp >= current_start AND timestamp < current_end) AS current_requests,
  countMergeIf(`count()`, timestamp >= baseline_start AND timestamp < current_start) AS baseline_requests,
  countIfMergeIf(
    `countIf(equals(actionClass, 'deny'))`,
    timestamp >= current_start AND timestamp < current_end
  ) AS siem_blocked_requests,
  countIfMergeIf(
    `countIf(equals(authOutcome, 'fail'))`,
    timestamp >= current_start AND timestamp < current_end
  ) AS siem_auth_fail_requests,
  avgIfMergeIf(
    `avgIf(botScore, greater(botScore, 0))`,
    timestamp >= current_start AND timestamp < current_end
  ) AS current_avg_bot_score,
  uniqMergeIf(`uniq(clientIP)`, timestamp >= current_start AND timestamp < current_end) AS current_unique_client_ips
FROM {table}
WHERE timestamp >= baseline_start
  AND timestamp < current_end
  AND {entity_expr} != ''
GROUP BY {entity_type}
HAVING current_requests > 0 OR siem_blocked_requests > 0 OR siem_auth_fail_requests > 0
ORDER BY siem_blocked_requests DESC, siem_auth_fail_requests DESC, current_requests DESC{limit_clause}
""".strip()


def scorecard_crawler_sql(
    database: str,
    start: datetime,
    end: datetime,
    baseline_start: datetime,
    entity_type: str,
    producer_limit: int,
) -> str:
    granularity = choose_granularity(start, end)
    table = f"{database}.bi_summary_{granularity}"
    if entity_type not in CRAWLER_ENTITY_SQL:
        raise SystemExit(
            "--entity-type "
            + entity_type
            + " is not supported for crawler_governance; use one of "
            + ", ".join(sorted(CRAWLER_ENTITY_SQL))
        )
    entity_expr = CRAWLER_ENTITY_SQL[entity_type]
    limit_clause = f"\nLIMIT {producer_limit}" if producer_limit > 0 else ""
    return f"""
WITH
  toDateTime('{sql_ts(start)}', 'UTC') AS current_start,
  toDateTime('{sql_ts(end)}', 'UTC') AS current_end,
  toDateTime('{sql_ts(baseline_start)}', 'UTC') AS baseline_start
SELECT
  {entity_expr} AS {entity_type},
  countMergeIf(`count()`, reqTimeSec >= current_start) AS current_requests,
  countMergeIf(`count()`, reqTimeSec < current_start) AS baseline_requests,
  if(current_requests > 0, countMergeIf(`count()`, reqTimeSec >= current_start AND statusCode = 429) / current_requests * 100, 0) AS current_rate_429_pct,
  if(baseline_requests > 0, countMergeIf(`count()`, reqTimeSec < current_start AND statusCode = 429) / baseline_requests * 100, 0) AS baseline_rate_429_pct,
  if(current_requests > 0, countMergeIf(`count()`, reqTimeSec >= current_start AND statusCode >= 500) / current_requests * 100, 0) AS current_rate_5xx_pct,
  if(baseline_requests > 0, countMergeIf(`count()`, reqTimeSec < current_start AND statusCode >= 500) / baseline_requests * 100, 0) AS baseline_rate_5xx_pct,
  countMergeIf(`count()`, reqTimeSec >= current_start AND trafficCohort = 'Bot' AND statusCode = 429) AS good_bot_429_requests,
  if(
    countMergeIf(`count()`, reqTimeSec >= current_start AND trafficCohort = 'Bot') > 0,
    countMergeIf(`count()`, reqTimeSec >= current_start AND trafficCohort = 'Bot' AND statusCode >= 400) /
      countMergeIf(`count()`, reqTimeSec >= current_start AND trafficCohort = 'Bot') * 100,
    0
  ) AS good_bot_error_rate_pct,
  toUInt64(0) AS policy_surface_failures,
  countMergeIf(`count()`, reqTimeSec >= current_start AND trafficCohort = 'AI') AS current_ai_crawler_requests,
  countMergeIf(`count()`, reqTimeSec < current_start AND trafficCohort = 'AI') AS baseline_ai_crawler_requests
FROM {table}
WHERE reqTimeSec >= baseline_start
  AND reqTimeSec < current_end
  AND {entity_expr} != ''
GROUP BY {entity_type}
ORDER BY current_requests DESC
{limit_clause}
""".strip()


def scorecard_edge_ops_sql(
    database: str,
    start: datetime,
    end: datetime,
    baseline_start: datetime,
    entity_type: str,
    producer_limit: int,
) -> str:
    granularity = choose_granularity(start, end)
    table = f"{database}.bi_summary_{granularity}"
    if entity_type not in EDGE_OPS_ENTITY_SQL:
        raise SystemExit(
            "--entity-type "
            + entity_type
            + " is not supported for edge_ops_impact; use one of "
            + ", ".join(sorted(EDGE_OPS_ENTITY_SQL))
        )
    entity_expr = EDGE_OPS_ENTITY_SQL[entity_type]
    limit_clause = f"\nLIMIT {producer_limit}" if producer_limit > 0 else ""
    return f"""
WITH
  toDateTime('{sql_ts(start)}', 'UTC') AS current_start,
  toDateTime('{sql_ts(end)}', 'UTC') AS current_end,
  toDateTime('{sql_ts(baseline_start)}', 'UTC') AS baseline_start,
  cluster_total AS (
    SELECT
      countMergeIf(`count()`, reqTimeSec >= current_start) * 1.0 AS cluster_requests
    FROM {table}
    WHERE reqTimeSec >= baseline_start
      AND reqTimeSec < current_end
      AND {entity_expr} != ''
  )
SELECT
  {entity_expr} AS {entity_type},
  countMergeIf(`count()`, reqTimeSec >= current_start) AS current_requests,
  countMergeIf(`count()`, reqTimeSec < current_start) AS baseline_requests,
  if(current_requests > 0, countMergeIf(`count()`, reqTimeSec >= current_start AND cacheStatus = false) / current_requests * 100, 0) AS current_cache_miss_pct,
  if(baseline_requests > 0, countMergeIf(`count()`, reqTimeSec < current_start AND cacheStatus = false) / baseline_requests * 100, 0) AS baseline_cache_miss_pct,
  null AS current_unique_qs,
  null AS baseline_unique_qs,
  null AS current_origin_p95_ms,
  null AS baseline_origin_p95_ms,
  if(
    (SELECT cluster_requests FROM cluster_total) > 0,
    current_requests / (SELECT cluster_requests FROM cluster_total) * 100,
    null
  ) AS origin_cost_contribution_pct
FROM {table}
WHERE reqTimeSec >= baseline_start
  AND reqTimeSec < current_end
  AND {entity_expr} != ''
GROUP BY {entity_type}
ORDER BY current_requests DESC
{limit_clause}
""".strip()


def cache_origin_path_sql(
    database: str,
    start: datetime,
    end: datetime,
    baseline_start: datetime,
    host_filter: str | None,
    producer_limit: int,
) -> str:
    granularity = choose_granularity(start, end)
    table = f"{database}.bot_agg_path_{granularity}"
    host_clause = f"\n  AND request_host = {sql_literal(host_filter)}" if host_filter else ""
    limit_clause = f"\nLIMIT {producer_limit}" if producer_limit > 0 else ""
    return f"""
WITH
  toDateTime('{sql_ts(start)}', 'UTC') AS current_start,
  toDateTime('{sql_ts(end)}', 'UTC') AS current_end,
  toDateTime('{sql_ts(baseline_start)}', 'UTC') AS baseline_start
SELECT
  request_host,
  request_path_norm,
  sumIf(cnt_all, timestamp >= current_start AND timestamp < current_end) AS current_requests,
  sumIf(cnt_all, timestamp >= baseline_start AND timestamp < current_start) AS baseline_requests,
  sumIf(cnt_cache_miss, timestamp >= current_start AND timestamp < current_end) AS current_cache_misses,
  sumIf(cnt_cache_miss, timestamp >= baseline_start AND timestamp < current_start) AS baseline_cache_misses,
  sumIf(uniq_qs, timestamp >= current_start AND timestamp < current_end) AS current_unique_query_strings,
  sumIf(uniq_qs, timestamp >= baseline_start AND timestamp < current_start) AS baseline_unique_query_strings,
  maxIf(p95_origin_ttfb, timestamp >= current_start AND timestamp < current_end) AS current_origin_p95_ms,
  maxIf(p95_origin_ttfb, timestamp >= baseline_start AND timestamp < current_start) AS baseline_origin_p95_ms
FROM {table}
WHERE timestamp >= baseline_start
  AND timestamp < current_end{host_clause}
GROUP BY request_host, request_path_norm
ORDER BY current_requests DESC
{limit_clause}
""".strip()
