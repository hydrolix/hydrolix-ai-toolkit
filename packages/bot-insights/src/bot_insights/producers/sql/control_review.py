"""SQL builders for the ``control_review`` report.

Two builders, both parameterized on ``control_source``:
  - ``posture`` routes against ``bi_summary_<granularity>``: cohort,
    cache, 429, and 5xx aggregates only.
  - ``siem-policy`` (default) routes against
    ``bi_siem_policy_summary_<granularity>``: SIEM block / auth-fail /
    avg-bot-score / unique-client-IP aggregates, with an optional
    ``policyId`` filter to scope to a specific control.

``control_review_sql`` returns scalar per-period totals. The companion
``control_review_timeseries_sql`` adds a time bucket so the
renderer can chart before/after side by side.
"""

from __future__ import annotations

from datetime import datetime

from producers.formatting import bucket_expr, choose_granularity, sql_literal, sql_ts


def control_review_sql(
    database: str,
    start: datetime,
    end: datetime,
    baseline_start: datetime,
    policy_id: str | None = None,
    control_source: str = "siem-policy",
) -> str:
    granularity = choose_granularity(start, end)
    if control_source == "posture":
        table = f"{database}.bi_summary_{granularity}"
        return f"""
WITH
  toDateTime('{sql_ts(start)}', 'UTC') AS after_start,
  toDateTime('{sql_ts(end)}', 'UTC') AS after_end,
  toDateTime('{sql_ts(baseline_start)}', 'UTC') AS before_start
SELECT
  if(reqTimeSec >= after_start, 'after', 'before') AS period,
  countMerge(`count()`) AS requests,
  countMergeIf(`count()`, trafficCohort IN ('Bot', 'AI')) AS bot_like_requests,
  countMergeIf(`count()`, trafficCohort = 'AI') AS ai_requests,
  countMergeIf(`count()`, cacheStatus = false) AS cache_misses,
  countMergeIf(`count()`, statusCode = 429) AS rate_limited_requests,
  countMergeIf(`count()`, statusCode >= 500) AS error_5xx_requests
FROM {table}
WHERE reqTimeSec >= before_start
  AND reqTimeSec < after_end
GROUP BY period
ORDER BY period
""".strip()

    table = f"{database}.bi_siem_policy_summary_{granularity}"
    policy_filter = f"\n  AND policyId = {sql_literal(policy_id)}" if policy_id else ""
    return f"""
WITH
  toDateTime('{sql_ts(start)}', 'UTC') AS after_start,
  toDateTime('{sql_ts(end)}', 'UTC') AS after_end,
  toDateTime('{sql_ts(baseline_start)}', 'UTC') AS before_start
SELECT
  if(timestamp >= after_start, 'after', 'before') AS period,
  countMerge(`count()`) AS requests,
  countIfMerge(`countIf(equals(actionClass, 'deny'))`) AS siem_blocked_requests,
  countIfMerge(`countIf(equals(authOutcome, 'fail'))`) AS siem_auth_fail_requests,
  avgIfMerge(`avgIf(botScore, greater(botScore, 0))`) AS avg_bot_score,
  uniqMerge(`uniq(clientIP)`) AS unique_client_ips
FROM {table}
WHERE timestamp >= before_start
  AND timestamp < after_end{policy_filter}
GROUP BY period
ORDER BY period
""".strip()


def control_review_timeseries_sql(
    database: str,
    start: datetime,
    end: datetime,
    baseline_start: datetime,
    policy_id: str | None = None,
    control_source: str = "siem-policy",
) -> str:
    granularity = choose_granularity(start, end)
    if control_source == "posture":
        table = f"{database}.bi_summary_{granularity}"
        bucket = bucket_expr("reqTimeSec", granularity)
        return f"""
WITH
  toDateTime('{sql_ts(start)}', 'UTC') AS after_start,
  toDateTime('{sql_ts(end)}', 'UTC') AS after_end,
  toDateTime('{sql_ts(baseline_start)}', 'UTC') AS before_start
SELECT
  if(reqTimeSec >= after_start, 'after', 'before') AS period,
  {bucket} AS bucket,
  countMerge(`count()`) AS requests,
  countMergeIf(`count()`, trafficCohort IN ('Bot', 'AI')) AS bot_like_requests,
  countMergeIf(`count()`, trafficCohort = 'AI') AS ai_requests,
  countMergeIf(`count()`, cacheStatus = false) AS cache_misses,
  countMergeIf(`count()`, statusCode = 429) AS rate_limited_requests,
  countMergeIf(`count()`, statusCode >= 500) AS error_5xx_requests
FROM {table}
WHERE reqTimeSec >= before_start
  AND reqTimeSec < after_end
GROUP BY period, bucket
ORDER BY period, bucket
""".strip()

    table = f"{database}.bi_siem_policy_summary_{granularity}"
    bucket = bucket_expr("timestamp", granularity)
    policy_filter = f"\n  AND policyId = {sql_literal(policy_id)}" if policy_id else ""
    return f"""
WITH
  toDateTime('{sql_ts(start)}', 'UTC') AS after_start,
  toDateTime('{sql_ts(end)}', 'UTC') AS after_end,
  toDateTime('{sql_ts(baseline_start)}', 'UTC') AS before_start
SELECT
  if(timestamp >= after_start, 'after', 'before') AS period,
  {bucket} AS bucket,
  countMerge(`count()`) AS requests,
  countIfMerge(`countIf(equals(actionClass, 'deny'))`) AS siem_blocked_requests,
  countIfMerge(`countIf(equals(authOutcome, 'fail'))`) AS siem_auth_fail_requests,
  avgIfMerge(`avgIf(botScore, greater(botScore, 0))`) AS avg_bot_score,
  uniqMerge(`uniq(clientIP)`) AS unique_client_ips
FROM {table}
WHERE timestamp >= before_start
  AND timestamp < after_end{policy_filter}
GROUP BY period, bucket
ORDER BY period, bucket
""".strip()
