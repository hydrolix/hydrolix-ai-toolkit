"""Window confirmation and volume timeseries SQL builders."""

from __future__ import annotations

from datetime import datetime

from producers.formatting import sql_ts

from .shared import (
    _incident_identifier,
    _incident_raw_scope_predicate,
    _incident_scope_predicate,
    _incident_summary_count_expr,
    _incident_summary_count_if_expr,
    _incident_summary_time_expr,
)

def _incident_window_confirmation_sql(
    summary_table: str,
    siem_table: str | None,
    start: datetime,
    end: datetime,
    baseline_start: datetime,
    baseline_end: datetime,
    host: str | None,
    asn: str | None,
    path_pattern: str | None,
    raw_drilldown_available: bool = False,
    raw_path_column: str = "request_path",
    summary_time_column: str = "reqTimeSec",
    summary_count_column: str = "count()",
    summary_status_column: str = "statusCode",
    summary_cohort_column: str = "trafficCohort",
    summary_path_pattern_column: str = "requestPathPattern",
) -> str:
    summary_time = _incident_summary_time_expr(summary_time_column)
    summary_count = _incident_summary_count_expr(summary_count_column)
    summary_count_if = lambda condition: _incident_summary_count_if_expr(  # noqa: E731
        condition, summary_count_column
    )
    summary_status = _incident_identifier(summary_status_column)
    summary_cohort = _incident_identifier(summary_cohort_column)
    scope = _incident_scope_predicate(
        host,
        asn,
        path_pattern,
        path_pattern_column=summary_path_pattern_column,
    )
    siem_join = ""
    if siem_table:
        # Two passes via UNION ALL — one for summary measures, one for
        # SIEM blocked share. Period is "current" or "baseline" so the
        # orchestrator can split locally.
        siem_join = f"""
UNION ALL
SELECT
  'siem' AS source,
  if(timestamp >= toDateTime('{sql_ts(start)}', 'UTC'), 'current', 'baseline') AS period,
  countMerge(`count()`) AS requests,
  toUInt64(0) AS bot_like_requests,
  toUInt64(0) AS req_429,
  toUInt64(0) AS req_5xx,
  countIfMerge(`countIf(equals(actionClass, 'deny'))`) AS blocked,
  toUInt64(0) AS denied_requests,
  toUInt64(0) AS monitored_requests
FROM {siem_table}
WHERE timestamp >= toDateTime('{sql_ts(baseline_start)}', 'UTC')
  AND timestamp < toDateTime('{sql_ts(end)}', 'UTC')
  AND (timestamp < toDateTime('{sql_ts(baseline_end)}', 'UTC')
       OR timestamp >= toDateTime('{sql_ts(start)}', 'UTC'))
  AND ({scope})
GROUP BY period
""".rstrip()
    raw_join = ""
    if raw_drilldown_available:
        raw_scope = _incident_raw_scope_predicate(
            host, asn, path_pattern, path_column=raw_path_column
        )
        # Third pass against raw akamai.logs to derive the edge-response
        # (action_applied) deny + monitor counts when a separate SIEM
        # summary table isn't present. For canonical-schema clusters the
        # Akamai DS2 stream carries action_applied / denied / denyRule
        # inline, so the edge response is visible directly from the raw
        # access log.
        raw_join = f"""
UNION ALL
SELECT
  'raw' AS source,
  if(reqTimeSec >= toDateTime('{sql_ts(start)}', 'UTC'), 'current', 'baseline') AS period,
  count() AS requests,
  countIf(trafficCohort IN ('Bot', 'AI')) AS bot_like_requests,
  countIf(statusCode = 429) AS req_429,
  countIf(statusCode BETWEEN 500 AND 599) AS req_5xx,
  toUInt64(0) AS blocked,
  countIf(action_applied = 'Deny') AS denied_requests,
  countIf(action_applied = 'Monitor') AS monitored_requests
FROM akamai.logs
WHERE reqTimeSec >= toDateTime('{sql_ts(baseline_start)}', 'UTC')
  AND reqTimeSec < toDateTime('{sql_ts(end)}', 'UTC')
  AND (reqTimeSec < toDateTime('{sql_ts(baseline_end)}', 'UTC')
       OR reqTimeSec >= toDateTime('{sql_ts(start)}', 'UTC'))
  AND ({raw_scope})
GROUP BY period
""".rstrip()
    return f"""
SELECT
  'summary' AS source,
  if({summary_time} >= toDateTime('{sql_ts(start)}', 'UTC'), 'current', 'baseline') AS period,
  {summary_count} AS requests,
  {summary_count_if(f"{summary_cohort} IN ('Bot', 'AI')")} AS bot_like_requests,
  {summary_count_if(f"{summary_status} = 429")} AS req_429,
  {summary_count_if(f"{summary_status} BETWEEN 500 AND 599")} AS req_5xx,
  toUInt64(0) AS blocked,
  toUInt64(0) AS denied_requests,
  toUInt64(0) AS monitored_requests
FROM {summary_table}
WHERE {summary_time} >= toDateTime('{sql_ts(baseline_start)}', 'UTC')
  AND {summary_time} < toDateTime('{sql_ts(end)}', 'UTC')
  AND ({summary_time} < toDateTime('{sql_ts(baseline_end)}', 'UTC')
       OR {summary_time} >= toDateTime('{sql_ts(start)}', 'UTC'))
  AND ({scope})
GROUP BY period
{siem_join}
{raw_join}
""".strip()
def _incident_volume_timeseries_sql(
    summary_table: str,
    granularity: str,
    start: datetime,
    end: datetime,
    baseline_start: datetime,
    baseline_end: datetime,
    host: str | None,
    asn: str | None,
    path_pattern: str | None,
    summary_time_column: str = "reqTimeSec",
    summary_count_column: str = "count()",
    summary_status_column: str = "statusCode",
    summary_cohort_column: str = "trafficCohort",
    summary_path_pattern_column: str = "requestPathPattern",
) -> str:
    """Per-bucket volume + 429 + bot-classified counts for current + baseline.

    Populates the ``volume_timeseries.series`` field on
    ``bot_incident_scope.v1`` so the renderer can mechanically pick the
    most relevant metric to chart based on which spike flag dominated.

    Bucket function is chosen from the report's granularity. The query
    runs against the same summary table the window-confirmation query
    uses (``bi_summary_<granularity>``), so it's cheap — one extra
    grouped scan over the same window the orchestrator already touched.
    """
    summary_time = _incident_summary_time_expr(summary_time_column)
    summary_count = _incident_summary_count_expr(summary_count_column)
    summary_count_if = lambda condition: _incident_summary_count_if_expr(  # noqa: E731
        condition, summary_count_column
    )
    summary_status = _incident_identifier(summary_status_column)
    summary_cohort = _incident_identifier(summary_cohort_column)
    scope = _incident_scope_predicate(
        host,
        asn,
        path_pattern,
        path_pattern_column=summary_path_pattern_column,
    )
    bucket_fn = {
        "minute": "toStartOfMinute",
        "hour": "toStartOfHour",
        "day": "toStartOfDay",
    }.get(granularity, "toStartOfMinute")
    return f"""
SELECT
  if({summary_time} >= toDateTime('{sql_ts(start)}', 'UTC'), 'current', 'baseline') AS period,
  {bucket_fn}({summary_time}) AS bucket,
  {summary_count} AS requests,
  {summary_count_if(f"{summary_status} = 429")} AS req_429,
  {summary_count_if(f"{summary_cohort} IN ('Bot', 'AI')")} AS bot_like_requests
FROM {summary_table}
WHERE {summary_time} >= toDateTime('{sql_ts(baseline_start)}', 'UTC')
  AND {summary_time} < toDateTime('{sql_ts(end)}', 'UTC')
  AND ({summary_time} < toDateTime('{sql_ts(baseline_end)}', 'UTC')
       OR {summary_time} >= toDateTime('{sql_ts(start)}', 'UTC'))
  AND ({scope})
GROUP BY period, bucket
ORDER BY period, bucket
""".strip()
