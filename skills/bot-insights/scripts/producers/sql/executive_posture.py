"""SQL builder for the ``executive_posture`` report.

Single-statement fleet snapshot: current-window vs. baseline-window
aggregates of requests, bot-like requests, AI requests, cache misses,
429s, and 5xx errors. The summary-table granularity
(``bi_summary_<granularity>``) is picked from the window length.
"""

from __future__ import annotations

from datetime import datetime

from producers.formatting import choose_granularity, sql_ts


def executive_posture_sql(
    database: str, start: datetime, end: datetime, baseline_start: datetime
) -> str:
    granularity = choose_granularity(start, end)
    table = f"{database}.bi_summary_{granularity}"
    return f"""
WITH
  toDateTime('{sql_ts(start)}', 'UTC') AS current_start,
  toDateTime('{sql_ts(end)}', 'UTC') AS current_end,
  toDateTime('{sql_ts(baseline_start)}', 'UTC') AS baseline_start
SELECT
  if(reqTimeSec >= current_start, 'current', 'baseline') AS period,
  countMerge(`count()`) AS requests,
  countMergeIf(`count()`, trafficCohort IN ('Bot', 'AI')) AS bot_like_requests,
  countMergeIf(`count()`, trafficCohort = 'AI') AS ai_requests,
  countMergeIf(`count()`, cacheStatus = false) AS cache_misses,
  countMergeIf(`count()`, statusCode = 429) AS rate_limited_requests,
  countMergeIf(`count()`, statusCode >= 500) AS error_5xx_requests
FROM {table}
WHERE reqTimeSec >= baseline_start
  AND reqTimeSec < current_end
GROUP BY period
ORDER BY period
""".strip()
