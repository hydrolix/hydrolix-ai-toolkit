"""Dimension, status, and action SQL builders."""

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
    _incident_time_predicate,
)

def _incident_dimension_sql(
    summary_table: str,
    dimension: str,
    start: datetime,
    end: datetime,
    baseline_start: datetime,
    baseline_end: datetime,
    host: str | None,
    asn: str | None,
    path_pattern: str | None,
    top_n: int,
    summary_time_column: str = "reqTimeSec",
    summary_count_column: str = "count()",
    summary_path_pattern_column: str = "requestPathPattern",
) -> str:
    """Per-dimension top-N + delta against the equal-length baseline."""
    summary_time = _incident_summary_time_expr(summary_time_column)
    summary_count_if = lambda condition: _incident_summary_count_if_expr(  # noqa: E731
        condition, summary_count_column
    )
    scope = _incident_scope_predicate(
        host,
        asn,
        path_pattern,
        path_pattern_column=summary_path_pattern_column,
    )
    return f"""
SELECT
  toString({_incident_identifier(dimension)}) AS value,
  {summary_count_if(f"{summary_time} >= toDateTime('{sql_ts(start)}', 'UTC')")} AS current_requests,
  {summary_count_if(f"{summary_time} < toDateTime('{sql_ts(baseline_end)}', 'UTC')")} AS baseline_requests
FROM {summary_table}
WHERE {summary_time} >= toDateTime('{sql_ts(baseline_start)}', 'UTC')
  AND {summary_time} < toDateTime('{sql_ts(end)}', 'UTC')
  AND ({summary_time} < toDateTime('{sql_ts(baseline_end)}', 'UTC')
       OR {summary_time} >= toDateTime('{sql_ts(start)}', 'UTC'))
  AND ({scope})
GROUP BY value
HAVING current_requests > 0
ORDER BY current_requests DESC
LIMIT {int(top_n)}
""".strip()
def _incident_edge_action_mix_sql(
    start: datetime,
    end: datetime,
    baseline_start: datetime,
    baseline_end: datetime,
    host: str | None,
    asn: str | None,
    path_pattern: str | None,
    top_n: int,
    raw_path_column: str = "request_path",
) -> str:
    """Top-N ``action_applied`` values + delta vs the equal-length baseline.

    Mirrors the shape of :func:`_incident_dimension_sql` so the
    orchestrator can feed the rows through ``_incident_dimension_rows``
    for the same ``(value, share_pct, delta_vs_baseline_pct)``
    projection used by the other scope mix tables. Queries raw
    ``akamai.logs`` because ``action_applied`` is not carried on the
    summary table.
    """
    scope = _incident_raw_scope_predicate(
        host, asn, path_pattern, path_column=raw_path_column
    )
    return f"""
SELECT
  toString(action_applied) AS value,
  countIf(reqTimeSec >= toDateTime('{sql_ts(start)}', 'UTC')) AS current_requests,
  countIf(reqTimeSec < toDateTime('{sql_ts(baseline_end)}', 'UTC')) AS baseline_requests
FROM akamai.logs
WHERE reqTimeSec >= toDateTime('{sql_ts(baseline_start)}', 'UTC')
  AND reqTimeSec < toDateTime('{sql_ts(end)}', 'UTC')
  AND (reqTimeSec < toDateTime('{sql_ts(baseline_end)}', 'UTC')
       OR reqTimeSec >= toDateTime('{sql_ts(start)}', 'UTC'))
  AND ({scope})
GROUP BY action_applied
HAVING current_requests > 0
ORDER BY current_requests DESC
LIMIT {int(top_n)}
""".strip()
def _incident_bot_source_mix_sql(
    start: datetime,
    end: datetime,
    baseline_start: datetime,
    baseline_end: datetime,
    host: str | None,
    asn: str | None,
    path_pattern: str | None,
    top_n: int,
    raw_path_column: str = "request_path",
    available_columns: set[str] | None = None,
) -> str:
    """Top source bot-manager metadata cells from raw logs.

    Uses lowercase source columns (``bot_category``, ``bot_type``,
    ``botnet_id``) only. These are provenance signals, not normalized
    Bot Insights class proof.
    """
    scope = _incident_raw_scope_predicate(
        host, asn, path_pattern, path_column=raw_path_column
    )
    columns = available_columns or {"bot_category", "bot_type", "botnet_id"}
    category_expr = "toString(bot_category)" if "bot_category" in columns else "''"
    type_expr = "toString(bot_type)" if "bot_type" in columns else "''"
    botnet_expr = "toString(botnet_id)" if "botnet_id" in columns else "''"
    nonempty = " OR ".join(
        f"nullIf({expr}, '') IS NOT NULL"
        for expr in (category_expr, type_expr, botnet_expr)
        if expr != "''"
    ) or "0"
    return f"""
SELECT
  arrayStringConcat(
    arrayFilter(x -> x != '', [
      ifNull(nullIf({category_expr}, ''), ''),
      ifNull(nullIf({type_expr}, ''), ''),
      if(nullIf({botnet_expr}, '') IS NULL, '', concat('botnet ', {botnet_expr}))
    ]),
    ' / '
  ) AS value,
  countIf(reqTimeSec >= toDateTime('{sql_ts(start)}', 'UTC')) AS current_requests,
  countIf(reqTimeSec < toDateTime('{sql_ts(baseline_end)}', 'UTC')) AS baseline_requests
FROM akamai.logs
WHERE reqTimeSec >= toDateTime('{sql_ts(baseline_start)}', 'UTC')
  AND reqTimeSec < toDateTime('{sql_ts(end)}', 'UTC')
  AND (reqTimeSec < toDateTime('{sql_ts(baseline_end)}', 'UTC')
       OR reqTimeSec >= toDateTime('{sql_ts(start)}', 'UTC'))
  AND ({scope})
  AND ({nonempty})
GROUP BY value
HAVING current_requests > 0 AND value != ''
ORDER BY current_requests DESC
LIMIT {int(top_n)}
""".strip()
def _incident_proxy_classification_mix_sql(
    start: datetime,
    end: datetime,
    baseline_start: datetime,
    baseline_end: datetime,
    host: str | None,
    asn: str | None,
    path_pattern: str | None,
    top_n: int,
    raw_path_column: str = "request_path",
    available_columns: set[str] | None = None,
) -> str:
    """Top EPD proxy-classification categories/actions from raw logs."""
    scope = _incident_raw_scope_predicate(
        host, asn, path_pattern, path_column=raw_path_column
    )
    columns = available_columns or {"epd_ActionName", "epd_Category", "epd_Match"}
    action_expr = "toString(epd_ActionName)" if "epd_ActionName" in columns else "''"
    match_expr = "toString(epd_Match)" if "epd_Match" in columns else "''"
    return f"""
SELECT
  arrayStringConcat(
    arrayFilter(x -> x != '', [
      ifNull(nullIf(toString(epd_Category), ''), ''),
      ifNull(nullIf({action_expr}, ''), ''),
      ifNull(nullIf({match_expr}, ''), '')
    ]),
    ' / '
  ) AS value,
  countIf(reqTimeSec >= toDateTime('{sql_ts(start)}', 'UTC')) AS current_requests,
  countIf(reqTimeSec < toDateTime('{sql_ts(baseline_end)}', 'UTC')) AS baseline_requests
FROM akamai.logs
WHERE reqTimeSec >= toDateTime('{sql_ts(baseline_start)}', 'UTC')
  AND reqTimeSec < toDateTime('{sql_ts(end)}', 'UTC')
  AND (reqTimeSec < toDateTime('{sql_ts(baseline_end)}', 'UTC')
       OR reqTimeSec >= toDateTime('{sql_ts(start)}', 'UTC'))
  AND ({scope})
  AND nullIf(toString(epd_Category), '') IS NOT NULL
GROUP BY value
HAVING current_requests > 0
ORDER BY current_requests DESC
LIMIT {int(top_n)}
""".strip()
def _incident_bucketed_dimension_timeseries_sql(
    summary_table: str,
    dimension: str,
    granularity: str,
    start: datetime,
    end: datetime,
    host: str | None,
    asn: str | None,
    path_pattern: str | None,
    top_n: int,
    summary_time_column: str = "reqTimeSec",
    summary_count_column: str = "count()",
    summary_path_pattern_column: str = "requestPathPattern",
) -> str:
    """Bucketed current-window series for a top dimension.

    This enriches incident artifacts without changing existing required
    fields. It is used only when the relevant summary dimension exists.
    """
    summary_time = _incident_summary_time_expr(summary_time_column)
    summary_count = _incident_summary_count_expr(summary_count_column)
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
    dim_expr = _incident_identifier(dimension)
    return f"""
SELECT
  {bucket_fn}({summary_time}) AS bucket,
  toString({dim_expr}) AS value,
  {summary_count} AS requests
FROM {summary_table}
WHERE {_incident_time_predicate(start, end).replace('reqTimeSec', summary_time)}
  AND ({scope})
GROUP BY bucket, value
HAVING requests > 0
ORDER BY bucket, requests DESC
LIMIT {int(top_n) * 500}
""".strip()
def _incident_bucketed_edge_action_timeseries_sql(
    granularity: str,
    start: datetime,
    end: datetime,
    host: str | None,
    asn: str | None,
    path_pattern: str | None,
    top_n: int,
    raw_path_column: str = "request_path",
) -> str:
    """Bucketed current-window edge-action mix from raw logs."""
    scope = _incident_raw_scope_predicate(
        host, asn, path_pattern, path_column=raw_path_column
    )
    bucket_fn = {
        "minute": "toStartOfMinute",
        "hour": "toStartOfHour",
        "day": "toStartOfDay",
    }.get(granularity, "toStartOfMinute")
    return f"""
SELECT
  {bucket_fn}(reqTimeSec) AS bucket,
  toString(action_applied) AS value,
  count() AS requests
FROM akamai.logs
WHERE {_incident_time_predicate(start, end)}
  AND ({scope})
GROUP BY bucket, value
HAVING requests > 0
ORDER BY bucket, requests DESC
LIMIT {int(top_n) * 500}
""".strip()
def _incident_deny_rule_mix_sql(
    start: datetime,
    end: datetime,
    baseline_start: datetime,
    baseline_end: datetime,
    host: str | None,
    asn: str | None,
    path_pattern: str | None,
    top_n: int,
    raw_path_column: str = "request_path",
) -> str:
    """Top-N ``denyRule`` values for actually-denied requests + delta.

    Same shape as ``_incident_edge_action_mix_sql``. Filters on
    ``action_applied = 'Deny'`` so the table answers "which rules
    produced a denial" — the ``denied`` boolean is set whenever a WAF
    rule MATCHED (including Monitor / Tarpit / Allow-with-flag policies),
    so a ``denied = 1`` filter over-counts a rule's actual blast radius
    by an order of magnitude on bot-heavy traffic. The Edge Action Mix
    table above already enumerates monitored / tarpit / etc.
    """
    scope = _incident_raw_scope_predicate(
        host, asn, path_pattern, path_column=raw_path_column
    )
    return f"""
SELECT
  toString(denyRule) AS value,
  countIf(reqTimeSec >= toDateTime('{sql_ts(start)}', 'UTC')) AS current_requests,
  countIf(reqTimeSec < toDateTime('{sql_ts(baseline_end)}', 'UTC')) AS baseline_requests
FROM akamai.logs
WHERE reqTimeSec >= toDateTime('{sql_ts(baseline_start)}', 'UTC')
  AND reqTimeSec < toDateTime('{sql_ts(end)}', 'UTC')
  AND (reqTimeSec < toDateTime('{sql_ts(baseline_end)}', 'UTC')
       OR reqTimeSec >= toDateTime('{sql_ts(start)}', 'UTC'))
  AND ({scope})
  AND action_applied = 'Deny'
GROUP BY denyRule
HAVING current_requests > 0
ORDER BY current_requests DESC
LIMIT {int(top_n)}
""".strip()
def _incident_status_mix_sql(
    summary_table: str,
    start: datetime,
    end: datetime,
    host: str | None,
    asn: str | None,
    path_pattern: str | None,
    top_n: int,
    summary_time_column: str = "reqTimeSec",
    summary_count_column: str = "count()",
    summary_status_column: str = "statusCode",
    summary_path_pattern_column: str = "requestPathPattern",
) -> str:
    summary_time = _incident_summary_time_expr(summary_time_column)
    summary_count = _incident_summary_count_expr(summary_count_column)
    summary_status = _incident_identifier(summary_status_column)
    scope = _incident_scope_predicate(
        host,
        asn,
        path_pattern,
        path_pattern_column=summary_path_pattern_column,
    )
    return f"""
SELECT
  toUInt32({summary_status}) AS status_code,
  {summary_count} AS requests
FROM {summary_table}
WHERE {summary_time} >= toDateTime('{sql_ts(start)}', 'UTC')
  AND {summary_time} < toDateTime('{sql_ts(end)}', 'UTC')
  AND ({scope})
GROUP BY status_code
ORDER BY requests DESC
LIMIT {int(top_n)}
""".strip()
def _incident_siem_dimension_sql(
    siem_table: str,
    dimension: str,
    start: datetime,
    end: datetime,
    baseline_start: datetime,
    baseline_end: datetime,
    host: str | None,
    asn: str | None,
    path_pattern: str | None,
    top_n: int,
) -> str:
    scope = _incident_scope_predicate(host, asn, path_pattern)
    return f"""
SELECT
  toString({dimension}) AS value,
  countMergeIf(`count()`, timestamp >= toDateTime('{sql_ts(start)}', 'UTC')) AS current_requests,
  countMergeIf(`count()`, timestamp < toDateTime('{sql_ts(baseline_end)}', 'UTC')) AS baseline_requests
FROM {siem_table}
WHERE timestamp >= toDateTime('{sql_ts(baseline_start)}', 'UTC')
  AND timestamp < toDateTime('{sql_ts(end)}', 'UTC')
  AND (timestamp < toDateTime('{sql_ts(baseline_end)}', 'UTC')
       OR timestamp >= toDateTime('{sql_ts(start)}', 'UTC'))
  AND ({scope})
GROUP BY value
HAVING current_requests > 0
ORDER BY current_requests DESC
LIMIT {int(top_n)}
""".strip()
