"""SQL builders for the ``incident_report`` flow.

Phase queries the orchestrator hands to ``bot_insights_capture.py``
during a window-scoped incident analysis. The pipeline is:

  1. Window confirmation — ``_incident_window_confirmation_sql``
     unions the summary table, optional SIEM table, and optional
     raw-log drilldown into one (source, period) result.
  2. Volume + dimension top-N — bucketed timeseries + per-dimension
     top-N + edge-action / deny-rule / status-code mix tables.
  3. Actor pipeline — two-step ``topK`` candidates + per-row
     scoped metrics, plus the joint cooccurrence query that feeds
     the disjoint-cohort heuristic.

Every builder is pure (no I/O); all of them route identifier
interpolation through ``producers.formatting.sql_literal`` and
share the scope predicates at the top of this module. Slightly over
the producers/-wide 500-line guideline because every function shares
the predicate helpers and the actor pipeline functions reference
each other — splitting would force the shared helpers into a
separate sub-module without improving readability.
"""

from __future__ import annotations

from datetime import datetime

from producers.formatting import sql_literal, sql_ts


def _incident_time_predicate(start: datetime, end: datetime) -> str:
    return (
        f"reqTimeSec >= toDateTime('{sql_ts(start)}', 'UTC') "
        f"AND reqTimeSec < toDateTime('{sql_ts(end)}', 'UTC')"
    )


def _incident_scope_predicate(
    host: str | None, asn: str | None, path_pattern: str | None
) -> str:
    parts: list[str] = []
    if host:
        parts.append(f"reqHost = {sql_literal(host)}")
    if asn:
        parts.append(f"toString(asn) = {sql_literal(str(asn))}")
    if path_pattern:
        parts.append(f"requestPathPattern = {sql_literal(path_pattern)}")
    return " AND ".join(parts) if parts else "1"


def _incident_raw_scope_predicate(
    host: str | None, asn: str | None, path_pattern: str | None
) -> str:
    """Same scope predicate but targeted at raw ``akamai.logs`` column names."""
    parts: list[str] = []
    if host:
        parts.append(f"reqHost = {sql_literal(host)}")
    if asn:
        parts.append(f"toString(asn) = {sql_literal(str(asn))}")
    if path_pattern:
        parts.append(f"request_path LIKE {sql_literal(path_pattern)}")
    return " AND ".join(parts) if parts else "1"


def _incident_columns_query(database: str, table: str) -> str:
    """Return a guarded SELECT against ``system.columns``.

    Capture's SQL guard rejects DESCRIBE TABLE because it isn't a SELECT,
    so introspection routes through ``system.columns``. The query is
    bounded by ``database`` + ``table`` literals so it stays cheap
    regardless of cluster size.
    """
    return (
        f"SELECT name FROM system.columns "
        f"WHERE database = {sql_literal(database)} "
        f"AND table = {sql_literal(table)} "
        f"ORDER BY name LIMIT 1000"
    )


def _incident_window_confirmation_sql(
    summary_table: str,
    siem_table: str | None,
    start: datetime,
    end: datetime,
    baseline_start: datetime,
    host: str | None,
    asn: str | None,
    path_pattern: str | None,
    raw_drilldown_available: bool = False,
) -> str:
    scope = _incident_scope_predicate(host, asn, path_pattern)
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
  AND ({scope})
GROUP BY period
""".rstrip()
    raw_join = ""
    if raw_drilldown_available:
        raw_scope = _incident_raw_scope_predicate(host, asn, path_pattern)
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
  toUInt64(0) AS bot_like_requests,
  toUInt64(0) AS req_429,
  toUInt64(0) AS req_5xx,
  toUInt64(0) AS blocked,
  countIf(action_applied = 'Deny') AS denied_requests,
  countIf(action_applied = 'Monitor') AS monitored_requests
FROM akamai.logs
WHERE reqTimeSec >= toDateTime('{sql_ts(baseline_start)}', 'UTC')
  AND reqTimeSec < toDateTime('{sql_ts(end)}', 'UTC')
  AND ({raw_scope})
GROUP BY period
""".rstrip()
    return f"""
SELECT
  'summary' AS source,
  if(reqTimeSec >= toDateTime('{sql_ts(start)}', 'UTC'), 'current', 'baseline') AS period,
  countMerge(`count()`) AS requests,
  countMergeIf(`count()`, trafficCohort IN ('Bot', 'AI')) AS bot_like_requests,
  countMergeIf(`count()`, statusCode = 429) AS req_429,
  countMergeIf(`count()`, statusCode BETWEEN 500 AND 599) AS req_5xx,
  toUInt64(0) AS blocked,
  toUInt64(0) AS denied_requests,
  toUInt64(0) AS monitored_requests
FROM {summary_table}
WHERE reqTimeSec >= toDateTime('{sql_ts(baseline_start)}', 'UTC')
  AND reqTimeSec < toDateTime('{sql_ts(end)}', 'UTC')
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
    host: str | None,
    asn: str | None,
    path_pattern: str | None,
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
    scope = _incident_scope_predicate(host, asn, path_pattern)
    bucket_fn = {
        "minute": "toStartOfMinute",
        "hour": "toStartOfHour",
        "day": "toStartOfDay",
    }.get(granularity, "toStartOfMinute")
    return f"""
SELECT
  if(reqTimeSec >= toDateTime('{sql_ts(start)}', 'UTC'), 'current', 'baseline') AS period,
  {bucket_fn}(reqTimeSec) AS bucket,
  countMerge(`count()`) AS requests,
  countMergeIf(`count()`, statusCode = 429) AS req_429,
  countMergeIf(`count()`, trafficCohort IN ('Bot', 'AI')) AS bot_like_requests
FROM {summary_table}
WHERE reqTimeSec >= toDateTime('{sql_ts(baseline_start)}', 'UTC')
  AND reqTimeSec < toDateTime('{sql_ts(end)}', 'UTC')
  AND ({scope})
GROUP BY period, bucket
ORDER BY period, bucket
""".strip()


def _incident_dimension_sql(
    summary_table: str,
    dimension: str,
    start: datetime,
    end: datetime,
    baseline_start: datetime,
    host: str | None,
    asn: str | None,
    path_pattern: str | None,
    top_n: int,
) -> str:
    """Per-dimension top-N + delta against the equal-length baseline."""
    scope = _incident_scope_predicate(host, asn, path_pattern)
    return f"""
SELECT
  toString({dimension}) AS value,
  countMergeIf(`count()`, reqTimeSec >= toDateTime('{sql_ts(start)}', 'UTC')) AS current_requests,
  countMergeIf(`count()`, reqTimeSec < toDateTime('{sql_ts(start)}', 'UTC')) AS baseline_requests
FROM {summary_table}
WHERE reqTimeSec >= toDateTime('{sql_ts(baseline_start)}', 'UTC')
  AND reqTimeSec < toDateTime('{sql_ts(end)}', 'UTC')
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
    host: str | None,
    asn: str | None,
    path_pattern: str | None,
    top_n: int,
) -> str:
    """Top-N ``action_applied`` values + delta vs the equal-length baseline.

    Mirrors the shape of :func:`_incident_dimension_sql` so the
    orchestrator can feed the rows through ``_incident_dimension_rows``
    for the same ``(value, share_pct, delta_vs_baseline_pct)``
    projection used by the other scope mix tables. Queries raw
    ``akamai.logs`` because ``action_applied`` is not carried on the
    summary table.
    """
    scope = _incident_raw_scope_predicate(host, asn, path_pattern)
    return f"""
SELECT
  toString(action_applied) AS value,
  countIf(reqTimeSec >= toDateTime('{sql_ts(start)}', 'UTC')) AS current_requests,
  countIf(reqTimeSec < toDateTime('{sql_ts(start)}', 'UTC')) AS baseline_requests
FROM akamai.logs
WHERE reqTimeSec >= toDateTime('{sql_ts(baseline_start)}', 'UTC')
  AND reqTimeSec < toDateTime('{sql_ts(end)}', 'UTC')
  AND ({scope})
GROUP BY action_applied
HAVING current_requests > 0
ORDER BY current_requests DESC
LIMIT {int(top_n)}
""".strip()


def _incident_deny_rule_mix_sql(
    start: datetime,
    end: datetime,
    baseline_start: datetime,
    host: str | None,
    asn: str | None,
    path_pattern: str | None,
    top_n: int,
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
    scope = _incident_raw_scope_predicate(host, asn, path_pattern)
    return f"""
SELECT
  toString(denyRule) AS value,
  countIf(reqTimeSec >= toDateTime('{sql_ts(start)}', 'UTC')) AS current_requests,
  countIf(reqTimeSec < toDateTime('{sql_ts(start)}', 'UTC')) AS baseline_requests
FROM akamai.logs
WHERE reqTimeSec >= toDateTime('{sql_ts(baseline_start)}', 'UTC')
  AND reqTimeSec < toDateTime('{sql_ts(end)}', 'UTC')
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
) -> str:
    scope = _incident_scope_predicate(host, asn, path_pattern)
    return f"""
SELECT
  toUInt32(statusCode) AS status_code,
  countMerge(`count()`) AS requests
FROM {summary_table}
WHERE reqTimeSec >= toDateTime('{sql_ts(start)}', 'UTC')
  AND reqTimeSec < toDateTime('{sql_ts(end)}', 'UTC')
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
  countMergeIf(`count()`, timestamp < toDateTime('{sql_ts(start)}', 'UTC')) AS baseline_requests
FROM {siem_table}
WHERE timestamp >= toDateTime('{sql_ts(baseline_start)}', 'UTC')
  AND timestamp < toDateTime('{sql_ts(end)}', 'UTC')
  AND ({scope})
GROUP BY value
HAVING current_requests > 0
ORDER BY current_requests DESC
LIMIT {int(top_n)}
""".strip()


def _incident_actor_topk_sql(
    field: str,
    start: datetime,
    end: datetime,
    host: str | None,
    asn: str | None,
    path_pattern: str | None,
    top_n: int,
) -> str:
    """Phase 1 of the two-step actor pipeline: extract top-K candidates only.

    ``topK(N)(column)`` runs as a space-saving sketch (Filtered
    Space-Saving algorithm, O(K) memory) so it does NOT exhaust the
    cluster's 2 GiB per-query memory cap the way a raw
    ``GROUP BY column ORDER BY count() DESC LIMIT N`` does over a
    high-cardinality field like ``client_ip``.

    Returns a single row whose ``candidates`` column is an array of
    top-K values for the field. Phase 2 (``_incident_actor_scoped_metrics_sql``)
    then computes per-row metrics scoped to that candidate list, which
    bounds the metrics GROUP BY hash table to at most ``top_n`` groups.
    """
    scope = _incident_raw_scope_predicate(host, asn, path_pattern)
    return f"""
SELECT topK({int(top_n)})({field}) AS candidates
FROM akamai.logs
WHERE {_incident_time_predicate(start, end)}
  AND ({scope})
""".strip()


def _incident_actor_topk_baseline_sql(
    field: str,
    baseline_start: datetime,
    current_start: datetime,
    host: str | None,
    asn: str | None,
    path_pattern: str | None,
    top_n: int,
) -> str:
    """Same as :func:`_incident_actor_topk_sql` but for the baseline window."""
    scope = _incident_raw_scope_predicate(host, asn, path_pattern)
    return f"""
SELECT topK({int(top_n)})({field}) AS candidates
FROM akamai.logs
WHERE reqTimeSec >= toDateTime('{sql_ts(baseline_start)}', 'UTC')
  AND reqTimeSec < toDateTime('{sql_ts(current_start)}', 'UTC')
  AND ({scope})
""".strip()


def _incident_actor_scoped_metrics_sql(
    field: str,
    candidates: list[str],
    start: datetime,
    end: datetime,
    host: str | None,
    asn: str | None,
    path_pattern: str | None,
    *,
    full_metrics: bool,
) -> str:
    """Phase 2 of the two-step actor pipeline: per-row metrics scoped to candidates.

    The IN-clause filters the rows scanned to those whose ``field``
    value is in the candidate set, which bounds the GROUP BY hash table
    to at most ``len(candidates)`` groups — well under the cluster's
    per-query memory cap regardless of underlying cardinality.

    ``full_metrics=True`` emits the current-window shape (with
    ``bytes`` + ``distinct_paths``); ``False`` emits the leaner
    baseline shape (counts only — what the ``anomaly`` +
    ``new_in_window`` primitives need without re-scanning columns the
    baseline query doesn't read).

    For the ``client_ip`` field, the current-window query also
    projects ``any(asn) AS asn`` so the orchestrator's per-row ASN
    pivot can fire ``single_asn_cluster`` + ``botnet_member`` against
    verified cluster membership instead of falling back to the coarse
    total-count approximation.
    """
    scope = _incident_raw_scope_predicate(host, asn, path_pattern)
    select_extras = (
        ",\n  sum(bytesOut) AS bytes,\n"
        "  uniqExact(request_path) AS distinct_paths"
    ) if full_metrics else ""
    asn_projection = (
        ",\n  any(asn) AS asn"
        if full_metrics and field == "client_ip"
        else ""
    )
    return f"""
SELECT
  toString({field}) AS value,
  count() AS requests{select_extras},
  countIf(statusCode = 429) AS req_429,
  countIf(statusCode BETWEEN 500 AND 599) AS req_5xx{asn_projection}
FROM akamai.logs
WHERE {_incident_time_predicate(start, end)}
  AND ({scope})
  AND {field} IN ({_incident_in_list(candidates)})
GROUP BY value
ORDER BY requests DESC
""".strip()


def _incident_actor_scoped_metrics_baseline_sql(
    field: str,
    candidates: list[str],
    baseline_start: datetime,
    current_start: datetime,
    host: str | None,
    asn: str | None,
    path_pattern: str | None,
) -> str:
    """Same as scoped metrics, but for the baseline window."""
    scope = _incident_raw_scope_predicate(host, asn, path_pattern)
    return f"""
SELECT
  toString({field}) AS value,
  count() AS requests,
  countIf(statusCode = 429) AS req_429,
  countIf(statusCode BETWEEN 500 AND 599) AS req_5xx
FROM akamai.logs
WHERE reqTimeSec >= toDateTime('{sql_ts(baseline_start)}', 'UTC')
  AND reqTimeSec < toDateTime('{sql_ts(current_start)}', 'UTC')
  AND ({scope})
  AND {field} IN ({_incident_in_list(candidates)})
GROUP BY value
ORDER BY requests DESC
""".strip()


def _incident_actor_cooccurrence_sql(
    field_a: str,
    field_b: str,
    candidates_a: list[str],
    candidates_b: list[str],
    start: datetime,
    end: datetime,
    host: str | None,
    asn: str | None,
    path_pattern: str | None,
) -> str:
    """Joint ``(field_a, field_b)`` cell counts scoped to both candidate sets.

    Feeds the orchestrator's ``actor_cooccurrence`` artifact slot,
    which the disjoint-cohorts finding consumes. Scoping to both
    candidate sets bounds the GROUP BY hash table to
    ``len(candidates_a) × len(candidates_b)`` cells (e.g., 2500 for
    K=50) — well under the per-query memory cap. Denominators for the
    overlap math come from the marginal rankings, so the bounded
    scope doesn't bias the result.
    """
    scope = _incident_raw_scope_predicate(host, asn, path_pattern)
    # When the second axis is small-cardinality (e.g. ``action_applied``
    # has 4–5 fixed values), it's wasteful to require a candidate list
    # — the GROUP BY hash stays bounded by ``len(candidates_a) ×
    # cardinality(field_b)``. Skip the second ``IN`` clause when the
    # caller hands us an empty candidate list for axis B.
    in_b_clause = (
        f"\n  AND {field_b} IN ({_incident_in_list(candidates_b)})"
        if candidates_b
        else ""
    )
    return f"""
SELECT
  toString({field_a}) AS value_a,
  toString({field_b}) AS value_b,
  count() AS requests
FROM akamai.logs
WHERE {_incident_time_predicate(start, end)}
  AND ({scope})
  AND {field_a} IN ({_incident_in_list(candidates_a)}){in_b_clause}
GROUP BY value_a, value_b
ORDER BY requests DESC
""".strip()


def _incident_in_list(values: list[str]) -> str:
    """Render a list of values as the body of an SQL IN clause.

    Returns ``NULL`` (a no-match value rather than a parse error) when
    the candidate list is empty so the outer query short-circuits to
    zero rows without raising a SQL error at the cluster.
    """
    if not values:
        return "NULL"
    return ", ".join(sql_literal(v) for v in values)
