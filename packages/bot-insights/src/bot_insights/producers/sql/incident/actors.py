"""Actor top-K and co-occurrence SQL builders."""

from __future__ import annotations

from datetime import datetime

from producers.formatting import sql_ts

from .shared import (
    _incident_in_list,
    _incident_raw_scope_predicate,
    _incident_time_predicate,
)

def _incident_actor_topk_sql(
    field_sql: str,
    start: datetime,
    end: datetime,
    host: str | None,
    asn: str | None,
    path_pattern: str | None,
    top_n: int,
    raw_path_column: str = "request_path",
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
    scope = _incident_raw_scope_predicate(
        host, asn, path_pattern, path_column=raw_path_column
    )
    return f"""
SELECT topK({int(top_n)})({field_sql}) AS candidates
FROM akamai.logs
WHERE {_incident_time_predicate(start, end)}
  AND ({scope})
""".strip()
def _incident_actor_topk_baseline_sql(
    field_sql: str,
    baseline_start: datetime,
    baseline_end: datetime,
    host: str | None,
    asn: str | None,
    path_pattern: str | None,
    top_n: int,
    raw_path_column: str = "request_path",
) -> str:
    """Same as :func:`_incident_actor_topk_sql` but for the baseline window."""
    scope = _incident_raw_scope_predicate(
        host, asn, path_pattern, path_column=raw_path_column
    )
    return f"""
SELECT topK({int(top_n)})({field_sql}) AS candidates
FROM akamai.logs
WHERE reqTimeSec >= toDateTime('{sql_ts(baseline_start)}', 'UTC')
  AND reqTimeSec < toDateTime('{sql_ts(baseline_end)}', 'UTC')
  AND ({scope})
""".strip()
def _incident_actor_scoped_metrics_sql(
    field: str,
    field_sql: str,
    candidates: list[str],
    start: datetime,
    end: datetime,
    host: str | None,
    asn: str | None,
    path_pattern: str | None,
    *,
    full_metrics: bool,
    bytes_column: str = "bytesOut",
    path_column: str = "request_path",
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
    scope = _incident_raw_scope_predicate(
        host, asn, path_pattern, path_column=path_column
    )
    select_extras = (
        f",\n  sum({bytes_column}) AS bytes,\n"
        f"  uniqExact({path_column}) AS distinct_paths"
    ) if full_metrics else ""
    asn_projection = (
        ",\n  any(asn) AS asn"
        if full_metrics and field == "client_ip"
        else ""
    )
    return f"""
SELECT
  toString({field_sql}) AS value,
  count() AS requests{select_extras},
  countIf(statusCode = 429) AS req_429,
  countIf(statusCode BETWEEN 500 AND 599) AS req_5xx{asn_projection}
FROM akamai.logs
WHERE {_incident_time_predicate(start, end)}
  AND ({scope})
  AND {field_sql} IN ({_incident_in_list(candidates)})
GROUP BY value
ORDER BY requests DESC
""".strip()
def _incident_actor_scoped_metrics_baseline_sql(
    field_sql: str,
    candidates: list[str],
    baseline_start: datetime,
    baseline_end: datetime,
    host: str | None,
    asn: str | None,
    path_pattern: str | None,
    raw_path_column: str = "request_path",
) -> str:
    """Same as scoped metrics, but for the baseline window."""
    scope = _incident_raw_scope_predicate(
        host, asn, path_pattern, path_column=raw_path_column
    )
    return f"""
SELECT
  toString({field_sql}) AS value,
  count() AS requests,
  countIf(statusCode = 429) AS req_429,
  countIf(statusCode BETWEEN 500 AND 599) AS req_5xx
FROM akamai.logs
WHERE reqTimeSec >= toDateTime('{sql_ts(baseline_start)}', 'UTC')
  AND reqTimeSec < toDateTime('{sql_ts(baseline_end)}', 'UTC')
  AND ({scope})
  AND {field_sql} IN ({_incident_in_list(candidates)})
GROUP BY value
ORDER BY requests DESC
""".strip()
def _incident_actor_cooccurrence_sql(
    field_a: str,
    field_b: str,
    field_a_sql: str,
    field_b_sql: str,
    candidates_a: list[str],
    candidates_b: list[str],
    start: datetime,
    end: datetime,
    host: str | None,
    asn: str | None,
    path_pattern: str | None,
    raw_path_column: str = "request_path",
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
    scope = _incident_raw_scope_predicate(
        host, asn, path_pattern, path_column=raw_path_column
    )
    # When the second axis is small-cardinality (e.g. ``action_applied``
    # has 4–5 fixed values), it's wasteful to require a candidate list
    # — the GROUP BY hash stays bounded by ``len(candidates_a) ×
    # cardinality(field_b)``. Skip the second ``IN`` clause when the
    # caller hands us an empty candidate list for axis B.
    in_b_clause = (
        f"\n  AND {field_b_sql} IN ({_incident_in_list(candidates_b)})"
        if candidates_b
        else ""
    )
    return f"""
SELECT
  toString({field_a_sql}) AS value_a,
  toString({field_b_sql}) AS value_b,
  count() AS requests
FROM akamai.logs
WHERE {_incident_time_predicate(start, end)}
  AND ({scope})
  AND {field_a_sql} IN ({_incident_in_list(candidates_a)}){in_b_clause}
GROUP BY value_a, value_b
ORDER BY requests DESC
""".strip()
def _incident_client_ip_bot_source_cooccurrence_sql(
    ip_candidates: list[str],
    start: datetime,
    end: datetime,
    baseline_start: datetime,
    baseline_end: datetime,
    host: str | None,
    asn: str | None,
    path_pattern: str | None,
    raw_ip_column: str = "client_ip",
    raw_path_column: str = "request_path",
    available_columns: set[str] | None = None,
) -> str:
    """Per-IP source bot metadata cells for top actor IPs."""
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
  toString({raw_ip_column}) AS ip,
  {category_expr} AS bot_category,
  {type_expr} AS bot_type,
  {botnet_expr} AS botnet_id,
  countIf(reqTimeSec >= toDateTime('{sql_ts(start)}', 'UTC')) AS requests,
  countIf(reqTimeSec < toDateTime('{sql_ts(baseline_end)}', 'UTC')) AS baseline_requests
FROM akamai.logs
WHERE reqTimeSec >= toDateTime('{sql_ts(baseline_start)}', 'UTC')
  AND reqTimeSec < toDateTime('{sql_ts(end)}', 'UTC')
  AND (reqTimeSec < toDateTime('{sql_ts(baseline_end)}', 'UTC')
       OR reqTimeSec >= toDateTime('{sql_ts(start)}', 'UTC'))
  AND ({scope})
  AND {raw_ip_column} IN ({_incident_in_list(ip_candidates)})
  AND ({nonempty})
GROUP BY ip, bot_category, bot_type, botnet_id
HAVING requests > 0
ORDER BY requests DESC
""".strip()
def _incident_client_ip_proxy_classification_cooccurrence_sql(
    ip_candidates: list[str],
    start: datetime,
    end: datetime,
    baseline_start: datetime,
    baseline_end: datetime,
    host: str | None,
    asn: str | None,
    path_pattern: str | None,
    raw_ip_column: str = "client_ip",
    raw_path_column: str = "request_path",
    available_columns: set[str] | None = None,
) -> str:
    """Per-IP EPD proxy-classification cells for top actor IPs."""
    scope = _incident_raw_scope_predicate(
        host, asn, path_pattern, path_column=raw_path_column
    )
    columns = available_columns or {"epd_ActionName", "epd_Category", "epd_Match"}
    action_expr = "toString(epd_ActionName)" if "epd_ActionName" in columns else "''"
    match_expr = "toString(epd_Match)" if "epd_Match" in columns else "''"
    return f"""
SELECT
  toString({raw_ip_column}) AS ip,
  toString(epd_Category) AS epd_Category,
  {action_expr} AS epd_ActionName,
  {match_expr} AS epd_Match,
  countIf(reqTimeSec >= toDateTime('{sql_ts(start)}', 'UTC')) AS requests,
  countIf(reqTimeSec < toDateTime('{sql_ts(baseline_end)}', 'UTC')) AS baseline_requests
FROM akamai.logs
WHERE reqTimeSec >= toDateTime('{sql_ts(baseline_start)}', 'UTC')
  AND reqTimeSec < toDateTime('{sql_ts(end)}', 'UTC')
  AND (reqTimeSec < toDateTime('{sql_ts(baseline_end)}', 'UTC')
       OR reqTimeSec >= toDateTime('{sql_ts(start)}', 'UTC'))
  AND ({scope})
  AND {raw_ip_column} IN ({_incident_in_list(ip_candidates)})
  AND nullIf(toString(epd_Category), '') IS NOT NULL
GROUP BY ip, epd_Category, epd_ActionName, epd_Match
HAVING requests > 0
ORDER BY requests DESC
""".strip()
