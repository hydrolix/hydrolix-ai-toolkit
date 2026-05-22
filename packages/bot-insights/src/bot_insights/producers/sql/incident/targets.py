"""Target and flagged-IP incident SQL builders."""

from __future__ import annotations

from datetime import datetime

from producers.formatting import sql_literal

from .shared import (
    _incident_in_list,
    _incident_raw_scope_predicate,
    _incident_time_predicate,
)

def _incident_flagged_client_ip_timeseries_sql(
    ip_candidates: list[str],
    granularity: str,
    start: datetime,
    end: datetime,
    host: str | None,
    asn: str | None,
    path_pattern: str | None,
    raw_ip_column: str = "client_ip",
    raw_path_column: str = "request_path",
    available_columns: set[str] | None = None,
) -> str:
    """Bounded current-window time series for flagged client IPs only."""
    scope = _incident_raw_scope_predicate(
        host, asn, path_pattern, path_column=raw_path_column
    )
    columns = available_columns or set()
    bucket_fn = {
        "minute": "toStartOfMinute",
        "hour": "toStartOfHour",
        "day": "toStartOfDay",
    }.get(granularity, "toStartOfMinute")
    action_deny_expr = (
        "countIf(action_applied = 'Deny')"
        if "action_applied" in columns
        else "toUInt64(0)"
    )
    action_allow_expr = (
        "countIf(action_applied IN ('Allow', ''))"
        if "action_applied" in columns
        else "toUInt64(0)"
    )
    action_challenge_expr = (
        "countIf(action_applied IN ('Challenge', 'Tarpit', 'Monitor'))"
        if "action_applied" in columns
        else "toUInt64(0)"
    )
    source_exprs = [
        f"nullIf(toString({column}), '') IS NOT NULL"
        for column in ("bot_category", "bot_type", "botnet_id")
        if column in columns
    ]
    bot_provenance_expr = (
        f"countIf({' OR '.join(source_exprs)})" if source_exprs else "toUInt64(0)"
    )
    proxy_expr = (
        "countIf(nullIf(toString(epd_Category), '') IS NOT NULL)"
        if "epd_Category" in columns
        else "toUInt64(0)"
    )
    lower_path = f"lower(toString({raw_path_column}))"
    auth_conditions = " OR ".join(
        f"{lower_path} LIKE {sql_literal('%' + marker + '%')}"
        for marker in (
            "/auth",
            "/login",
            "/signin",
            "/sign-in",
            "/oauth",
            "/sso",
            "/token",
            "/session",
            "credential",
        )
    )
    return f"""
SELECT
  {bucket_fn}(reqTimeSec) AS bucket,
  count() AS flagged_requests,
  countIf(statusCode = 429) AS req_429,
  countIf(statusCode BETWEEN 500 AND 599) AS req_5xx,
  {action_deny_expr} AS edge_deny,
  {action_allow_expr} AS edge_allow,
  {action_challenge_expr} AS edge_challenge,
  {bot_provenance_expr} AS bot_provenance,
  {proxy_expr} AS proxy_classification,
  countIf({lower_path} LIKE '%/graphql%') AS graphql,
  countIf({auth_conditions}) AS auth_path
FROM akamai.logs
WHERE {_incident_time_predicate(start, end)}
  AND ({scope})
  AND {raw_ip_column} IN ({_incident_in_list(ip_candidates)})
GROUP BY bucket
ORDER BY bucket
""".strip()
def _incident_target_bucket_evidence_sql(
    targets: list[dict],
    granularity: str,
    start: datetime,
    end: datetime,
    host: str | None,
    asn: str | None,
    path_pattern: str | None,
    raw_column_by_field: dict[str, str],
    raw_path_column: str = "request_path",
    top_n: int = 10,
) -> str:
    """Bucketed per-target telemetry for already-computed suspicious targets.

    The query is intentionally current-window only. It supports
    first/last/peak derivation, dominant path / UA / cohort / edge action,
    and overlap-based behavior clustering without implying mitigation
    response or synchronization by itself.
    """
    scope = _incident_raw_scope_predicate(
        host, asn, path_pattern, path_column=raw_path_column
    )
    bucket_fn = {
        "minute": "toStartOfMinute",
        "hour": "toStartOfHour",
        "day": "toStartOfDay",
    }.get(granularity, "toStartOfMinute")
    clauses: list[str] = []
    allowed = {"client_ip", "user_agent", "request_path", "trafficCohort", "country", "asn"}
    ua_expr = raw_column_by_field.get("user_agent")
    cohort_expr = raw_column_by_field.get("trafficCohort")
    action_expr = raw_column_by_field.get("action_applied")
    for target in targets[: int(top_n)]:
        target_type = str(target.get("target_type") or "")
        target_value = str(target.get("target_value") or "")
        if target_type not in allowed or not target_value:
            continue
        column = raw_column_by_field.get(target_type, target_type)
        clauses.append(
            f"SELECT {sql_literal(target_type)} AS target_type, "
            f"{sql_literal(target_value)} AS target_value, "
            f"{bucket_fn}(reqTimeSec) AS bucket, "
            "count() AS requests, "
            f"anyHeavy(toString({raw_path_column})) AS dominant_path, "
            + (
                f"anyHeavy(toString({ua_expr})) AS dominant_user_agent, "
                if ua_expr else "'' AS dominant_user_agent, "
            )
            + (
                f"anyHeavy(toString({cohort_expr})) AS dominant_cohort, "
                if cohort_expr else "'' AS dominant_cohort, "
            )
            + (
                f"anyHeavy(toString({action_expr})) AS dominant_edge_action "
                if action_expr else "'' AS dominant_edge_action "
            )
            + "FROM akamai.logs "
            f"WHERE {_incident_time_predicate(start, end)} "
            f"AND ({scope}) "
            f"AND toString({column}) = {sql_literal(target_value)} "
            "GROUP BY bucket"
        )
    if not clauses:
        return "SELECT '' AS target_type, '' AS target_value, now() AS bucket, toUInt64(0) AS requests WHERE 0"
    return "\nUNION ALL\n".join(clauses)
