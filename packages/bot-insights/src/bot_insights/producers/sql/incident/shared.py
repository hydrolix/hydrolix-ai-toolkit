"""Shared SQL helpers for incident-report query builders."""

from __future__ import annotations

from datetime import datetime
import re

from producers.formatting import sql_literal, sql_ts

_SIMPLE_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
def _incident_identifier(name: str) -> str:
    """Render a ClickHouse identifier, quoting function-like physical names."""
    if _SIMPLE_IDENTIFIER_RE.match(name):
        return name
    return "`" + name.replace("`", "``") + "`"
def _incident_summary_time_expr(time_column: str = "reqTimeSec") -> str:
    return _incident_identifier(time_column)
def _incident_summary_count_expr(count_column: str = "count()") -> str:
    return f"countMerge({_incident_identifier(count_column)})"
def _incident_summary_count_if_expr(
    condition: str, count_column: str = "count()"
) -> str:
    return f"countMergeIf({_incident_identifier(count_column)}, {condition})"
def _incident_time_predicate(start: datetime, end: datetime) -> str:
    return (
        f"reqTimeSec >= toDateTime('{sql_ts(start)}', 'UTC') "
        f"AND reqTimeSec < toDateTime('{sql_ts(end)}', 'UTC')"
    )
def _incident_scope_predicate(
    host: str | None,
    asn: str | None,
    path_pattern: str | None,
    *,
    host_column: str = "reqHost",
    asn_column: str = "asn",
    path_pattern_column: str = "requestPathPattern",
) -> str:
    parts: list[str] = []
    if host:
        parts.append(f"{_incident_identifier(host_column)} = {sql_literal(host)}")
    if asn:
        parts.append(
            f"toString({_incident_identifier(asn_column)}) = {sql_literal(str(asn))}"
        )
    if path_pattern:
        parts.append(
            f"{_incident_identifier(path_pattern_column)} = {sql_literal(path_pattern)}"
        )
    return " AND ".join(parts) if parts else "1"
def _incident_raw_scope_predicate(
    host: str | None,
    asn: str | None,
    path_pattern: str | None,
    *,
    path_column: str = "request_path",
) -> str:
    """Same scope predicate but targeted at raw ``akamai.logs`` column names."""
    parts: list[str] = []
    if host:
        parts.append(f"reqHost = {sql_literal(host)}")
    if asn:
        parts.append(f"toString(asn) = {sql_literal(str(asn))}")
    if path_pattern:
        parts.append(f"{path_column} LIKE {sql_literal(path_pattern)}")
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
def _incident_in_list(values: list[str]) -> str:
    """Render a list of values as the body of an SQL IN clause.

    Returns ``NULL`` (a no-match value rather than a parse error) when
    the candidate list is empty so the outer query short-circuits to
    zero rows without raising a SQL error at the cluster.
    """
    if not values:
        return "NULL"
    return ", ".join(sql_literal(v) for v in values)
