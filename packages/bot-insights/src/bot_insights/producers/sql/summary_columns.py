"""Shared resolution of physical posture-summary column names.

The TrafficPeak/Akamai posture summary (``bi_summary_*``) renamed its
path-pattern dimension across bundle versions. The currently-deployed
``bot_insights_cdn/1.1`` bundle emits ``reqPathPattern`` (verified against
live clusters and the bundle's ``hydrolix/tables/bi_summary_*.sql``); older
iterations used ``requestPathPattern``. Resolving the physical column from
introspected metadata lets producers target either shape without a hard switch
that would break not-yet-migrated clusters.
"""

from __future__ import annotations

from collections.abc import Iterable

from producers.formatting import sql_literal

# Physical columns that can back the canonical path-pattern dimension, in
# preference order. ``reqPathPattern`` is the currently-deployed name
# (bot_insights_cdn/1.1) and stays first so introspection-less defaults target
# live clusters; ``requestPathPattern`` is the older pre-1.1 name; the
# ``*Coarse`` variants are older coarse buckets retained for back-compat.
PATH_PATTERN_PHYSICAL_COLUMNS = (
    "reqPathPattern",
    "requestPathPattern",
    "reqPathPatternCoarse",
    "requestPathPatternCoarse",
)

DEFAULT_PATH_PATTERN_COLUMN = "reqPathPattern"


def resolve_path_pattern_column(
    summary_columns: Iterable[str],
    default: str = DEFAULT_PATH_PATTERN_COLUMN,
) -> str:
    """Return the physical path-pattern column present in ``summary_columns``.

    Falls back to ``default`` (the currently-deployed name) when none of the
    known physical variants are present, so callers without introspected
    metadata keep their existing behavior.
    """
    columns = set(summary_columns)
    for candidate in PATH_PATTERN_PHYSICAL_COLUMNS:
        if candidate in columns:
            return candidate
    return default


def summary_columns_query(database: str, table: str) -> str:
    """Guarded ``system.columns`` SELECT used to introspect a table's columns.

    Capture's SQL guard rejects ``DESCRIBE TABLE`` (not a SELECT), so column
    introspection routes through ``system.columns``. Bounded by ``database`` +
    ``table`` literals so it stays cheap regardless of cluster size.
    """
    return (
        f"SELECT name FROM system.columns "
        f"WHERE database = {sql_literal(database)} "
        f"AND table = {sql_literal(table)} "
        f"ORDER BY name LIMIT 1000"
    )
