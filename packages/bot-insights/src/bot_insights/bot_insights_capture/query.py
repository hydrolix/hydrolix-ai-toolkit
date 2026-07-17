from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from reportkit.extract import hydrolix as hdx

from .constants import HANDOFF_SCHEMA
from .hydrolix_bridge import CredentialState, ensure_format_json, reject_invalid_sql
from .timewindow import (
    apply_time_window_to_sql,
    require_time_window,
    selected_granularity,
    selected_table,
    selected_time_column,
    sql_timestamp,
)


def read_sql(args: argparse.Namespace) -> str:
    if args.preset:
        if args.sql or args.sql_file:
            raise SystemExit("Use either --preset or --sql/--sql-file, not both.")
        sql = render_preset_sql(args)
    else:
        if args.sql and args.sql_file:
            raise SystemExit("Use either --sql or --sql-file, not both.")
        if args.sql:
            sql = args.sql
        elif args.sql_file:
            sql = Path(args.sql_file).read_text(encoding="utf-8")
        elif not sys.stdin.isatty():
            sql = sys.stdin.read()
        else:
            raise SystemExit("Provide SQL with --preset, --sql, --sql-file, or stdin.")
        sql = apply_time_window_to_sql(sql.strip(), args)
    sql = ensure_format_json(sql)
    reject_invalid_sql(sql, require_time_range=args.require_time_range)
    return sql


def render_preset_sql(args: argparse.Namespace) -> str:
    start, end = require_time_window(args)
    surface = "siem-policy" if args.preset.startswith("siem-") else "posture"
    granularity = selected_granularity(start, end, args.granularity)
    table = selected_table(args.database, surface, granularity)
    time_column = selected_time_column(surface)
    time_filter = f"{time_column} >= {sql_timestamp(start)} AND {time_column} < {sql_timestamp(end)}"
    limit = args.limit

    if args.preset == "posture-overview":
        return f"""
SELECT
  trafficCohort,
  aiCategory,
  userAgentCategory,
  countMerge(`count()`) AS requests,
  countMergeIf(`count()`, cacheStatus = false) AS cache_misses,
  countMergeIf(`count()`, statusCode = 429) AS rate_limited_requests,
  countMergeIf(`count()`, statusCode >= 500) AS error_5xx_requests,
  round(
    sumIfMerge(`sumIf(Origin_TurnAroundTime, and(isNotNull(Origin_TurnAroundTime), greaterOrEquals(Origin_TurnAroundTime, 0)))`)
    / nullIf(countIfMerge(`countIf(and(isNotNull(Origin_TurnAroundTime), greaterOrEquals(Origin_TurnAroundTime, 0)))`), 0),
    2
  ) AS avg_origin_tat_ms
FROM {table}
WHERE {time_filter}
GROUP BY trafficCohort, aiCategory, userAgentCategory
ORDER BY requests DESC
LIMIT {limit}
""".strip()

    if args.preset == "posture-by-asn":
        return f"""
SELECT
  asn AS client_asn,
  reqHost AS request_host,
  trafficCohort,
  countMerge(`count()`) AS requests,
  countMergeIf(`count()`, cacheStatus = false) AS cache_misses,
  countMergeIf(`count()`, statusCode = 429) AS rate_limited_requests,
  countMergeIf(`count()`, statusCode >= 500) AS error_5xx_requests
FROM {table}
WHERE {time_filter}
GROUP BY client_asn, request_host, trafficCohort
ORDER BY requests DESC
LIMIT {limit}
""".strip()

    if args.preset == "posture-by-path":
        return f"""
SELECT
  reqPathPattern AS request_path_pattern,
  reqHost AS request_host,
  trafficCohort,
  resourceCategory,
  countMerge(`count()`) AS requests,
  countMergeIf(`count()`, cacheStatus = false) AS cache_misses,
  countMergeIf(`count()`, statusCode = 429) AS rate_limited_requests,
  countMergeIf(`count()`, statusCode >= 500) AS error_5xx_requests
FROM {table}
WHERE {time_filter}
GROUP BY request_path_pattern, request_host, trafficCohort, resourceCategory
ORDER BY requests DESC
LIMIT {limit}
""".strip()

    if args.preset == "siem-policy":
        return f"""
SELECT
  policyId,
  actionClass,
  botType,
  host AS request_host,
  asn AS client_asn,
  countMerge(`count()`) AS requests,
  countIfMerge(`countIf(equals(actionClass, 'deny'))`) AS blocked_requests,
  countIfMerge(`countIf(equals(authOutcome, 'fail'))`) AS auth_fail_requests,
  avgIfMerge(`avgIf(botScore, greater(botScore, 0))`) AS avg_bot_score,
  uniqMerge(`uniq(clientIP)`) AS unique_client_ips
FROM {table}
WHERE {time_filter}
GROUP BY policyId, actionClass, botType, request_host, client_asn
ORDER BY blocked_requests DESC, auth_fail_requests DESC, requests DESC
LIMIT {limit}
""".strip()

    raise AssertionError(args.preset)


def build_handoff_packet(
    args: argparse.Namespace,
    sql: str,
    credentials: CredentialState,
    output_path: Path,
) -> dict[str, Any]:
    report_context = {
        "preset": args.preset,
        "start": args.start,
        "end": args.end,
        "granularity": args.granularity,
        "limit": args.limit,
    }
    return hdx.build_handoff_packet(
        cluster=args.cluster,
        database=args.database,
        sql=sql,
        credentials=credentials,
        output_path=output_path,
        shape=args.shape,
        schema_version=HANDOFF_SCHEMA,
        preset=args.preset,
        report_context=report_context,
    )
