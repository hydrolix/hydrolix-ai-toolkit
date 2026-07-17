from __future__ import annotations

import argparse
import json
from pathlib import Path

from .constants import NEEDS_MCP_EXIT, PRESET_CHOICES
from .hydrolix_bridge import (
    build_query_config,
    credential_state,
    extract_query_stats,
    merged_environment,
    response_row_count,
    shape_output,
    write_json_atomic,
)
from .query import build_handoff_packet, read_sql


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Capture vetted Bot Insights Hydrolix query JSON or emit an MCP handoff."
    )
    parser.add_argument("--cluster", help="Hydrolix cluster alias or .env file path.")
    parser.add_argument(
        "--preset",
        choices=PRESET_CHOICES,
        help="Use a vetted Bot Insights summary-table query preset.",
    )
    parser.add_argument(
        "--start",
        help="Inclusive ISO-8601 UTC start timestamp, for example 2026-05-01T00:00:00Z.",
    )
    parser.add_argument(
        "--end",
        help="Exclusive ISO-8601 UTC end timestamp, for example 2026-05-08T00:00:00Z.",
    )
    parser.add_argument(
        "--database",
        default="akamai",
        help="Hydrolix database/project name for Bot Insights summary presets.",
    )
    parser.add_argument(
        "--granularity",
        choices=("auto", "minute", "hour", "day"),
        default="auto",
        help="Summary-table granularity. Auto uses <3h minute, <48h hour, else day.",
    )
    parser.add_argument("--limit", type=int, default=100, help="LIMIT used by query presets.")
    parser.add_argument("--sql", help="Guarded Bot Insights SQL text.")
    parser.add_argument("--sql-file", help="Path to a guarded Bot Insights SQL file.")
    parser.add_argument("--output", required=True, help="Output JSON path.")
    parser.add_argument(
        "--shape",
        choices=("clickhouse", "rows"),
        default="clickhouse",
        help="Write the full ClickHouse JSON response or only the data row array.",
    )
    parser.add_argument(
        "--no-require-time-range",
        dest="require_time_range",
        action="store_false",
        help="Allow custom SQL without an explicit timestamp or reqTimeSec predicate.",
    )
    parser.set_defaults(require_time_range=True)
    args = parser.parse_args()
    if args.limit <= 0:
        raise SystemExit("--limit must be positive.")
    return args


def main() -> int:
    args = parse_args()
    sql = read_sql(args)
    output_path = Path(args.output).expanduser().resolve()
    env, env_path = merged_environment(args.cluster)
    credentials = credential_state(env, env_path)
    if not credentials.configured:
        print(json.dumps(build_handoff_packet(args, sql, credentials, output_path), sort_keys=True))
        return NEEDS_MCP_EXIT

    config = build_query_config(env)
    # Resolve query_hydrolix from the package namespace at call time so the shim
    # patch point (_package_bootstrap.main_proxy, used by tests) is honored.
    from bot_insights import bot_insights_capture as _package

    response, meta = _package.query_hydrolix(sql, config)
    shaped = shape_output(response, args.shape)
    bytes_written = write_json_atomic(output_path, shaped)
    rows = response_row_count(response, shaped)

    summary = {
        "auth_mode": config.auth_mode,
        "bytes_written": bytes_written,
        "cluster": args.cluster,
        "output": str(output_path),
        "preset": args.preset,
        "query_url": config.url,
        "rows": rows,
        "shape": args.shape,
        "verify_tls": config.verify_tls,
    }
    summary.update(extract_query_stats(meta, response))
    print(json.dumps(summary, sort_keys=True))
    return 0
