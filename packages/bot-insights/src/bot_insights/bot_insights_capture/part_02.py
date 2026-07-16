from __future__ import annotations

from ._shared import *
from .part_01 import *

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

def query_hydrolix(sql: str, config: QueryConfig) -> tuple[dict[str, Any], dict[str, Any]]:
    context = None
    if config.url.startswith("https://") and not config.verify_tls:
        context = ssl._create_unverified_context()
    request = urllib.request.Request(
        config.url,
        data=sql.encode("utf-8"),
        headers=config.headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, context=context) as response:
            body = response.read()
            headers = dict(response.headers.items())
            status = response.status
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:1000]
        raise SystemExit(f"Hydrolix query failed with HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise SystemExit(f"Hydrolix query failed: {exc.reason}") from exc

    try:
        parsed = json.loads(body.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit("Hydrolix query did not return valid JSON.") from exc
    if not isinstance(parsed, dict):
        raise SystemExit("Hydrolix query JSON was not a ClickHouse object.")
    return parsed, {"status": status, "headers": headers, "response_bytes": len(body)}

def shape_output(response: Any, shape: str) -> Any:
    if shape == "clickhouse":
        return response
    if shape == "rows":
        if isinstance(response, dict) and isinstance(response.get("data"), list):
            return response["data"]
        if isinstance(response, dict) and isinstance(response.get("rows"), list):
            return response["rows"]
        if isinstance(response, list):
            return response
        raise SystemExit("Cannot shape Hydrolix response as rows: JSON has no data or rows array.")
    raise AssertionError(shape)

def write_json_atomic(path: Path, data: Any) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=str(path.parent),
        prefix=f".{path.name}.",
        suffix=".tmp",
        delete=False,
    ) as handle:
        tmp_path = Path(handle.name)
        json.dump(data, handle, indent=2, sort_keys=True)
        handle.write("\n")
    tmp_path.replace(path)
    return path.stat().st_size

def response_row_count(response: Any, shaped: Any) -> int | None:
    if isinstance(shaped, list):
        return len(shaped)
    if isinstance(response, dict):
        rows = response.get("rows")
        if isinstance(rows, int):
            return rows
        data = response.get("data")
        if isinstance(data, list):
            return len(data)
    return None

def extract_query_stats(meta: dict[str, Any], response: dict[str, Any]) -> dict[str, Any]:
    stats: dict[str, Any] = {}
    if isinstance(response.get("statistics"), dict):
        stats["statistics"] = response["statistics"]
    headers = meta.get("headers") or {}
    for key, value in headers.items():
        if key.lower() == "x-hdx-query-stats":
            try:
                stats["hdx_query_stats"] = json.loads(value)
            except json.JSONDecodeError:
                stats["hdx_query_stats"] = value
    return stats

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
    instruction = (
        "Run Hydrolix MCP run_select_query with the supplied cluster and validated_sql, "
        f"then save the complete JSON result to {output_path}."
    )
    packet: dict[str, Any] = {
        "schema_version": HANDOFF_SCHEMA,
        "cluster": args.cluster,
        "database": args.database,
        "preset": args.preset,
        "report_context": {key: value for key, value in report_context.items() if value is not None},
        "validated_sql": sql,
        "expected_output_shape": args.shape,
        "target_raw_output_path": str(output_path),
        "mcp": {
            "server": "hydrolix_mux",
            "tool": "run_select_query",
            "arguments": {
                "cluster": args.cluster,
                "query": sql,
            },
        },
        "instruction": instruction,
        "credential_status": {
            "configured": False,
            "missing": list(credentials.missing),
            "unresolved_op": list(credentials.unresolved_op),
            "env_file": credentials.env_file,
            "op_resolution": credentials.op_resolution,
        },
    }
    return packet

QueryConfig = hdx.QueryConfig

CredentialState = hdx.CredentialState

parse_env_file = hdx.parse_env_file

file_may_need_op = hdx.file_may_need_op

normalize_query_url = hdx.normalize_query_url

bool_env = hdx.bool_env

first_env = hdx.first_env

is_unresolved_secret = hdx.is_unresolved_secret

secret_error = hdx.secret_error

build_query_config = hdx.build_query_config

ensure_format_json = hdx.ensure_format_json

reject_invalid_sql = hdx.reject_invalid_sql

query_hydrolix = hdx.query_hydrolix

shape_output = hdx.shape_output

write_json_atomic = hdx.write_json_atomic

response_row_count = hdx.response_row_count

extract_query_stats = hdx.extract_query_stats

def cluster_env_dir(env: dict[str, str] | None = None) -> Path:
    return hdx.cluster_env_dir(env, cluster_dir_env=CLUSTER_DIR_ENV)

def cluster_env_path(alias: str, env: dict[str, str] | None = None) -> Path:
    return hdx.cluster_env_path(alias, env, cluster_dir_env=CLUSTER_DIR_ENV)

def should_reexec_with_op(path: Path, env: dict[str, str] | None = None) -> bool:
    return hdx.should_reexec_with_op(path, env, sentinel_env=SENTINEL_ENV)

def reexec_with_op(path: Path) -> None:
    return hdx.reexec_with_op(path, sentinel_env=SENTINEL_ENV)

def resolved_cluster_env_path(cluster: str | None) -> Path | None:
    return hdx.resolved_cluster_env_path(cluster, cluster_dir_env=CLUSTER_DIR_ENV)

def merged_environment(cluster: str | None) -> tuple[dict[str, str], Path | None]:
    return hdx.merged_environment(
        cluster,
        cluster_dir_env=CLUSTER_DIR_ENV,
        sentinel_env=SENTINEL_ENV,
    )

def credential_state(
    env: dict[str, str],
    env_path: Path | None = None,
) -> CredentialState:
    return hdx.credential_state(env, env_path, sentinel_env=SENTINEL_ENV)

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
    response, meta = query_hydrolix(sql, config)
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

if __name__ == "__main__":
    raise SystemExit(main())

__all__ = [name for name in globals() if not name.startswith("__")]
