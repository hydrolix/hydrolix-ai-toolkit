"""Local-input producer for ``bot_threat_hunt.v3`` artifacts."""

from __future__ import annotations

import csv
import glob
import ipaddress
import json
import math
import os
import re
import shutil
import subprocess
import tempfile
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

from producers.formatting import parse_time, sql_literal, sql_ts
from producers.runtime import result_rows
from producers.threat_classifier import attach_classifications, conservative_modifier
from producers.threat_hunt_campaigns import attach_campaigns
from producers.threat_hunt_ua_plausibility import parse_user_agent, score_ua_plausibility


SCHEMA = "bot_threat_hunt.v3"
RAW_COOCCURRENCE_MAX_SECONDS = 21_600
DEFAULT_COOCCURRENCE_TOP_N = 50
DEFAULT_MUX_PROJECT = Path.home() / "src/mcp-hydrolix-mux"


_PATH_MARKERS = {
    "api": ("/api", "/v1", "/v2", "/v3"),
    "catalog": ("catalog", "product", "inventory", "search", "listing"),
    "graphql": ("graphql", "gql"),
    "auth": ("login", "auth", "token", "session", "oauth"),
    "transaction": (
        "checkout",
        "book",
        "booking",
        "reserve",
        "reservation",
        "cart",
        "hold",
        "purchase",
        "payment",
        "order",
    ),
}

_TRACKING_STATIC_PATHS = (
    "/cl/2x2.json",
    "/travel-pixel-js",
    "/egds/fonts",
    "/favicon.ico",
    "/landing-pwa/css",
)

_ENDPOINT_TARGETING_MARKERS = {"api", "catalog", "graphql", "auth"}
_CONFIRMED_ENDPOINT_COVERAGE_PCT = 1.0

_AUTOMATION_UA_MARKERS = (
    "bot",
    "crawl",
    "scrap",
    "spider",
    "python",
    "curl",
    "wget",
    "httpclient",
    "go-http-client",
    "aiohttp",
    "okhttp",
    "java/",
    "headless",
    "playwright",
    "selenium",
)

_KNOWN_INFRASTRUCTURE_UA_PATTERNS = (
    "akamaiimageserver",
    "akamaiimageuploader",
    "velocitudemp",
)

_KNOWN_CRAWLER_UA_PATTERNS = (
    "gsa/",
    "googlebot",
    "adidxbot",
    "bingbot",
    "adsbot-google",
    "mediapartners-google",
)

SCRAPER_EVIDENCE_FAMILIES = (
    "ua_ip_fanout",
    "ua_anomaly",
    "endpoint_targeting",
    "temporal_regularity",
    "baseline_novelty_or_growth",
    "automation_signature",
    "rate_limit_or_error_pressure",
    "infrastructure_topology",
    "classification_gap",
    "coordinated_activity",
)


@dataclass(frozen=True)
class Windows:
    start: str
    end: str
    baseline_start: str
    baseline_end: str


def _num(value: Any, default: float = 0.0) -> float:
    if value is None or value == "":
        return default
    try:
        n = float(value)
    except (TypeError, ValueError):
        return default
    if math.isnan(n) or math.isinf(n):
        return default
    return n


def _int(value: Any) -> int:
    return int(_num(value))


def _first(row: dict[str, Any], names: Iterable[str], default: Any = None) -> Any:
    for name in names:
        if name in row and row[name] not in (None, ""):
            return row[name]
    return default


def _period(row: dict[str, Any]) -> str | None:
    raw = _first(row, ("period", "window", "time_window", "comparison_period"))
    if raw is None:
        return None
    value = str(raw).strip().lower()
    if value in {"current", "after", "curr"}:
        return "current"
    if value in {"baseline", "before", "previous", "prev"}:
        return "baseline"
    return value


def _read_json_rows(path: Path) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return []
    if path.suffix == ".jsonl":
        return [
            row
            for row in (json.loads(line) for line in text.splitlines() if line.strip())
            if isinstance(row, dict)
        ]
    value = json.loads(text)
    if isinstance(value, list):
        return [row for row in value if isinstance(row, dict)]
    if isinstance(value, dict):
        cells = value.get("cells")
        if isinstance(cells, list):
            return [row for row in cells if isinstance(row, dict)]
        columns = value.get("columns")
        rows = value.get("rows")
        if (
            isinstance(columns, list)
            and all(isinstance(col, str) for col in columns)
            and isinstance(rows, list)
        ):
            return [
                dict(zip(columns, row))
                for row in rows
                if isinstance(row, list)
            ]
        return [row for row in result_rows(value) if isinstance(row, dict)]
    return []


def _read_csv_rows(path: Path) -> list[dict[str, Any]]:
    with path.open(newline="", encoding="utf-8") as f:
        return [dict(row) for row in csv.DictReader(f)]


def _read_parquet_rows(path: Path) -> list[dict[str, Any]]:
    try:
        import pyarrow.parquet as pq  # type: ignore[import-not-found]
    except ModuleNotFoundError as exc:
        script = (
            "import json, sys; "
            "import pyarrow.parquet as pq; "
            "print(json.dumps(pq.read_table(sys.argv[1]).to_pylist(), default=str))"
        )
        result = subprocess.run(
            ["uv", "run", "--quiet", "--with", "pyarrow", "python", "-c", script, str(path)],
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise SystemExit(
                "Reading --summary-parquet-glob requires pyarrow for .parquet files. "
                f"uv failed to provision pyarrow: {result.stderr.strip()}"
            ) from exc
        value = json.loads(result.stdout)
        return [row for row in value if isinstance(row, dict)]
    table = pq.read_table(path)
    return table.to_pylist()


def read_rows_from_glob(pattern: str) -> list[dict[str, Any]]:
    paths = [Path(p) for p in sorted(glob.glob(pattern))]
    if not paths:
        raise SystemExit(f"--summary-parquet-glob matched no files: {pattern}")
    rows: list[dict[str, Any]] = []
    for path in paths:
        suffixes = "".join(path.suffixes[-2:])
        if path.suffix == ".parquet":
            rows.extend(_read_parquet_rows(path))
        elif path.suffix in {".json", ".jsonl"}:
            rows.extend(_read_json_rows(path))
        elif path.suffix == ".csv" or suffixes == ".csv.gz":
            rows.extend(_read_csv_rows(path))
        else:
            raise SystemExit(f"Unsupported summary input extension: {path}")
    return rows


def _normalize_summary_row(row: dict[str, Any]) -> dict[str, Any]:
    requests = _num(_first(row, ("requests", "request_count", "count", "hits")))
    bytes_value = _num(
        _first(row, ("bytes", "response_bytes", "total_bytes", "egress_bytes", "sum_totalBytes"))
    )
    if not requests:
        requests = _num(_first(row, ("cnt_all",)))
    status_429 = _num(_first(row, ("status_429", "requests_429", "429", "rate_limited_requests", "req_429")))
    status_5xx = _num(_first(row, ("status_5xx", "requests_5xx", "5xx", "error_5xx_requests", "req_5xx")))
    status_code = str(_first(row, ("statusCode", "status_code"), ""))
    if status_code == "429" and not status_429:
        status_429 = requests
    if status_code.startswith("5") and not status_5xx:
        status_5xx = requests
    return {
        "period": _period(row),
        "request_path": str(
            _first(row, ("request_path", "requestPath", "path", "requestPathPattern"), "")
        ),
        "country": str(_first(row, ("country", "country_code", "client_country"), "")),
        "traffic_cohort": str(
            _first(row, ("trafficCohort", "traffic_cohort", "cohort", "bot_class"), "")
        ),
        "bot_requests": _num(_first(row, ("bot_requests", "bot_like_requests", "bad_bot_requests"))),
        "human_requests": _num(_first(row, ("human_requests", "browser_requests"))),
        "requests": requests,
        "bytes": bytes_value,
        "status_429": status_429,
        "status_5xx": status_5xx,
    }


def _load_actor_file(path: Path, actor_type: str, period: str) -> list[dict[str, Any]]:
    rows = _read_json_rows(path)
    normalized = []
    for row in rows:
        actor_value = _first(
            row,
            (
                actor_type,
                "actor",
                "value",
                "entity",
                "clientIp" if actor_type == "client_ip" else "userAgent",
            ),
        )
        if not actor_value:
            continue
        normalized.append(
            {
                "period": _period(row) or period,
                "actor_type": actor_type,
                "value": str(actor_value),
                "requests": _num(_first(row, ("requests", "request_count", "count", "hits"))),
                "bytes": _num(_first(row, ("bytes", "response_bytes", "total_bytes"))),
                "status_429": _num(_first(row, ("status_429", "requests_429", "429", "req_429"))),
                "status_5xx": _num(_first(row, ("status_5xx", "requests_5xx", "5xx", "req_5xx"))),
                "country": str(_first(row, ("country", "country_code", "client_country"), "")),
                "request_path": str(_first(row, ("request_path", "requestPath", "path"), "")),
            }
        )
    return normalized


def load_raw_actor_rows(raw_actor_dir: str | None) -> list[dict[str, Any]]:
    if not raw_actor_dir:
        return []
    base = Path(raw_actor_dir).expanduser().resolve()
    if not base.is_dir():
        raise SystemExit(f"--raw-actor-dir is not a directory: {base}")
    specs = [
        ("expedia-actors-current-client_ip.json", "client_ip", "current"),
        ("expedia-actors-baseline-client_ip.json", "client_ip", "baseline"),
        ("expedia-actors-current-user_agent.json", "user_agent", "current"),
        ("expedia-actors-baseline-user_agent.json", "user_agent", "baseline"),
    ]
    rows: list[dict[str, Any]] = []
    for filename, actor_type, period in specs:
        path = base / filename
        if path.exists():
            rows.extend(_load_actor_file(path, actor_type, period))
    return rows


def split_raw_cooccurrence_window(
    start: datetime,
    end: datetime,
    *,
    max_seconds: int = RAW_COOCCURRENCE_MAX_SECONDS,
) -> list[tuple[datetime, datetime]]:
    if end <= start:
        raise SystemExit("--end must be later than --start")
    if max_seconds <= 0:
        raise SystemExit("max_seconds must be positive")
    chunks = []
    cursor = start
    delta = timedelta(seconds=max_seconds)
    while cursor < end:
        chunk_end = min(cursor + delta, end)
        chunks.append((cursor, chunk_end))
        cursor = chunk_end
    return chunks


def _top_actor_values(
    actor_rows: list[dict[str, Any]], actor_type: str, top_n: int
) -> list[str]:
    values = [
        (str(row.get("value")), _num(row.get("requests")))
        for row in actor_rows
        if row.get("period") == "current"
        and row.get("actor_type") == actor_type
        and str(row.get("value") or "").strip()
    ]
    values.sort(key=lambda item: (-item[1], item[0]))
    return [value for value, _requests in values[:top_n]]


def _actor_value_field(actor_type: str) -> str:
    if actor_type == "client_ip":
        return "client_ip"
    if actor_type == "user_agent":
        return "user_agent"
    raise AssertionError(actor_type)


def _sql_in(values: list[str]) -> str:
    if not values:
        return "NULL"
    return ", ".join(sql_literal(value) for value in values)


def _raw_actor_sql(
    *,
    database: str,
    actor_type: str,
    start: datetime,
    end: datetime,
    top_n: int,
    bytes_column: str = "bytes",
    path_column: str = "reqPath",
) -> str:
    if actor_type == "client_ip":
        value_expr = "toString(cliIP)"
    elif actor_type == "user_agent":
        value_expr = "toString(UA)"
    else:
        raise AssertionError(actor_type)
    value_field = _actor_value_field(actor_type)
    return f"""
SELECT
  {value_expr} AS {value_field},
  count() AS requests,
  sum({bytes_column}) AS bytes,
  countIf(statusCode = 429) AS status_429,
  countIf(statusCode BETWEEN 500 AND 599) AS status_5xx,
  any(country) AS country,
  any({path_column}) AS request_path
FROM {database}.logs
WHERE reqTimeSec >= toDateTime('{sql_ts(start)}', 'UTC')
  AND reqTimeSec < toDateTime('{sql_ts(end)}', 'UTC')
  AND nullIf({value_expr}, '') IS NOT NULL
GROUP BY {value_field}
ORDER BY requests DESC
LIMIT {int(top_n)}
""".strip()


def _merge_actor_rows(
    rows: Iterable[dict[str, Any]], actor_type: str, top_n: int, period: str
) -> list[dict[str, Any]]:
    value_field = _actor_value_field(actor_type)
    cells: dict[str, dict[str, Any]] = {}
    countries: dict[str, set[str]] = defaultdict(set)
    paths: dict[str, set[str]] = defaultdict(set)
    for row in rows:
        value = str(_first(row, (value_field, "actor", "value", "entity"), "")).strip()
        if not value:
            continue
        cell = cells.setdefault(
            value,
            {
                "period": period,
                actor_type: value,
                "actor_type": actor_type,
                "value": value,
                "requests": 0.0,
                "bytes": 0.0,
                "status_429": 0.0,
                "status_5xx": 0.0,
                "country": "",
                "request_path": "",
            },
        )
        for key in ("requests", "bytes", "status_429", "status_5xx"):
            cell[key] += _num(_first(row, (key, "request_count", "count", "hits")))
        country = str(_first(row, ("country", "country_code"), "")).strip()
        if country:
            countries[value].add(country)
        request_path = str(_first(row, ("request_path", "requestPath", "path"), "")).strip()
        if request_path:
            paths[value].add(request_path)
    for value, cell in cells.items():
        if countries[value]:
            cell["country"] = sorted(countries[value])[0]
        if paths[value]:
            cell["request_path"] = sorted(paths[value])[0]
        for key in ("requests", "bytes", "status_429", "status_5xx"):
            if float(cell[key]).is_integer():
                cell[key] = int(cell[key])
    return sorted(
        cells.values(),
        key=lambda row: (-_num(row.get("requests")), str(row.get("value"))),
    )[:top_n]


def _raw_cooccurrence_sql(
    *,
    database: str,
    start: datetime,
    end: datetime,
    client_ips: list[str],
    user_agents: list[str],
    client_ip_column: str = "cliIP",
    user_agent_column: str = "UA",
    country_column: str = "country",
) -> str:
    return f"""
SELECT
  toString({client_ip_column}) AS client_ip,
  toString({user_agent_column}) AS user_agent,
  any({country_column}) AS country,
  count() AS requests
FROM {database}.logs
WHERE reqTimeSec >= toDateTime('{sql_ts(start)}', 'UTC')
  AND reqTimeSec < toDateTime('{sql_ts(end)}', 'UTC')
  AND {client_ip_column} IN ({_sql_in(client_ips)})
  AND {user_agent_column} IN ({_sql_in(user_agents)})
GROUP BY client_ip, user_agent
ORDER BY requests DESC
""".strip()


def _raw_scraper_drilldown_sql(
    *,
    database: str,
    start: datetime,
    end: datetime,
    client_ips: list[str],
    user_agents: list[str],
    client_ip_column: str = "cliIP",
    user_agent_column: str = "UA",
    country_column: str = "country",
    path_column: str = "reqPath",
    row_limit: int | None = None,
) -> str:
    limit_clause = ""
    if row_limit is not None:
        if row_limit <= 0:
            raise SystemExit("row_limit must be positive")
        limit_clause = f"\nLIMIT {row_limit}"
    return f"""
SELECT
  toString({user_agent_column}) AS user_agent,
  toString({client_ip_column}) AS client_ip,
  toString({path_column}) AS request_path,
  toStartOfHour(reqTimeSec) AS hour,
  any({country_column}) AS country,
  countIf(statusCode = 429) AS status_429,
  countIf(statusCode BETWEEN 500 AND 599) AS status_5xx,
  count() AS requests
FROM {database}.logs
WHERE reqTimeSec >= toDateTime('{sql_ts(start)}', 'UTC')
  AND reqTimeSec < toDateTime('{sql_ts(end)}', 'UTC')
  AND {client_ip_column} IN ({_sql_in(client_ips)})
  AND {user_agent_column} IN ({_sql_in(user_agents)})
GROUP BY user_agent, client_ip, request_path, hour
ORDER BY requests DESC{limit_clause}
""".strip()


def _raw_scraper_hourly_sql(
    *,
    database: str,
    start: datetime,
    end: datetime,
    user_agents: list[str],
    user_agent_column: str = "UA",
) -> str:
    return f"""
SELECT
  toString({user_agent_column}) AS user_agent,
  toStartOfHour(reqTimeSec) AS hour,
  count() AS requests
FROM {database}.logs
WHERE reqTimeSec >= toDateTime('{sql_ts(start)}', 'UTC')
  AND reqTimeSec < toDateTime('{sql_ts(end)}', 'UTC')
  AND {user_agent_column} IN ({_sql_in(user_agents)})
GROUP BY user_agent, hour
ORDER BY user_agent, hour
""".strip()


def _raw_ua_fanout_sql(
    *,
    database: str,
    start: datetime,
    end: datetime,
    user_agents: list[str],
    client_ip_column: str = "cliIP",
    user_agent_column: str = "UA",
) -> str:
    return f"""
SELECT
  toString({user_agent_column}) AS user_agent,
  uniqExact(toString({client_ip_column})) AS unique_ips,
  count() AS hits,
  sum(totalBytes) AS bytes
FROM {database}.logs
WHERE reqTimeSec >= toDateTime('{sql_ts(start)}', 'UTC')
  AND reqTimeSec < toDateTime('{sql_ts(end)}', 'UTC')
  AND {user_agent_column} IN ({_sql_in(user_agents)})
GROUP BY user_agent
ORDER BY unique_ips DESC, hits DESC
""".strip()


def _summary_hour_ua_support_sql(*, database: str) -> str:
    return f"""
SELECT count() AS matching_columns
FROM system.columns
WHERE database = {sql_literal(database)}
  AND table = 'summary_hour'
  AND name = 'UA'
""".strip()


def _summary_hour_fanout_sql(
    *,
    database: str,
    start: datetime,
    end: datetime,
    user_agent: str,
) -> str:
    return f"""
SELECT
  toString(UA) AS user_agent,
  uniqMerge(`uniq(cliIP)`) AS unique_ips,
  countMerge(`count()`) AS hits,
  sumMerge(`sum(totalBytes)`) AS bytes
FROM {database}.summary_hour
WHERE reqTimeSec >= toDateTime('{sql_ts(start)}', 'UTC')
  AND reqTimeSec < toDateTime('{sql_ts(end)}', 'UTC')
  AND UA = {sql_literal(user_agent)}
GROUP BY user_agent
ORDER BY unique_ips DESC, hits DESC
""".strip()


def _logs_probe_fanout_sql(
    *,
    database: str,
    start: datetime,
    end: datetime,
    user_agent: str,
) -> str:
    return f"""
SELECT
  toString(UA) AS user_agent,
  uniqExact(toString(cliIP)) AS unique_ips,
  count() AS hits,
  sum(totalBytes) AS bytes
FROM {database}.logs
WHERE reqTimeSec >= toDateTime('{sql_ts(start)}', 'UTC')
  AND reqTimeSec < toDateTime('{sql_ts(end)}', 'UTC')
  AND UA = {sql_literal(user_agent)}
GROUP BY user_agent
ORDER BY unique_ips DESC, hits DESC
""".strip()


def _raw_background_ua_sample_sql(
    *,
    database: str,
    start: datetime,
    end: datetime,
    excluded_user_agents: list[str],
    min_requests: int = 100,
    max_requests: int = 10_000,
    sample_limit: int = 200,
    client_ip_column: str = "cliIP",
    user_agent_column: str = "UA",
    path_column: str = "reqPath",
) -> str:
    excluded_clause = ""
    if excluded_user_agents:
        excluded_clause = f"\n  AND user_agent NOT IN ({_sql_in(excluded_user_agents)})"
    return f"""
SELECT
  user_agent,
  requests,
  unique_client_ips,
  targeted_endpoint_requests,
  status_429,
  status_5xx,
  any_path
FROM (
  SELECT
    toString({user_agent_column}) AS user_agent,
    count() AS requests,
    uniqExact(toString({client_ip_column})) AS unique_client_ips,
    countIf(
      positionCaseInsensitive(toString({path_column}), '/api') > 0
      OR positionCaseInsensitive(toString({path_column}), 'catalog') > 0
      OR positionCaseInsensitive(toString({path_column}), 'product') > 0
      OR positionCaseInsensitive(toString({path_column}), 'search') > 0
      OR positionCaseInsensitive(toString({path_column}), 'graphql') > 0
      OR positionCaseInsensitive(toString({path_column}), 'auth') > 0
    ) AS targeted_endpoint_requests,
    countIf(statusCode = 429) AS status_429,
    countIf(statusCode BETWEEN 500 AND 599) AS status_5xx,
    any(toString({path_column})) AS any_path
  FROM {database}.logs
  WHERE reqTimeSec >= toDateTime('{sql_ts(start)}', 'UTC')
    AND reqTimeSec < toDateTime('{sql_ts(end)}', 'UTC')
    AND nullIf(toString({user_agent_column}), '') IS NOT NULL
  GROUP BY user_agent
)
WHERE requests BETWEEN {int(min_requests)} AND {int(max_requests)}{excluded_clause}
ORDER BY cityHash64(user_agent)
LIMIT {int(sample_limit)}
""".strip()


def _raw_baseline_ua_timeseries_sql(
    *,
    database: str,
    baseline_start: datetime,
    baseline_end: datetime,
    user_agents: list[str],
    granularity: str = "day",
    user_agent_column: str = "UA",
) -> str:
    if granularity not in {"hour", "day"}:
        raise SystemExit("baseline UA timeseries granularity must be hour or day")
    bucket_expr = "toStartOfHour(reqTimeSec)" if granularity == "hour" else "toDate(reqTimeSec)"
    return f"""
SELECT
  toString({user_agent_column}) AS user_agent,
  {bucket_expr} AS bucket,
  count() AS requests
FROM {database}.logs
WHERE reqTimeSec >= toDateTime('{sql_ts(baseline_start)}', 'UTC')
  AND reqTimeSec < toDateTime('{sql_ts(baseline_end)}', 'UTC')
  AND {user_agent_column} IN ({_sql_in(user_agents)})
GROUP BY user_agent, bucket
ORDER BY user_agent, bucket
""".strip()


def _raw_iat_sample_sql(
    *,
    database: str,
    start: datetime,
    end: datetime,
    client_ips: list[str],
    user_agents: list[str],
    sample_limit_per_ua: int = 5_000,
    client_ip_column: str = "cliIP",
    user_agent_column: str = "UA",
    path_column: str = "reqPath",
) -> str:
    if sample_limit_per_ua <= 0:
        raise SystemExit("sample_limit_per_ua must be positive")
    return f"""
SELECT
  user_agent,
  client_ip,
  reqTimeSec,
  request_path,
  status_code
FROM (
  SELECT
    toString({user_agent_column}) AS user_agent,
    toString({client_ip_column}) AS client_ip,
    reqTimeSec,
    toString({path_column}) AS request_path,
    statusCode AS status_code,
    row_number() OVER (PARTITION BY toString({user_agent_column}) ORDER BY reqTimeSec, toString({client_ip_column})) AS ua_sample_rank
  FROM {database}.logs
  WHERE reqTimeSec >= toDateTime('{sql_ts(start)}', 'UTC')
    AND reqTimeSec < toDateTime('{sql_ts(end)}', 'UTC')
    AND {client_ip_column} IN ({_sql_in(client_ips)})
    AND {user_agent_column} IN ({_sql_in(user_agents)})
)
WHERE ua_sample_rank <= {int(sample_limit_per_ua)}
ORDER BY user_agent, client_ip, reqTimeSec
""".strip()


def export_raw_actor_fixtures(
    *,
    actor_dir: str,
    start: str,
    end: str,
    baseline_start: str,
    baseline_end: str,
    cluster: str,
    database: str = "akamai",
    top_n: int = DEFAULT_COOCCURRENCE_TOP_N,
) -> Path:
    output_dir = Path(actor_dir).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    windows = {
        "current": (parse_time(start, "start"), parse_time(end, "end")),
        "baseline": (
            parse_time(baseline_start, "baseline-start"),
            parse_time(baseline_end, "baseline-end"),
        ),
    }
    with tempfile.TemporaryDirectory(prefix="threat-hunt-actors-") as tmpdir:
        tmp = Path(tmpdir)
        for period, (window_start, window_end) in windows.items():
            for actor_type in ("client_ip", "user_agent"):
                chunk_rows: list[dict[str, Any]] = []
                for index, (chunk_start, chunk_end) in enumerate(
                    split_raw_cooccurrence_window(window_start, window_end),
                    start=1,
                ):
                    chunk_output = tmp / f"{period}-{actor_type}-{index}.json"
                    _run_mux_export(
                        cluster,
                        _raw_actor_sql(
                            database=database,
                            actor_type=actor_type,
                            start=chunk_start,
                            end=chunk_end,
                            top_n=top_n,
                        ),
                        chunk_output,
                    )
                    chunk_rows.extend(_read_json_rows(chunk_output))
                merged = _merge_actor_rows(chunk_rows, actor_type, top_n, period)
                output_path = output_dir / f"expedia-actors-{period}-{actor_type}.json"
                output_path.write_text(
                    json.dumps(merged, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
    return output_dir


def _mux_export_command() -> list[str]:
    mux_project = Path(
        os.environ.get("HYDROLIX_MUX_PROJECT") or DEFAULT_MUX_PROJECT
    ).expanduser()
    if (mux_project / "pyproject.toml").exists():
        uv = shutil.which("uv")
        if uv:
            return [
                uv,
                "run",
                "--project",
                str(mux_project),
                "mcp-hydrolix-mux",
                "export-select-query",
            ]
    binary = shutil.which("mcp-hydrolix-mux")
    if binary:
        return [binary, "export-select-query"]
    raise SystemExit(
        "Could not find mcp-hydrolix-mux. Set HYDROLIX_MUX_PROJECT to the standalone "
        "mcp-hydrolix-mux checkout, or install the mcp-hydrolix-mux console script."
    )


def _run_mux_export(cluster: str, sql: str, output: Path) -> None:
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".sql", delete=False) as handle:
        sql_file = Path(handle.name)
        handle.write(sql)
        handle.write("\n")
    command = [
        *_mux_export_command(),
        "--cluster",
        cluster,
        "--query-file",
        str(sql_file),
        "--output",
        str(output),
    ]
    try:
        result = subprocess.run(command, text=True, capture_output=True, check=False)
    finally:
        sql_file.unlink(missing_ok=True)
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise SystemExit(f"mcp-hydrolix-mux export-select-query failed: {detail}")


def merge_cooccurrence_rows(rows: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    cells: dict[tuple[str, str], dict[str, Any]] = {}
    countries: dict[tuple[str, str], set[str]] = defaultdict(set)
    for row in rows:
        client_ip = str(_first(row, ("client_ip", "clientIp", "cliIP", "ip", "value_a"), "")).strip()
        user_agent = str(_first(row, ("user_agent", "userAgent", "UA", "ua", "value_b"), "")).strip()
        if not client_ip or not user_agent:
            continue
        key = (client_ip, user_agent)
        cell = cells.setdefault(
            key,
            {"client_ip": client_ip, "user_agent": user_agent, "country": "", "requests": 0.0},
        )
        cell["requests"] += _num(_first(row, ("requests", "request_count", "count", "hits")))
        country = str(_first(row, ("country", "country_code"), "")).strip()
        if country:
            countries[key].add(country)
    for key, cell in cells.items():
        if countries[key]:
            cell["country"] = sorted(countries[key])[0]
        if float(cell["requests"]).is_integer():
            cell["requests"] = int(cell["requests"])
    return sorted(
        cells.values(),
        key=lambda row: (-_num(row.get("requests")), str(row.get("client_ip")), str(row.get("user_agent"))),
    )


def merge_scraper_drilldown_rows(rows: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    cells: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    countries: dict[tuple[str, str, str, str], set[str]] = defaultdict(set)
    for row in rows:
        user_agent = str(_first(row, ("user_agent", "userAgent", "UA", "ua"), "")).strip()
        client_ip = str(_first(row, ("client_ip", "clientIp", "cliIP", "ip"), "")).strip()
        request_path = str(_first(row, ("request_path", "requestPath", "path", "reqPath"), "")).strip()
        hour = str(_first(row, ("hour", "bucket", "timestamp"), "")).strip()
        if not user_agent or not client_ip:
            continue
        key = (user_agent, client_ip, request_path, hour)
        cell = cells.setdefault(
            key,
            {
                "user_agent": user_agent,
                "client_ip": client_ip,
                "request_path": request_path,
                "hour": hour,
                "country": "",
                "status_429": 0.0,
                "status_5xx": 0.0,
                "requests": 0.0,
            },
        )
        cell["status_429"] += _num(_first(row, ("status_429", "requests_429", "429", "req_429")))
        cell["status_5xx"] += _num(_first(row, ("status_5xx", "requests_5xx", "5xx", "req_5xx")))
        cell["requests"] += _num(_first(row, ("requests", "request_count", "count", "hits")))
        country = str(_first(row, ("country", "country_code"), "")).strip()
        if country:
            countries[key].add(country)
    for key, cell in cells.items():
        if countries[key]:
            cell["country"] = sorted(countries[key])[0]
        for numeric in ("status_429", "status_5xx", "requests"):
            if float(cell[numeric]).is_integer():
                cell[numeric] = int(cell[numeric])
    return sorted(
        cells.values(),
        key=lambda row: (
            -_num(row.get("requests")),
            str(row.get("user_agent")),
            str(row.get("client_ip")),
            str(row.get("request_path")),
            str(row.get("hour")),
        ),
    )


def merge_iat_sample_rows(rows: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized = []
    seen: set[tuple[str, str, str, str, str]] = set()
    for row in rows:
        user_agent = str(_first(row, ("user_agent", "userAgent", "UA", "ua"), "")).strip()
        client_ip = str(_first(row, ("client_ip", "clientIp", "cliIP", "ip"), "")).strip()
        timestamp = _first(row, ("timestamp", "reqTimeSec", "request_time", "time"))
        if not user_agent or not client_ip or timestamp in (None, ""):
            continue
        request_path = str(_first(row, ("request_path", "requestPath", "path", "reqPath"), "")).strip()
        status_code = str(_first(row, ("status_code", "statusCode"), "")).strip()
        key = (user_agent, client_ip, str(timestamp), request_path, status_code)
        if key in seen:
            continue
        seen.add(key)
        cell = {
            "user_agent": user_agent,
            "client_ip": client_ip,
            "timestamp": timestamp,
            "request_path": request_path,
            "status_code": status_code,
        }
        response_time = _first(row, ("response_time_ms", "responseTimeMs", "responseTime", "duration_ms"))
        if response_time not in (None, ""):
            cell["response_time_ms"] = _num(response_time)
        normalized.append(cell)
    return sorted(
        normalized,
        key=lambda row: (
            str(row.get("user_agent")),
            str(row.get("client_ip")),
            _timestamp_seconds(row.get("timestamp")) or 0.0,
            str(row.get("request_path")),
        ),
    )


def export_raw_ua_cooccurrence(
    *,
    actor_dir: str,
    start: str,
    end: str,
    cluster: str,
    database: str = "akamai",
    top_n: int = DEFAULT_COOCCURRENCE_TOP_N,
    output: str,
) -> list[dict[str, Any]]:
    actor_rows = load_raw_actor_rows(actor_dir)
    client_ips = _top_actor_values(actor_rows, "client_ip", top_n)
    user_agents = _top_actor_values(actor_rows, "user_agent", top_n)
    if not client_ips:
        raise SystemExit("--raw-actor-dir has no current client_ip actors")
    if not user_agents:
        raise SystemExit("--raw-actor-dir has no current user_agent actors")

    start_dt = parse_time(start, "start")
    end_dt = parse_time(end, "end")
    output_path = Path(output).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    chunk_rows: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="threat-hunt-cooccurrence-") as tmpdir:
        tmp = Path(tmpdir)
        for index, (chunk_start, chunk_end) in enumerate(
            split_raw_cooccurrence_window(start_dt, end_dt), start=1
        ):
            chunk_output = tmp / f"chunk-{index}.json"
            _run_mux_export(
                cluster,
                _raw_cooccurrence_sql(
                    database=database,
                    start=chunk_start,
                    end=chunk_end,
                    client_ips=client_ips,
                    user_agents=user_agents,
                ),
                chunk_output,
            )
            chunk_rows.extend(_read_json_rows(chunk_output))

    merged = merge_cooccurrence_rows(chunk_rows)
    output_path.write_text(json.dumps(merged, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return merged


def _top_scraper_user_agents(
    actor_rows: list[dict[str, Any]],
    cooccurrence_rows: list[dict[str, Any]],
    top_leads: int,
) -> list[str]:
    requests_by_ua: Counter[str] = Counter()
    for row in actor_rows:
        if row.get("period") == "current" and row.get("actor_type") == "user_agent":
            value = str(row.get("value") or "").strip()
            if value:
                requests_by_ua[value] += _num(row.get("requests"))
    for row in cooccurrence_rows:
        value = str(row.get("user_agent") or "").strip()
        if value and value not in requests_by_ua:
            requests_by_ua[value] += _num(row.get("requests"))
    return [
        ua
        for ua, _requests in sorted(
            requests_by_ua.items(), key=lambda item: (-item[1], item[0])
        )[:top_leads]
    ]


def _is_public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def scraper_drilldown_scope(
    *,
    actor_dir: str,
    cooccurrence_in: str,
    start: str,
    end: str,
    database: str = "akamai",
    top_leads: int = 5,
    chunk_seconds: int = 3_600,
    row_limit_per_chunk: int | None = None,
    include_non_public_ips: bool = False,
) -> dict[str, Any]:
    actor_rows = load_raw_actor_rows(actor_dir)
    cooccurrence = _cooccurrence_rows(cooccurrence_in, "ua")
    user_agents = _top_scraper_user_agents(actor_rows, cooccurrence, top_leads)
    if not user_agents:
        raise SystemExit("--cooccurrence-in or --actor-dir has no current user_agent rows")

    selected_user_agents = set(user_agents)
    all_scoped_ips = sorted(
        {
            str(row.get("client_ip")).strip()
            for row in cooccurrence
            if row.get("user_agent") in selected_user_agents and row.get("client_ip")
        }
    )
    client_ips = [
        ip
        for ip in all_scoped_ips
        if include_non_public_ips or _is_public_ip(ip)
    ]
    if not client_ips:
        raise SystemExit("--cooccurrence-in has no public client_ip rows for selected user agents")

    start_dt = parse_time(start, "start")
    end_dt = parse_time(end, "end")
    chunks = split_raw_cooccurrence_window(
        start_dt, end_dt, max_seconds=chunk_seconds
    )
    first_start, first_end = chunks[0]
    return {
        "selected_user_agents": user_agents,
        "selected_client_ips": client_ips,
        "excluded_non_public_client_ips": [
            ip for ip in all_scoped_ips if ip not in set(client_ips)
        ],
        "chunks": [
            {
                "start": chunk_start.isoformat().replace("+00:00", "Z"),
                "end": chunk_end.isoformat().replace("+00:00", "Z"),
            }
            for chunk_start, chunk_end in chunks
        ],
        "first_sql": _raw_scraper_drilldown_sql(
            database=database,
            start=first_start,
            end=first_end,
            client_ips=client_ips,
            user_agents=user_agents,
            row_limit=row_limit_per_chunk,
        ),
    }


def iat_sample_scope(
    *,
    actor_dir: str,
    cooccurrence_in: str,
    start: str,
    end: str,
    database: str = "akamai",
    top_leads: int = 25,
    sample_limit_per_ua: int = 5_000,
    include_non_public_ips: bool = False,
) -> dict[str, Any]:
    actor_rows = load_raw_actor_rows(actor_dir)
    cooccurrence = _cooccurrence_rows(cooccurrence_in, "ua")
    user_agents = _top_scraper_user_agents(actor_rows, cooccurrence, top_leads)
    if not user_agents:
        raise SystemExit("--cooccurrence-in or --actor-dir has no current user_agent rows")

    selected_user_agents = set(user_agents)
    all_scoped_ips = sorted(
        {
            str(row.get("client_ip")).strip()
            for row in cooccurrence
            if row.get("user_agent") in selected_user_agents and row.get("client_ip")
        }
    )
    client_ips = [
        ip
        for ip in all_scoped_ips
        if include_non_public_ips or _is_public_ip(ip)
    ]
    if not client_ips:
        raise SystemExit("--cooccurrence-in has no public client_ip rows for selected user agents")

    start_dt = parse_time(start, "start")
    end_dt = parse_time(end, "end")
    return {
        "selected_user_agents": user_agents,
        "selected_client_ips": client_ips,
        "excluded_non_public_client_ips": [
            ip for ip in all_scoped_ips if ip not in set(client_ips)
        ],
        "sample_limit_per_ua": sample_limit_per_ua,
        "sample_sql": _raw_iat_sample_sql(
            database=database,
            start=start_dt,
            end=end_dt,
            client_ips=client_ips,
            user_agents=user_agents,
            sample_limit_per_ua=sample_limit_per_ua,
        ),
    }


def export_scraper_drilldowns(
    *,
    actor_dir: str,
    cooccurrence_in: str,
    start: str,
    end: str,
    cluster: str,
    database: str = "akamai",
    top_leads: int = 5,
    output: str,
    chunk_seconds: int = 3_600,
    row_limit_per_chunk: int | None = 100_000,
    include_non_public_ips: bool = False,
    run_summary: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    scope = scraper_drilldown_scope(
        actor_dir=actor_dir,
        cooccurrence_in=cooccurrence_in,
        start=start,
        end=end,
        database=database,
        top_leads=top_leads,
        chunk_seconds=chunk_seconds,
        row_limit_per_chunk=row_limit_per_chunk,
        include_non_public_ips=include_non_public_ips,
    )
    start_dt = parse_time(start, "start")
    end_dt = parse_time(end, "end")
    user_agents = scope["selected_user_agents"]
    client_ips = scope["selected_client_ips"]
    output_path = Path(output).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    chunk_rows: list[dict[str, Any]] = []
    chunk_row_counts: list[int] = []
    with tempfile.TemporaryDirectory(prefix="threat-hunt-scraper-drilldown-") as tmpdir:
        tmp = Path(tmpdir)
        for index, (chunk_start, chunk_end) in enumerate(
            split_raw_cooccurrence_window(start_dt, end_dt, max_seconds=chunk_seconds),
            start=1,
        ):
            chunk_output = tmp / f"chunk-{index}.json"
            _run_mux_export(
                cluster,
                _raw_scraper_drilldown_sql(
                    database=database,
                    start=chunk_start,
                    end=chunk_end,
                    client_ips=client_ips,
                    user_agents=user_agents,
                    row_limit=row_limit_per_chunk,
                ),
                chunk_output,
            )
            rows = _read_json_rows(chunk_output)
            chunk_row_counts.append(len(rows))
            chunk_rows.extend(rows)

    merged = merge_scraper_drilldown_rows(chunk_rows)
    output_path.write_text(json.dumps(merged, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if run_summary is not None:
        run_summary.clear()
        run_summary.update(
            {
                "rows": len(merged),
                "selected_user_agents": user_agents,
                "selected_client_ips": client_ips,
                "excluded_non_public_client_ips": scope["excluded_non_public_client_ips"],
                "chunks": len(scope["chunks"]),
                "chunk_row_counts": chunk_row_counts,
            }
        )
    return merged


def export_scraper_hourly_profiles(
    *,
    actor_dir: str,
    cooccurrence_in: str | None,
    start: str,
    end: str,
    cluster: str,
    database: str = "akamai",
    top_leads: int = 25,
    output: str,
    chunk_seconds: int = RAW_COOCCURRENCE_MAX_SECONDS,
    run_summary: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    if chunk_seconds <= 0:
        raise SystemExit("chunk_seconds must be positive")
    actor_rows = load_raw_actor_rows(actor_dir)
    cooccurrence = _cooccurrence_rows(cooccurrence_in, "ua") if cooccurrence_in else []
    user_agents = _top_scraper_user_agents(actor_rows, cooccurrence, top_leads)
    if not user_agents:
        raise SystemExit("--actor-dir or --cooccurrence-in has no current user_agent rows")
    output_path = Path(output).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    start_dt = parse_time(start, "start")
    end_dt = parse_time(end, "end")
    chunk_rows: list[dict[str, Any]] = []
    chunk_row_counts: list[int] = []
    with tempfile.TemporaryDirectory(prefix="threat-hunt-scraper-hourly-") as tmpdir:
        tmp = Path(tmpdir)
        chunks = split_raw_cooccurrence_window(start_dt, end_dt, max_seconds=chunk_seconds)
        for index, (chunk_start, chunk_end) in enumerate(chunks, start=1):
            raw_output = tmp / f"scraper-hourly-{index}.json"
            _run_mux_export(
                cluster,
                _raw_scraper_hourly_sql(
                    database=database,
                    start=chunk_start,
                    end=chunk_end,
                    user_agents=user_agents,
                ),
                raw_output,
            )
            rows = _read_json_rows(raw_output)
            chunk_row_counts.append(len(rows))
            chunk_rows.extend(rows)
    merged = merge_scraper_hourly_rows(chunk_rows)
    output_path.write_text(json.dumps(merged, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if run_summary is not None:
        run_summary.clear()
        run_summary.update(
            {
                "rows": len(merged),
                "selected_user_agents": user_agents,
                "chunks": len(chunk_row_counts),
                "chunk_row_counts": chunk_row_counts,
            }
        )
    return merged


def _normalize_fanout_source(value: Any) -> str:
    source = str(value or "").strip() or "summary_hour"
    aliases = {
        "ua_fanout": "summary_hour",
        "exact_ua": "summary_hour",
        "scoped_fallback": "cooccurrence_lower_bound",
        "cooccurrence": "cooccurrence_lower_bound",
    }
    return aliases.get(source, source)


def _fanout_caveat(source: str, probe_window_hours: float | None = None) -> str:
    if source == "summary_hour":
        return "Full-window summary-hour unique-IP count for this byte-identical UA."
    if source == "logs_probe":
        hours = probe_window_hours or 1.0
        return (
            f"Peak-hour raw-log probe over {hours:g} hour(s); effective IPs use a conservative bounded "
            "24h lower-bound estimate, not a full-window exact union."
        )
    if source == "cooccurrence_lower_bound":
        return "Lower bound from existing UA/IP cooccurrence evidence; true full-window fan-out is unknown."
    return "Fan-out enrichment source is not available."


def _fanout_effective_ips(row: dict[str, Any]) -> float:
    unique_ips = _num(row.get("effective_ips") or row.get("unique_ips") or row.get("unique_client_ips"))
    if str(row.get("source") or "") == "logs_probe":
        hours = _num(row.get("probe_window_hours"), 1.0) or 1.0
        return unique_ips * min(hours * 3.0, 24.0)
    return unique_ips


def merge_fanout_rows(rows: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for row in rows:
        user_agent = str(_first(row, ("user_agent", "userAgent", "UA", "ua"), "")).strip()
        if not user_agent:
            continue
        source = _normalize_fanout_source(_first(row, ("source", "fanout_source"), "summary_hour"))
        probe_window_hours = _num(_first(row, ("probe_window_hours", "probe_hours", "window_hours")), 0.0) or None
        cell = merged.setdefault(
            user_agent,
            {
                "user_agent": user_agent,
                "unique_ips": 0.0,
                "hits": 0.0,
                "bytes": 0.0,
                "source": source,
                "probe_window_hours": probe_window_hours,
            },
        )
        source_rank = {"summary_hour": 3, "logs_probe": 2, "cooccurrence_lower_bound": 1}
        if source_rank.get(source, 0) > source_rank.get(str(cell.get("source")), 0):
            cell["source"] = source
        if probe_window_hours is not None:
            cell["probe_window_hours"] = min(
                probe_window_hours,
                _num(cell.get("probe_window_hours"), probe_window_hours) or probe_window_hours,
            )
        cell["unique_ips"] = max(
            _num(cell.get("unique_ips")),
            _num(_first(row, ("unique_ips", "unique_client_ips", "distinct_client_ips", "client_ip_count", "ips"))),
        )
        cell["hits"] += _num(_first(row, ("hits", "requests", "request_count", "count")))
        cell["bytes"] += _num(_first(row, ("bytes", "total_bytes", "sum_totalBytes")))
    out = []
    for row in merged.values():
        unique_ips = int(row["unique_ips"])
        hits = int(row["hits"]) if float(row["hits"]).is_integer() else row["hits"]
        bytes_value = int(row["bytes"]) if float(row["bytes"]).is_integer() else row["bytes"]
        source = str(row.get("source") or "summary_hour")
        out.append(
            {
                "user_agent": row["user_agent"],
                "unique_ips": unique_ips,
                "effective_ips": int(_fanout_effective_ips({**row, "unique_ips": unique_ips})),
                "hits": hits,
                "bytes": bytes_value,
                "source": source,
                "probe_window_hours": row.get("probe_window_hours"),
                "caveat": _fanout_caveat(source, row.get("probe_window_hours")),
                # Backward-compatible field names for older callers/tests.
                "unique_client_ips": unique_ips,
                "requests": hits,
            }
        )
    return sorted(out, key=lambda row: (-_num(row.get("unique_ips")), -_num(row.get("hits")), str(row.get("user_agent"))))


def merge_ua_fanout_rows(rows: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    return merge_fanout_rows(rows)


def cooccurrence_fanout_lower_bound_rows(rows: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    ips_by_ua: dict[str, set[str]] = defaultdict(set)
    hits_by_ua: Counter[str] = Counter()
    bytes_by_ua: Counter[str] = Counter()
    for row in rows:
        user_agent = str(_first(row, ("user_agent", "userAgent", "UA", "ua"), "")).strip()
        client_ip = str(_first(row, ("client_ip", "clientIp", "cliIP", "ip"), "")).strip()
        if not user_agent:
            continue
        if client_ip:
            ips_by_ua[user_agent].add(client_ip)
        hits_by_ua[user_agent] += _num(_first(row, ("hits", "requests", "request_count", "count")))
        bytes_by_ua[user_agent] += _num(_first(row, ("bytes", "total_bytes", "sum_totalBytes")))
    return merge_fanout_rows(
        {
            "user_agent": ua,
            "unique_ips": len(ips),
            "hits": hits_by_ua.get(ua, 0),
            "bytes": bytes_by_ua.get(ua, 0),
            "source": "cooccurrence_lower_bound",
        }
        for ua, ips in ips_by_ua.items()
    )


def export_ua_fanout(
    *,
    actor_dir: str,
    start: str,
    end: str,
    cluster: str,
    database: str = "akamai",
    top_leads: int = 25,
    output: str,
    run_summary: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    actor_rows = load_raw_actor_rows(actor_dir)
    user_agents = _top_actor_values(actor_rows, "user_agent", top_leads)
    if not user_agents:
        raise SystemExit("--raw-actor-dir has no current user_agent actors")
    output_path = Path(output).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    raw_output = output_path.with_suffix(output_path.suffix + ".raw")
    _run_mux_export(
        cluster,
        _raw_ua_fanout_sql(
            database=database,
            start=parse_time(start, "start"),
            end=parse_time(end, "end"),
            user_agents=user_agents,
        ),
        raw_output,
    )
    merged = merge_ua_fanout_rows(_read_json_rows(raw_output))
    raw_output.unlink(missing_ok=True)
    output_path.write_text(json.dumps(merged, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if run_summary is not None:
        run_summary.clear()
        run_summary.update({"rows": len(merged), "selected_user_agents": user_agents})
    return merged


def _summary_hour_supports_ua(*, cluster: str, database: str) -> bool:
    with tempfile.TemporaryDirectory(prefix="threat-hunt-summary-hour-probe-") as tmpdir:
        output = Path(tmpdir) / "summary-hour-support.json"
        try:
            _run_mux_export(cluster, _summary_hour_ua_support_sql(database=database), output)
            rows = _read_json_rows(output)
        except SystemExit:
            return False
    for row in rows:
        if _num(_first(row, ("matching_columns", "count", "count()"))) > 0:
            return True
    return False


def _hour_start(value: Any) -> datetime | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).replace(minute=0, second=0, microsecond=0)


def _peak_hours_by_ua(hourly_rows: list[dict[str, Any]]) -> dict[str, datetime]:
    peaks: dict[str, tuple[float, datetime]] = {}
    for row in hourly_rows:
        user_agent = str(_first(row, ("user_agent", "userAgent", "UA", "ua"), "")).strip()
        hour = _hour_start(_first(row, ("hour", "bucket", "timestamp")))
        if not user_agent or hour is None:
            continue
        requests = _num(_first(row, ("requests", "request_count", "count", "hits")))
        if user_agent not in peaks or requests > peaks[user_agent][0]:
            peaks[user_agent] = (requests, hour)
    return {ua: hour for ua, (_requests, hour) in peaks.items()}


def _export_fanout_query_rows(
    *,
    cluster: str,
    sql_rows: list[tuple[str, str]],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="threat-hunt-fanout-") as tmpdir:
        tmp = Path(tmpdir)
        for index, (source, sql) in enumerate(sql_rows, start=1):
            output = tmp / f"fanout-{index}.json"
            _run_mux_export(cluster, sql, output)
            for row in _read_json_rows(output):
                if isinstance(row, dict):
                    rows.append({**row, "source": source})
    return rows


def export_fanout_enrichment(
    *,
    actor_dir: str,
    start: str,
    end: str,
    cluster: str,
    database: str = "akamai",
    top_leads: int = 25,
    output: str,
    strategy: str = "auto",
    scraper_hourly_in: str | None = None,
    cooccurrence_in: str | None = None,
    run_summary: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    if strategy not in {"auto", "summary_hour", "logs_probe", "skip"}:
        raise SystemExit("--fanout-strategy must be one of auto, summary_hour, logs_probe, skip")
    actor_rows = load_raw_actor_rows(actor_dir)
    user_agents = _top_actor_values(actor_rows, "user_agent", top_leads)
    if not user_agents:
        raise SystemExit("--raw-actor-dir has no current user_agent actors")
    start_dt = parse_time(start, "start")
    end_dt = parse_time(end, "end")
    output_path = Path(output).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    errors: list[str] = []
    selected_strategy = strategy
    rows: list[dict[str, Any]] = []

    if strategy in {"auto", "summary_hour"}:
        if _summary_hour_supports_ua(cluster=cluster, database=database):
            try:
                rows = _export_fanout_query_rows(
                    cluster=cluster,
                    sql_rows=[
                        (
                            "summary_hour",
                            _summary_hour_fanout_sql(
                                database=database,
                                start=start_dt,
                                end=end_dt,
                                user_agent=user_agent,
                            ),
                        )
                        for user_agent in user_agents
                    ],
                )
                selected_strategy = "summary_hour"
            except SystemExit as exc:
                errors.append(str(exc))
                rows = []
        elif strategy == "summary_hour":
            errors.append(f"{database}.summary_hour does not expose UA in system.columns")
        if strategy == "summary_hour" and not rows:
            raise SystemExit("--fanout-strategy summary_hour could not produce usable fan-out rows: " + "; ".join(errors))

    if strategy in {"auto", "logs_probe"} and not rows:
        hourly = _scraper_hourly_rows(scraper_hourly_in)
        peak_hours = _peak_hours_by_ua(hourly)
        missing = [ua for ua in user_agents if ua not in peak_hours]
        if peak_hours:
            try:
                rows = _export_fanout_query_rows(
                    cluster=cluster,
                    sql_rows=[
                        (
                            "logs_probe",
                            _logs_probe_fanout_sql(
                                database=database,
                                start=hour,
                                end=min(hour + timedelta(hours=1), end_dt),
                                user_agent=user_agent,
                            ),
                        )
                        for user_agent, hour in peak_hours.items()
                        if user_agent in user_agents
                    ],
                )
                rows = [{**row, "probe_window_hours": 1} for row in rows]
                selected_strategy = "logs_probe"
            except SystemExit as exc:
                errors.append(str(exc))
                rows = []
        elif strategy == "logs_probe":
            errors.append("--fanout-strategy logs_probe requires --scraper-hourly-in peak-hour rows")
        if strategy == "logs_probe" and (not rows or missing):
            raise SystemExit(
                "--fanout-strategy logs_probe could not produce usable fan-out rows"
                + (f"; missing peak-hour rows for {len(missing)} lead UA(s)" if missing else "")
                + ("; " + "; ".join(errors) if errors else "")
            )

    if strategy in {"auto", "skip"} and not rows:
        rows = cooccurrence_fanout_lower_bound_rows(_cooccurrence_rows(cooccurrence_in, "ua"))
        selected_strategy = "cooccurrence_lower_bound" if rows else "skip"
        if strategy == "skip" and not rows:
            selected_strategy = "skip"

    merged = merge_fanout_rows(rows)
    output_path.write_text(json.dumps(merged, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if run_summary is not None:
        run_summary.clear()
        run_summary.update(
            {
                "rows": len(merged),
                "selected_user_agents": user_agents,
                "strategy": selected_strategy,
                "fallback_errors": errors,
            }
        )
    return merged


def export_background_ua_sample(
    *,
    start: str,
    end: str,
    cluster: str,
    database: str = "akamai",
    excluded_user_agents: list[str] | None = None,
    output: str,
    sample_limit: int = 200,
    run_summary: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    output_path = Path(output).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    raw_output = output_path.with_suffix(output_path.suffix + ".raw")
    _run_mux_export(
        cluster,
        _raw_background_ua_sample_sql(
            database=database,
            start=parse_time(start, "start"),
            end=parse_time(end, "end"),
            excluded_user_agents=excluded_user_agents or [],
            sample_limit=sample_limit,
        ),
        raw_output,
    )
    rows = _read_json_rows(raw_output)
    raw_output.unlink(missing_ok=True)
    output_path.write_text(json.dumps(rows, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if run_summary is not None:
        run_summary.clear()
        run_summary.update({"rows": len(rows), "sample_limit": sample_limit})
    return rows


def export_baseline_ua_timeseries(
    *,
    baseline_start: str,
    baseline_end: str,
    user_agents: list[str],
    cluster: str,
    database: str = "akamai",
    output: str,
    granularity: str = "day",
    run_summary: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    if not user_agents:
        raise SystemExit("baseline significance export requires selected user agents")
    output_path = Path(output).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    raw_output = output_path.with_suffix(output_path.suffix + ".raw")
    _run_mux_export(
        cluster,
        _raw_baseline_ua_timeseries_sql(
            database=database,
            baseline_start=parse_time(baseline_start, "baseline-start"),
            baseline_end=parse_time(baseline_end, "baseline-end"),
            user_agents=user_agents,
            granularity=granularity,
        ),
        raw_output,
    )
    rows = _read_json_rows(raw_output)
    raw_output.unlink(missing_ok=True)
    output_path.write_text(json.dumps(rows, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if run_summary is not None:
        run_summary.clear()
        run_summary.update(
            {"rows": len(rows), "selected_user_agents": user_agents, "granularity": granularity}
        )
    return rows


def export_iat_samples(
    *,
    actor_dir: str,
    cooccurrence_in: str,
    start: str,
    end: str,
    cluster: str,
    database: str = "akamai",
    top_leads: int = 25,
    sample_limit_per_ua: int = 5_000,
    output: str,
    include_non_public_ips: bool = False,
    run_summary: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    scope = iat_sample_scope(
        actor_dir=actor_dir,
        cooccurrence_in=cooccurrence_in,
        start=start,
        end=end,
        database=database,
        top_leads=top_leads,
        sample_limit_per_ua=sample_limit_per_ua,
        include_non_public_ips=include_non_public_ips,
    )
    output_path = Path(output).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="threat-hunt-iat-samples-") as tmpdir:
        raw_output = Path(tmpdir) / "iat-samples.json"
        _run_mux_export(cluster, str(scope["sample_sql"]), raw_output)
        merged = merge_iat_sample_rows(_read_json_rows(raw_output))
    output_path.write_text(json.dumps(merged, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if run_summary is not None:
        run_summary.clear()
        run_summary.update(
            {
                "rows": len(merged),
                "selected_user_agents": scope["selected_user_agents"],
                "selected_client_ips": scope["selected_client_ips"],
                "excluded_non_public_client_ips": scope["excluded_non_public_client_ips"],
                "sample_limit_per_ua": sample_limit_per_ua,
            }
        )
    return merged


def _read_optional_rows(path_value: str | None) -> list[dict[str, Any]]:
    if not path_value:
        return []
    path = Path(path_value).expanduser().resolve()
    if path.suffix in {".json", ".jsonl"}:
        return _read_json_rows(path)
    if path.suffix == ".csv":
        return _read_csv_rows(path)
    if path.suffix == ".parquet":
        return _read_parquet_rows(path)
    raise SystemExit(f"Unsupported optional artifact extension: {path}")


def _geoip_map(paths: Iterable[str | None]) -> dict[str, dict[str, Any]]:
    mapping: dict[str, dict[str, Any]] = {}
    for path_value in paths:
        for row in _read_optional_rows(path_value):
            ip = _first(row, ("client_ip", "ip", "network", "prefix"))
            if not ip:
                continue
            mapping[str(ip)] = {
                "asn": _first(row, ("asn", "autonomous_system_number", "client_asn")),
                "asn_org": _first(row, ("asn_org", "organization", "org", "as_name")),
                "country": _first(row, ("country", "country_code")),
            }
    return mapping


def _geo_for_ip(ip: str, geo: dict[str, dict[str, Any]]) -> dict[str, Any]:
    if ip in geo:
        return geo[ip]
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return {}
    for key, value in geo.items():
        try:
            network = ipaddress.ip_network(key, strict=False)
        except ValueError:
            continue
        if address in network:
            return value
    return {}


def _sum_period(rows: Iterable[dict[str, Any]], period: str) -> dict[str, float]:
    totals = defaultdict(float)
    for row in rows:
        if row.get("period") != period:
            continue
        for key in ("requests", "bytes", "status_429", "status_5xx", "bot_requests", "human_requests"):
            totals[key] += _num(row.get(key))
    return dict(totals)


def _pct(part: float, whole: float) -> float | None:
    if whole <= 0:
        return None
    return part / whole * 100.0


def _metric_delta(name: str, current: dict[str, float], baseline: dict[str, float]) -> dict[str, Any]:
    cur = current.get(name, 0.0)
    base = baseline.get(name, 0.0)
    return {
        "metric": name,
        "current": cur,
        "baseline": base,
        "absolute_delta": cur - base,
        "pct_change": _pct(cur - base, base),
    }


def _rank_dimension(rows: list[dict[str, Any]], field: str, top_n: int) -> list[dict[str, Any]]:
    by_value: dict[str, dict[str, float]] = defaultdict(lambda: defaultdict(float))
    for row in rows:
        if row.get("period") != "current":
            continue
        value = str(row.get(field) or "").strip()
        if not value:
            continue
        bucket = by_value[value]
        for key in ("requests", "bytes", "status_429", "status_5xx"):
            bucket[key] += _num(row.get(key))
    ranked = sorted(by_value.items(), key=lambda item: (-item[1]["requests"], item[0]))
    out = []
    for rank, (value, metrics) in enumerate(ranked[:top_n], start=1):
        requests = metrics.get("requests", 0.0)
        out.append(
            {
                "rank": rank,
                "value": value,
                "requests": requests,
                "bytes": metrics.get("bytes", 0.0),
                "rate_429_pct": _pct(metrics.get("status_429", 0.0), requests),
                "rate_5xx_pct": _pct(metrics.get("status_5xx", 0.0), requests),
            }
        )
    return out


def _path_markers(path: str) -> list[str]:
    lowered = path.lower()
    if _is_tracking_static_path(lowered):
        return []
    return [
        marker
        for marker, needles in _PATH_MARKERS.items()
        if any(needle in lowered for needle in needles)
    ]


def _is_tracking_static_path(path: str) -> bool:
    lowered = str(path or "").lower()
    return any(lowered.startswith(prefix) for prefix in _TRACKING_STATIC_PATHS)


def _endpoint_category(path: str, markers: list[str] | None = None) -> str:
    lowered = str(path or "").lower()
    markers = markers if markers is not None else _path_markers(lowered)
    if markers:
        if "graphql" in markers:
            return "graphql"
        if "auth" in markers:
            return "auth"
        if "transaction" in markers:
            return "transaction"
        if "catalog" in markers:
            return "catalog_search_product_content"
        if "api" in markers:
            return "api"
    if _is_tracking_static_path(lowered):
        return "tracking_static_asset"
    if lowered.endswith((".css", ".js", ".ico", ".woff", ".woff2", ".ttf", ".png", ".jpg", ".jpeg", ".gif", ".svg")):
        return "static_asset"
    return "general_site"


def _endpoint_targeting_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        row
        for row in rows
        if set(row.get("markers") or []) & _ENDPOINT_TARGETING_MARKERS
    ]


def _endpoint_rows(summary_rows: list[dict[str, Any]], top_n: int) -> list[dict[str, Any]]:
    rows = _rank_dimension(summary_rows, "request_path", top_n)
    total = sum(_num(row.get("requests")) for row in rows)
    for row in rows:
        row["request_share_pct"] = _pct(_num(row.get("requests")), total)
        markers = _path_markers(str(row.get("value", "")))
        row["markers"] = markers
        row["endpoint_category"] = _endpoint_category(str(row.get("value", "")), markers)
    return rows


def _baseline_actor_map(actor_rows: list[dict[str, Any]], actor_type: str) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for row in actor_rows:
        if row.get("period") == "baseline" and row.get("actor_type") == actor_type:
            out[str(row.get("value"))] = row
    return out


def _cooccurrence_rows(path_value: str | None, kind: str) -> list[dict[str, Any]]:
    rows = _read_optional_rows(path_value)
    normalized = []
    for row in rows:
        ua = _first(row, ("user_agent", "userAgent", "ua"))
        if ua is None and kind == "ua":
            ua = _first(row, ("value_b",))
        ip = _first(row, ("client_ip", "clientIp", "ip", "value_a"))
        if not ua and not ip:
            continue
        normalized.append(
            {
                "user_agent": str(ua) if ua else "",
                "client_ip": str(ip) if ip else "",
                "request_path": str(
                    _first(row, ("request_path", "requestPath", "path"), "")
                    or (_first(row, ("value_b",), "") if kind == "path" else "")
                ),
                "country": str(_first(row, ("country", "country_code"), "")),
                "requests": _num(_first(row, ("requests", "request_count", "count", "hits"))),
            }
        )
    return normalized


def _drilldown_rows(path_value: str | None) -> list[dict[str, Any]]:
    rows = _read_optional_rows(path_value)
    normalized = []
    for row in rows:
        user_agent = str(_first(row, ("user_agent", "userAgent", "UA", "ua"), "")).strip()
        client_ip = str(_first(row, ("client_ip", "clientIp", "cliIP", "ip"), "")).strip()
        if not user_agent and not client_ip:
            continue
        normalized.append(
            {
                "user_agent": user_agent,
                "client_ip": client_ip,
                "request_path": str(_first(row, ("request_path", "requestPath", "path", "reqPath"), "")),
                "hour": str(_first(row, ("hour", "bucket", "timestamp"), "")),
                "country": str(_first(row, ("country", "country_code"), "")),
                "status_429": _num(_first(row, ("status_429", "requests_429", "429", "req_429"))),
                "status_5xx": _num(_first(row, ("status_5xx", "requests_5xx", "5xx", "req_5xx"))),
                "requests": _num(_first(row, ("requests", "request_count", "count", "hits"))),
            }
        )
    return normalized


def merge_scraper_hourly_rows(rows: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[tuple[str, str], float] = defaultdict(float)
    for row in rows:
        user_agent = str(_first(row, ("user_agent", "userAgent", "UA", "ua"), "")).strip()
        hour = str(_first(row, ("hour", "bucket", "timestamp"), "")).strip()
        if not user_agent or not hour:
            continue
        merged[(user_agent, hour)] += _num(_first(row, ("requests", "request_count", "count", "hits")))
    return [
        {"user_agent": user_agent, "hour": hour, "requests": requests}
        for (user_agent, hour), requests in sorted(
            merged.items(), key=lambda item: (item[0][0], item[0][1])
        )
    ]


def _scraper_hourly_rows(path_value: str | None) -> list[dict[str, Any]]:
    return merge_scraper_hourly_rows(_read_optional_rows(path_value))


def _ua_fanout_rows(path_value: str | None) -> list[dict[str, Any]]:
    return merge_fanout_rows(_read_optional_rows(path_value))


def _iat_sample_rows(path_value: str | None) -> list[dict[str, Any]]:
    return merge_iat_sample_rows(_read_optional_rows(path_value))


def _timestamp_seconds(value: Any) -> float | None:
    if value in (None, ""):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    raw = str(value).strip()
    if not raw:
        return None
    try:
        return float(raw)
    except ValueError:
        pass
    normalized = raw.replace("Z", "+00:00")
    if " " in normalized and "T" not in normalized:
        normalized = normalized.replace(" ", "T", 1)
    try:
        dt = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)  # type: ignore[name-defined]
    return dt.timestamp()


def _median(values: list[float]) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    mid = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[mid]
    return (ordered[mid - 1] + ordered[mid]) / 2.0


def _percentile(values: list[float], percentile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * percentile
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[int(position)]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def _entropy(counter: Counter[int]) -> float | None:
    total = sum(counter.values())
    if total <= 0:
        return None
    entropy = 0.0
    for count in counter.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


def _lag1_autocorrelation(values: list[float]) -> float | None:
    if len(values) < 3:
        return None
    left = values[:-1]
    right = values[1:]
    left_mean = sum(left) / len(left)
    right_mean = sum(right) / len(right)
    numerator = sum((a - left_mean) * (b - right_mean) for a, b in zip(left, right))
    left_den = math.sqrt(sum((a - left_mean) ** 2 for a in left))
    right_den = math.sqrt(sum((b - right_mean) ** 2 for b in right))
    if left_den <= 0 or right_den <= 0:
        return None
    return numerator / (left_den * right_den)


def _spectral_peak_ratio(values: list[float]) -> float | None:
    if len(values) < 8:
        return None
    sample = values[: min(len(values), 128)]
    mean = sum(sample) / len(sample)
    centered = [value - mean for value in sample]
    if not any(abs(value) > 1e-9 for value in centered):
        return None
    powers = []
    max_k = min(len(centered) // 2, 24)
    for k in range(1, max_k + 1):
        real = 0.0
        imag = 0.0
        for index, value in enumerate(centered):
            angle = 2.0 * math.pi * k * index / len(centered)
            real += value * math.cos(angle)
            imag -= value * math.sin(angle)
        powers.append(real * real + imag * imag)
    if not powers:
        return None
    average = sum(powers) / len(powers)
    if average <= 0:
        return None
    return max(powers) / average


def _lz_complexity_ratio(values: list[float]) -> float | None:
    if len(values) < 2:
        return None
    median = _median(values)
    if median is None:
        return None
    sequence = "".join("1" if value > median else "0" for value in values)
    phrases: set[str] = set()
    index = 0
    while index < len(sequence):
        end = index + 1
        while end <= len(sequence) and sequence[index:end] in phrases:
            end += 1
        phrases.add(sequence[index:end])
        index = end
    return len(phrases) / len(sequence)


def _bimodality(values: list[float]) -> tuple[bool, float | None]:
    if len(values) < 20:
        return False, None
    median = _median(values)
    if median is None or median <= 0:
        return False, None
    lower = [value for value in values if value <= median]
    upper = [value for value in values if value > median]
    if len(lower) < max(5, len(values) * 0.2) or len(upper) < max(5, len(values) * 0.2):
        return False, None
    low_med = _median(lower)
    high_med = _median(upper)
    if low_med is None or high_med is None or low_med <= 0:
        return False, None
    separation = high_med / low_med
    return separation >= 2.0, separation


def _iat_deltas(rows: list[dict[str, Any]], *, user_agent: str, client_ip: str | None = None) -> list[float]:
    timestamps = []
    for row in rows:
        if row.get("user_agent") != user_agent:
            continue
        if client_ip is not None and row.get("client_ip") != client_ip:
            continue
        seconds = _timestamp_seconds(row.get("timestamp"))
        if seconds is not None:
            timestamps.append(seconds)
    timestamps.sort()
    return [
        later - earlier
        for earlier, later in zip(timestamps, timestamps[1:])
        if later > earlier
    ]


def _iat_metrics(deltas: list[float]) -> dict[str, Any] | None:
    if len(deltas) < 50:
        return None
    mean = sum(deltas) / len(deltas)
    median = _median(deltas)
    stddev = math.sqrt(sum((value - mean) ** 2 for value in deltas) / len(deltas))
    p10 = _percentile(deltas, 0.10)
    p90 = _percentile(deltas, 0.90)
    mad = _median([abs(value - (median or 0.0)) for value in deltas])
    bins = Counter(max(0, int(math.floor(math.log2(max(value, 1e-9))))) for value in deltas)
    dominant = max(bins.values()) / len(deltas) if bins else None
    bimodal, separation = _bimodality(deltas)
    return {
        "count": len(deltas),
        "sample_size": len(deltas),
        "mean_iat_sec": mean,
        "median_iat_sec": median,
        "stddev_iat_sec": stddev,
        "cv": stddev / mean if mean > 0 else None,
        "normalized_mad": (mad / median) if median and median > 0 and mad is not None else None,
        "p10_sec": p10,
        "p90_sec": p90,
        "p10_p90_ratio": (p10 / p90) if p10 and p10 > 0 and p90 is not None and p90 > 0 else None,
        "p90_p10_ratio": (p90 / p10) if p10 and p10 > 0 and p90 is not None else None,
        "log_bucket_entropy": _entropy(bins),
        "dominant_bin_share": dominant,
        "lag1_autocorrelation": _lag1_autocorrelation(deltas),
        "spectral_peak_ratio": _spectral_peak_ratio(deltas),
        "lz_complexity_ratio": _lz_complexity_ratio(deltas),
        "bimodal": bimodal,
        "bimodal_peak_separation": separation,
    }


def _fine_archetype(metrics: dict[str, Any]) -> str | None:
    cv = metrics.get("cv")
    entropy = metrics.get("log_bucket_entropy")
    p90_p10 = metrics.get("p90_p10_ratio")
    spectral = metrics.get("spectral_peak_ratio")
    lag1 = metrics.get("lag1_autocorrelation")
    if cv is not None and cv < 0.1:
        return "metronome"
    if entropy is not None and entropy < 1.0 and _num(metrics.get("dominant_bin_share")) >= 0.9:
        return "metronome"
    if cv is not None and 0.1 <= cv < 0.35 and (p90_p10 is None or p90_p10 <= 3.0) and (entropy is None or entropy < 2.0):
        return "jittered_metronome"
    if metrics.get("bimodal") or _num(spectral) > 3.0 or abs(_num(lag1)) >= 0.45:
        return "burst_pause"
    return None


def _fine_timing_signal(metrics: dict[str, Any]) -> bool:
    return (
        _num(metrics.get("sample_size")) >= 50
        and (
            (_num(metrics.get("cv"), 999.0) < 0.3)
            or (_num(metrics.get("log_bucket_entropy"), 999.0) < 1.5)
            or (_num(metrics.get("spectral_peak_ratio")) > 3.0)
            or (_num(metrics.get("bimodal_peak_separation")) > 2.0)
            or (_num(metrics.get("lz_complexity_ratio"), 999.0) < 0.4)
        )
    )


def _hourly_counter_for_user_agent(user_agent: str, hourly_rows: list[dict[str, Any]]) -> Counter[str]:
    counter: Counter[str] = Counter()
    for row in hourly_rows:
        if row.get("user_agent") != user_agent:
            continue
        hour = str(row.get("hour") or "").strip()
        if hour:
            counter[hour] += _num(row.get("requests"))
    return counter


def _window_hour_count(start: datetime, end: datetime) -> int:
    seconds = max(0.0, (end - start).total_seconds())
    return max(1, int(math.ceil(seconds / 3600.0)))


def _hourly_timing_profile(
    user_agent: str,
    hourly_rows: list[dict[str, Any]],
    *,
    window_hour_count: int | None = None,
    source: str = "scraper_hourly",
) -> dict[str, Any]:
    counter = _hourly_counter_for_user_agent(user_agent, hourly_rows)
    active_hours = [value for value in counter.values() if value > 0]
    inferred_window = len(counter) if counter else 0
    window_hours = max(1, window_hour_count or inferred_window)
    active_count = len(active_hours)
    coverage_pct = _pct(active_count, window_hours)
    base = {
        "status": "unavailable" if not active_hours else "insufficient_coverage",
        "source": source,
        "resolution": "hourly_coarse",
        "active_hour_count": active_count,
        "window_hour_count": window_hours,
        "coverage_pct": coverage_pct,
        "hourly_request_cv": None,
        "max_min_hourly_ratio": None,
        "mean_hourly_requests": None,
        "total_profile_requests": sum(active_hours),
        "hourly_profile": [
            {"hour": hour, "requests": requests}
            for hour, requests in sorted(counter.items())
            if requests > 0
        ],
        "temporal": None,
    }
    min_active = min(6, window_hours)
    if active_count < min_active or (coverage_pct is not None and coverage_pct < 75.0):
        return base
    if not active_hours:
        return base
    mean = sum(active_hours) / len(active_hours)
    stddev = math.sqrt(sum((value - mean) ** 2 for value in active_hours) / len(active_hours))
    cv = stddev / mean if mean > 0 else None
    ratio = max(active_hours) / min(active_hours) if min(active_hours) > 0 else None
    total = sum(active_hours)
    base.update(
        {
            "status": "irregular",
            "hourly_request_cv": cv,
            "max_min_hourly_ratio": ratio,
            "mean_hourly_requests": mean,
            "total_profile_requests": total,
        }
    )
    regular = _num(cv, 999.0) <= 0.35 or (_num(ratio, 999.0) <= 3.0 and active_count >= 12)
    if not regular:
        return base
    metrics = {
        "active_hour_count": active_count,
        "window_hour_count": window_hours,
        "coverage_pct": coverage_pct,
        "hourly_request_cv": cv,
        "max_min_hourly_ratio": ratio,
        "mean_hourly_requests": mean,
        "total_profile_requests": total,
    }
    temporal = {
        "resolution": "hourly_coarse",
        "archetype": "hourly_regular",
        "sample_size": active_count,
        "active_hour_count": active_count,
        "window_hour_count": window_hours,
        "coverage_pct": coverage_pct,
        "hourly_request_cv": cv,
        "max_min_hourly_ratio": ratio,
        "mean_hourly_requests": mean,
        "total_profile_requests": total,
        "metrics": metrics,
        "top_pairs": [],
        "hourly_profile": base["hourly_profile"],
        "summary": (
            f"Hourly coarse profile shows regular request-count cadence across {active_count} "
            f"of {window_hours} report-window hours."
        ),
    }
    base["status"] = "regular"
    base["temporal"] = temporal
    return base


def _legacy_hourly_timing_profile(user_agent: str, drilldown_rows: list[dict[str, Any]]) -> dict[str, Any] | None:
    counter = _hourly_counter_for_user_agent(user_agent, drilldown_rows)
    active_hours = [value for value in counter.values() if value > 0]
    if len(active_hours) < 6:
        return None
    mean = sum(active_hours) / len(active_hours)
    stddev = math.sqrt(sum((value - mean) ** 2 for value in active_hours) / len(active_hours))
    repeated = sum(count for count in Counter(active_hours).values() if count > 1)
    metrics = {
        "active_hour_count": len(active_hours),
        "hourly_request_cv": stddev / mean if mean > 0 else None,
        "max_min_hourly_ratio": max(active_hours) / min(active_hours) if min(active_hours) > 0 else None,
        "repeated_count_share": repeated / len(active_hours) if active_hours else None,
    }
    if _num(metrics["hourly_request_cv"], 999.0) >= 0.2:
        return None
    return {
        "resolution": "hourly_coarse",
        "archetype": "hourly_regular",
        "sample_size": len(active_hours),
        "metrics": metrics,
        "top_pairs": [],
        "summary": (
            f"Hourly drilldown shows low request-count variation across {len(active_hours)} active hours."
        ),
    }


def _temporal_regularity(user_agent: str, iat_rows: list[dict[str, Any]], drilldown_rows: list[dict[str, Any]]) -> dict[str, Any] | None:
    ua_metrics = _iat_metrics(_iat_deltas(iat_rows, user_agent=user_agent))
    pair_rows = []
    for ip in sorted({str(row.get("client_ip")) for row in iat_rows if row.get("user_agent") == user_agent and row.get("client_ip")}):
        metrics = _iat_metrics(_iat_deltas(iat_rows, user_agent=user_agent, client_ip=ip))
        if not metrics:
            continue
        archetype = _fine_archetype(metrics)
        signal = archetype is not None and _fine_timing_signal(metrics)
        pair_rows.append(
            {
                "client_ip": ip,
                "archetype": archetype,
                "signal": signal,
                "sample_size": metrics["sample_size"],
                "cv": metrics.get("cv"),
                "log_bucket_entropy": metrics.get("log_bucket_entropy"),
                "spectral_peak_ratio": metrics.get("spectral_peak_ratio"),
            }
        )
    pair_signals = [row for row in pair_rows if row.get("signal")]
    ua_archetype = _fine_archetype(ua_metrics) if ua_metrics else None
    if len(pair_signals) >= 2 and ua_archetype not in {"metronome", "jittered_metronome"}:
        archetype = "rotation_mask"
        return {
            "resolution": "request_iat",
            "archetype": archetype,
            "sample_size": sum(_int(row.get("sample_size")) for row in pair_signals),
            "metrics": ua_metrics or {},
            "top_pairs": sorted(pair_signals, key=lambda row: (-_num(row.get("sample_size")), str(row.get("client_ip"))))[:5],
            "summary": (
                f"UA-level timing is not independently regular, but {len(pair_signals)} UA x IP pairs show regular timing evidence."
            ),
        }
    if ua_metrics and _fine_timing_signal(ua_metrics):
        archetype = ua_archetype or "timing_regular"
        return {
            "resolution": "request_iat",
            "archetype": archetype,
            "sample_size": ua_metrics["sample_size"],
            "metrics": ua_metrics,
            "top_pairs": sorted(pair_rows, key=lambda row: (-_num(row.get("sample_size")), str(row.get("client_ip"))))[:5],
            "summary": (
                f"Request-level inter-arrival timing matches {archetype.replace('_', ' ')} behavior in the sampled rows."
            ),
        }
    if iat_rows:
        return None
    return _legacy_hourly_timing_profile(user_agent, drilldown_rows)


def _timing_analysis(
    user_agent: str,
    iat_rows: list[dict[str, Any]],
    drilldown_rows: list[dict[str, Any]],
    hourly_rows: list[dict[str, Any]],
    *,
    window_hour_count: int,
) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    temporal = _temporal_regularity(user_agent, iat_rows, drilldown_rows)
    if temporal and temporal.get("resolution") == "request_iat":
        return temporal, {
            "status": "regular",
            "source": "iat_samples",
            "resolution": "request_iat",
            "archetype": temporal.get("archetype"),
            "sample_size": temporal.get("sample_size"),
        }
    if iat_rows:
        return None, {
            "status": "irregular",
            "source": "iat_samples",
            "resolution": "request_iat",
            "sample_size": 0,
        }
    source = "scraper_hourly" if hourly_rows else "scraper_drilldown"
    profile = _hourly_timing_profile(
        user_agent,
        hourly_rows or drilldown_rows,
        window_hour_count=window_hour_count,
        source=source,
    )
    return profile.get("temporal"), {key: value for key, value in profile.items() if key != "temporal"}


def _fingerprints(
    actor_rows: list[dict[str, Any]],
    cooccurrence: list[dict[str, Any]],
    geo: dict[str, dict[str, Any]],
    top_n: int,
) -> list[dict[str, Any]]:
    baseline = _baseline_actor_map(actor_rows, "user_agent")
    ip_by_ua: dict[str, set[str]] = defaultdict(set)
    countries_by_ua: dict[str, set[str]] = defaultdict(set)
    asn_by_ua: dict[str, set[str]] = defaultdict(set)
    for row in cooccurrence:
        ua = row.get("user_agent")
        ip = row.get("client_ip")
        if not ua:
            continue
        if ip:
            ip_by_ua[ua].add(ip)
            geo_row = _geo_for_ip(ip, geo)
            if geo_row.get("asn"):
                asn_by_ua[ua].add(str(geo_row["asn"]))
            if geo_row.get("country"):
                countries_by_ua[ua].add(str(geo_row["country"]))
        if row.get("country"):
            countries_by_ua[ua].add(str(row["country"]))

    current = [
        row
        for row in actor_rows
        if row.get("period") == "current" and row.get("actor_type") == "user_agent"
    ]
    current.sort(key=lambda row: (-_num(row.get("requests")), str(row.get("value"))))
    out = []
    for rank, row in enumerate(current[:top_n], start=1):
        value = str(row.get("value"))
        base = baseline.get(value, {})
        out.append(
            {
                "rank": rank,
                "user_agent": value,
                "requests": _num(row.get("requests")),
                "bytes": _num(row.get("bytes")),
                "baseline_requests": _num(base.get("requests")),
                "request_delta": _num(row.get("requests")) - _num(base.get("requests")),
                "unique_client_ips": len(ip_by_ua[value]) if cooccurrence else None,
                "unique_asns": len(asn_by_ua[value]) if cooccurrence else None,
                "unique_countries": len(countries_by_ua[value]) if cooccurrence else None,
                "sample_asns": sorted(asn_by_ua[value])[:5],
                "sample_countries": sorted(countries_by_ua[value])[:5],
            }
        )
    return out


def _infrastructure(
    actor_rows: list[dict[str, Any]],
    cooccurrence: list[dict[str, Any]],
    geo: dict[str, dict[str, Any]],
    top_n: int,
) -> dict[str, Any]:
    ip_requests = Counter()
    for row in actor_rows:
        if row.get("period") == "current" and row.get("actor_type") == "client_ip":
            ip_requests[str(row.get("value"))] += _num(row.get("requests"))
    for row in cooccurrence:
        ip = row.get("client_ip")
        if ip:
            ip_requests[str(ip)] += _num(row.get("requests"))
    asn_rollup: dict[str, dict[str, Any]] = defaultdict(lambda: {"requests": 0.0, "client_ips": set(), "asn_org": None, "countries": set()})
    for ip, requests in ip_requests.items():
        geo_row = _geo_for_ip(ip, geo)
        asn = str(geo_row.get("asn") or "unknown")
        item = asn_rollup[asn]
        item["requests"] += requests
        item["client_ips"].add(ip)
        if geo_row.get("asn_org"):
            item["asn_org"] = geo_row.get("asn_org")
        if geo_row.get("country"):
            item["countries"].add(str(geo_row["country"]))
    rows = []
    for rank, (asn, item) in enumerate(
        sorted(asn_rollup.items(), key=lambda pair: (-pair[1]["requests"], pair[0]))[:top_n],
        start=1,
    ):
        rows.append(
            {
                "rank": rank,
                "asn": asn,
                "asn_org": item["asn_org"],
                "requests": item["requests"],
                "client_ip_count": len(item["client_ips"]),
                "country_count": len(item["countries"]),
                "sample_countries": sorted(item["countries"])[:5],
            }
        )
    return {
        "asn_rollups": rows,
        "topology_hints": _topology_hints(rows),
        "availability": "evidence_backed" if rows and geo else "partial" if rows else "not_available",
    }


def _topology_hints(asn_rows: list[dict[str, Any]]) -> list[str]:
    known_rows = [row for row in asn_rows if row.get("asn") not in {None, "", "unknown"}]
    if not known_rows:
        return []
    total_requests = sum(_num(row.get("requests")) for row in known_rows)
    top = known_rows[0]
    hints = []
    if _pct(_num(top.get("requests")), total_requests) and _pct(_num(top.get("requests")), total_requests) >= 70:
        hints.append("concentrated_asn")
    if len(known_rows) >= 5:
        hints.append("distributed_pool")
    if any(_int(row.get("client_ip_count")) >= 10 for row in known_rows):
        hints.append("multi_ip_asn_cluster")
    return hints


def _classification_gap(edge_rows: list[dict[str, Any]], siem_rows: list[dict[str, Any]]) -> dict[str, Any]:
    if not edge_rows and not siem_rows:
        return {
            "module": "classification_gap",
            "availability": "not_available",
            "verdict": "not_enough_data",
            "summary": "Bot/SIEM/edge classification artifacts were not supplied.",
            "rows": [],
        }
    rows = edge_rows or siem_rows
    total = sum(_num(_first(row, ("requests", "count", "hits"))) for row in rows)
    covered = sum(
        _num(_first(row, ("classified_requests", "bot_requests", "blocked_requests", "edge_action_requests")))
        for row in rows
    )
    return {
        "module": "classification_gap",
        "availability": "evidence_backed",
        "verdict": "possible" if total and covered < total else "likely",
        "summary": "Classification coverage supplied by optional local artifacts.",
        "coverage_pct": _pct(covered, total),
        "rows": rows[:20],
    }


def _classification_gap_is_signal(classification: dict[str, Any]) -> bool:
    if classification.get("availability") == "not_available":
        return False
    coverage = classification.get("coverage_pct")
    return coverage is not None and _num(coverage) < 90


def _data_limits(
    summary_rows: list[dict[str, Any]],
    actor_rows: list[dict[str, Any]],
    cooccurrence: list[dict[str, Any]],
    fanout: list[dict[str, Any]],
    drilldown: list[dict[str, Any]],
    hourly: list[dict[str, Any]],
    iat_samples: list[dict[str, Any]],
    geo: dict[str, dict[str, Any]],
    classification: dict[str, Any],
) -> list[dict[str, str]]:
    checks = [
        ("summary_parquet", bool(summary_rows), "baseline movement and endpoint rankings"),
        ("raw_actor_exports", bool(actor_rows), "exact client IP and user-agent evidence"),
        ("cooccurrence", bool(cooccurrence), "UA fanout, unique-IP, country, and ASN spread"),
        (
            "fanout_enrichment",
            bool(fanout),
            _fanout_limit_detail(fanout),
        ),
        ("scraper_drilldown", bool(drilldown), "UA x endpoint, client IP x endpoint, and hourly burst detail"),
        ("scraper_hourly", bool(hourly), "complete UA x hour request profiles for coarse timing regularity"),
        ("iat_samples", bool(iat_samples), "request-level sampled timestamp evidence for inter-arrival timing"),
        ("geoip_asn", bool(geo), "ASN organization and topology enrichment"),
        ("classification_gap", classification.get("availability") != "not_available", "SIEM/Bot/edge coverage"),
    ]
    return [
        {
            "module": name,
            "availability": "evidence_backed" if available else "not_available",
            "detail": detail if available else f"{detail} not supplied",
        }
        for name, available, detail in checks
    ]


def _fanout_limit_detail(fanout: list[dict[str, Any]]) -> str:
    if not fanout:
        return "source-aware UA fan-out enrichment"
    sources = sorted({str(row.get("source") or "unknown") for row in fanout})
    if sources == ["summary_hour"]:
        return "full-window source-aware UA fan-out enrichment from summary_hour"
    if sources == ["logs_probe"]:
        return "peak-hour logs_probe fan-out enrichment; effective counts are conservative bounded lower-bound estimates"
    if sources == ["cooccurrence_lower_bound"]:
        return "cooccurrence-derived lower-bound UA fan-out enrichment; true full-window fan-out is unknown"
    return "mixed-source UA fan-out enrichment; campaign totals are composite lower-bound estimates"


def _score_baseline(current: dict[str, float], baseline: dict[str, float]) -> dict[str, Any]:
    req_delta_pct = _pct(current.get("requests", 0) - baseline.get("requests", 0), baseline.get("requests", 0))
    strong = req_delta_pct is not None and abs(req_delta_pct) >= 50 and current.get("requests", 0) >= 1000
    return {
        "module": "baseline_movement",
        "verdict": "likely" if strong else "possible" if current.get("requests", 0) else "not_enough_data",
        "rationale": "Current-vs-baseline request movement is large." if strong else "Baseline movement is present but not independently conclusive.",
        "metrics": [_metric_delta(name, current, baseline) for name in ("requests", "bytes", "status_429", "status_5xx", "bot_requests", "human_requests")],
    }


def _score_ua(
    fingerprints: list[dict[str, Any]],
    cooccurrence_available: bool,
    fanout: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    top = fingerprints[0] if fingerprints else {}
    top_fanout = (fanout or [None])[0] if fanout else None
    top_fanout_ips = _fanout_effective_ips(top_fanout or {}) if top_fanout else 0.0
    if not top and not top_fanout:
        verdict = "not_enough_data"
    elif top_fanout_ips >= 50_000:
        verdict = "confirmed"
    elif top_fanout_ips >= 10_000:
        verdict = "likely"
    elif cooccurrence_available and _int(top.get("unique_client_ips")) >= 20 and _int(top.get("unique_asns")) >= 3 and _int(top.get("unique_countries")) >= 3:
        verdict = "confirmed"
    elif cooccurrence_available and (_int(top.get("unique_client_ips")) >= 10 or _int(top.get("unique_asns")) >= 2):
        verdict = "likely"
    else:
        verdict = "possible"
    return {
        "module": "ua_fanout",
        "verdict": verdict,
        "rationale": "UA fanout is scored from source-aware enrichment when available, otherwise from cooccurrence IP/ASN/country spread.",
        "top_user_agent": (top_fanout or top).get("user_agent"),
        "top_fanout_source": (top_fanout or {}).get("source"),
    }


def _score_endpoint(endpoints: list[dict[str, Any]]) -> dict[str, Any]:
    marker_rows = [row for row in endpoints if row.get("markers")]
    if not endpoints:
        verdict = "not_enough_data"
    elif marker_rows and _num(endpoints[0].get("request_share_pct")) >= 50:
        verdict = "likely"
    elif marker_rows or _num(endpoints[0].get("requests")) > 0:
        verdict = "possible"
    else:
        verdict = "not_enough_data"
    return {
        "module": "endpoint_harvest",
        "verdict": verdict,
        "rationale": "Endpoint-harvest scoring looks for concentrated paths plus API/catalog/GraphQL/auth markers.",
        "marker_count": len(marker_rows),
    }


def _score_infra(infra: dict[str, Any]) -> dict[str, Any]:
    hints = infra.get("topology_hints") or []
    if infra.get("availability") == "not_available":
        verdict = "not_enough_data"
    elif {"concentrated_asn", "multi_ip_asn_cluster"} <= set(hints):
        verdict = "likely"
    elif hints:
        verdict = "possible"
    else:
        verdict = "possible"
    return {
        "module": "infrastructure",
        "verdict": verdict,
        "rationale": "Infrastructure scoring reports concentration or distributed-pool hints without inferring operator identity.",
        "topology_hints": hints,
    }


def _score_bhu(fingerprints: list[dict[str, Any]], endpoints: list[dict[str, Any]], infra: dict[str, Any]) -> dict[str, Any]:
    signals = 0
    if fingerprints and _int(fingerprints[0].get("unique_client_ips")) >= 10:
        signals += 1
    if endpoints and endpoints[0].get("markers"):
        signals += 1
    if infra.get("topology_hints"):
        signals += 1
    verdict = "confirmed" if signals == 3 else "likely" if signals == 2 else "possible" if signals == 1 else "not_enough_data"
    return {
        "module": "bhu_style_scraper_indicators",
        "verdict": verdict,
        "rationale": "BHU-style indicators combine exact-UA fanout, endpoint harvesting, and infrastructure topology as a module, not as attribution.",
        "signals_present": signals,
    }


def _ua_actor_row(actor_rows: list[dict[str, Any]], user_agent: str) -> dict[str, Any]:
    for row in actor_rows:
        if (
            row.get("period") == "current"
            and row.get("actor_type") == "user_agent"
            and str(row.get("value")) == user_agent
        ):
            return row
    return {}


def _drilldown_profile(
    user_agent: str,
    drilldown_rows: list[dict[str, Any]],
    geo: dict[str, dict[str, Any]],
    top_n: int,
) -> dict[str, Any]:
    rows = [row for row in drilldown_rows if row.get("user_agent") == user_agent]
    if not rows:
        return {"available": False, "rows": [], "endpoint_targets": [], "hourly_bursts": []}
    endpoint_counter: Counter[str] = Counter()
    hourly_counter: Counter[str] = Counter()
    ip_counter: Counter[str] = Counter()
    country_counter: Counter[str] = Counter()
    asn_counter: Counter[str] = Counter()
    status_429 = 0.0
    status_5xx = 0.0
    total = 0.0
    for row in rows:
        requests = _num(row.get("requests"))
        total += requests
        status_429 += _num(row.get("status_429"))
        status_5xx += _num(row.get("status_5xx"))
        path = str(row.get("request_path") or "")
        if path:
            endpoint_counter[path] += requests
        hour = str(row.get("hour") or "")
        if hour:
            hourly_counter[hour] += requests
        ip = str(row.get("client_ip") or "")
        if ip:
            ip_counter[ip] += requests
            geo_row = _geo_for_ip(ip, geo)
            if geo_row.get("asn"):
                asn_counter[str(geo_row["asn"])] += requests
            if geo_row.get("country"):
                country_counter[str(geo_row["country"])] += requests
        if row.get("country"):
            country_counter[str(row["country"])] += requests
    endpoint_targets = [
        {
            "request_path": path,
            "requests": requests,
            "share_pct": _pct(requests, total),
            "markers": _path_markers(path),
            "endpoint_category": _endpoint_category(path),
        }
        for path, requests in endpoint_counter.most_common(top_n)
    ]
    hourly = [
        {"hour": hour, "requests": requests, "share_pct": _pct(requests, total)}
        for hour, requests in hourly_counter.most_common(top_n)
    ]
    return {
        "available": True,
        "rows": rows[: min(len(rows), 50)],
        "endpoint_targets": endpoint_targets,
        "hourly_bursts": hourly,
        "top_client_ips": [
            {"client_ip": ip, "requests": requests} for ip, requests in ip_counter.most_common(top_n)
        ],
        "countries": [country for country, _ in country_counter.most_common(top_n)],
        "asns": [asn for asn, _ in asn_counter.most_common(top_n)],
        "requests": total,
        "rate_429_pct": _pct(status_429, total),
        "rate_5xx_pct": _pct(status_5xx, total),
    }


def _coverage_status(coverage_pct: float | None, *, has_rows: bool) -> str:
    if not has_rows:
        return "unavailable"
    if coverage_pct is None or coverage_pct < 0.01:
        return "uncharacterized"
    if coverage_pct < 1.0:
        return "thin_slice"
    if coverage_pct < 25.0:
        return "partial"
    if coverage_pct < 75.0:
        return "substantial"
    return "focused"


def _drilldown_coverage(total_requests: float, drilldown_requests: float, has_rows: bool) -> dict[str, Any]:
    coverage_pct = _pct(drilldown_requests, total_requests)
    status = _coverage_status(coverage_pct, has_rows=has_rows)
    return {
        "drilldown_requests": drilldown_requests,
        "total_requests": total_requests,
        "coverage_pct": coverage_pct,
        "status": status,
    }


def _add_family(
    families: dict[str, dict[str, Any]],
    name: str,
    *,
    label: str,
    rows: list[dict[str, Any]] | None = None,
) -> None:
    families[name] = {"family": name, "label": label, "rows": rows or []}


def _automation_signature(user_agent: str) -> bool:
    lowered = user_agent.lower()
    return any(marker in lowered for marker in _AUTOMATION_UA_MARKERS)


def _known_traffic_disposition(user_agent: str) -> dict[str, Any] | None:
    lowered = user_agent.lower()
    if any(pattern in lowered for pattern in _KNOWN_INFRASTRUCTURE_UA_PATTERNS):
        return {
            "disposition": "known_infrastructure",
            "reason": "Akamai image infrastructure user-agent pattern; informational traffic, not a threat-hunt finding.",
        }
    if any(pattern in lowered for pattern in _KNOWN_CRAWLER_UA_PATTERNS):
        return {
            "disposition": "known_crawler",
            "reason": "Major search or app crawler user-agent pattern; informational traffic unless crawler-specific analysis is requested.",
        }
    return None


def _mark_known_traffic(scraper_cases: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    active_cases: list[dict[str, Any]] = []
    known_rows: list[dict[str, Any]] = []
    for case in scraper_cases:
        ua = str(case.get("user_agent") or "")
        disposition = _known_traffic_disposition(ua)
        if not disposition:
            active_cases.append(case)
            continue
        case["known_traffic"] = True
        case["known_traffic_disposition"] = disposition["disposition"]
        case["known_traffic_reason"] = disposition["reason"]
        case["threat_classification"] = {"primary": None, "secondary": [], "ambiguity_note": None}
        case["recommended_actions"] = []
        known_rows.append(
            {
                "user_agent": ua,
                "disposition": disposition["disposition"],
                "reason": disposition["reason"],
                "requests": case.get("requests"),
                "baseline_requests": case.get("baseline_requests"),
                "evidence_flags": case.get("evidence_flags") or [],
            }
        )
    return active_cases, known_rows


def _scraper_case_verdict(families: dict[str, dict[str, Any]]) -> str:
    count = len(families)
    if count >= 3:
        return "strong_lead"
    if count >= 2:
        return "lead"
    if count == 1:
        return "weak_lead"
    return "not_enough_data"


def _case_for_against(
    families: dict[str, dict[str, Any]],
    drilldown_coverage: dict[str, Any],
    endpoint_evidence: dict[str, Any],
) -> tuple[list[str], list[str]]:
    case_for = [families[name]["label"] for name in SCRAPER_EVIDENCE_FAMILIES if name in families]
    missing = [
        name
        for name in SCRAPER_EVIDENCE_FAMILIES
        if name not in families
    ]
    case_against = [f"No {name.replace('_', ' ')} evidence in supplied artifacts." for name in missing]
    status = str(drilldown_coverage.get("status") or "unavailable")
    coverage_pct = drilldown_coverage.get("coverage_pct")
    if status == "unavailable":
        case_against.append(
            "Scoped raw scraper drilldown was unavailable, so endpoint targeting is inferred only from site-level patterns when shown."
        )
    elif status == "uncharacterized":
        case_against.append(
            "Scoped endpoint drilldown captures <0.01% of this lead's traffic; primary request surface remains uncharacterized."
        )
    elif status == "thin_slice":
        case_against.append(
            f"Scoped endpoint drilldown captures {_num(coverage_pct):.2f}% of this lead's traffic; primary request surface remains only thinly characterized."
        )
    elif status == "partial":
        case_against.append(
            f"Scoped endpoint drilldown captures {_num(coverage_pct):.1f}% of this lead's traffic; endpoint targeting requires scoped category rows to count for the verdict."
        )
    elif "endpoint_targeting" in families:
        case_for.append(
            f"Scoped endpoint drilldown covers {_num(coverage_pct):.1f}% of this lead's traffic; scoped endpoint targeting is confirmed."
        )
    if not endpoint_evidence.get("counts_for_verdict"):
        tier = str(endpoint_evidence.get("tier") or "not_available")
        if tier == "inferred_site_context":
            case_against.append(
                "Endpoint context is inferred from site-level summary rows and is not confirmed for this UA."
            )
        elif tier == "unconfirmed_scoped":
            case_against.append(
                "Scoped endpoint rows are unavailable, too thinly sampled, or outside scoring categories, so endpoint targeting is not verdict-driving."
            )
        elif tier == "not_available":
            case_against.append("No scoped or site-level endpoint context was supplied for this lead.")
    return case_for, case_against


def _global_endpoint_evidence(endpoints: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        row
        for row in endpoints
        if row.get("markers") and (_num(row.get("request_share_pct")) >= 10 or _num(row.get("requests")) > 0)
    ][:5]


def _endpoint_evidence_qualification(
    *,
    scoped_rows: list[dict[str, Any]],
    fallback_rows: list[dict[str, Any]],
    drilldown_coverage: dict[str, Any],
) -> dict[str, Any]:
    scoped_targeting_rows = _endpoint_targeting_rows(scoped_rows)
    coverage_pct = _num(drilldown_coverage.get("coverage_pct"))
    status = str(drilldown_coverage.get("status") or "unavailable")
    if (
        scoped_targeting_rows
        and status not in {"unavailable", "uncharacterized", "thin_slice"}
        and coverage_pct >= _CONFIRMED_ENDPOINT_COVERAGE_PCT
    ):
        return {
            "tier": "confirmed",
            "source": "scoped_drilldown",
            "counts_for_verdict": True,
            "reason": "scoped_drilldown_ge_1pct_with_target_categories",
            "categories": sorted(
                {
                    str(row.get("endpoint_category") or _endpoint_category(str(row.get("request_path") or row.get("value") or ""), row.get("markers")))
                    for row in scoped_targeting_rows
                }
            ),
        }
    if scoped_rows:
        if not scoped_targeting_rows:
            reason = "scoped_rows_without_target_categories"
        elif status in {"uncharacterized", "thin_slice"} or coverage_pct < _CONFIRMED_ENDPOINT_COVERAGE_PCT:
            reason = "scoped_coverage_below_1pct"
        else:
            reason = "scoped_endpoint_unconfirmed"
        return {
            "tier": "unconfirmed_scoped",
            "source": "scoped_drilldown",
            "counts_for_verdict": False,
            "reason": reason,
            "categories": sorted(
                {
                    str(row.get("endpoint_category") or _endpoint_category(str(row.get("request_path") or row.get("value") or ""), row.get("markers")))
                    for row in scoped_rows
                }
            ),
        }
    if fallback_rows:
        return {
            "tier": "inferred_site_context",
            "source": "site_summary_fallback",
            "counts_for_verdict": False,
            "reason": "no_scoped_endpoint_rows_site_summary_available",
            "categories": sorted(
                {
                    str(row.get("endpoint_category") or _endpoint_category(str(row.get("request_path") or row.get("value") or ""), row.get("markers")))
                    for row in fallback_rows
                }
            ),
        }
    return {
        "tier": "not_available",
        "source": None,
        "counts_for_verdict": False,
        "reason": "no_endpoint_rows",
        "categories": [],
    }


def _baseline_growth_family(requests: float, baseline_requests: float, request_delta: Any) -> dict[str, Any] | None:
    delta_pct = _pct(requests - baseline_requests, baseline_requests)
    if requests >= 100 and baseline_requests <= 10:
        tier = "novel"
        label = "The UA is new or near-new versus the baseline window."
    elif baseline_requests >= 1_000 and delta_pct is not None and delta_pct >= 100:
        tier = "aggressive_growth"
        label = "The UA more than doubled versus the baseline window."
    elif baseline_requests >= 1_000 and delta_pct is not None and delta_pct >= 50:
        tier = "elevated_growth"
        label = "The UA is elevated at least 1.5x versus the baseline window."
    else:
        return None
    ratio = requests / baseline_requests if baseline_requests > 0 else None
    return {
        "tier": tier,
        "requests": requests,
        "baseline_requests": baseline_requests,
        "request_delta": request_delta,
        "pct_change": delta_pct,
        "current_to_baseline_ratio": ratio,
        "label": label,
    }


def _row_evidence_families(row: dict[str, Any], *, window_end: datetime | None = None) -> set[str]:
    raw_flags = row.get("evidence_flags")
    if isinstance(raw_flags, list):
        return {str(flag) for flag in raw_flags if str(flag) in SCRAPER_EVIDENCE_FAMILIES}
    user_agent = str(_first(row, ("user_agent", "userAgent", "UA", "ua"), ""))
    requests = _num(_first(row, ("requests", "request_count", "count", "hits")))
    baseline_requests = _num(_first(row, ("baseline_requests", "baseline_count", "previous_requests")))
    unique_ips = _num(_first(row, ("unique_client_ips", "distinct_client_ips", "client_ip_count", "ips")))
    unique_asns = _num(_first(row, ("unique_asns", "distinct_asns", "asn_count")))
    unique_countries = _num(_first(row, ("unique_countries", "distinct_countries", "country_count")))
    targeted = _num(_first(row, ("targeted_endpoint_requests", "endpoint_target_requests", "api_requests")))
    status_429 = _num(_first(row, ("status_429", "requests_429", "429", "req_429")))
    status_5xx = _num(_first(row, ("status_5xx", "requests_5xx", "5xx", "req_5xx")))
    families: set[str] = set()
    if unique_ips >= 10 or unique_asns >= 2:
        families.add("ua_ip_fanout")
    path = str(_first(row, ("request_path", "any_path", "path", "requestPath"), ""))
    if targeted > 0 or _path_markers(path):
        families.add("endpoint_targeting")
    if _automation_signature(user_agent):
        families.add("automation_signature")
    if baseline_requests <= 10 and requests >= 100:
        families.add("baseline_novelty_or_growth")
    elif baseline_requests >= 1_000 and _pct(requests - baseline_requests, baseline_requests) and _pct(requests - baseline_requests, baseline_requests) >= 50:
        families.add("baseline_novelty_or_growth")
    if requests > 0 and any(_pct(value, requests) and _pct(value, requests) >= 2 for value in (status_429, status_5xx)):
        families.add("rate_limit_or_error_pressure")
    if unique_asns >= 3 or unique_countries >= 3:
        families.add("infrastructure_topology")
    explicit_temporal = str(_first(row, ("temporal_regularity", "timing_status", "temporal_status"), "")).lower()
    if explicit_temporal in {"regular", "metronome", "jittered_metronome", "burst_pause", "rotation_mask"}:
        families.add("temporal_regularity")
    if _first(row, ("classification_gap", "coverage_gap"), None) in {True, "true", "yes", "1"}:
        families.add("classification_gap")
    if window_end is not None:
        plausibility = score_ua_plausibility(
            user_agent=user_agent,
            window_end=window_end,
            fanout_by_ua={},
            fallback_unique_ips=unique_ips,
            family_request_totals=Counter(),
            total_family_requests=0,
            browser_fingerprint_count=0,
            source="background_sample",
        )
        if plausibility.get("counts_for_verdict"):
            families.add("ua_anomaly")
    return families


def _background_rates(
    rows: list[dict[str, Any]],
    *,
    window_end: datetime,
) -> dict[str, Any]:
    if not rows:
        return {
            "status": "unavailable",
            "sample_size": 0,
            "families": {
                family: {"triggered": 0, "sample_size": 0, "rate_pct": None, "concern": "unavailable"}
                for family in SCRAPER_EVIDENCE_FAMILIES
            },
        }
    counts: Counter[str] = Counter()
    for row in rows:
        counts.update(_row_evidence_families(row, window_end=window_end))
    sample_size = len(rows)
    families = {}
    for family in SCRAPER_EVIDENCE_FAMILIES:
        rate = _pct(counts.get(family, 0), sample_size)
        concern = "high" if _num(rate) >= 20 else "moderate" if _num(rate) >= 10 else "low"
        families[family] = {
            "triggered": counts.get(family, 0),
            "sample_size": sample_size,
            "rate_pct": rate,
            "concern": concern,
        }
    return {"status": "available", "sample_size": sample_size, "families": families}


def _baseline_significance_by_ua(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    buckets: dict[str, list[float]] = defaultdict(list)
    for row in rows:
        ua = str(_first(row, ("user_agent", "userAgent", "UA", "ua"), "")).strip()
        if not ua:
            continue
        buckets[ua].append(_num(_first(row, ("requests", "request_count", "count", "hits"))))
    out = {}
    for ua, values in buckets.items():
        mean = sum(values) / len(values) if values else 0.0
        stddev = math.sqrt(sum((value - mean) ** 2 for value in values) / len(values)) if values else 0.0
        out[ua] = {
            "status": "available" if len(values) >= 3 and stddev > 0 else "insufficient_distribution" if values else "unavailable",
            "bucket_count": len(values),
            "mean_requests": mean,
            "stddev_requests": stddev,
            "z_score": None,
        }
    return out


def _baseline_significance_for_case(
    case: dict[str, Any],
    by_ua: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    ua = str(case.get("user_agent") or "")
    base = dict(by_ua.get(ua) or {})
    if not base:
        return {"status": "unavailable", "reason": "no_per_ua_baseline_buckets"}
    if base.get("status") != "available":
        base["reason"] = "requires_at_least_three_nonflat_baseline_buckets"
        return base
    z_score = (_num(case.get("requests")) - _num(base.get("mean_requests"))) / _num(base.get("stddev_requests"), 1.0)
    base["z_score"] = z_score
    if z_score >= 5:
        base["significance"] = "very_high"
    elif z_score >= 3:
        base["significance"] = "high"
    elif z_score >= 2:
        base["significance"] = "moderate"
    else:
        base["significance"] = "low"
    return base


def _consistency_checks(flags: set[str]) -> list[dict[str, Any]]:
    checks = [
        (
            "temporal_regularity_plus_ua_anomaly",
            {"temporal_regularity", "ua_anomaly"},
            "Timing regularity reinforces a UA plausibility anomaly.",
        ),
        (
            "ua_anomaly_plus_coordinated_activity",
            {"ua_anomaly", "coordinated_activity"},
            "UA anomaly appears inside a coordinated multi-lead pattern.",
        ),
        (
            "endpoint_targeting_plus_rate_limit_or_error_pressure",
            {"endpoint_targeting", "rate_limit_or_error_pressure"},
            "Endpoint targeting coincides with 429 or 5xx pressure.",
        ),
    ]
    return [
        {
            "check": name,
            "status": "present" if required <= flags else "incomplete",
            "required_families": sorted(required),
            "missing_families": sorted(required - flags),
            "summary": summary,
        }
        for name, required, summary in checks
    ]


def _evidence_shelf_life(case: dict[str, Any]) -> list[dict[str, Any]]:
    flags = set(str(flag) for flag in case.get("evidence_flags") or [])
    notes = []
    if "ua_ip_fanout" in flags:
        notes.append(
            {
                "evidence": "ua_ip_fanout",
                "shelf_life": "next_hunt_window",
                "guidance": (
                    "Fan-out counts are hunt-window specific; re-query them in the next hunt window "
                    "because proxy pools, app releases, and device populations change."
                ),
            }
        )
    plausibility = case.get("ua_plausibility") if isinstance(case.get("ua_plausibility"), dict) else {}
    version_signal = (plausibility.get("signals") or {}).get("version_currency") if isinstance(plausibility.get("signals"), dict) else None
    if "ua_anomaly" in flags or version_signal:
        notes.append(
            {
                "evidence": "ua_version_currency",
                "shelf_life": "8_weeks",
                "guidance": "Re-validate browser version currency after 8 weeks or before enforcement changes.",
            }
        )
    if "coordinated_activity" in flags or "infrastructure_topology" in flags:
        notes.append(
            {
                "evidence": "shared_ip_or_infrastructure_linking",
                "shelf_life": "proxy_pool_rotation_risk",
                "guidance": "Re-check shared IP, ASN, and country links because proxy pools can rotate between hunt windows.",
            }
        )
    if "temporal_regularity" in flags:
        notes.append(
            {
                "evidence": "timing_regularity",
                "shelf_life": "next_observation_window",
                "guidance": "Re-sample timing in the next observation window; cadence can change after throttling or operator changes.",
            }
        )
    return notes


def _confidence_assessment(
    case: dict[str, Any],
    background: dict[str, Any],
    baseline_significance: dict[str, Any],
) -> dict[str, Any]:
    flags = set(str(flag) for flag in case.get("evidence_flags") or [])
    checks = _consistency_checks(flags)
    present_checks = [check for check in checks if check["status"] == "present"]
    background_families = background.get("families") if isinstance(background, dict) else {}
    high_background = [
        family
        for family in flags
        if isinstance(background_families, dict)
        and isinstance(background_families.get(family), dict)
        and background_families[family].get("concern") == "high"
    ]
    score = min(0.92, len(flags) * 0.16 + len(present_checks) * 0.13)
    if baseline_significance.get("status") == "available":
        z = _num(baseline_significance.get("z_score"))
        if z >= 5:
            score += 0.10
        elif z >= 3:
            score += 0.06
    if high_background:
        score -= 0.18
    if not flags:
        score = 0.0
    score = max(0.0, min(score, 1.0))
    if not flags:
        qualifier = "unavailable"
    elif score >= 0.70 and present_checks and not high_background:
        qualifier = "high"
    elif score >= 0.40:
        qualifier = "partial"
    else:
        qualifier = "low"
    reasons = []
    if present_checks:
        reasons.extend(check["summary"] for check in present_checks)
    if high_background:
        reasons.append(
            "Some evidence families also fire in the organic background sample: "
            + ", ".join(sorted(high_background))
            + "."
        )
    if baseline_significance.get("status") == "available":
        reasons.append(
            f"Per-UA baseline bucket z-score is {baseline_significance.get('z_score'):.2f}."
        )
    elif baseline_significance.get("status") == "unavailable":
        reasons.append("Per-UA baseline bucket distribution was unavailable; ratio-based baseline growth is preserved.")
    if not reasons:
        reasons.append("Confidence is bounded by the available evidence families and missing corroboration.")
    return {
        "qualifier": qualifier,
        "score": round(score, 3),
        "reasons": reasons,
        "background_rates": {
            family: background_families.get(family)
            for family in sorted(flags)
            if isinstance(background_families, dict)
        },
        "consistency_checks": checks,
        "baseline_significance": baseline_significance,
        "evidence_shelf_life": _evidence_shelf_life(case),
    }


def _attach_confidence_assessments(
    scraper_cases: list[dict[str, Any]],
    campaigns: list[dict[str, Any]],
    *,
    background: dict[str, Any],
    baseline_by_ua: dict[str, dict[str, Any]],
) -> None:
    case_by_ua = {str(case.get("user_agent")): case for case in scraper_cases if case.get("user_agent")}
    for case in scraper_cases:
        baseline_significance = _baseline_significance_for_case(case, baseline_by_ua)
        case["confidence_assessment"] = _confidence_assessment(case, background, baseline_significance)
        qualifier = case["confidence_assessment"]["qualifier"]
        if qualifier in {"partial", "low"}:
            for family, rate in (case["confidence_assessment"].get("background_rates") or {}).items():
                if isinstance(rate, dict) and rate.get("concern") == "high":
                    case.setdefault("case_against", []).append(
                        f"{family.replace('_', ' ').title()} fired, but the organic background rate is high ({_num(rate.get('rate_pct')):.1f}%)."
                    )
    for campaign in campaigns:
        member_assessments = [
            case_by_ua[ua].get("confidence_assessment")
            for ua in campaign.get("leads") or []
            if ua in case_by_ua and isinstance(case_by_ua[ua].get("confidence_assessment"), dict)
        ]
        qualifiers = Counter(str(item.get("qualifier") or "unavailable") for item in member_assessments)
        reinforcing = Counter()
        max_background = {"family": None, "rate_pct": None, "concern": "unavailable"}
        baseline_available = 0
        for item in member_assessments:
            for check in item.get("consistency_checks") or []:
                if isinstance(check, dict) and check.get("status") == "present":
                    reinforcing[str(check.get("check"))] += 1
            for family, rate in (item.get("background_rates") or {}).items():
                if isinstance(rate, dict) and rate.get("rate_pct") is not None:
                    if max_background["rate_pct"] is None or _num(rate.get("rate_pct")) > _num(max_background["rate_pct"]):
                        max_background = {"family": family, "rate_pct": rate.get("rate_pct"), "concern": rate.get("concern")}
            baseline = item.get("baseline_significance") if isinstance(item.get("baseline_significance"), dict) else {}
            if baseline.get("status") == "available":
                baseline_available += 1
        member_count = len(member_assessments)
        ua_summary = campaign.get("ua_plausibility_summary") if isinstance(campaign.get("ua_plausibility_summary"), dict) else {}
        confirmed_ua = _num(ua_summary.get("anomalous_member_count"))
        elevated_ua = _num(ua_summary.get("weak_member_count"))
        confirmed_or_elevated_share = (
            (confirmed_ua + elevated_ua) / member_count
            if member_count
            else 0.0
        )
        confirmed_share = confirmed_ua / member_count if member_count else 0.0
        dominant = qualifiers.most_common(1)[0][0] if qualifiers else "unavailable"
        evidence_weighted = dominant
        if member_count and confirmed_share >= 0.50:
            evidence_weighted = "high"
        elif member_count and confirmed_or_elevated_share >= 0.50:
            evidence_weighted = "partial"
        elif reinforcing and sum(reinforcing.values()) / member_count >= 0.50 and dominant == "low":
            evidence_weighted = "partial"
        campaign["confidence_summary"] = {
            "member_count": member_count,
            "qualifier_counts": dict(sorted(qualifiers.items())),
            "dominant_qualifier": evidence_weighted,
            "raw_dominant_qualifier": dominant,
            "aggregate_support": {
                "confirmed_or_elevated_ua_members": int(confirmed_ua + elevated_ua),
                "confirmed_ua_members": int(confirmed_ua),
                "confirmed_or_elevated_share": round(confirmed_or_elevated_share, 3),
            },
            "strongest_reinforcing_combinations": [
                {"check": name, "member_count": count}
                for name, count in reinforcing.most_common(3)
            ],
            "max_background_rate_concern": max_background,
            "baseline_significance_available_count": baseline_available,
        }


def _future_dated_ua(case: dict[str, Any]) -> bool:
    plausibility = case.get("ua_plausibility") if isinstance(case.get("ua_plausibility"), dict) else {}
    signals = plausibility.get("signals") if isinstance(plausibility.get("signals"), dict) else {}
    version = signals.get("version_currency") if isinstance(signals.get("version_currency"), dict) else {}
    return str(version.get("status") or "") == "future_dated"


def _stale_ua(case: dict[str, Any]) -> bool:
    plausibility = case.get("ua_plausibility") if isinstance(case.get("ua_plausibility"), dict) else {}
    signals = plausibility.get("signals") if isinstance(plausibility.get("signals"), dict) else {}
    version = signals.get("version_currency") if isinstance(signals.get("version_currency"), dict) else {}
    return str(version.get("status") or "") in {"stale", "very_stale", "outdated"}


def _action_tier(case: dict[str, Any], *, campaign: bool = False) -> tuple[str, str]:
    flags = set(str(flag) for flag in case.get("evidence_flags") or [])
    plausibility = case.get("ua_plausibility") if isinstance(case.get("ua_plausibility"), dict) else {}
    parsed = plausibility.get("parsed") if isinstance(plausibility.get("parsed"), dict) else {}
    ua_class = str(parsed.get("ua_class") or "")
    native_app_distribution_evidence = {
        "ua_ip_fanout",
        "baseline_novelty_or_growth",
        "infrastructure_topology",
        "temporal_regularity",
        "rate_limit_or_error_pressure",
    }
    abnormal_native_evidence = {
        "automation_signature",
        "endpoint_targeting",
        "ua_anomaly",
        "coordinated_activity",
    }
    if ua_class == "first_party_native_app" and flags and flags <= native_app_distribution_evidence:
        return "tier_4", "monitor_and_revalidate"
    if _future_dated_ua(case) or "automation_signature" in flags:
        return "tier_1", "challenge_or_block_ua"
    if ua_class == "first_party_native_app" and not (flags & abnormal_native_evidence):
        return "tier_4", "monitor_and_revalidate"
    if ua_class == "browser" and {"ua_ip_fanout", "ua_anomaly", "temporal_regularity"} <= flags:
        return "tier_2", "challenge_and_rate_limit"
    if (
        _num(case.get("unique_client_ips")) >= 20
        or "endpoint_targeting" in flags
        or {"temporal_regularity", "rate_limit_or_error_pressure"} <= flags
    ):
        return "tier_2", "challenge_and_rate_limit"
    if campaign or _stale_ua(case) or "coordinated_activity" in flags:
        return "tier_3", "campaign_watchlist_or_challenge"
    return "tier_4", "monitor_and_revalidate"


def _action_for_case(case: dict[str, Any], *, scope: str = "lead", covered_by_campaign: bool = False) -> dict[str, Any]:
    if scope == "ua_family":
        tier, action_type = "tier_3", "campaign_watchlist_or_challenge"
        block_allowed = False
        target_values = {
            "ua_family_id": case.get("family_id"),
            "ua_family_template": case.get("template"),
            "user_agents": case.get("members") or [],
        }
    else:
        tier, action_type = _action_tier(case, campaign=scope == "campaign")
        block_allowed = _future_dated_ua(case) or "automation_signature" in set(case.get("evidence_flags") or [])
        target_values = {"user_agents": [case.get("user_agent")]} if scope == "lead" else {
            "campaign_id": case.get("campaign_id"),
            "user_agents": case.get("leads") or [],
        }
    if case.get("endpoint_targets"):
        target_values["endpoint_prefixes"] = [
            str(row.get("endpoint_prefix") or row.get("request_path") or row.get("value"))
            for row in (case.get("endpoint_targets") or [])[:5]
            if isinstance(row, dict)
        ]
    action = {
        "tier": tier,
        "scope": scope,
        "action_type": action_type,
        "target_values": target_values,
        "supporting_evidence": list(case.get("evidence_flags") or [])[:6],
        "estimated_observed_window_impact": {
            "requests": case.get("total_requests") if scope in {"campaign", "ua_family"} else case.get("requests"),
            "bytes": case.get("bytes"),
        },
        "validation_notes": [
            "Verify current Bot Manager, SIEM, and edge policy coverage before enforcement.",
            "Re-check the target values in a fresh observation window because scraper operators can rotate UA strings, IPs, and endpoints.",
        ],
        "false_positive_caveat": (
            "Challenge-first handling is recommended unless the UA is future-dated or has explicit automation tooling markers."
        ),
        "rollback_monitoring": [
            "Track requests, 429s, 5xxs, and conversion/business-safe traffic for the target scope after deployment.",
            "Remove or relax the rule if protected traffic appears in the validation sample.",
        ],
        "enforcement_wording": "block_candidate" if block_allowed else "challenge_first",
        "covered_by_campaign": covered_by_campaign,
    }
    classification = case.get("threat_classification") if isinstance(case.get("threat_classification"), dict) else {}
    primary = classification.get("primary") if isinstance(classification.get("primary"), dict) else {}
    modifier = conservative_modifier(classification) if classification else None
    if primary:
        action["threat_category"] = primary.get("category")
        action["threat_confidence"] = primary.get("confidence")
    if modifier:
        action["threat_action_modifier"] = modifier
        action["false_positive_caveat"] = modifier
        action["validation_notes"] = [*action["validation_notes"], modifier]
    if classification.get("ambiguity_note"):
        action["classification_ambiguity_note"] = classification.get("ambiguity_note")
    return action


_BROWSER_VERSION_TOKEN_RE = re.compile(
    r"\b(Chrome|CriOS|Chromium|Firefox|Edg|EdgA|EdgiOS|Edge|Version)/(\d+)((?:\.\d+){0,3})",
    re.I,
)


def _ua_family_template(user_agent: str, parsed: dict[str, Any]) -> str | None:
    if parsed.get("ua_class") != "browser" or parsed.get("browser_major") is None:
        return None

    def repl(match: re.Match[str]) -> str:
        return f"{match.group(1)}/{{ver}}{match.group(3)}"

    template = _BROWSER_VERSION_TOKEN_RE.sub(repl, user_agent)
    return template if template != user_agent else None


def _population_cv(values: list[float]) -> float | None:
    if not values:
        return None
    mean = sum(values) / len(values)
    if mean <= 0:
        return None
    variance = sum((value - mean) ** 2 for value in values) / len(values)
    return math.sqrt(variance) / mean


def _campaign_overlaps(members: list[str], campaigns: list[dict[str, Any]]) -> list[dict[str, Any]]:
    member_set = set(members)
    overlaps: list[dict[str, Any]] = []
    for campaign in campaigns:
        campaign_members = [
            str(ua) for ua in campaign.get("leads") or [] if str(ua) in member_set
        ]
        if not campaign_members:
            continue
        overlaps.append(
            {
                "campaign_id": campaign.get("campaign_id"),
                "member_count": len(campaign_members),
                "members": campaign_members,
            }
        )
    return overlaps


def _build_ua_families(
    scraper_cases: list[dict[str, Any]], campaigns: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for case in scraper_cases:
        ua = str(case.get("user_agent") or "")
        parsed = ((case.get("ua_plausibility") or {}).get("parsed") or {})
        template = _ua_family_template(ua, parsed)
        if template:
            grouped[template].append(case)

    candidates: list[dict[str, Any]] = []
    for template, members in grouped.items():
        versions = sorted(
            {
                int(((case.get("ua_plausibility") or {}).get("parsed") or {}).get("browser_major"))
                for case in members
                if ((case.get("ua_plausibility") or {}).get("parsed") or {}).get("browser_major") is not None
            }
        )
        if len(members) < 3 or len(versions) < 3:
            continue
        request_counts = [_num(case.get("requests")) for case in members]
        request_cv = _population_cv(request_counts)
        if request_cv is None or request_cv >= 0.5:
            continue
        member_uas = [str(case.get("user_agent")) for case in members if case.get("user_agent")]
        total_requests = sum(request_counts)
        total_baseline = sum(_num(case.get("baseline_requests")) for case in members)
        common_flags = sorted(
            set.intersection(
                *[set(str(flag) for flag in case.get("evidence_flags") or []) for case in members]
            )
        ) if members else []
        structural_checks = sorted(
            {
                str(check)
                for case in members
                for check in ((case.get("ua_plausibility") or {}).get("fired_structural_checks") or [])
            }
        )
        candidates.append(
            {
                "template": template,
                "members": member_uas,
                "member_count": len(member_uas),
                "version_range": {
                    "min": min(versions),
                    "max": max(versions),
                },
                "version_count": len(versions),
                "versions": versions,
                "total_requests": total_requests,
                "total_baseline": total_baseline,
                "request_volume_cv": round(request_cv, 4),
                "common_evidence": [
                    "Browser user-agent strings share the same template after replacing browser major versions.",
                    "Request volumes are uniform enough to suggest parameterized UA-version rotation.",
                    *common_flags,
                ],
                "structural_checks": structural_checks,
                "campaign_overlaps": _campaign_overlaps(member_uas, campaigns),
                "evidence_flags": ["ua_family_version_rotation"],
            }
        )
    candidates.sort(key=lambda family: (-_num(family.get("total_requests")), str(family.get("template"))))
    for idx, family in enumerate(candidates, start=1):
        family["family_id"] = f"ua-family-{idx}"
        family["recommended_actions"] = [_action_for_case(family, scope="ua_family")]
        for case in scraper_cases:
            if case.get("user_agent") not in set(family["members"]):
                continue
            case["ua_family_id"] = family["family_id"]
            case["ua_family_template"] = family["template"]
            case["nested_under_family"] = not bool(case.get("campaign_id"))
    return candidates


def _attach_recommended_actions(
    campaigns: list[dict[str, Any]],
    ua_families: list[dict[str, Any]],
    scraper_cases: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    case_by_ua = {str(case.get("user_agent")): case for case in scraper_cases if case.get("user_agent")}
    covered_leads: set[str] = set()
    actions: list[dict[str, Any]] = []
    for campaign in campaigns:
        member_cases = [case_by_ua[ua] for ua in campaign.get("leads") or [] if ua in case_by_ua]
        if not member_cases:
            continue
        prototype = {
            **campaign,
            "campaign_id": campaign.get("campaign_id"),
            "evidence_flags": campaign.get("evidence_flags") or sorted({flag for case in member_cases for flag in case.get("evidence_flags", [])}),
            "endpoint_targets": campaign.get("endpoint_targets") or [],
            "bytes": sum(_num(case.get("bytes")) for case in member_cases) or None,
        }
        action = _action_for_case(prototype, scope="campaign")
        campaign["recommended_actions"] = [action]
        covered_leads.update(str(ua) for ua in campaign.get("leads") or [])
        actions.append(action)
    family_leads: set[str] = set()
    for family in ua_families:
        family_action = _action_for_case(family, scope="ua_family")
        family["recommended_actions"] = [family_action]
        family_leads.update(str(ua) for ua in family.get("members") or [])
        actions.append(family_action)
    for case in scraper_cases:
        ua = str(case.get("user_agent") or "")
        if ua in covered_leads or ua in family_leads:
            case["recommended_actions"] = []
            continue
        flags = [str(flag) for flag in case.get("evidence_flags") or [] if str(flag)]
        if case.get("known_traffic") or not flags:
            case["recommended_actions"] = []
            continue
        if str(case.get("verdict") or "") == "not_enough_data" and not flags:
            case["recommended_actions"] = []
            continue
        action = _action_for_case(case, scope="lead")
        case["recommended_actions"] = [action]
        actions.append(action)
    order = {"tier_1": 0, "tier_2": 1, "tier_3": 2, "tier_4": 3}
    actions.sort(
        key=lambda action: (
            {"campaign": 0, "ua_family": 1}.get(str(action.get("scope")), 2),
            order.get(str(action.get("tier")), 9),
            -_num((action.get("estimated_observed_window_impact") or {}).get("requests")),
        )
    )
    return actions


def _scraper_cases(
    *,
    fingerprints: list[dict[str, Any]],
    actor_rows: list[dict[str, Any]],
    endpoints: list[dict[str, Any]],
    drilldown_rows: list[dict[str, Any]],
    iat_rows: list[dict[str, Any]],
    hourly_rows: list[dict[str, Any]],
    ua_fanout_rows: list[dict[str, Any]],
    ua_fanout_source: str,
    window_hour_count: int,
    window_end: datetime,
    geo: dict[str, dict[str, Any]],
    classification: dict[str, Any],
    top_n: int,
) -> list[dict[str, Any]]:
    cases = []
    global_endpoint_rows = _global_endpoint_evidence(endpoints)
    fanout_by_ua = {str(row.get("user_agent")): row for row in ua_fanout_rows if row.get("user_agent")}
    parsed_by_ua = {
        str(fp.get("user_agent")): parse_user_agent(str(fp.get("user_agent") or ""))
        for fp in fingerprints
        if fp.get("user_agent")
    }
    family_request_totals: Counter[str] = Counter()
    total_family_requests = 0.0
    browser_fingerprint_count = 0
    for fp in fingerprints:
        ua = str(fp.get("user_agent") or "")
        family = str((parsed_by_ua.get(ua) or {}).get("browser_family") or "Unknown")
        requests = _num(fp.get("requests"))
        if family != "Unknown" and requests > 0:
            family_request_totals[family] += requests
            total_family_requests += requests
            browser_fingerprint_count += 1
    for fp in fingerprints[:top_n]:
        user_agent = str(fp.get("user_agent") or "")
        if not user_agent:
            continue
        actor = _ua_actor_row(actor_rows, user_agent)
        drilldown = _drilldown_profile(user_agent, drilldown_rows, geo, top_n)
        drilldown_coverage = _drilldown_coverage(
            _num(fp.get("requests")),
            _num(drilldown.get("requests")),
            bool(drilldown.get("available")),
        )
        temporal, timing_status = _timing_analysis(
            user_agent,
            iat_rows,
            drilldown_rows,
            hourly_rows,
            window_hour_count=window_hour_count,
        )
        families: dict[str, dict[str, Any]] = {}

        if _int(fp.get("unique_client_ips")) >= 10 or _int(fp.get("unique_asns")) >= 2:
            _add_family(
                families,
                "ua_ip_fanout",
                label=(
                    f"Exact UA/IP cooccurrence observed {_int(fp.get('unique_client_ips'))} "
                    f"client IPs across {_int(fp.get('unique_asns'))} ASNs."
                ),
                rows=[
                    {
                        "unique_client_ips": fp.get("unique_client_ips"),
                        "unique_asns": fp.get("unique_asns"),
                        "unique_countries": fp.get("unique_countries"),
                        "sample_asns": fp.get("sample_asns") or [],
                        "sample_countries": fp.get("sample_countries") or [],
                    }
                ],
            )

        scoped_endpoint_rows = [
            row for row in drilldown.get("endpoint_targets", []) if isinstance(row, dict)
        ]
        endpoint_rows = _endpoint_targeting_rows(scoped_endpoint_rows)
        endpoint_evidence = _endpoint_evidence_qualification(
            scoped_rows=scoped_endpoint_rows,
            fallback_rows=global_endpoint_rows,
            drilldown_coverage=drilldown_coverage,
        )
        display_endpoint_rows = scoped_endpoint_rows or global_endpoint_rows
        if endpoint_evidence.get("counts_for_verdict"):
            _add_family(
                families,
                "endpoint_targeting",
                label="Scoped endpoint targeting confirmed from per-UA drilldown.",
                rows=endpoint_rows,
            )

        if temporal:
            if temporal.get("resolution") == "hourly_coarse":
                label = "Hourly drilldown shows coarse timing regularity; request-level timestamp samples were not supplied."
            else:
                label = f"Request-level timing sample shows {str(temporal.get('archetype')).replace('_', ' ')} regularity."
            _add_family(
                families,
                "temporal_regularity",
                label=label,
                rows=[temporal],
            )

        baseline_requests = _num(fp.get("baseline_requests"))
        requests = _num(fp.get("requests"))
        baseline_growth = _baseline_growth_family(
            requests, baseline_requests, fp.get("request_delta")
        )
        if baseline_growth:
            _add_family(
                families,
                "baseline_novelty_or_growth",
                label=str(baseline_growth["label"]),
                rows=[
                    {key: value for key, value in baseline_growth.items() if key != "label"}
                ],
            )

        if _automation_signature(user_agent):
            _add_family(
                families,
                "automation_signature",
                label="The user-agent string has automation/crawler tooling markers.",
                rows=[{"user_agent": user_agent}],
            )

        ua_requests = _num(actor.get("requests")) or requests
        ua_429 = _pct(_num(actor.get("status_429")), ua_requests)
        ua_5xx = _pct(_num(actor.get("status_5xx")), ua_requests)
        drill_429 = drilldown.get("rate_429_pct")
        drill_5xx = drilldown.get("rate_5xx_pct")
        if any(_num(value) >= 2 for value in (ua_429, ua_5xx, drill_429, drill_5xx)):
            _add_family(
                families,
                "rate_limit_or_error_pressure",
                label="The UA carried elevated 429 or 5xx pressure in supplied rows.",
                rows=[
                    {
                        "actor_rate_429_pct": ua_429,
                        "actor_rate_5xx_pct": ua_5xx,
                        "drilldown_rate_429_pct": drill_429,
                        "drilldown_rate_5xx_pct": drill_5xx,
                    }
                ],
            )

        if _int(fp.get("unique_asns")) >= 3 or _int(fp.get("unique_countries")) >= 3:
            _add_family(
                families,
                "infrastructure_topology",
                label="The UA spans multiple ASNs or countries in the exact cooccurrence evidence.",
                rows=[
                    {
                        "unique_asns": fp.get("unique_asns"),
                        "unique_countries": fp.get("unique_countries"),
                        "sample_asns": fp.get("sample_asns") or [],
                        "sample_countries": fp.get("sample_countries") or [],
                    }
                ],
            )

        if _classification_gap_is_signal(classification):
            _add_family(
                families,
                "classification_gap",
                label="Optional classification artifacts show incomplete bot/edge coverage.",
                rows=[
                    {
                        "coverage_pct": classification.get("coverage_pct"),
                        "verdict": classification.get("verdict"),
                    }
                ],
            )

        ua_plausibility = score_ua_plausibility(
            user_agent=user_agent,
            window_end=window_end,
            fanout_by_ua=fanout_by_ua,
            fallback_unique_ips=fp.get("unique_client_ips"),
            family_request_totals=family_request_totals,
            total_family_requests=total_family_requests,
            browser_fingerprint_count=browser_fingerprint_count,
            source=ua_fanout_source,
        )
        fanout_signal = (ua_plausibility.get("signals") or {}).get("fanout")
        if isinstance(fanout_signal, dict) and fanout_signal.get("threshold_class") in {"strong", "elevated"}:
            label = str(fanout_signal.get("caveat") or "Source-aware UA fan-out enrichment crossed the suspicious threshold.")
            _add_family(
                families,
                "ua_ip_fanout",
                label=label,
                rows=[
                    {
                        "unique_ips": fanout_signal.get("unique_ips"),
                        "effective_ips": fanout_signal.get("effective_ips"),
                        "source": fanout_signal.get("source"),
                        "threshold_class": fanout_signal.get("threshold_class"),
                        "probe_window_hours": fanout_signal.get("probe_window_hours"),
                        "caveat": fanout_signal.get("caveat"),
                    }
                ],
            )
        if ua_plausibility.get("counts_for_verdict"):
            _add_family(
                families,
                "ua_anomaly",
                label=str(ua_plausibility.get("trigger_reason") or "UA plausibility anomaly confirmed."),
                rows=[ua_plausibility],
            )

        case_for, case_against = _case_for_against(families, drilldown_coverage, endpoint_evidence)
        if ua_plausibility.get("verdict") == "elevated":
            case_for.append(
                "UA plausibility elevated but not verdict-driving: "
                + str(ua_plausibility.get("trigger_reason") or "weak browser-token anomaly")
            )
        cases.append(
            {
                "user_agent": user_agent,
                "verdict": _scraper_case_verdict(families),
                "requests": requests,
                "bytes": fp.get("bytes"),
                "baseline_requests": baseline_requests,
                "request_delta": fp.get("request_delta"),
                "unique_client_ips": fp.get("unique_client_ips"),
                "unique_asns": fp.get("unique_asns"),
                "unique_countries": fp.get("unique_countries"),
                "client_ips": drilldown.get("top_client_ips", []),
                "countries": drilldown.get("countries") or fp.get("sample_countries") or [],
                "asns": drilldown.get("asns") or fp.get("sample_asns") or [],
                "endpoint_targets": display_endpoint_rows,
                "endpoint_evidence": endpoint_evidence,
                "ua_plausibility": ua_plausibility,
                "fanout_enrichment": fanout_signal if isinstance(fanout_signal, dict) else {},
                "hourly_bursts": drilldown.get("hourly_bursts", []),
                "temporal_regularity": temporal,
                "timing_status": timing_status,
                "evidence_flags": [name for name in SCRAPER_EVIDENCE_FAMILIES if name in families],
                "evidence_families": [families[name] for name in SCRAPER_EVIDENCE_FAMILIES if name in families],
                "case_for": case_for,
                "case_against": case_against,
                "missing_evidence": [
                    name for name in SCRAPER_EVIDENCE_FAMILIES if name not in families
                ],
                "drilldown_available": bool(drilldown.get("available")),
                "drilldown_coverage": drilldown_coverage,
            }
        )
    return sorted(
        cases,
        key=lambda row: (
            {"strong_lead": 0, "lead": 1, "weak_lead": 2, "not_enough_data": 3}.get(
                str(row.get("verdict")), 9
            ),
            -_num(row.get("requests")),
            str(row.get("user_agent")),
        ),
    )


def build_threat_hunt_artifact(
    *,
    cluster: str,
    database: str,
    summary_parquet_glob: str,
    start: str,
    end: str,
    baseline_start: str,
    baseline_end: str,
    raw_actor_dir: str | None = None,
    top_n: int = 10,
    geoip_asn_v4: str | None = None,
    geoip_asn_v6: str | None = None,
    cooccurrence_in: str | None = None,
    cooccurrence_path_in: str | None = None,
    scraper_drilldown_in: str | None = None,
    scraper_hourly_in: str | None = None,
    fanout_in: str | None = None,
    fanout_strategy: str = "auto",
    ua_fanout_in: str | None = None,
    ua_fanout_query: str = "off",
    iat_sample_in: str | None = None,
    background_ua_sample_in: str | None = None,
    background_query: str = "auto",
    baseline_ua_timeseries_in: str | None = None,
    baseline_significance_query: str = "auto",
    edge_response_in: str | None = None,
) -> dict[str, Any]:
    current_start = parse_time(start, "start")
    current_end = parse_time(end, "end")
    base_start = parse_time(baseline_start, "baseline-start")
    base_end = parse_time(baseline_end, "baseline-end")
    if current_end - current_start != base_end - base_start:
        raise SystemExit("--baseline window must match the current window duration")
    rows = [_normalize_summary_row(row) for row in read_rows_from_glob(summary_parquet_glob)]
    actor_rows = load_raw_actor_rows(raw_actor_dir)
    geo = _geoip_map((geoip_asn_v4, geoip_asn_v6))
    cooccurrence = _cooccurrence_rows(cooccurrence_in, "ua") + _cooccurrence_rows(cooccurrence_path_in, "path")
    drilldown = _drilldown_rows(scraper_drilldown_in)
    hourly = _scraper_hourly_rows(scraper_hourly_in)
    if fanout_in is None:
        fanout_in = ua_fanout_in
    fanout = _ua_fanout_rows(fanout_in)
    iat_samples = _iat_sample_rows(iat_sample_in)
    background_rows = _read_optional_rows(background_ua_sample_in)
    baseline_timeseries_rows = _read_optional_rows(baseline_ua_timeseries_in)
    edge_rows = _read_optional_rows(edge_response_in)
    siem_rows: list[dict[str, Any]] = []
    if ua_fanout_query not in {"auto", "off", "required", "summary_hour", "logs_probe", "skip"}:
        raise SystemExit("--ua-fanout-query must be one of auto, off, required")
    if fanout_strategy not in {"auto", "summary_hour", "logs_probe", "skip"}:
        raise SystemExit("--fanout-strategy must be one of auto, summary_hour, logs_probe, skip")
    if ua_fanout_query in {"summary_hour", "logs_probe", "skip"} and fanout_strategy == "auto":
        fanout_strategy = ua_fanout_query
    if ua_fanout_query == "off":
        fanout_strategy = "skip"
    if ua_fanout_query == "required" and not fanout:
        raise SystemExit("--ua-fanout-query required needs --ua-fanout-in or a producer-side export step.")
    if background_query not in {"auto", "off", "required"}:
        raise SystemExit("--background-query must be one of auto, off, required")
    if background_query == "required" and not background_rows:
        raise SystemExit("--background-query required needs --background-ua-sample-in or a producer-side export step.")
    if baseline_significance_query not in {"auto", "off", "required"}:
        raise SystemExit("--baseline-significance-query must be one of auto, off, required")
    if baseline_significance_query == "required" and not baseline_timeseries_rows:
        raise SystemExit("--baseline-significance-query required needs --baseline-ua-timeseries-in or a producer-side export step.")

    current = _sum_period(rows, "current")
    baseline = _sum_period(rows, "baseline")
    endpoints = _endpoint_rows(rows, top_n)
    fingerprints = _fingerprints(actor_rows, cooccurrence, geo, top_n)
    countries = _rank_dimension(rows, "country", top_n)
    cohorts = _rank_dimension(rows, "traffic_cohort", top_n)
    infra = _infrastructure(actor_rows, cooccurrence, geo, top_n)
    classification = _classification_gap(edge_rows, siem_rows)
    scraper_cases = _scraper_cases(
        fingerprints=fingerprints,
        actor_rows=actor_rows,
        endpoints=endpoints,
        drilldown_rows=drilldown,
        iat_rows=iat_samples,
        hourly_rows=hourly,
        ua_fanout_rows=fanout,
        ua_fanout_source="fanout_enrichment" if fanout else "cooccurrence_lower_bound" if cooccurrence else "unavailable",
        window_hour_count=_window_hour_count(current_start, current_end),
        window_end=current_end,
        geo=geo,
        classification=classification,
        top_n=top_n,
    )
    scraper_cases, known_traffic = _mark_known_traffic(scraper_cases)
    campaigns, scraper_cases = attach_campaigns(
        scraper_cases=scraper_cases,
        cooccurrence_rows=cooccurrence,
        drilldown_rows=drilldown,
        geo=geo,
    )
    background_rates = _background_rates(background_rows, window_end=current_end)
    baseline_by_ua = _baseline_significance_by_ua(baseline_timeseries_rows)
    _attach_confidence_assessments(
        scraper_cases,
        campaigns,
        background=background_rates,
        baseline_by_ua=baseline_by_ua,
    )
    ua_families = _build_ua_families(scraper_cases, campaigns)
    attach_classifications(
        scraper_cases=scraper_cases,
        campaigns=campaigns,
        ua_families=ua_families,
    )
    recommended_actions = _attach_recommended_actions(campaigns, ua_families, scraper_cases)

    scorecards = [
        _score_baseline(current, baseline),
        _score_ua(fingerprints, bool(cooccurrence), fanout),
        _score_endpoint(endpoints),
        _score_infra(infra),
        classification,
        _score_bhu(fingerprints, endpoints, infra),
    ]

    return {
        "schema_version": SCHEMA,
        "artifact_id": "bot_threat_hunt",
        "scope": {
            "cluster": cluster,
            "database": database,
            "current_window": {"start": start, "end": end},
            "baseline_window": {"start": baseline_start, "end": baseline_end},
            "analysis_mode": "single_customer_single_window",
        },
        "module_scorecards": scorecards,
        "baseline_movement": {
            "current": current,
            "baseline": baseline,
            "metric_deltas": [_metric_delta(name, current, baseline) for name in ("requests", "bytes", "status_429", "status_5xx", "bot_requests", "human_requests")],
            "countries": countries,
            "traffic_cohorts": cohorts,
        },
        "fingerprints": fingerprints,
        "campaigns": campaigns,
        "ua_families": ua_families,
        "scraper_cases": scraper_cases,
        "known_traffic": known_traffic,
        "confidence_metadata": {
            "background_rates": background_rates,
            "baseline_significance": {
                "status": "available" if baseline_by_ua else "unavailable",
                "user_agent_count": len(baseline_by_ua),
            },
        },
        "recommended_actions": recommended_actions,
        "endpoints": endpoints,
        "infrastructure": infra,
        "classification_gap": classification,
        "fanout_enrichment": {
            "strategy": fanout_strategy,
            "rows": fanout,
            "availability": "evidence_backed" if fanout else "not_available",
            "sources": sorted({str(row.get("source") or "unknown") for row in fanout}),
            "caveat": _fanout_limit_detail(fanout),
        },
        "limitations": _data_limits(rows, actor_rows, cooccurrence, fanout, drilldown, hourly, iat_samples, geo, classification),
        "interpretation_constraints": [
            "single_customer_single_window_only",
            "scraper_means_behavioral_repeated_automated_access",
            "no_operator_identity_claim",
            "no_malicious_intent_claim",
            "no_cross_customer_exact_ua_reuse_claim",
        ],
    }
