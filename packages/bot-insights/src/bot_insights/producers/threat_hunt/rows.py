from __future__ import annotations

from ._shared import *

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
    response_body_bytes = _num(_first(row, ("response_body_bytes", "response_bytes", "bytes")))
    akamai_billed_bytes = _num(_first(row, ("akamai_billed_bytes", "totalBytes", "sum_totalBytes")))
    hydrolix_log_ingest_bytes_raw = _first(row, ("hydrolix_log_ingest_bytes",))
    hydrolix_log_ingest_bytes = (
        _num(hydrolix_log_ingest_bytes_raw)
        if hydrolix_log_ingest_bytes_raw not in (None, "")
        else None
    )
    bytes_value = response_body_bytes
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
        "response_body_bytes": response_body_bytes,
        "akamai_billed_bytes": akamai_billed_bytes,
        "hydrolix_log_ingest_bytes": hydrolix_log_ingest_bytes,
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
                "bytes": _num(_first(row, ("bytes", "response_body_bytes", "response_bytes"))),
                "response_body_bytes": _num(_first(row, ("response_body_bytes", "response_bytes", "bytes"))),
                "akamai_billed_bytes": _num(_first(row, ("akamai_billed_bytes", "totalBytes", "sum_totalBytes"))),
                "hydrolix_log_ingest_bytes": (
                    _num(_first(row, ("hydrolix_log_ingest_bytes",)))
                    if _first(row, ("hydrolix_log_ingest_bytes",)) not in (None, "")
                    else None
                ),
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

__all__ = [name for name in globals() if not name.startswith("__")]
