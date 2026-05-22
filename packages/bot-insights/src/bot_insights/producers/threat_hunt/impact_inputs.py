from __future__ import annotations

from ._shared import *

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
        for key in (
            "requests",
            "bytes",
            "response_body_bytes",
            "akamai_billed_bytes",
            "status_429",
            "status_5xx",
            "bot_requests",
            "human_requests",
        ):
            totals[key] += _num(row.get(key))
        if row.get("hydrolix_log_ingest_bytes") not in (None, ""):
            totals["hydrolix_log_ingest_bytes"] += _num(row.get("hydrolix_log_ingest_bytes"))
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

def _load_cost_estimate_config(path_value: str | None) -> dict[str, Any] | None:
    if not path_value:
        return None
    path = Path(path_value).expanduser().resolve()
    if path.suffix.lower() != ".json":
        raise SystemExit("--cost-estimate-config accepts JSON files only.")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"--cost-estimate-config is not valid JSON: {path}") from exc
    if not isinstance(value, dict):
        raise SystemExit("--cost-estimate-config must contain a JSON object.")
    if not value.get("enabled"):
        return None
    return {
        "enabled": True,
        "egress_rate_low_per_gb": _num(value.get("egress_rate_low_per_gb")),
        "egress_rate_high_per_gb": _num(value.get("egress_rate_high_per_gb")),
        "basis_label": str(value.get("basis_label") or "CDN egress estimate"),
        "disclaimer": str(value.get("disclaimer") or "Estimated from observed response bytes and configured egress rates."),
    }

def _hydrolix_usagemeter_estimate_from_rows(
    rows: list[dict[str, Any]],
    *,
    project_deployment_id: str | None,
    table_name: str | None,
    metadata_window: dict[str, str] | None,
) -> dict[str, Any]:
    total_rows = 0.0
    billing_bytes = 0.0
    raw_usage_bytes = 0.0
    window_start = None
    window_end = None
    for row in rows:
        total_rows += _num(_first(row, ("rows", "usage_rows", "row_count")))
        billing_bytes += _num(_first(row, ("billing_bytes", "sum_billing_bytes")))
        raw_usage_bytes += _num(_first(row, ("raw_usage_bytes", "bytes", "sum_bytes")))
        window_start = window_start or _first(row, ("metadata_window_start", "window_start", "start"))
        window_end = window_end or _first(row, ("metadata_window_end", "window_end", "end"))
        project_deployment_id = project_deployment_id or _first(row, ("project_deployment_id",))
        table_name = table_name or _first(row, ("table_name",))
    if total_rows <= 0 or billing_bytes <= 0:
        return {
            "availability": "not_available",
            "source": "hydro.logs usagemeter",
            "estimated": True,
            "reason": "No Hydrolix usagemeter rows with positive rows and billing_bytes were supplied.",
        }
    billing_bytes_per_row = billing_bytes / total_rows
    raw_usage_bytes_per_row = raw_usage_bytes / total_rows if raw_usage_bytes > 0 else None
    return {
        "availability": "available",
        "source": "hydro.logs usagemeter",
        "estimated": True,
        "metric": "billing_bytes_per_row",
        "project_deployment_id": str(project_deployment_id or ""),
        "table_name": str(table_name or "logs"),
        "metadata_window": metadata_window
        or {
            "start": str(window_start or ""),
            "end": str(window_end or ""),
        },
        "rows": total_rows,
        "billing_bytes": billing_bytes,
        "raw_usage_bytes": raw_usage_bytes,
        "billing_bytes_per_row": billing_bytes_per_row,
        "raw_usage_bytes_per_row": raw_usage_bytes_per_row,
    }

def _load_hydrolix_usagemeter_estimate(
    path_value: str | None,
    *,
    project_deployment_id: str | None,
    table_name: str | None,
    metadata_window: dict[str, str] | None,
) -> dict[str, Any] | None:
    if not path_value:
        return None
    rows = _read_optional_rows(path_value)
    if not rows:
        return {
            "availability": "not_available",
            "source": "hydro.logs usagemeter",
            "estimated": True,
            "reason": "Hydrolix usagemeter input was empty.",
        }
    return _hydrolix_usagemeter_estimate_from_rows(
        rows,
        project_deployment_id=project_deployment_id,
        table_name=table_name,
        metadata_window=metadata_window,
    )

def _apply_hydrolix_ingest_estimate(
    rows: list[dict[str, Any]],
    actor_rows: list[dict[str, Any]],
    estimate: dict[str, Any] | None,
) -> None:
    if not estimate or estimate.get("availability") != "available":
        return
    bytes_per_row = _num(estimate.get("billing_bytes_per_row"))
    if bytes_per_row <= 0:
        return
    for row in rows:
        if row.get("hydrolix_log_ingest_bytes") in (None, ""):
            row["hydrolix_log_ingest_bytes"] = _num(row.get("requests")) * bytes_per_row
    for row in actor_rows:
        if row.get("hydrolix_log_ingest_bytes") in (None, ""):
            row["hydrolix_log_ingest_bytes"] = _num(row.get("requests")) * bytes_per_row

def _share_fraction(part: float, whole: float) -> float | None:
    if whole <= 0:
        return None
    return part / whole

def _share_severity(share: float | None) -> str:
    value = share if share is not None else 0.0
    if value > 0.20:
        return "dominant"
    if value > 0.05:
        return "significant"
    if value > 0.01:
        return "moderate"
    return "minor"

def _trend_severity(current_share: float | None, baseline_share: float | None) -> str:
    current_value = current_share if current_share is not None else 0.0
    baseline_value = baseline_share if baseline_share is not None else 0.0
    if baseline_value <= 0:
        return "new_entrant" if current_value > 0.001 else "stable"
    ratio = current_value / baseline_value
    if ratio >= 2.0:
        return "accelerating"
    if ratio > 1.10:
        return "growing"
    if ratio < 0.90:
        return "declining"
    return "stable"

def _share_direction(current_share: float | None, baseline_share: float | None) -> str:
    current_value = current_share if current_share is not None else 0.0
    baseline_value = baseline_share if baseline_share is not None else 0.0
    if current_value > baseline_value * 1.05:
        return "growing_share"
    if current_value < baseline_value * 0.95:
        return "shrinking_share"
    return "stable_share"

BYTE_LANE_FIELDS = (
    "hydrolix_log_ingest_bytes",
    "response_body_bytes",
    "akamai_billed_bytes",
)

def _sum_optional_lane(rows: Iterable[dict[str, Any]], field: str) -> float | None:
    total = 0.0
    available = False
    for row in rows:
        value = row.get(field)
        if value in (None, ""):
            continue
        total += _num(value)
        available = True
    return total if available else None

def _lane_share(part: float | None, whole: float | None) -> float | None:
    if part is None or whole is None:
        return None
    return _share_fraction(part, whole)

__all__ = [name for name in globals() if not name.startswith("__")]
