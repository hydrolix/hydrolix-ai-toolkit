from __future__ import annotations

from ._shared import *

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

__all__ = [name for name in globals() if not name.startswith("__")]
