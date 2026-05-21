"""Corroborating explanation signals for the incident assessment."""

from __future__ import annotations

from math import log2, sqrt
from typing import Any

from .claim_gates import _AUTH_PATH_MARKERS, compute_provenance_overlap
from .formatters import _format_count, _format_pct, _safe_number

_API_PATH_MARKERS = ("/api", "/graphql", "/v1/", "/v2/", "/rest")


def _positive(value: Any) -> float:
    number = _safe_number(value)
    return max(float(number or 0), 0.0)


def _flagged_client_ips(targets: list[dict[str, Any]]) -> dict[str, float]:
    out: dict[str, float] = {}
    for target in targets or []:
        if target.get("target_type") != "client_ip":
            continue
        ip = str(target.get("target_value") or "")
        requests = _positive((target.get("supporting") or {}).get("requests"))
        if ip and requests > 0:
            out[ip] = out.get(ip, 0.0) + requests
    return out


def _is_auth_path(path: str) -> bool:
    lower = path.lower()
    return any(marker in lower for marker in _AUTH_PATH_MARKERS)


def _is_api_path(path: str) -> bool:
    lower = path.lower()
    return any(marker in lower for marker in _API_PATH_MARKERS)


def _path_ip_convergence(
    actors_art: dict[str, Any],
    targets: list[dict[str, Any]],
) -> dict[str, Any]:
    flagged_ips = _flagged_client_ips(targets)
    total_flagged = sum(flagged_ips.values())
    result = {
        "available": False,
        "flagged_client_ip_count": len(flagged_ips),
        "total_flagged_client_ip_requests": total_flagged,
        "total_flagged_client_ip_requests_display": _format_count(total_flagged),
        "top_paths": [],
        "summary": "",
    }
    if not flagged_ips:
        return result

    cells = (actors_art.get("actor_cooccurrence") or {}).get(
        "client_ip__request_path"
    ) or []
    path_requests: dict[str, float] = {}
    path_ips: dict[str, set[str]] = {}
    saw_relevant_cell = False
    for cell in cells:
        ip = str(cell.get("ip") or "")
        path = str(cell.get("path") or "")
        requests = _positive(cell.get("requests"))
        if ip not in flagged_ips or not path or requests <= 0:
            continue
        saw_relevant_cell = True
        path_requests[path] = path_requests.get(path, 0.0) + requests
        path_ips.setdefault(path, set()).add(ip)
    if not saw_relevant_cell or total_flagged <= 0:
        return result

    rows: list[dict[str, Any]] = []
    for path, requests in sorted(path_requests.items(), key=lambda item: (-item[1], item[0]))[:5]:
        share = requests / total_flagged
        rows.append(
            {
                "path": path,
                "requests": requests,
                "requests_display": _format_count(requests),
                "share": round(share, 4),
                "share_display": _format_pct(share * 100.0),
                "flagged_ip_count": len(path_ips.get(path, set())),
                "auth_related": _is_auth_path(path),
                "api_related": _is_api_path(path),
            }
        )
    primary = [row for row in rows if row["share"] >= 0.1] or rows[:2]
    primary_share = sum(float(row["share"]) for row in primary)
    result.update(
        {
            "available": bool(rows),
            "top_paths": rows,
            "summary": (
                f"Flagged IPs converged on {len(primary)} primary "
                f"{'path' if len(primary) == 1 else 'paths'} accounting for "
                f"{_format_pct(primary_share * 100.0)} of flagged client-IP requests."
            ),
        }
    )
    return result


def _entropy_metrics(counts: list[float]) -> tuple[float, float]:
    total = sum(counts)
    if total <= 0 or len(counts) <= 1:
        return 0.0, 0.0
    entropy = -sum((count / total) * log2(count / total) for count in counts if count > 0)
    max_entropy = log2(len(counts))
    normalized = entropy / max_entropy if max_entropy > 0 else 0.0
    return entropy, normalized


def _rotation_label(distinct: int, top_share: float, normalized_entropy: float) -> str:
    if (distinct >= 10 and top_share < 0.5) or normalized_entropy >= 0.70:
        return "high"
    if distinct >= 4 or normalized_entropy >= 0.40:
        return "moderate"
    return "low"


def _user_agent_rotation(
    actors_art: dict[str, Any],
    targets: list[dict[str, Any]],
) -> dict[str, Any]:
    flagged_ips = _flagged_client_ips(targets)
    result = {
        "available": False,
        "rows": [],
        "summary": "",
        "boundary": (
            "UA rotation is consistent with automation or aggregator behavior; "
            "it does not prove operator intent."
        ),
    }
    if not flagged_ips:
        return result
    cells = (actors_art.get("actor_cooccurrence") or {}).get(
        "client_ip__user_agent"
    ) or []
    by_ip: dict[str, dict[str, float]] = {ip: {} for ip in flagged_ips}
    for cell in cells:
        ip = str(cell.get("ip") or "")
        ua = str(cell.get("ua") or cell.get("user_agent") or "")
        requests = _positive(cell.get("requests"))
        if ip not in by_ip or not ua or requests <= 0:
            continue
        by_ip[ip][ua] = by_ip[ip].get(ua, 0.0) + requests

    rows: list[dict[str, Any]] = []
    for ip, ua_counts in by_ip.items():
        if not ua_counts:
            continue
        ordered = sorted(ua_counts.items(), key=lambda item: (-item[1], item[0]))
        total = sum(ua_counts.values())
        top_ua, top_requests = ordered[0]
        top_share = top_requests / total if total > 0 else 0.0
        entropy, normalized = _entropy_metrics(list(ua_counts.values()))
        rows.append(
            {
                "client_ip": ip,
                "requests": flagged_ips[ip],
                "requests_display": _format_count(flagged_ips[ip]),
                "distinct_user_agents": len(ua_counts),
                "top_user_agent": top_ua,
                "top_user_agent_requests": top_requests,
                "top_user_agent_requests_display": _format_count(top_requests),
                "top_user_agent_share": round(top_share, 4),
                "top_user_agent_share_display": _format_pct(top_share * 100.0),
                "entropy_bits": round(entropy, 3),
                "normalized_entropy": round(normalized, 3),
                "rotation_label": _rotation_label(len(ua_counts), top_share, normalized),
            }
        )
    rows.sort(
        key=lambda row: (
            {"high": 0, "moderate": 1, "low": 2}.get(row["rotation_label"], 9),
            -float(row["requests"]),
            row["client_ip"],
        )
    )
    if not rows:
        return result
    high = sum(1 for row in rows if row["rotation_label"] == "high")
    moderate = sum(1 for row in rows if row["rotation_label"] == "moderate")
    result.update(
        {
            "available": True,
            "rows": rows[:5],
            "summary": (
                f"{high} flagged IPs showed high UA rotation and {moderate} "
                "showed moderate UA rotation."
            ),
        }
    )
    return result


def _pearson(xs: list[float], ys: list[float]) -> float | None:
    if len(xs) < 3 or len(xs) != len(ys):
        return None
    x_mean = sum(xs) / len(xs)
    y_mean = sum(ys) / len(ys)
    numerator = sum((x - x_mean) * (y - y_mean) for x, y in zip(xs, ys))
    x_var = sum((x - x_mean) ** 2 for x in xs)
    y_var = sum((y - y_mean) ** 2 for y in ys)
    denom = sqrt(x_var * y_var)
    if denom <= 0:
        return None
    return round(numerator / denom, 3)


def _flagged_ip_timeseries_alignment(
    action_targets_art: dict[str, Any],
) -> dict[str, Any]:
    rows = action_targets_art.get("flagged_client_ip_timeseries") or []
    result = {
        "available": False,
        "series": [],
        "peak_bucket": "",
        "peak_requests": 0,
        "peak_requests_display": "—",
        "peak_signals": [],
        "correlations": [],
        "summary": "",
    }
    series = [
        {
            "bucket": str(row.get("bucket") or ""),
            "flagged_requests": _positive(row.get("flagged_requests") or row.get("requests")),
            "req_429": _positive(row.get("req_429")),
            "req_5xx": _positive(row.get("req_5xx")),
            "edge_deny": _positive(row.get("edge_deny")),
            "edge_allow": _positive(row.get("edge_allow")),
            "edge_challenge": _positive(row.get("edge_challenge")),
            "bot_provenance": _positive(row.get("bot_provenance")),
            "proxy_classification": _positive(row.get("proxy_classification")),
            "graphql": _positive(row.get("graphql")),
            "auth_path": _positive(row.get("auth_path")),
        }
        for row in rows
        if str(row.get("bucket") or "") and _positive(row.get("flagged_requests") or row.get("requests")) > 0
    ]
    series.sort(key=lambda row: row["bucket"])
    if not series:
        return result
    peak_index, peak_row = max(
        enumerate(series), key=lambda item: (item[1]["flagged_requests"], item[1]["bucket"])
    )
    signal_specs = [
        ("req_429", "429s"),
        ("req_5xx", "5xxs"),
        ("edge_deny", "edge deny"),
        ("bot_provenance", "bot provenance"),
        ("proxy_classification", "proxy classification"),
        ("graphql", "/graphql"),
        ("auth_path", "auth-path"),
    ]
    peak_signals: list[str] = []
    correlations: list[dict[str, Any]] = []
    flagged_values = [float(row["flagged_requests"]) for row in series]
    for key, label in signal_specs:
        values = [float(row[key]) for row in series]
        if max(values or [0]) > 0:
            signal_peak = max(range(len(values)), key=lambda idx: (values[idx], series[idx]["bucket"]))
            if abs(signal_peak - peak_index) <= 1:
                peak_signals.append(label)
        corr = _pearson(flagged_values, values)
        if corr is not None:
            correlations.append({"signal": label, "correlation": corr})
    result.update(
        {
            "available": True,
            "series": series,
            "peak_bucket": peak_row["bucket"],
            "peak_requests": peak_row["flagged_requests"],
            "peak_requests_display": _format_count(peak_row["flagged_requests"]),
            "peak_signals": peak_signals,
            "correlations": correlations,
            "summary": (
                f"Flagged client-IP requests peaked at {peak_row['bucket']} "
                f"with {_format_count(peak_row['flagged_requests'])} requests"
                + (f"; adjacent peaks included {', '.join(peak_signals)}." if peak_signals else ".")
            ),
        }
    )
    return result


def assessment_explainers(
    actors_art: dict[str, Any],
    action_targets_art: dict[str, Any],
    suspicious_targets: list[dict[str, Any]],
) -> dict[str, Any]:
    path = _path_ip_convergence(actors_art, suspicious_targets)
    timeseries = _flagged_ip_timeseries_alignment(action_targets_art)
    ua_rotation = _user_agent_rotation(actors_art, suspicious_targets)
    provenance = compute_provenance_overlap(actors_art, suspicious_targets)
    provenance_available = bool(provenance.get("available"))
    if provenance_available:
        provenance = {
            **provenance,
            "summary": (
                f"{provenance.get('overlap_share_display')} of flagged client-IP "
                "requests overlapped bot/proxy provenance cells."
            ),
            "boundary": (
                "Bot/proxy provenance is source metadata overlap. It corroborates "
                "the assessment but does not prove root cause, operator intent, or "
                "an automation conclusion."
            ),
        }
    return {
        "available": any(
            block.get("available")
            for block in (path, timeseries, ua_rotation, provenance)
        ),
        "path_ip_convergence": path,
        "flagged_ip_timeseries_alignment": timeseries,
        "user_agent_rotation": ua_rotation,
        "bot_proxy_provenance_overlap": provenance,
        "boundary": (
            "These signals explain why the assessment is credible, but they are "
            "corroborating evidence only and do not change confidence gates, "
            "risk score, or target priority."
        ),
    }
