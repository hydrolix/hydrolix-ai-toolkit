"""Small incident-report environment and layout helpers."""

from __future__ import annotations

import argparse
import os
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from pathlib import Path

from .contracts import _IncidentCtx

_EXPEDIA_RAW_COLUMN_MAP = {
    "client_ip": "cliIP",
    "request_path": "reqPath",
    "user_agent": "UA",
    "status_code": "statusCode",
    "request_method": "reqMethod",
}
def _incident_raw_column_candidates(args: argparse.Namespace, field_name: str) -> list[str]:
    candidates = [field_name]
    if args.cluster == "expedia":
        mapped = _EXPEDIA_RAW_COLUMN_MAP.get(field_name)
        if mapped:
            candidates.insert(0, mapped)
    return candidates
def _timeseries_has_current_requests(volume_timeseries: dict | None) -> bool:
    if not volume_timeseries:
        return False
    requests = (
        (volume_timeseries.get("series") or {})
        .get("requests_per_minute", {})
        .get("current")
        or []
    )
    return any(float(value or 0) > 0 for value in requests)
def _summary_dimension_column(ctx: _IncidentCtx, requested: str) -> str | None:
    if requested in ctx.summary_columns:
        return requested
    if requested == "requestPathPattern" and "reqPathPatternCoarse" in ctx.summary_columns:
        return "reqPathPatternCoarse"
    return None
def _resolve_summary_layout(ctx: _IncidentCtx) -> None:
    """Resolve physical posture-summary columns from introspected metadata."""
    if "reqTimeSec" in ctx.summary_columns:
        ctx.summary_time_column = "reqTimeSec"
    else:
        bucket_key = f"toStartOf{ctx.granularity.title()}(reqTimeSec)"
        if bucket_key in ctx.summary_columns:
            ctx.summary_time_column = bucket_key

    if "count()" in ctx.summary_columns:
        ctx.summary_count_column = "count()"
    if "statusCode" in ctx.summary_columns:
        ctx.summary_status_column = "statusCode"
    if "trafficCohort" in ctx.summary_columns:
        ctx.summary_cohort_column = "trafficCohort"
    resolved_path = _summary_dimension_column(ctx, "requestPathPattern")
    if resolved_path:
        ctx.summary_path_pattern_column = resolved_path
def _incident_cluster_env(args: argparse.Namespace) -> dict[str, str]:
    env_path = Path(
        f"~/.config/hydrolix/clusters/{args.cluster}.env"
    ).expanduser()
    values: dict[str, str] = {}
    if env_path.exists():
        for line in env_path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            key, value = stripped.split("=", 1)
            if key.startswith("BI_INCIDENT_"):
                values[key] = value.strip().strip("'\"")
    return values
def _resolve_incident_env_value(
    args: argparse.Namespace,
    cluster_env: dict[str, str],
    key: str,
    arg_name: str | None = None,
) -> str:
    if arg_name:
        arg_value = getattr(args, arg_name, None)
        if arg_value:
            return str(arg_value).strip()
    return (cluster_env.get(key) or os.environ.get(key, "")).strip()
def _grafana_host_base(hostname: str) -> str:
    hostname = hostname.strip().rstrip("/")
    if not hostname:
        return ""
    if "://" in hostname:
        return hostname
    return f"https://{hostname}"
def _resolve_dashboard_url(args: argparse.Namespace) -> str:
    """Resolve the optional Grafana drilldown URL for incident reports.

    ``BI_INCIDENT_DASHBOARD_URL`` is a full-template escape hatch and
    intentionally wins over structured host/path inputs. Structured mode
    treats the dashboard path as deployment-specific configuration.
    Returns ``""`` when no complete URL configuration is present.
    """
    cluster_env = _incident_cluster_env(args)
    template = _resolve_incident_env_value(
        args, cluster_env, "BI_INCIDENT_DASHBOARD_URL"
    )
    if not template:
        hostname = _resolve_incident_env_value(
            args,
            cluster_env,
            "BI_INCIDENT_GRAFANA_HOSTNAME",
            "grafana_hostname",
        )
        dashboard_path = _resolve_incident_env_value(
            args,
            cluster_env,
            "BI_INCIDENT_DASHBOARD_PATH",
            "grafana_dashboard_path",
        )
        if not hostname or not dashboard_path:
            return ""

        base = _grafana_host_base(hostname)
        path = dashboard_path if dashboard_path.startswith("/") else f"/{dashboard_path}"
        split = urlsplit(f"{base}{path}")
        params = parse_qsl(split.query, keep_blank_values=True)
        params.extend([("from", args.start), ("to", args.end)])
        if args.host:
            params.append(("var-filter", f"reqHost|=|{args.host}"))
        if args.asn:
            params.append(("var-filter", f"asn|=|{args.asn}"))
        if args.path_pattern:
            params.append(
                ("var-filter", f"requestPathPattern|=|{args.path_pattern}")
            )
        return urlunsplit(
            (
                split.scheme,
                split.netloc,
                split.path,
                urlencode(params),
                split.fragment,
            )
        )

    return (
        template.replace("{start}", args.start)
        .replace("{end}", args.end)
        .replace("{host}", args.host or "")
        .replace("{asn}", str(args.asn) if args.asn else "")
        .replace("{path_pattern}", args.path_pattern or "")
    )
