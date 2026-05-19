"""End-to-end orchestrator for ``--report incident_report``.

Drives the multi-phase capture pipeline:

  1. Introspect column availability via ``system.columns`` queries
     to detect ``akamai.logs`` and the SIEM policy summary table;
     validate the requested ``--fields`` against the discovered
     raw-log schema before running any phase-2 query.
  2. Run the phase-1 SQL (window confirmation + optional SIEM
     blocked share) plus the per-bucket timeseries query plus the
     dimension / status / edge-action / deny-rule / SIEM dimension
     captures.
  3. If raw drilldown is available, run the two-step actor pipeline
     (topK candidates + scoped per-row metrics) per resolved field,
     plus the actor-cooccurrence query.
  4. Assemble ``bot_incident_scope.v1`` +
     ``bot_incident_actors.v1`` artifacts, run the heuristic
     suspicious-target ladder against the actor rankings, build a
     ``bot_report_evidence.v1`` packet, then either emit it
     (``--mode evidence``) or render via ``render_report.py``.

MCP-handoff protocol: any capture call that exits ``NEEDS_MCP_EXIT``
is re-emitted upstream with the per-call ``report_context``
metadata appended so the MCP client can resume from the right
phase.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

# Import the package's sys.path entry so ``heuristics`` / ``baselines``
# (top-level under scripts/) resolve when this module is loaded from
# producers.orchestrators.
_SCRIPTS_DIR = Path(__file__).resolve().parents[2]
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

from producers.evidence.incident import (
    _INCIDENT_DEFAULT_FIELDS,
    _INCIDENT_FIELD_LABELS,
    _build_action_targets_artifact,
    _incident_actor_rows,
    _incident_behavior_clusters,
    _incident_bucketed_mix_timeseries,
    _incident_compute_timeseries,
    _incident_compute_window_confirmation,
    _incident_dimension_rows,
    _incident_entity_clusters,
    _incident_mitigation_effectiveness,
    _incident_status_rows,
    _incident_target_evidence_rows,
)
from producers.evidence.labeling import humanize_evidence_packet
from producers.formatting import choose_granularity
from producers.runtime import (
    CAPTURE,
    HANDOFF_SCHEMA,
    NEEDS_MCP_EXIT,
    PUBLIC_SKILLS,
    load_raw_query_result,
    result_rows,
    run,
)
from producers.rendering import render_report_command
from producers.sql.incident import (
    _incident_actor_cooccurrence_sql,
    _incident_actor_scoped_metrics_baseline_sql,
    _incident_actor_scoped_metrics_sql,
    _incident_actor_topk_baseline_sql,
    _incident_actor_topk_sql,
    _incident_bucketed_dimension_timeseries_sql,
    _incident_bucketed_edge_action_timeseries_sql,
    _incident_columns_query,
    _incident_deny_rule_mix_sql,
    _incident_dimension_sql,
    _incident_edge_action_mix_sql,
    _incident_siem_dimension_sql,
    _incident_status_mix_sql,
    _incident_target_bucket_evidence_sql,
    _incident_volume_timeseries_sql,
    _incident_window_confirmation_sql,
)
from producers.suspicious_targets import _compute_suspicious_targets
from producers.wrapper import analyst_note_from_args, build_report_wrapper


INCIDENT_INTERPRETATION_CONTRACT: dict[str, list[str]] = {
    "allowed": [
        "Lead the executive_summary slot with separate confidence statements "
        "for: traffic anomaly, targeted-automation hypothesis, operational "
        "impact, credential-access hypothesis, and attribution/intent. Make "
        "clear which confidence applies to which claim.",
        "Explain *why* the evidence reads that way - which combination of "
        "spike flags, suspicious-target reason flags, and SIEM signals "
        "is driving the call. State this as an opinion grounded in the "
        "named evidence, not a generic narration.",
        "Format the executive_summary as a hybrid when there are 3+ "
        "distinct parallel signals (different evidence sources concurring): "
        "a 1-sentence prose lead naming the pattern, a bulleted reasoning "
        "trail with one bullet per signal, then an optional 1-sentence "
        "closing interpretation. With 1-2 tightly-coupled signals or when "
        "reasoning interweaves with limitations, prefer integrated prose. "
        "Do not pad prose with inline (1)(2)(3) numbered reasons - use "
        "Markdown bullets instead. The colored criticality + confidence "
        "pills render above the slot already; do not restate them inside "
        "the prose.",
        "Summarize the incident's shape from the scope-confirmation evidence: "
        "request volume, 429 rate, 5xx rate, bot share, SIEM-blocked share.",
        "Describe actor concentration using the top rows in the actors section.",
        "When describing infrastructure topology, count the distinct ASN or "
        "ASN-organization values present in the evidence. Say 'single-ASN' "
        "only when every named actor in the claim has the same ASN. Otherwise "
        "use wording such as 'across N hosting ASN clusters' and name the "
        "ASNs only when they are present in the evidence.",
        "Reference evidence with human-readable labels (Client IP, Client ASN, "
        "Request Path, User Agent, Country, Request host, Status code).",
        "State limitations explicitly when the actors section is empty, only a "
        "single prior-day or prior-window baseline exists, auth telemetry is "
        "missing, or SIEM evidence is missing - including how that affects "
        "confidence in targeted-automation and credential-access hypotheses.",
        "Name the top 1-3 suspicious targets explicitly using their "
        "human-readable label (Client IP `203.0.113.10`, Client ASN 64500, "
        "User Agent `python-requests/2.31`).",
        "Cite the reason flags that promoted each target - for example "
        "'flagged for high volume share and single-path concentration'.",
        "When the `anomaly` primitive fires on a target, name the "
        "baseline-relative magnitude explicitly (e.g. 'Browser cohort "
        "error rate climbed to X% vs ~Y% baseline, an N× departure'). "
        "The anomaly flag carries baseline corroboration the share-based "
        "primitives don't, so it warrants a sentence in the lede when "
        "present.",
        "Reference at least one target from the action-targets artifact in "
        "the next-steps slot.",
        "Frame authentication-abuse labels as evidence-bounded investigation "
        "leads. Credential-access mappings without auth-specific telemetry "
        "must be called a 'possible investigation lead', not credential "
        "stuffing or brute force.",
        "Say 'human-classified anomalous traffic' when a Human/Browser cohort "
        "is anomalous. Do not call it a Human-cohort attack or a proven "
        "Human-cohort anomaly unless classifier-validation evidence is present.",
    ],
    "forbidden": [
        "Do not name internal tables (akamai.logs, bi_summary_*, "
        "bi_siem_policy_summary_*) — refer to 'this report's evidence' or to "
        "the report type by name.",
        "Do not claim malicious intent, abuse, attack causality, actor intent, "
        "or root cause.",
        "Do not use targeted, attack, credential stuffing, brute force, botnet, "
        "actor intent, or root cause as firm claims unless the evidence packet "
        "contains the required corroborating fields. Targeted automation "
        "requires multi-signal actor/path evidence and a rolling or multi-day "
        "baseline before it can be high confidence. Credential access requires "
        "an auth endpoint plus auth outcomes, account identifiers, or explicit "
        "auth/SIEM correlation.",
        "Do not invent metrics, rankings, share percentages, deltas, severity "
        "labels, or dashboard URLs.",
        "Do not invent business or customer-impact facts such as revenue, "
        "booking failures, checkout errors, funnel completion, customer "
        "reports, or latency. Those require explicit supplied evidence; log "
        "volume, status, and actor data are not enough.",
        "Do not invent response-timeline facts such as WAF push time, deny-list "
        "updates, rate-limit changes, post-push drops, threat-intel tickets, "
        "or prior incident waves. Only mention them when they are explicit "
        "fields in the evidence packet or quoted user-supplied context.",
        "Do not convert edge-action evidence into configuration certainty. "
        "No Action / Monitor / Deny shares may support 'edge enforcement was "
        "limited in this window'; they do not prove a rule was absent, a "
        "specific IP was not on a list, or a policy was misconfigured.",
        "Do not collapse multiple ASN clusters into a single-ASN claim. If "
        "the evidence names multiple ASN values or organizations, preserve "
        "that plurality.",
        "Do not query Hydrolix from the interpretation step.",
        "Do not emit final HTML or Markdown layout.",
        "Do not write an executive_summary that only restates the Impact "
        "tiles - the slot must carry a criticality call and reasoning the "
        "tiles do not already convey.",
        "Do not summarize actor concentration in generic terms ('a small "
        "number of actors covered most traffic') without naming the specific "
        "top targets and their reason flags.",
        "Do not propose a specific mitigation action (block, rate-limit, "
        "challenge) - `suggested_action_hint` is mechanical and the LLM's "
        "job is to describe evidence, not propose enforcement.",
        "Do not modify the action-targets list or invent targets, reason "
        "flags, severities, or confidence labels.",
    ],
}




class _IncidentHandoff(Exception):
    """Propagate a capture MCP handoff packet out of nested helpers."""

    def __init__(self, packet: dict, label: str) -> None:
        super().__init__(label)
        self.packet = packet
        self.label = label


@dataclass
class _IncidentCtx:
    """Accumulated state threaded through the incident-report phase functions."""

    granularity: str
    summary_table: str
    raw_drilldown_available: bool = False
    siem_available: bool = False
    siem_table: str | None = None
    logs_columns: set[str] = field(default_factory=set)
    summary_columns: set[str] = field(default_factory=set)
    summary_time_column: str = "reqTimeSec"
    summary_count_column: str = "count()"
    summary_status_column: str = "statusCode"
    summary_cohort_column: str = "trafficCohort"
    summary_path_pattern_column: str = "requestPathPattern"
    fields_resolved: list[str] = field(default_factory=list)
    fields_unresolved: list[str] = field(default_factory=list)
    raw_column_by_field: dict[str, str] = field(default_factory=dict)
    raw_path_column: str = "request_path"
    raw_bytes_column: str = "bytesOut"
    top_n: int = 10
    limitations_scope: list[str] = field(default_factory=list)
    limitations_actors: list[str] = field(default_factory=list)
    window_confirmation: dict = field(default_factory=dict)
    volume_timeseries: dict | None = None
    scope_meta: dict = field(default_factory=dict)
    scope_artifact: dict = field(default_factory=dict)
    actors_artifact: dict = field(default_factory=dict)
    action_targets_artifact: dict = field(default_factory=dict)
    action_targets_limitations: list[str] = field(default_factory=list)
    suspicious_targets: list[dict] = field(default_factory=list)
    target_evidence: dict[str, dict] = field(default_factory=dict)
    behavior_clusters: list[dict] = field(default_factory=list)
    entity_clusters: list[dict] = field(default_factory=list)
    detection_source: str = "summary"
    raw_fallback_used: bool = False


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


def _capture_sql_to_rows(
    args: argparse.Namespace,
    sql: str,
    output_path: Path,
    *,
    label: str,
) -> tuple[list[dict], dict | None]:
    """Run a single ``capture --sql`` invocation and return parsed rows.

    Returns ``(rows, handoff_packet)``. ``handoff_packet`` is non-None
    when capture exited ``NEEDS_MCP_EXIT`` with a
    ``bot_hydrolix_mcp_query_request.v1`` packet. The orchestrator
    re-emits that packet upstream so the existing MCP handoff
    contract carries over unchanged.
    """
    capture_cmd = [
        sys.executable,
        str(CAPTURE),
        "--cluster",
        args.cluster,
        "--database",
        args.database,
        "--sql",
        sql,
        "--output",
        str(output_path),
    ]
    if "system.columns" in sql.lower():
        capture_cmd.append("--no-require-time-range")
    capture_text = run(
        capture_cmd,
        allowed_returncodes=(NEEDS_MCP_EXIT,),
    )
    try:
        summary = json.loads(capture_text) if capture_text else {}
    except json.JSONDecodeError as exc:
        raise SystemExit(
            f"{label}: capture did not return machine-readable JSON ({exc})."
        ) from exc
    if (
        isinstance(summary, dict)
        and summary.get("schema_version") == HANDOFF_SCHEMA
    ):
        return [], summary
    raw_value = load_raw_query_result(output_path)
    return result_rows(raw_value), None








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


def _emit_handoff_packet(
    packet: dict,
    args: argparse.Namespace,
    granularity: str,
    baseline_start: datetime,
    baseline_end: datetime,
    artifact: str,
) -> int:
    report_context = packet.get("report_context")
    if not isinstance(report_context, dict):
        report_context = {}
    report_context.update(
        {
            "report": args.report,
            "mode": args.mode,
            "artifact": artifact,
            "start": args.start,
            "end": args.end,
            "baseline_start": baseline_start.isoformat().replace("+00:00", "Z"),
            "baseline_end": baseline_end.isoformat().replace("+00:00", "Z"),
            "granularity": granularity,
        }
    )
    packet["report_context"] = report_context
    print(json.dumps(packet, sort_keys=True))
    return NEEDS_MCP_EXIT

def _capture_or_raise(
    args: argparse.Namespace,
    sql: str,
    output_path: Path,
    *,
    label: str,
    artifact: str | None = None,
) -> list[dict]:
    """Run a capture call; raise ``_IncidentHandoff`` on MCP handoff.

    ``artifact`` is the value re-emitted as ``report_context.artifact``
    in the handoff packet — distinct from the human-readable ``label``.
    """
    rows, hop = _capture_sql_to_rows(args, sql, output_path, label=label)
    if hop is not None:
        raise _IncidentHandoff(hop, artifact if artifact is not None else label)
    return rows


def _incident_introspect_columns(
    args: argparse.Namespace,
    ctx: _IncidentCtx,
    *,
    sample_dir: Path,
) -> None:
    """Introspect raw / SIEM column availability and validate ``--fields``.

    Exits 2 on field-name validation failure (mirrors the prior in-line
    error path). Raises ``_IncidentHandoff`` if either column-introspection
    capture exits with an MCP handoff packet.
    """
    requested_fields = [
        name.strip()
        for name in (args.fields or _INCIDENT_DEFAULT_FIELDS).split(",")
        if name.strip()
    ]
    ctx.top_n = max(1, int(args.top_n or 10))

    columns_logs_path = sample_dir / f"{args.report}-columns-logs.json"
    logs_rows = _capture_or_raise(
        args,
        _incident_columns_query(args.database, "logs"),
        columns_logs_path,
        label="akamai.logs columns",
        artifact="columns_logs",
    )
    ctx.logs_columns = {row.get("name") for row in logs_rows if row.get("name")}
    ctx.raw_drilldown_available = bool(ctx.logs_columns)

    summary_table_name = ctx.summary_table.split(".", 1)[1]
    columns_summary_path = sample_dir / f"{args.report}-columns-summary.json"
    summary_rows = _capture_or_raise(
        args,
        _incident_columns_query(args.database, summary_table_name),
        columns_summary_path,
        label="summary columns",
        artifact="columns_summary",
    )
    ctx.summary_columns = {row.get("name") for row in summary_rows if row.get("name")}
    _resolve_summary_layout(ctx)

    columns_siem_path = sample_dir / f"{args.report}-columns-siem.json"
    siem_rows = _capture_or_raise(
        args,
        _incident_columns_query(
            args.database, f"bi_siem_policy_summary_{ctx.granularity}"
        ),
        columns_siem_path,
        label="SIEM columns",
        artifact="columns_siem",
    )
    ctx.siem_available = bool(
        {row.get("name") for row in siem_rows if row.get("name")}
    )
    ctx.siem_table = (
        f"{args.database}.bi_siem_policy_summary_{ctx.granularity}"
        if ctx.siem_available
        else None
    )

    if ctx.raw_drilldown_available:
        for fname in requested_fields:
            resolved_column = next(
                (
                    candidate
                    for candidate in _incident_raw_column_candidates(args, fname)
                    if candidate in ctx.logs_columns
                ),
                None,
            )
            if resolved_column:
                ctx.fields_resolved.append(fname)
                ctx.raw_column_by_field[fname] = resolved_column
            else:
                ctx.fields_unresolved.append(fname)
        if ctx.fields_unresolved:
            print(
                "ERROR: --fields contains names not present on this cluster's "
                f"raw access log: {', '.join(ctx.fields_unresolved)}. "
                "Resolve the column names before re-running.",
                file=sys.stderr,
            )
            sys.exit(2)
        ctx.raw_path_column = ctx.raw_column_by_field.get("request_path", "request_path")
        for optional_field in ("trafficCohort", "action_applied"):
            if optional_field in ctx.logs_columns:
                ctx.raw_column_by_field.setdefault(optional_field, optional_field)
        ctx.raw_bytes_column = "bytes" if args.cluster == "expedia" else "bytesOut"
        if ctx.raw_bytes_column not in ctx.logs_columns:
            ctx.raw_bytes_column = "bytesOut" if "bytesOut" in ctx.logs_columns else "bytes"

    if not ctx.siem_available:
        ctx.limitations_scope.append(
            "SIEM policy summary table not present on this cluster; SIEM "
            "mixes are not available."
        )
    if not ctx.raw_drilldown_available:
        ctx.limitations_actors.append(
            "akamai.logs is not present on this cluster; per-actor "
            "drilldown is not available."
        )


def _incident_phase1_window_and_timeseries(
    args: argparse.Namespace,
    ctx: _IncidentCtx,
    *,
    start: datetime,
    end: datetime,
    baseline_start: datetime,
    baseline_end: datetime,
    sample_dir: Path,
) -> None:
    """Run the phase-1 window-confirmation + per-bucket volume timeseries.

    Mutates ``ctx`` with ``window_confirmation`` and ``volume_timeseries``.
    """
    wc_path = sample_dir / f"{args.report}-phase1-window.json"
    wc_rows = _capture_or_raise(
        args,
        _incident_window_confirmation_sql(
            ctx.summary_table,
            ctx.siem_table,
            start,
            end,
            baseline_start,
            baseline_end,
            args.host,
            args.asn,
            args.path_pattern,
            raw_drilldown_available=ctx.raw_drilldown_available,
            raw_path_column=ctx.raw_path_column,
            summary_time_column=ctx.summary_time_column,
            summary_count_column=ctx.summary_count_column,
            summary_status_column=ctx.summary_status_column,
            summary_cohort_column=ctx.summary_cohort_column,
            summary_path_pattern_column=ctx.summary_path_pattern_column,
        ),
        wc_path,
        label="window confirmation",
        artifact="phase1_window",
    )
    window_confirmation, _baseline_stats = (
        _incident_compute_window_confirmation(wc_rows, ctx.siem_available)
    )
    ctx.window_confirmation = window_confirmation
    if window_confirmation.get("source") == "raw":
        ctx.detection_source = "raw"
        ctx.raw_fallback_used = True

    # Per-bucket volume timeseries (drives the Impact chart). One
    # extra grouped scan of the same summary table the window-
    # confirmation query already touched. Same time bounds, same
    # scope predicate. Returns per-bucket
    # (period, requests, req_429, bot_like_requests) which the
    # compute helper reshapes into three series consumed by the
    # renderer's mechanical chart-selection rule.
    ts_path = sample_dir / f"{args.report}-phase1-timeseries.json"
    ts_rows = _capture_or_raise(
        args,
        _incident_volume_timeseries_sql(
            ctx.summary_table,
            ctx.granularity,
            start,
            end,
            baseline_start,
            baseline_end,
            args.host,
            args.asn,
            args.path_pattern,
            summary_time_column=ctx.summary_time_column,
            summary_count_column=ctx.summary_count_column,
            summary_status_column=ctx.summary_status_column,
            summary_cohort_column=ctx.summary_cohort_column,
            summary_path_pattern_column=ctx.summary_path_pattern_column,
        ),
        ts_path,
        label="volume timeseries",
        artifact="phase1_timeseries",
    )
    ctx.volume_timeseries = _incident_compute_timeseries(
        ts_rows,
        granularity=ctx.granularity,
        current_start=start,
        current_end=end,
        baseline_start=baseline_start,
        baseline_end=baseline_end,
    )
    if not _timeseries_has_current_requests(ctx.volume_timeseries):
        ctx.limitations_scope.append(
            "Summary volume timeseries returned no current-window requests; "
            "raw logs were not used as a summary fallback."
        )
        ctx.volume_timeseries = None


def _incident_phase1_dimensions(
    args: argparse.Namespace,
    ctx: _IncidentCtx,
    *,
    start: datetime,
    end: datetime,
    baseline_start: datetime,
    baseline_end: datetime,
    sample_dir: Path,
) -> None:
    """Run dimension / status / edge-action / deny-rule / SIEM-dimension captures.

    Assembles ``scope_meta`` and ``scope_artifact``. Uses two local
    closures that share nine context vars; kept inline so those don't
    have to thread through a free-function signature.
    """
    def _run_dimension(table: str, dimension: str, label: str) -> list[dict]:
        resolved_dimension = _summary_dimension_column(ctx, dimension)
        if resolved_dimension is None:
            ctx.limitations_scope.append(
                f"Summary dimension {dimension} is not present on {ctx.summary_table}; "
                f"{label.replace('_', ' ')} is omitted."
            )
            return []
        out_path = sample_dir / f"{args.report}-phase1-{label}.json"
        return _capture_or_raise(
            args,
            _incident_dimension_sql(
                table,
                resolved_dimension,
                start,
                end,
                baseline_start,
                baseline_end,
                args.host,
                args.asn,
                args.path_pattern,
                ctx.top_n,
                summary_time_column=ctx.summary_time_column,
                summary_count_column=ctx.summary_count_column,
                summary_path_pattern_column=ctx.summary_path_pattern_column,
            ),
            out_path,
            label=label,
        )

    def _run_siem_dimension(dimension: str, label: str) -> list[dict]:
        assert ctx.siem_table is not None
        out_path = sample_dir / f"{args.report}-phase1-{label}.json"
        return _capture_or_raise(
            args,
            _incident_siem_dimension_sql(
                ctx.siem_table,
                dimension,
                start,
                end,
                baseline_start,
                baseline_end,
                args.host,
                args.asn,
                args.path_pattern,
                ctx.top_n,
            ),
            out_path,
            label=label,
        )

    hosts_rows = _run_dimension(ctx.summary_table, "reqHost", "top_hosts")
    if not hosts_rows:
        ctx.limitations_scope.append(
            "Summary top-host rows were empty; raw logs were not used as a "
            "top-host fallback."
        )
    path_rows = _run_dimension(
        ctx.summary_table, "requestPathPattern", "top_path_patterns"
    )
    if not path_rows:
        ctx.limitations_scope.append(
            "Summary top path-pattern rows were empty; raw logs were not used "
            "as a top-path fallback."
        )
    country_rows = _run_dimension(ctx.summary_table, "country", "country_mix")
    status_rows = _capture_or_raise(
        args,
        _incident_status_mix_sql(
            ctx.summary_table,
            start,
            end,
            args.host,
            args.asn,
            args.path_pattern,
            ctx.top_n,
            summary_time_column=ctx.summary_time_column,
            summary_count_column=ctx.summary_count_column,
            summary_status_column=ctx.summary_status_column,
            summary_path_pattern_column=ctx.summary_path_pattern_column,
        ),
        sample_dir / f"{args.report}-phase1-status_mix.json",
        label="status mix",
        artifact="status_mix",
    )
    siem_action_rows: list[dict] = []
    siem_policy_rows: list[dict] = []
    siem_bot_type_rows: list[dict] = []
    if ctx.siem_available:
        siem_action_rows = _run_siem_dimension("actionClass", "siem_action")
        siem_policy_rows = _run_siem_dimension("policyId", "siem_policy")
        siem_bot_type_rows = _run_siem_dimension("botType", "siem_bot_type")
    edge_action_mix_rows: list[dict] = []
    deny_rule_mix_rows: list[dict] = []
    edge_action_timeseries_rows: list[dict] = []
    if ctx.raw_drilldown_available:
        edge_action_mix_rows = _capture_or_raise(
            args,
            _incident_edge_action_mix_sql(
                start,
                end,
                baseline_start,
                baseline_end,
                args.host,
                args.asn,
                args.path_pattern,
                ctx.top_n,
            ),
            sample_dir / f"{args.report}-phase1-edge_action_mix.json",
            label="edge action mix",
            artifact="edge_action_mix",
        )
        deny_rule_mix_rows = _capture_or_raise(
            args,
            _incident_deny_rule_mix_sql(
                start,
                end,
                baseline_start,
                baseline_end,
                args.host,
                args.asn,
                args.path_pattern,
                ctx.top_n,
            ),
            sample_dir / f"{args.report}-phase1-deny_rule_mix.json",
            label="deny rule mix",
            artifact="deny_rule_mix",
        )
        edge_action_timeseries_rows = _capture_or_raise(
            args,
            _incident_bucketed_edge_action_timeseries_sql(
                ctx.granularity,
                start,
                end,
                args.host,
                args.asn,
                args.path_pattern,
                ctx.top_n,
                ctx.raw_path_column,
            ),
            sample_dir / f"{args.report}-phase2-edge_action_timeseries.json",
            label="edge action timeseries",
            artifact="edge_action_timeseries",
        )

    cohort_timeseries_rows: list[dict] = []
    cohort_dimension = _summary_dimension_column(ctx, "trafficCohort")
    if cohort_dimension is not None:
        cohort_timeseries_rows = _capture_or_raise(
            args,
            _incident_bucketed_dimension_timeseries_sql(
                ctx.summary_table,
                cohort_dimension,
                ctx.granularity,
                start,
                end,
                args.host,
                args.asn,
                args.path_pattern,
                ctx.top_n,
                summary_time_column=ctx.summary_time_column,
                summary_count_column=ctx.summary_count_column,
                summary_path_pattern_column=ctx.summary_path_pattern_column,
            ),
            sample_dir / f"{args.report}-phase2-cohort_timeseries.json",
            label="cohort timeseries",
            artifact="cohort_timeseries",
        )

    path_timeseries_rows: list[dict] = []
    path_dimension = _summary_dimension_column(ctx, "requestPathPattern")
    if path_dimension is not None:
        path_timeseries_rows = _capture_or_raise(
            args,
            _incident_bucketed_dimension_timeseries_sql(
                ctx.summary_table,
                path_dimension,
                ctx.granularity,
                start,
                end,
                args.host,
                args.asn,
                args.path_pattern,
                ctx.top_n,
                summary_time_column=ctx.summary_time_column,
                summary_count_column=ctx.summary_count_column,
                summary_path_pattern_column=ctx.summary_path_pattern_column,
            ),
            sample_dir / f"{args.report}-phase2-path_timeseries.json",
            label="path timeseries",
            artifact="path_timeseries",
        )

    total_current = float(ctx.window_confirmation.get("requests") or 0)

    ctx.scope_meta = {
        "cluster": args.cluster,
        "database": args.database,
        "start": args.start,
        "end": args.end,
        "baseline_start": baseline_start.isoformat().replace("+00:00", "Z"),
        "baseline_end": baseline_end.isoformat().replace("+00:00", "Z"),
        "granularity": ctx.granularity,
        "host": args.host,
        "asn": args.asn,
        "path_pattern": args.path_pattern,
        "siem_available": ctx.siem_available,
        "detection_source": getattr(ctx, "detection_source", "summary"),
        "raw_fallback_used": getattr(ctx, "raw_fallback_used", False),
    }

    ctx.scope_artifact = {
        "artifact_id": "incident-scope-1",
        "schema_version": "bot_incident_scope.v1",
        "scope": ctx.scope_meta,
        "detection_source": getattr(ctx, "detection_source", "summary"),
        "raw_fallback_used": getattr(ctx, "raw_fallback_used", False),
        "window_confirmation": ctx.window_confirmation,
        "volume_timeseries": ctx.volume_timeseries,
        "evidence_timeseries": {
            "cohorts": _incident_bucketed_mix_timeseries(
                cohort_timeseries_rows,
                series_type="cohort",
                value_label="Traffic cohort",
            ),
            "paths": _incident_bucketed_mix_timeseries(
                path_timeseries_rows,
                series_type="path",
                value_label="Path pattern",
            ),
            "edge_actions": _incident_bucketed_mix_timeseries(
                edge_action_timeseries_rows,
                series_type="edge_action",
                value_label="Edge action",
            ),
        },
        "top_targeted_hosts": _incident_dimension_rows(
            hosts_rows, total_current=total_current
        ),
        "top_targeted_path_patterns": _incident_dimension_rows(
            path_rows, total_current=total_current
        ),
        "status_mix": _incident_status_rows(
            status_rows, total_current=total_current
        ),
        "country_mix": _incident_dimension_rows(
            country_rows, total_current=total_current
        ),
        "siem_action_mix": (
            _incident_dimension_rows(siem_action_rows, total_current=total_current)
            if ctx.siem_available
            else None
        ),
        "siem_policy_mix": (
            _incident_dimension_rows(siem_policy_rows, total_current=total_current)
            if ctx.siem_available
            else None
        ),
        "siem_bot_type_mix": (
            _incident_dimension_rows(
                siem_bot_type_rows, total_current=total_current
            )
            if ctx.siem_available
            else None
        ),
        "edge_action_mix": (
            _incident_dimension_rows(
                edge_action_mix_rows, total_current=total_current
            )
            if ctx.raw_drilldown_available
            else None
        ),
        "deny_rule_mix": (
            _incident_dimension_rows(
                deny_rule_mix_rows, total_current=total_current
            )
            if ctx.raw_drilldown_available
            else None
        ),
        "dashboard_url": _resolve_dashboard_url(args),
        "limitations": ctx.limitations_scope,
    }


def _incident_phase2_current_actor_field(
    args: argparse.Namespace,
    ctx: _IncidentCtx,
    fname: str,
    *,
    start: datetime,
    end: datetime,
    sample_dir: Path,
) -> tuple[list[str], dict]:
    """Capture topK + scoped metrics for one current-window field.

    Two-step pattern: ``topK(N)`` (Filtered Space-Saving, O(K) memory)
    yields the candidate list, then a scoped metrics ``GROUP BY``
    computes per-actor stats bounded to that list.

    Returns ``(candidates, actor_ranking_entry)``.
    """
    topk_path = sample_dir / f"{args.report}-phase2-{fname}-topk.json"
    topk_rows = _capture_or_raise(
        args,
        _incident_actor_topk_sql(
            ctx.raw_column_by_field.get(fname, fname),
            start,
            end,
            args.host,
            args.asn,
            args.path_pattern,
            ctx.top_n,
            ctx.raw_path_column,
        ),
        topk_path,
        label=f"actors_topk:{fname}",
        artifact=f"actors_topk_{fname}",
    )
    candidates = (
        [str(v) for v in (topk_rows[0].get("candidates") or []) if v]
        if topk_rows else []
    )
    field_label = _INCIDENT_FIELD_LABELS.get(
        fname, fname.replace("_", " ").title()
    )
    if not candidates:
        return candidates, {
            "field": fname,
            "field_label": field_label,
            "rows": [],
        }

    metrics_path = sample_dir / f"{args.report}-phase2-{fname}.json"
    rows = _capture_or_raise(
        args,
        _incident_actor_scoped_metrics_sql(
            fname,
            ctx.raw_column_by_field.get(fname, fname),
            candidates,
            start,
            end,
            args.host, args.asn, args.path_pattern,
            full_metrics=True,
            bytes_column=ctx.raw_bytes_column,
            path_column=ctx.raw_path_column,
        ),
        metrics_path,
        label=f"actors:{fname}",
        artifact=f"actors_{fname}",
    )
    return candidates, {
        "field": fname,
        "field_label": field_label,
        "rows": _incident_actor_rows(rows),
    }


def _incident_phase2_current_actors(
    args: argparse.Namespace,
    ctx: _IncidentCtx,
    *,
    start: datetime,
    end: datetime,
    sample_dir: Path,
) -> dict[str, list[str]]:
    """Capture current-window actor rankings for every resolved field.

    Populates ``ctx.actors_artifact``. Returns a
    ``{field: candidates}`` mapping consumed by the cooccurrence
    sub-phase.
    """
    actor_rankings: list[dict] = []
    current_candidates_by_field: dict[str, list[str]] = {}
    if ctx.raw_drilldown_available and ctx.fields_resolved:
        for fname in ctx.fields_resolved:
            candidates, entry = _incident_phase2_current_actor_field(
                args, ctx, fname, start=start, end=end, sample_dir=sample_dir,
            )
            current_candidates_by_field[fname] = candidates
            actor_rankings.append(entry)

    ctx.actors_artifact = {
        "artifact_id": "incident-actors-1",
        "schema_version": "bot_incident_actors.v1",
        "scope": ctx.scope_meta,
        "raw_drilldown_available": ctx.raw_drilldown_available,
        "raw_table": "akamai.logs",
        "fields_resolved": ctx.fields_resolved,
        "fields_unresolved": ctx.fields_unresolved,
        "top_n": ctx.top_n,
        "actor_rankings": actor_rankings,
        "limitations": ctx.limitations_actors,
    }
    return current_candidates_by_field


def _incident_phase2_baseline_actor_field(
    args: argparse.Namespace,
    ctx: _IncidentCtx,
    fname: str,
    *,
    start: datetime,
    baseline_start: datetime,
    baseline_end: datetime,
    sample_dir: Path,
) -> dict[str, dict]:
    """Capture baseline topK + scoped metrics for one field.

    Same two-step pattern as the current-window helper, against the
    baseline window. The baseline topK is its own candidate set,
    matching the v1 baseline ``GROUP BY LIMIT N`` semantics.
    """
    baseline_topk_path = (
        sample_dir / f"{args.report}-phase2-{fname}-baseline-topk.json"
    )
    topk_rows = _capture_or_raise(
        args,
        _incident_actor_topk_baseline_sql(
            ctx.raw_column_by_field.get(fname, fname),
            baseline_start,
            baseline_end,
            args.host,
            args.asn,
            args.path_pattern,
            ctx.top_n,
            ctx.raw_path_column,
        ),
        baseline_topk_path,
        label=f"actors_baseline_topk:{fname}",
        artifact=f"actors_baseline_topk_{fname}",
    )
    baseline_candidates = (
        [str(v) for v in (topk_rows[0].get("candidates") or []) if v]
        if topk_rows else []
    )
    if not baseline_candidates:
        return {}

    baseline_path = sample_dir / f"{args.report}-phase2-{fname}-baseline.json"
    rows = _capture_or_raise(
        args,
        _incident_actor_scoped_metrics_baseline_sql(
            ctx.raw_column_by_field.get(fname, fname),
            baseline_candidates,
            baseline_start,
            baseline_end,
            args.host,
            args.asn,
            args.path_pattern,
            ctx.raw_path_column,
        ),
        baseline_path,
        label=f"actors_baseline:{fname}",
        artifact=f"actors_baseline_{fname}",
    )
    return {
        str(row["value"]): {
            "requests": float(row.get("requests") or 0),
            "req_429": float(row.get("req_429") or 0),
            "req_5xx": float(row.get("req_5xx") or 0),
        }
        for row in rows
        if row.get("value") is not None
    }


def _incident_phase2_baseline_actors(
    args: argparse.Namespace,
    ctx: _IncidentCtx,
    *,
    start: datetime,
    baseline_start: datetime,
    baseline_end: datetime,
    sample_dir: Path,
) -> dict[str, dict[str, dict]]:
    """Capture baseline-actor rows for every resolved field.

    Feeds the heuristic's ``new_in_window`` primitive — a value
    absent from this mapping is considered "not in baseline's top-N"
    (semantics the existing snapshot tests pin).
    """
    out: dict[str, dict[str, dict]] = {}
    for fname in ctx.fields_resolved:
        out[fname] = _incident_phase2_baseline_actor_field(
            args, ctx, fname,
            start=start,
            baseline_start=baseline_start,
            baseline_end=baseline_end,
            sample_dir=sample_dir,
        )
    return out


# Joint-cooccurrence pair table. Each row says: run a joint GROUP BY
# bounded to ``candidates_a`` (and ``candidates_b`` when
# ``b_required=True``). Bounded to top_n × top_n cells per pair.
#
#   - client_ip × user_agent: feeds Finding 03 (disjoint cohort) and
#     the cohort_topology block in the IOC export.
#   - client_ip × request_path: feeds per-indicator scope qualifiers
#     (``seen_at`` / ``seen_with``) so SOAR consumers can compose
#     path-scoped blocks instead of site-wide ones.
#   - client_ip × action_applied: ``action_applied`` is
#     small-cardinality (Allow / Deny / Monitor / Tarpit), so no
#     topK candidate set is needed — the joint GROUP BY stays
#     bounded by len(ip_candidates) × ~5 actions.
_COOCCURRENCE_PAIRS: tuple[tuple[str, str, str, str, str, bool], ...] = (
    ("client_ip__user_agent", "client_ip", "user_agent", "ip", "ua", True),
    ("client_ip__request_path", "client_ip", "request_path", "ip", "path", True),
    ("client_ip__action_applied", "client_ip", "action_applied", "ip", "action", False),
)


def _incident_phase2_cooccurrence(
    args: argparse.Namespace,
    ctx: _IncidentCtx,
    current_candidates_by_field: dict[str, list[str]],
    *,
    start: datetime,
    end: datetime,
    sample_dir: Path,
) -> None:
    """Capture joint-cooccurrence GROUP BYs and attach to ``actors_artifact``.

    No-op when no candidate set is populated for the pair's primary
    field (``client_ip``).
    """
    cooccurrence: dict[str, list[dict]] = {}
    candidate_sets = {
        "client_ip": current_candidates_by_field.get("client_ip") or [],
        "user_agent": current_candidates_by_field.get("user_agent") or [],
        "request_path": current_candidates_by_field.get("request_path") or [],
        "action_applied": [],
    }
    for pair_label, field_a, field_b, key_a, key_b, b_required in (
        _COOCCURRENCE_PAIRS
    ):
        candidates_a = candidate_sets.get(field_a) or []
        candidates_b = candidate_sets.get(field_b) or []
        if not candidates_a:
            continue
        if b_required and not candidates_b:
            continue
        cooccur_path = (
            sample_dir
            / f"{args.report}-phase2-{pair_label}-cooccurrence.json"
        )
        rows = _capture_or_raise(
            args,
            _incident_actor_cooccurrence_sql(
                field_a, field_b,
                ctx.raw_column_by_field.get(field_a, field_a),
                ctx.raw_column_by_field.get(field_b, field_b),
                candidates_a, candidates_b,
                start, end,
                args.host, args.asn, args.path_pattern,
                ctx.raw_path_column,
            ),
            cooccur_path,
            label=f"actors_cooccurrence:{pair_label}",
            artifact=f"actors_cooccurrence_{pair_label}",
        )
        cooccurrence[pair_label] = [
            {
                key_a: str(row.get("value_a") or ""),
                key_b: str(row.get("value_b") or ""),
                "requests": int(float(row.get("requests") or 0)),
            }
            for row in rows
            if row.get("value_a") and row.get("value_b")
        ]
    if cooccurrence:
        ctx.actors_artifact["actor_cooccurrence"] = cooccurrence


def _incident_phase2_actors_and_heuristic(
    args: argparse.Namespace,
    ctx: _IncidentCtx,
    *,
    start: datetime,
    end: datetime,
    baseline_start: datetime,
    baseline_end: datetime,
    sample_dir: Path,
) -> None:
    """Phase 4: actor capture + cooccurrence + suspicious-target heuristic.

    Thin orchestrator that chains the current-actor, baseline-actor,
    cooccurrence, and heuristic sub-phases. The two-step ``topK`` →
    scoped-metrics pattern replaces the v1 single-shot
    ``GROUP BY field ORDER BY count() DESC LIMIT N`` that OOM'd at
    scale on high-cardinality fields like ``client_ip``.

    Assembles ``actors_artifact``, ``action_targets_artifact``, and
    ``suspicious_targets`` on the context.
    """
    current_candidates_by_field = _incident_phase2_current_actors(
        args, ctx, start=start, end=end, sample_dir=sample_dir,
    )

    if ctx.raw_drilldown_available and ctx.fields_resolved:
        baseline_actor_rows_by_field = _incident_phase2_baseline_actors(
            args, ctx,
            start=start,
            baseline_start=baseline_start,
            baseline_end=baseline_end,
            sample_dir=sample_dir,
        )
        _incident_phase2_cooccurrence(
            args, ctx, current_candidates_by_field,
            start=start, end=end, sample_dir=sample_dir,
        )
        # Read the active thresholds (primed by ``producers.cli.main``
        # from ``--config`` before this orchestrator runs) so an
        # operator override propagates into the heuristic ladder.
        from config import active_thresholds

        ctx.suspicious_targets = _compute_suspicious_targets(
            ctx.scope_artifact,
            ctx.actors_artifact,
            baseline_actor_rows_by_field,
            thresholds=active_thresholds(),
        )
    else:
        ctx.suspicious_targets = []
        ctx.action_targets_limitations.append(
            "Suspicious-target heuristics produced no flagged rows because "
            "the cluster has no raw access log; only summary-level scope "
            "evidence is available."
        )

    if ctx.raw_drilldown_available and ctx.suspicious_targets:
        target_rows = _capture_or_raise(
            args,
            _incident_target_bucket_evidence_sql(
                ctx.suspicious_targets,
                ctx.granularity,
                start,
                end,
                args.host,
                args.asn,
                args.path_pattern,
                ctx.raw_column_by_field,
                ctx.raw_path_column,
                ctx.top_n,
            ),
            sample_dir / f"{args.report}-phase2-target_evidence.json",
            label="target evidence",
            artifact="target_evidence",
        )
        ctx.target_evidence = _incident_target_evidence_rows(target_rows)
        ctx.behavior_clusters = _incident_behavior_clusters(
            ctx.suspicious_targets,
            ctx.target_evidence,
        )
        ctx.entity_clusters = _incident_entity_clusters(
            ctx.suspicious_targets,
            ctx.target_evidence,
        )
    elif not ctx.raw_drilldown_available:
        ctx.action_targets_limitations.append(
            "Per-target temporal evidence and entity clusters are not "
            "available without raw-log drilldown."
        )

    mitigation_effectiveness = _incident_mitigation_effectiveness(
        ctx.scope_artifact,
        ctx.suspicious_targets,
    )
    if mitigation_effectiveness:
        ctx.scope_artifact["mitigation_effectiveness"] = mitigation_effectiveness

    ctx.action_targets_artifact = _build_action_targets_artifact(
        ctx.scope_meta,
        ctx.suspicious_targets,
        heuristic_version="v2",
        limitations=ctx.action_targets_limitations,
        target_evidence=ctx.target_evidence,
        behavior_clusters=ctx.behavior_clusters,
        entity_clusters=ctx.entity_clusters,
    )


def _incident_emit_or_render(
    args: argparse.Namespace,
    ctx: _IncidentCtx,
    *,
    baseline_start: datetime,
    baseline_end: datetime,
    sample_dir: Path,
    output_path: Path,
) -> int:
    """Build the evidence packet then emit JSON (``--mode evidence``) or render."""
    evidence_packet = {
        "schema_version": "bot_report_evidence.v1",
        "report_type": args.report,
        "cluster": args.cluster,
        "database": args.database,
        "granularity": ctx.granularity,
        "current_window": {"start": args.start, "end": args.end},
        "baseline_windows": [
            {
                "start": baseline_start.isoformat().replace("+00:00", "Z"),
                "end": baseline_end.isoformat().replace("+00:00", "Z"),
            }
        ],
        "scope": {
            "host": args.host,
            "asn": args.asn,
            "path_pattern": args.path_pattern,
        },
        "detection_source": getattr(ctx, "detection_source", "summary"),
        "raw_fallback_used": getattr(ctx, "raw_fallback_used", False),
        "window_confirmation": ctx.window_confirmation,
        "top_targeted_hosts": ctx.scope_artifact["top_targeted_hosts"],
        "top_targeted_path_patterns": ctx.scope_artifact["top_targeted_path_patterns"],
        "status_mix": ctx.scope_artifact["status_mix"],
        "country_mix": ctx.scope_artifact["country_mix"],
        "evidence_timeseries": ctx.scope_artifact.get("evidence_timeseries") or {},
        "siem_action_mix": ctx.scope_artifact["siem_action_mix"],
        "siem_policy_mix": ctx.scope_artifact["siem_policy_mix"],
        "siem_bot_type_mix": ctx.scope_artifact["siem_bot_type_mix"],
        "actor_rankings": ctx.actors_artifact["actor_rankings"],
        "raw_drilldown_available": ctx.raw_drilldown_available,
        "siem_available": ctx.siem_available,
        "suspicious_targets": ctx.suspicious_targets,
        "target_evidence": getattr(ctx, "target_evidence", {}),
        "behavior_clusters": getattr(ctx, "behavior_clusters", []),
        "heuristic_version": "v2",
        "limitations": (
            ctx.limitations_scope
            + ctx.limitations_actors
            + ctx.action_targets_limitations
        ),
        "interpretation_contract": INCIDENT_INTERPRETATION_CONTRACT,
    }
    evidence_packet = humanize_evidence_packet(evidence_packet)

    if args.mode == "evidence":
        output_path.write_text(
            json.dumps(evidence_packet, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(
            json.dumps(
                {
                    "cluster": args.cluster,
                    "database": args.database,
                    "granularity": ctx.granularity,
                    "mode": args.mode,
                    "output": str(output_path),
                    "siem_available": ctx.siem_available,
                    "raw_drilldown_available": ctx.raw_drilldown_available,
                },
                sort_keys=True,
            )
        )
        return 0

    wrapper_report_type = getattr(args, "incident_report_type", args.report)
    wrapper = build_report_wrapper(
        args=args,
        artifacts=[
            ctx.scope_artifact,
            ctx.actors_artifact,
            ctx.action_targets_artifact,
        ],
        analyst_note=analyst_note_from_args(args),
        report_type=wrapper_report_type,
    )
    wrapper_path = sample_dir / f"{wrapper_report_type}-wrapper.json"
    wrapper_path.write_text(
        json.dumps(wrapper, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    run(
        render_report_command(
            wrapper_path=wrapper_path,
            output_path=output_path,
            output_format=args.format,
            title=args.title,
        ),
        cwd=PUBLIC_SKILLS,
    )

    print(
        json.dumps(
            {
                "cluster": args.cluster,
                "database": args.database,
                "granularity": ctx.granularity,
                "mode": args.mode,
                "output": str(output_path),
                "siem_available": ctx.siem_available,
                "raw_drilldown_available": ctx.raw_drilldown_available,
            },
            sort_keys=True,
        )
    )
    return 0


def _run_incident_report(
    args: argparse.Namespace,
    start: datetime,
    end: datetime,
    baseline_start: datetime,
    baseline_end: datetime,
    sample_dir: Path,
    output_path: Path,
) -> int:
    """End-to-end orchestrator for ``--report incident_report``.

    Threads ``_IncidentCtx`` through introspection + three capture
    phases. Any ``_IncidentHandoff`` raised from a phase is caught
    once here and re-emitted as an MCP handoff packet via
    ``_emit_handoff_packet``. The render / emit phase runs outside
    the try block — by then all captures have completed.
    """
    summary_suffix = "_exp" if args.cluster == "expedia" else ""
    granularity = choose_granularity(start, end)
    ctx = _IncidentCtx(
        granularity=granularity,
        summary_table=f"{args.database}.bi_summary_{granularity}{summary_suffix}",
    )
    try:
        _incident_introspect_columns(args, ctx, sample_dir=sample_dir)
        _incident_phase1_window_and_timeseries(
            args, ctx, start=start, end=end,
            baseline_start=baseline_start,
            baseline_end=baseline_end,
            sample_dir=sample_dir,
        )
        _incident_phase1_dimensions(
            args, ctx, start=start, end=end,
            baseline_start=baseline_start,
            baseline_end=baseline_end,
            sample_dir=sample_dir,
        )
        _incident_phase2_actors_and_heuristic(
            args, ctx, start=start, end=end,
            baseline_start=baseline_start,
            baseline_end=baseline_end,
            sample_dir=sample_dir,
        )
    except _IncidentHandoff as exc:
        return _emit_handoff_packet(
            exc.packet,
            args,
            granularity,
            baseline_start,
            baseline_end,
            artifact=exc.label,
        )
    return _incident_emit_or_render(
        args, ctx,
        baseline_start=baseline_start,
        baseline_end=baseline_end,
        sample_dir=sample_dir, output_path=output_path,
    )
