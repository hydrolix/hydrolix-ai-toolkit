"""Column introspection for incident reports."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from producers.evidence.incident import _INCIDENT_DEFAULT_FIELDS
from producers.sql.incident import _incident_columns_query

from .capture import _capture_or_raise
from .contracts import _IncidentCtx
from .helpers import _incident_raw_column_candidates, _resolve_summary_layout

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
        ctx.bot_source_columns = {
            column
            for column in ("bot_category", "bot_type", "botnet_id")
            if column in ctx.logs_columns
        }
        ctx.proxy_classification_columns = {
            column
            for column in ("epd_ActionName", "epd_Category", "epd_Match")
            if column in ctx.logs_columns
        }
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
