"""Capture invocation and MCP handoff helpers for incident reports."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

from producers.runtime import (
    CAPTURE,
    HANDOFF_SCHEMA,
    NEEDS_MCP_EXIT,
    load_raw_query_result,
    result_rows,
    run,
)

from .contracts import _IncidentHandoff

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
