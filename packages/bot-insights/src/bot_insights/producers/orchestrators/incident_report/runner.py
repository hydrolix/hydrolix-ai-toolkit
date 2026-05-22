"""Public incident-report orchestration entrypoint."""

from __future__ import annotations

import argparse
from datetime import datetime
from pathlib import Path

from producers.formatting import choose_granularity

from .capture import _emit_handoff_packet
from .contracts import _IncidentCtx, _IncidentHandoff
from .emit import _incident_emit_or_render
from .introspection import _incident_introspect_columns
from .phase1 import _incident_phase1_dimensions, _incident_phase1_window_and_timeseries
from .phase2 import _incident_phase2_actors_and_heuristic

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
