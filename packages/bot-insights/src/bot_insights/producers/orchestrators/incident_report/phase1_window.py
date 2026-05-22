"""Incident phase-1 window and timeseries collection."""

from __future__ import annotations

import argparse
from datetime import datetime
from pathlib import Path

from producers.evidence.incident import (
    _incident_compute_timeseries,
    _incident_compute_window_confirmation,
)
from producers.sql.incident import (
    _incident_volume_timeseries_sql,
    _incident_window_confirmation_sql,
)

from .capture import _capture_or_raise
from .contracts import _IncidentCtx
from .helpers import _timeseries_has_current_requests

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
