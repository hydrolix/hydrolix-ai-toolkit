"""Incident phase-1 dimension, status, action, and SIEM collection."""

from __future__ import annotations

import argparse
from datetime import datetime
from pathlib import Path

from producers.evidence.incident import (
    _incident_bucketed_mix_timeseries,
    _incident_dimension_rows,
    _incident_status_rows,
)
from producers.sql.incident import (
    _incident_bot_source_mix_sql,
    _incident_bucketed_dimension_timeseries_sql,
    _incident_bucketed_edge_action_timeseries_sql,
    _incident_deny_rule_mix_sql,
    _incident_dimension_sql,
    _incident_edge_action_mix_sql,
    _incident_proxy_classification_mix_sql,
    _incident_siem_dimension_sql,
    _incident_status_mix_sql,
)

from .capture import _capture_or_raise
from .contracts import _IncidentCtx
from .helpers import _resolve_dashboard_url, _summary_dimension_column

def _incident_run_dimension(
    args: argparse.Namespace,
    ctx: _IncidentCtx,
    table: str,
    dimension: str,
    label: str,
    *,
    start: datetime,
    end: datetime,
    baseline_start: datetime,
    baseline_end: datetime,
    sample_dir: Path,
) -> list[dict]:
    resolved_dimension = _summary_dimension_column(ctx, dimension)
    if resolved_dimension is None:
        ctx.limitations_scope.append(
            f"Summary dimension {dimension} is not present on {ctx.summary_table}; "
            f"{label.replace('_', ' ')} is omitted."
        )
        return []
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
        sample_dir / f"{args.report}-phase1-{label}.json",
        label=label,
    )
def _incident_run_siem_dimension(
    args: argparse.Namespace,
    ctx: _IncidentCtx,
    dimension: str,
    label: str,
    *,
    start: datetime,
    end: datetime,
    baseline_start: datetime,
    baseline_end: datetime,
    sample_dir: Path,
) -> list[dict]:
    assert ctx.siem_table is not None
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
        sample_dir / f"{args.report}-phase1-{label}.json",
        label=label,
    )
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

    Assembles ``scope_meta`` and ``scope_artifact``.
    """
    hosts_rows = _incident_run_dimension(
        args, ctx, ctx.summary_table, "reqHost", "top_hosts",
        start=start, end=end, baseline_start=baseline_start,
        baseline_end=baseline_end, sample_dir=sample_dir,
    )
    if not hosts_rows:
        ctx.limitations_scope.append(
            "Summary top-host rows were empty; raw logs were not used as a "
            "top-host fallback."
        )
    path_rows = _incident_run_dimension(
        args, ctx, ctx.summary_table, "requestPathPattern", "top_path_patterns",
        start=start, end=end, baseline_start=baseline_start,
        baseline_end=baseline_end, sample_dir=sample_dir,
    )
    if not path_rows:
        ctx.limitations_scope.append(
            "Summary top path-pattern rows were empty; raw logs were not used "
            "as a top-path fallback."
        )
    country_rows = _incident_run_dimension(
        args, ctx, ctx.summary_table, "country", "country_mix",
        start=start, end=end, baseline_start=baseline_start,
        baseline_end=baseline_end, sample_dir=sample_dir,
    )
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
        siem_action_rows = _incident_run_siem_dimension(
            args, ctx, "actionClass", "siem_action",
            start=start, end=end, baseline_start=baseline_start,
            baseline_end=baseline_end, sample_dir=sample_dir,
        )
        siem_policy_rows = _incident_run_siem_dimension(
            args, ctx, "policyId", "siem_policy",
            start=start, end=end, baseline_start=baseline_start,
            baseline_end=baseline_end, sample_dir=sample_dir,
        )
        siem_bot_type_rows = _incident_run_siem_dimension(
            args, ctx, "botType", "siem_bot_type",
            start=start, end=end, baseline_start=baseline_start,
            baseline_end=baseline_end, sample_dir=sample_dir,
        )
    edge_action_mix_rows: list[dict] = []
    deny_rule_mix_rows: list[dict] = []
    edge_action_timeseries_rows: list[dict] = []
    bot_source_rows: list[dict] = []
    proxy_classification_rows: list[dict] = []
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
        if ctx.bot_source_columns:
            bot_source_rows = _capture_or_raise(
                args,
                _incident_bot_source_mix_sql(
                    start,
                    end,
                    baseline_start,
                    baseline_end,
                    args.host,
                    args.asn,
                    args.path_pattern,
                    ctx.top_n,
                    ctx.raw_path_column,
                    ctx.bot_source_columns,
                ),
                sample_dir / f"{args.report}-phase1-bot_source_mix.json",
                label="bot source mix",
                artifact="bot_source_mix",
            )
        if "epd_Category" in ctx.proxy_classification_columns:
            proxy_classification_rows = _capture_or_raise(
                args,
                _incident_proxy_classification_mix_sql(
                    start,
                    end,
                    baseline_start,
                    baseline_end,
                    args.host,
                    args.asn,
                    args.path_pattern,
                    ctx.top_n,
                    ctx.raw_path_column,
                    ctx.proxy_classification_columns,
                ),
                sample_dir / f"{args.report}-phase1-proxy_classification_mix.json",
                label="proxy classification mix",
                artifact="proxy_classification_mix",
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
        "bot_source_mix": (
            _incident_dimension_rows(
                bot_source_rows, total_current=total_current
            )
            if bot_source_rows
            else None
        ),
        "proxy_classification_mix": (
            _incident_dimension_rows(
                proxy_classification_rows, total_current=total_current
            )
            if proxy_classification_rows
            else None
        ),
        "dashboard_url": _resolve_dashboard_url(args),
        "limitations": ctx.limitations_scope,
    }
