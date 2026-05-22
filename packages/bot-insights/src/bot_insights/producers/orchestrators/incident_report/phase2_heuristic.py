"""Incident phase-2 heuristic and action-target assembly."""

from __future__ import annotations

import argparse
from datetime import datetime
from pathlib import Path

from producers.evidence.incident import (
    _build_action_targets_artifact,
    _incident_behavior_clusters,
    _incident_entity_clusters,
    _incident_mitigation_effectiveness,
    _incident_target_evidence_rows,
)
from producers.sql.incident import _incident_target_bucket_evidence_sql
from producers.suspicious_targets import _compute_suspicious_targets

from .capture import _capture_or_raise
from .contracts import _IncidentCtx
from .phase2 import (
    _incident_phase2_baseline_actors,
    _incident_phase2_cooccurrence,
    _incident_phase2_current_actors,
    _incident_phase2_flagged_ip_timeseries,
    _incident_phase2_provenance_cooccurrence,
)

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
        _incident_phase2_provenance_cooccurrence(
            args, ctx, current_candidates_by_field,
            start=start, end=end,
            baseline_start=baseline_start,
            baseline_end=baseline_end,
            sample_dir=sample_dir,
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
        _incident_phase2_flagged_ip_timeseries(
            args, ctx, start=start, end=end, sample_dir=sample_dir,
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
    if ctx.flagged_client_ip_timeseries:
        ctx.action_targets_artifact["flagged_client_ip_timeseries"] = (
            ctx.flagged_client_ip_timeseries
        )
