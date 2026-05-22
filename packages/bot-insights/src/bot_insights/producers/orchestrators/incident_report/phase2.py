"""Phase-2 actor, co-occurrence, and provenance collection."""

from __future__ import annotations

import argparse
from datetime import datetime
from pathlib import Path

from producers.evidence.incident import _INCIDENT_FIELD_LABELS, _incident_actor_rows
from producers.sql.incident import (
    _incident_actor_cooccurrence_sql,
    _incident_actor_scoped_metrics_baseline_sql,
    _incident_actor_scoped_metrics_sql,
    _incident_actor_topk_baseline_sql,
    _incident_actor_topk_sql,
    _incident_client_ip_bot_source_cooccurrence_sql,
    _incident_client_ip_proxy_classification_cooccurrence_sql,
    _incident_flagged_client_ip_timeseries_sql,
)

from .capture import _capture_or_raise
from .contracts import _IncidentCtx

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

def _incident_phase2_provenance_cooccurrence(
    args: argparse.Namespace,
    ctx: _IncidentCtx,
    current_candidates_by_field: dict[str, list[str]],
    *,
    start: datetime,
    end: datetime,
    baseline_start: datetime,
    baseline_end: datetime,
    sample_dir: Path,
) -> None:
    """Attach optional source bot/proxy provenance cells for top IPs."""
    ip_candidates = current_candidates_by_field.get("client_ip") or []
    if not ip_candidates:
        return
    cooccurrence = ctx.actors_artifact.setdefault("actor_cooccurrence", {})
    ip_column = ctx.raw_column_by_field.get("client_ip", "client_ip")
    if ctx.bot_source_columns:
        rows = _capture_or_raise(
            args,
            _incident_client_ip_bot_source_cooccurrence_sql(
                ip_candidates,
                start,
                end,
                baseline_start,
                baseline_end,
                args.host,
                args.asn,
                args.path_pattern,
                ip_column,
                ctx.raw_path_column,
                ctx.bot_source_columns,
            ),
            sample_dir / f"{args.report}-phase2-client_ip-bot_source-cooccurrence.json",
            label="actors_cooccurrence:client_ip__bot_source",
            artifact="actors_cooccurrence_client_ip__bot_source",
        )
        cooccurrence["client_ip__bot_source"] = [
            {
                "ip": str(row.get("ip") or ""),
                "bot_category": str(row.get("bot_category") or ""),
                "bot_type": str(row.get("bot_type") or ""),
                "botnet_id": str(row.get("botnet_id") or ""),
                "requests": int(float(row.get("requests") or 0)),
                "baseline_requests": int(float(row.get("baseline_requests") or 0)),
            }
            for row in rows
            if row.get("ip") and int(float(row.get("requests") or 0)) > 0
        ]
    if "epd_Category" in ctx.proxy_classification_columns:
        rows = _capture_or_raise(
            args,
            _incident_client_ip_proxy_classification_cooccurrence_sql(
                ip_candidates,
                start,
                end,
                baseline_start,
                baseline_end,
                args.host,
                args.asn,
                args.path_pattern,
                ip_column,
                ctx.raw_path_column,
                ctx.proxy_classification_columns,
            ),
            sample_dir / f"{args.report}-phase2-client_ip-proxy_classification-cooccurrence.json",
            label="actors_cooccurrence:client_ip__proxy_classification",
            artifact="actors_cooccurrence_client_ip__proxy_classification",
        )
        cooccurrence["client_ip__proxy_classification"] = [
            {
                "ip": str(row.get("ip") or ""),
                "epd_Category": str(row.get("epd_Category") or ""),
                "epd_ActionName": str(row.get("epd_ActionName") or ""),
                "epd_Match": str(row.get("epd_Match") or ""),
                "requests": int(float(row.get("requests") or 0)),
                "baseline_requests": int(float(row.get("baseline_requests") or 0)),
            }
            for row in rows
            if row.get("ip")
            and row.get("epd_Category")
            and int(float(row.get("requests") or 0)) > 0
        ]

def _incident_phase2_flagged_ip_timeseries(
    args: argparse.Namespace,
    ctx: _IncidentCtx,
    *,
    start: datetime,
    end: datetime,
    sample_dir: Path,
) -> None:
    """Attach bounded current-window series for flagged client-IP targets."""
    ip_candidates = [
        str(target.get("target_value") or "")
        for target in ctx.suspicious_targets
        if target.get("target_type") == "client_ip" and target.get("target_value")
    ]
    if not ip_candidates:
        return
    rows = _capture_or_raise(
        args,
        _incident_flagged_client_ip_timeseries_sql(
            ip_candidates,
            ctx.granularity,
            start,
            end,
            args.host,
            args.asn,
            args.path_pattern,
            ctx.raw_column_by_field.get("client_ip", "client_ip"),
            ctx.raw_path_column,
            ctx.logs_columns,
        ),
        sample_dir / f"{args.report}-phase2-flagged-client-ip-timeseries.json",
        label="flagged client-IP timeseries",
        artifact="flagged_client_ip_timeseries",
    )
    ctx.flagged_client_ip_timeseries = [
        {
            "bucket": str(row.get("bucket") or ""),
            "flagged_requests": int(float(row.get("flagged_requests") or 0)),
            "req_429": int(float(row.get("req_429") or 0)),
            "req_5xx": int(float(row.get("req_5xx") or 0)),
            "edge_deny": int(float(row.get("edge_deny") or 0)),
            "edge_allow": int(float(row.get("edge_allow") or 0)),
            "edge_challenge": int(float(row.get("edge_challenge") or 0)),
            "bot_provenance": int(float(row.get("bot_provenance") or 0)),
            "proxy_classification": int(float(row.get("proxy_classification") or 0)),
            "graphql": int(float(row.get("graphql") or 0)),
            "auth_path": int(float(row.get("auth_path") or 0)),
        }
        for row in rows
        if row.get("bucket") and int(float(row.get("flagged_requests") or 0)) > 0
    ]

from .phase2_heuristic import _incident_phase2_actors_and_heuristic

__all__ = [
    "_incident_phase2_actors_and_heuristic",
    "_incident_phase2_baseline_actor_field",
    "_incident_phase2_baseline_actors",
    "_incident_phase2_cooccurrence",
    "_incident_phase2_current_actor_field",
    "_incident_phase2_current_actors",
    "_incident_phase2_flagged_ip_timeseries",
    "_incident_phase2_provenance_cooccurrence",
]
