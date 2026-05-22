"""Incident report evidence emission and rendering."""

from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path

from producers.evidence.labeling import humanize_evidence_packet
from producers.rendering import render_report_command
from producers.runtime import PUBLIC_SKILLS, run
from producers.wrapper import analyst_note_from_args, build_report_wrapper

from .contracts import INCIDENT_INTERPRETATION_CONTRACT, _IncidentCtx

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
        "bot_source_mix": ctx.scope_artifact.get("bot_source_mix"),
        "proxy_classification_mix": ctx.scope_artifact.get("proxy_classification_mix"),
        "actor_rankings": ctx.actors_artifact["actor_rankings"],
        "actor_cooccurrence": ctx.actors_artifact.get("actor_cooccurrence") or {},
        "raw_drilldown_available": ctx.raw_drilldown_available,
        "siem_available": ctx.siem_available,
        "suspicious_targets": ctx.suspicious_targets,
        "target_evidence": getattr(ctx, "target_evidence", {}),
        "flagged_client_ip_timeseries": getattr(
            ctx, "flagged_client_ip_timeseries", []
        ),
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
            config_path=getattr(args, "config", None),
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
