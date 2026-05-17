"""Wrapper-construction helpers shared across per-report orchestrators.

Lifts raw deterministic artifacts into the
``bot_report_input.v1`` wrapper shape the renderer consumes.

Surface:
  - ``build_timeseries_artifact``: project a control_review raw
    timeseries query result into the canonical
    ``bot_report_timeseries.v1`` shape.
  - ``add_report_metadata`` / ``add_control_metadata`` /
    ``add_scorecard_metadata``: pin the wrapper's ``metadata``
    block (cluster, database, scope, window, granularity, table_used)
    so the renderer can show provenance without consuming evidence-
    packet fields.
  - ``analyst_note_from_args``: build the optional analyst-note
    payload from ``--note-text`` / ``--note-data-source-*`` flags.
  - ``build_report_wrapper``: wrap the deterministic artifacts +
    analyst note + the engine-routing hint into the final wrapper
    dict the renderer reads from ``--file``.
  - ``render_template_packet``: render an evidence packet into a
    prompt template for the LLM interpretation step (used by
    ``--mode interpret``).
"""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone

from producers.evidence.metrics import (
    METRIC_LABELS,
    metric_map_from_control_effects,
)
from producers.formatting import human_number
from producers.runtime import result_rows
from producers.sql.scorecard import CRAWLER_POPULATION_BY_ENTITY


def build_timeseries_artifact(
    *,
    args: argparse.Namespace,
    raw_value: dict,
    control_artifact: dict,
    table_used: str,
    granularity: str,
) -> dict:
    metrics = metric_map_from_control_effects(control_artifact)
    before_by_metric: dict[str, list[dict]] = {name: [] for name in metrics}
    after_by_metric: dict[str, list[dict]] = {name: [] for name in metrics}
    for row in result_rows(raw_value):
        period = str(row.get("period", "")).lower()
        bucket = row.get("bucket")
        if period not in {"before", "after"} or bucket is None:
            continue
        for name in metrics:
            value = row.get(name)
            point = {"timestamp": bucket, "value": value}
            if period == "before":
                before_by_metric[name].append(point)
            else:
                after_by_metric[name].append(point)

    series = []
    for name, metric in metrics.items():
        before_values = sorted(
            before_by_metric[name], key=lambda item: str(item.get("timestamp"))
        )
        after_values = sorted(
            after_by_metric[name], key=lambda item: str(item.get("timestamp"))
        )
        length = max(len(before_values), len(after_values))
        points = []
        for index in range(length):
            before_point = before_values[index] if index < len(before_values) else {}
            after_point = after_values[index] if index < len(after_values) else {}
            points.append(
                {
                    "baseline_timestamp": before_point.get("timestamp"),
                    "current_timestamp": after_point.get("timestamp"),
                    "baseline": before_point.get("value"),
                    "current": after_point.get("value"),
                }
            )
        if points:
            series.append(
                {
                    "name": name,
                    "label": METRIC_LABELS.get(name, name),
                    "current": metric.get("current"),
                    "baseline": metric.get("baseline"),
                    "absolute_delta": metric.get("absolute_delta"),
                    "pct_change": metric.get("pct_change"),
                    "points": points,
                }
            )

    return {
        "schema_version": "bot_timeseries.v1",
        "artifact_id": f"{args.report}-timeseries",
        "title": "Control Review Trends",
        "report_type": "control_review",
        "scope": control_artifact.get("scope", {}),
        "table_used": table_used,
        "granularity": granularity,
        "current_window": control_artifact.get("after_window", {}),
        "baseline_windows": [control_artifact.get("before_window", {})],
        "metrics": series,
        "interpretation_constraints": [
            "trend_shape_only",
            "no_causal_claim",
            "llm_may_summarize_structured_evidence_only",
        ],
    }


def add_report_metadata(
    *,
    raw_value: dict,
    args: argparse.Namespace,
    granularity: str,
    table_used: str,
    baseline_start: datetime,
) -> dict:
    enriched = dict(raw_value)
    enriched.update(
        {
            "comparison_type": "previous_window",
            "granularity": granularity,
            "table_used": table_used,
            "scope": {
                "cluster": args.cluster,
                "database": args.database,
            },
            "current_window": {
                "start": args.start,
                "end": args.end,
            },
            "baseline_windows": [
                {
                    "start": baseline_start.isoformat().replace("+00:00", "Z"),
                    "end": args.start,
                }
            ],
        }
    )
    return enriched


def add_control_metadata(
    *,
    raw_value: dict,
    args: argparse.Namespace,
    granularity: str,
    table_used: str,
    baseline_start: datetime,
) -> dict:
    enriched = dict(raw_value)
    if args.control_source == "posture":
        target = {"control_scope": "posture_summary"}
        target_metrics = [
            "requests",
            "bot_like_requests",
            "ai_requests",
            "cache_misses",
            "rate_limited_requests",
            "error_5xx_requests",
        ]
    else:
        target = (
            {"policy_id": args.policy_id}
            if args.policy_id
            else {"policy_scope": "all_policies"}
        )
        target_metrics = [
            "siem_blocked_requests",
            "siem_auth_fail_requests",
            "requests",
            "avg_bot_score",
            "unique_client_ips",
        ]
    enriched.update(
        {
            "comparison_type": "post_change_vs_expected",
            "granularity": granularity,
            "table_used": table_used,
            "change_time": args.change_time or args.start,
            "target": target,
            "scope": {
                "cluster": args.cluster,
                "database": args.database,
            },
            "before_window": {
                "start": baseline_start.isoformat().replace("+00:00", "Z"),
                "end": args.start,
            },
            "after_window": {
                "start": args.start,
                "end": args.end,
            },
            "expected_window": {
                "start": baseline_start.isoformat().replace("+00:00", "Z"),
                "end": args.start,
            },
            "expected_basis": "before_window",
            "target_metrics": target_metrics,
        }
    )
    return enriched


def add_scorecard_metadata(
    *,
    raw_value: dict,
    args: argparse.Namespace,
    granularity: str,
    table_used: str,
    baseline_start: datetime,
) -> dict:
    enriched = dict(raw_value)
    enriched.update(
        {
            "comparison_type": "previous_window",
            "granularity": granularity,
            "table_used": table_used,
            "scope": {
                "cluster": args.cluster,
                "database": args.database,
                "entity_type": args.entity_type,
            },
            "current_window": {
                "start": args.start,
                "end": args.end,
            },
            "baseline_windows": [
                {
                    "start": baseline_start.isoformat().replace("+00:00", "Z"),
                    "end": args.start,
                }
            ],
            "summary_table_used": True,
            "rowset_complete": False,
            "source_row_count": enriched.get("rows"),
            "producer_limit": args.scorecard_limit,
        }
    )
    if args.domains:
        enriched["analysis_domains"] = [
            item.strip() for item in args.domains.split(",") if item.strip()
        ]
    if args.report == "crawler_governance":
        population = CRAWLER_POPULATION_BY_ENTITY.get(args.entity_type)
        if population is not None:
            enriched["rowset_scope"] = {"population": population}
    return enriched


def analyst_note_from_args(args: argparse.Namespace) -> dict | None:
    text = args.analyst_notes
    if args.analyst_notes_file:
        text = Path(args.analyst_notes_file).expanduser().read_text(encoding="utf-8")
    if not text:
        return None
    return {
        "note_id": "llm-interpretation",
        "author_type": "llm",
        "title": {
            "executive_posture": "Executive Interpretation",
            "control_review": "Control Review Interpretation",
            "scorecard_brief": "Scorecard Interpretation",
            "soc_triage": "SOC Triage Interpretation",
            "crawler_governance": "Crawler Governance Interpretation",
            "edge_ops_impact": "Edge & Origin Cost Interpretation",
        }.get(args.report, "Analyst Interpretation"),
        "text": text.strip(),
        "show_data_sources": False,
        "data_sources": [],
    }


def build_report_wrapper(
    *,
    args: argparse.Namespace,
    artifacts: list[dict],
    analyst_note: dict | None = None,
) -> dict:
    wrapper = {
        "schema_version": "bot_report_input.v1",
        "report_type": args.report,
        "title": args.title
        or {
            "executive_posture": "Bot & Edge Movement",
            "control_review": "Bot Insights Control Review",
            "scorecard_brief": "Bot Insights Scorecard Brief",
            # The auto-generated form lowercases the SOC acronym ("Soc
            # Triage") which reads wrong; spell it explicitly.
            "soc_triage": "SOC Triage",
            "crawler_governance": "Crawler Governance",
            "edge_ops_impact": "Edge & Origin Cost",
        }.get(args.report, f"Bot Insights {args.report.replace('_', ' ').title()}"),
        "scope_label": f"{args.cluster}/{args.database}",
        "artifacts": artifacts,
        "analyst_notes": [analyst_note] if analyst_note else [],
    }
    return wrapper


def render_template_packet(packet: dict) -> str:
    findings = "\n".join(
        f"- {item['title']}: {item['evidence']}"
        for item in packet.get("headline_findings", [])
    )
    rates = "\n".join(
        "- "
        + f"{rate['label']}: {rate['current_display']} current vs "
        + f"{rate['baseline_display']} baseline "
        + f"({rate['delta_points_display']} percentage points)."
        for rate in packet.get("derived_rates", [])
    )
    metrics = "\n".join(
        "- "
        + f"{metric['label']}: {metric['current_display']} current vs "
        + f"{metric['baseline_display']} baseline; "
        + f"{metric['pct_change_display']} change."
        for metric in packet.get("metric_cards", [])
    )
    effects = "\n".join(
        "- "
        + f"{effect['label']}: {effect['after_display']} after vs "
        + f"{effect['expected_display']} expected; "
        + f"{effect['pct_change_vs_expected_display']} vs expected."
        for effect in packet.get("target_effects", [])
    )
    selected_entity = packet.get("selected_entity") or {}
    # Prefer the labelled domain_scores_labeled when present (added by
    # humanize_evidence_packet). Falls back to the raw domain_scores so
    # this renderer continues to work on packets that haven't been
    # enriched.
    domain_scores_source = packet.get("domain_scores_labeled") or packet.get("domain_scores") or {}
    domain_scores = "\n".join(
        f"- {domain}: {score}"
        for domain, score in domain_scores_source.items()
    )
    feature_evidence = "\n".join(
        "- "
        + f"{feature.get('domain_label') or feature.get('domain')} / "
        + f"{feature.get('name_label') or feature.get('name')}: "
        + f"{feature.get('evidence')}"
        for feature in packet.get("evaluated_feature_evidence", [])
        if isinstance(feature, dict)
    )
    followups = (
        "\n".join(
            f"- {item['question']} (`{item['capture_preset']}`)"
            for item in packet["suggested_followups"]
        )
        if "suggested_followups" in packet
        else "\n".join(
            f"- {item['detail'] if isinstance(item, dict) else item}"
            for item in packet.get("recommended_next_steps", [])
        )
    )
    context = packet["query_context"]
    return f"""# {packet["title"]}

## Executive Summary

LLM: Write 2-4 concise sentences using only the evidence below. Do not infer root cause.

## Key Changes

{findings or "- No headline findings available."}

## Rates

{rates or "- No derived rates available."}

## Metrics

{metrics or "- No metrics available."}

## Control Effects

{effects or "- No control effects available."}

## Selected Scorecard Entity

- Entity: {selected_entity.get("entity_type_label") or selected_entity.get("entity_type", "unavailable")}={selected_entity.get("entity", "unavailable")}
- Rank: {selected_entity.get("rank", "unavailable")}
- Score: {selected_entity.get("score", "unavailable")}
- Band: {selected_entity.get("band_label") or selected_entity.get("band", "unavailable")}
- Confidence: {selected_entity.get("confidence_label") or selected_entity.get("confidence", "unavailable")}

## Domain Scores

{domain_scores or "- No domain scores available."}

## Evaluated Feature Evidence

{feature_evidence or "- No evaluated feature evidence available."}

## Operational Interpretation

LLM: Explain what the changes may mean operationally. Keep this as hypotheses or checks, not causal claims.

## Recommended Follow-ups

{followups}

## Method and Caveats

- Data source: `{context["table_used"]}`
- Cluster: `{context["cluster"]}`
- Database: `{context["database"]}`
- Granularity: `{context["granularity"]}`
- Current/after window: `{json.dumps(packet.get("current_window") or packet.get("after_window"), sort_keys=True)}`
- Baseline/before windows: `{json.dumps(packet.get("baseline_windows") or packet.get("before_window"), sort_keys=True)}`
- This report is based on deterministic summary-table evidence. It does not identify root cause by itself.
"""
