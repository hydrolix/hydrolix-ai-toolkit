"""Evidence-packet builder for the ``executive_posture`` report."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path

from producers.evidence.metrics import (
    metric_by_name,
    metric_card_from_metric,
    standard_derived_rates,
)
from producers.formatting import human_number, label_change


def build_evidence_packet(
    *,
    args: argparse.Namespace,
    artifact: dict,
    raw_path: Path,
    artifact_path: Path,
    granularity: str,
    table_used: str,
    baseline_start: datetime,
) -> dict:
    metrics = metric_by_name(artifact)
    metric_cards = []
    for metric in artifact.get("metrics", []):
        if not isinstance(metric, dict):
            continue
        metric_cards.append(metric_card_from_metric(metric))

    derived_rates = standard_derived_rates(metrics)

    total = metrics.get("requests", {})
    bot_like = metrics.get("bot_like_requests", {})
    ai = metrics.get("ai_requests", {})
    cache = metrics.get("cache_misses", {})
    findings = []
    for source, title in (
        (total, "Total request volume changed"),
        (bot_like, "Bot-like request volume changed"),
        (ai, "AI request volume changed"),
        (cache, "Cache-miss volume changed"),
    ):
        if not source:
            continue
        findings.append(
            {
                "title": title,
                "change_label": label_change(source.get("pct_change")),
                "evidence": (
                    f"{human_number(source.get('current'))} current vs "
                    f"{human_number(source.get('baseline'))} baseline "
                    f"({human_number(source.get('pct_change'), percent=True, signed=True)})."
                ),
            }
        )

    return {
        "schema_version": "bot_report_evidence.v1",
        "report_type": args.report,
        "title": args.title or "Bot & Edge Movement",
        "scope": {"cluster": args.cluster, "database": args.database},
        "query_context": {
            "cluster": args.cluster,
            "database": args.database,
            "table_used": table_used,
            "granularity": granularity,
            "raw_artifact_path": str(raw_path),
            "deterministic_artifact_path": str(artifact_path),
        },
        "current_window": artifact.get("current_window"),
        "baseline_windows": artifact.get("baseline_windows"),
        "metric_cards": metric_cards,
        "derived_rates": derived_rates,
        "headline_findings": findings,
        "suggested_followups": [
            {
                "question": "Which ASNs drove the bot-like request movement?",
                "capture_preset": "posture-by-asn",
            },
            {
                "question": "Which paths drove the cache-miss movement?",
                "capture_preset": "posture-by-path",
            },
            {
                "question": "Do SIEM policy outcomes line up with the bot-like movement?",
                "capture_preset": "siem-policy",
            },
        ],
        "interpretation_contract": {
            "allowed": [
                "Summarize only the fields in this packet.",
                "Compare metric changes and derived rates.",
                "Recommend follow-up queries from suggested_followups.",
            ],
            "forbidden": [
                "Do not claim root cause.",
                "Do not call traffic malicious without additional evidence.",
                "Do not introduce values not present in this packet.",
                "Do not query Hydrolix from the interpretation step.",
            ],
        },
        "template": {
            "sections": [
                "Executive Summary",
                "Key Changes",
                "Operational Interpretation",
                "Recommended Follow-ups",
                "Method and Caveats",
            ]
        },
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "baseline_start": baseline_start.isoformat().replace("+00:00", "Z"),
    }
