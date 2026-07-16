"""Evidence-packet builder for the ``control_review`` report."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path

from producers.evidence.metrics import (
    METRIC_LABELS,
    metric_card_from_metric,
    metric_map_from_control_effects,
    standard_derived_rates,
)
from producers.formatting import human_number


def control_followups(args: argparse.Namespace) -> list[dict]:
    if args.control_source == "posture":
        return [
            {
                "question": "Which ASNs drove the bot-like request movement?",
                "capture_preset": "posture-by-asn",
            },
            {
                "question": "Which paths drove the cache-miss or 429 movement?",
                "capture_preset": "posture-by-path",
            },
            {
                "question": "If SIEM summaries are available for another scope, do policy outcomes line up with this posture movement?",
                "capture_preset": "siem-policy",
            },
        ]
    return [
        {
            "question": "Which policy, action, or bot type drove the after-window movement?",
            "capture_preset": "siem-policy",
        },
        {
            "question": "Did protected crawler or verified bot populations see collateral rate-limit or deny changes?",
            "capture_preset": "siem-policy",
        },
        {
            "question": "Did traffic shift to other ASNs, paths, hosts, or bot categories after the control changed?",
            "capture_preset": "posture-by-asn",
        },
    ]


def build_control_evidence_packet(
    *,
    args: argparse.Namespace,
    artifact: dict,
    raw_path: Path,
    artifact_path: Path,
    granularity: str,
    table_used: str,
    baseline_start: datetime,
) -> dict:
    metrics = metric_map_from_control_effects(artifact)
    metric_cards = [metric_card_from_metric(metric) for metric in metrics.values()]
    derived_rates = standard_derived_rates(metrics)
    effect_cards = []
    findings = []
    for effect in artifact.get("target_effects", []):
        if not isinstance(effect, dict):
            continue
        metric = str(effect.get("metric", ""))
        card = {
            "metric": metric,
            "label": METRIC_LABELS.get(metric, metric),
            "before": effect.get("before"),
            "after": effect.get("after"),
            "expected": effect.get("expected"),
            "absolute_delta_vs_expected": effect.get("absolute_delta_vs_expected"),
            "pct_change_vs_expected": effect.get("pct_change_vs_expected"),
            "before_display": human_number(effect.get("before")),
            "after_display": human_number(effect.get("after")),
            "expected_display": human_number(effect.get("expected")),
            "absolute_delta_vs_expected_display": human_number(
                effect.get("absolute_delta_vs_expected"),
                signed=True,
            ),
            "pct_change_vs_expected_display": human_number(
                effect.get("pct_change_vs_expected"),
                percent=True,
                signed=True,
            ),
            "direction": effect.get("direction"),
            "status": effect.get("status"),
            "confidence": effect.get("confidence"),
        }
        effect_cards.append(card)
        findings.append(
            {
                "title": f"{card['label']} vs expected",
                "change_label": str(effect.get("status") or "not evaluated"),
                "evidence": (
                    f"{card['after_display']} after vs {card['expected_display']} expected "
                    f"({card['pct_change_vs_expected_display']})."
                ),
            }
        )

    return {
        "schema_version": "bot_report_evidence.v1",
        "report_type": args.report,
        "title": args.title or "Bot Insights Control Review",
        "scope": {"cluster": args.cluster, "database": args.database},
        "query_context": {
            "cluster": args.cluster,
            "database": args.database,
            "table_used": table_used,
            "granularity": granularity,
            "raw_artifact_path": str(raw_path),
            "deterministic_artifact_path": str(artifact_path),
        },
        "change_time": artifact.get("change_time"),
        "target": artifact.get("target"),
        "before_window": artifact.get("before_window"),
        "after_window": artifact.get("after_window"),
        "expected_window": artifact.get("expected_window"),
        "expected_basis": artifact.get("expected_basis"),
        "target_effects": effect_cards,
        "metric_cards": metric_cards,
        "derived_rates": derived_rates,
        "collateral_checks": artifact.get("collateral_checks", []),
        "displacement_checks": artifact.get("displacement_checks", []),
        "headline_findings": findings,
        "suggested_followups": control_followups(args),
        "interpretation_contract": {
            "allowed": [
                "Summarize only the fields in this packet.",
                "Compare after-window metrics, derived rates, and expected values.",
                "Describe control-review caveats and recommend follow-up checks.",
            ],
            "forbidden": [
                "Do not claim the control caused the movement without external change evidence.",
                "Do not call traffic malicious without additional artifacts.",
                "Do not introduce values not present in this packet.",
                "Do not query Hydrolix from the interpretation step.",
                "Do not emit final HTML or Markdown layout.",
            ],
        },
        "template": {
            "sections": [
                "Control Review Summary",
                "Target Effects",
                "Collateral and Displacement Checks",
                "Operational Interpretation",
                "Recommended Follow-ups",
                "Method and Caveats",
            ]
        },
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "baseline_start": baseline_start.isoformat().replace("+00:00", "Z"),
    }
