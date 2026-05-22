"""SOC evidence tables and method context for incident reports."""

from __future__ import annotations

from ..formatters import _format_count, _format_pct, _safe_number
from ..targets import (
    _compute_edge_action_for_indicator,
    _compute_provenance_for_indicator,
)

from .constants import SCHEMA
from .scope import _sum_numeric


def _target_by_value(suspicious_targets: list[dict], target_type: str) -> dict[str, dict]:
    return {
        str(target.get("target_value") or ""): target
        for target in suspicious_targets
        if target.get("target_type") == target_type and target.get("target_value") is not None
    }


def _evidence_ref_text(refs: list[dict]) -> str:
    return "; ".join(
        f"{ref.get('artifact', 'artifact')} {ref.get('json_pointer', '')}".strip()
        for ref in refs
    ) or "—"


def _raw_actor_soc_rows(
    actors_art: dict, suspicious_targets: list[dict], *, limit: int = 10
) -> list[dict]:
    ranking = next(
        (r for r in (actors_art.get("actor_rankings") or []) if r.get("field") == "client_ip"),
        None,
    )
    if not ranking:
        return []
    rows = ranking.get("rows") or []
    total = _sum_numeric([row.get("requests") for row in rows])
    target_lookup = _target_by_value(suspicious_targets, "client_ip")
    out: list[dict] = []
    for idx, row in enumerate(rows[:limit], start=1):
        value = str(row.get("value") or "")
        target = target_lookup.get(value, {})
        edge_action = _compute_edge_action_for_indicator(
            {"target_type": "client_ip", "target_value": value}, actors_art
        )
        provenance = _compute_provenance_for_indicator(
            {"target_type": "client_ip", "target_value": value}, actors_art
        )
        requests = _safe_number(row.get("requests")) or 0
        share = (100.0 * float(requests) / total) if total > 0 else 0.0
        flags = target.get("reason_flags") or []
        evidence_refs = target.get("evidence_refs") or [
            {
                "artifact": "bot_incident_actors.v1",
                "json_pointer": f"/actor_rankings/0/rows/{idx - 1}",
            }
        ]
        out.append(
            {
                "rank": idx,
                "value": value,
                "requests": requests,
                "requests_display": _format_count(requests),
                "share_display": _format_pct(share),
                "req_429_display": _format_count(row.get("req_429")),
                "req_429_rate_display": _format_pct(row.get("req_429_share_pct")),
                "req_5xx_display": _format_count(row.get("req_5xx")),
                "req_5xx_rate_display": _format_pct(row.get("req_5xx_share_pct")),
                "distinct_paths_display": _format_count(row.get("distinct_paths")),
                "asn": (target.get("supporting") or {}).get("asn_cluster_id") or "—",
                "baseline_presence": (
                    "absent from baseline" if "new_in_window" in flags else "not flagged as new"
                ),
                "edge_action": (
                    f"{_format_pct(100.0 * edge_action['top_action_share'])} {edge_action['top_action_label']}"
                    if edge_action else "not available"
                ),
                "provenance": (provenance or {}).get("display") or "not available",
                "severity_label": target.get("severity_label") or "Raw volume only",
                "action_class_label": target.get("action_class_label") or "No action-target row",
                "confidence_label": target.get("confidence_label") or "—",
                "why_ranked_here": (
                    f"Raw volume rank {idx}; "
                    f"{target.get('severity_label', 'no heuristic severity')}; "
                    f"{target.get('action_class_label', 'not promoted to action target')}; "
                    f"{target.get('confidence_label', 'no')} confidence."
                ),
                "evidence_refs_display": _evidence_ref_text(evidence_refs),
            }
        )
    return out


def _action_target_soc_rows(suspicious_targets: list[dict], raw_actor_rows: list[dict]) -> list[dict]:
    raw_rank_by_value = {row["value"]: row["rank"] for row in raw_actor_rows}
    out: list[dict] = []
    for idx, target in enumerate(suspicious_targets, start=1):
        raw_rank = raw_rank_by_value.get(target.get("target_value"))
        out.append(
            {
                **target,
                "priority_rank": idx,
                "volume_rank": raw_rank,
                "volume_rank_display": str(raw_rank) if raw_rank else "not in raw IP top 10",
                "why_ranked_here": (
                    f"Priority rank {idx}; volume rank {raw_rank if raw_rank else 'n/a'}; "
                    f"{target.get('severity_label')} severity; "
                    f"{target.get('action_class_label')} action class; "
                    f"{target.get('confidence_label')} confidence."
                ),
            }
        )
    return out


def _build_soc_evidence_block(
    actors_art: dict, action_targets_art: dict, suspicious_targets: list[dict]
) -> dict:
    raw_actor_rows = _raw_actor_soc_rows(actors_art, suspicious_targets)
    action_target_rows = _action_target_soc_rows(suspicious_targets, raw_actor_rows)
    return {
        "source_map": [
            {
                "claim": "Scope metrics and baseline deltas",
                "artifact": "bot_incident_scope.v1",
                "source": "window_confirmation, volume_timeseries, and scope dimension rows",
            },
            {
                "claim": "Highest-volume raw actors",
                "artifact": "bot_incident_actors.v1",
                "source": "actor_rankings/client_ip",
            },
            {
                "claim": "Highest-priority action targets",
                "artifact": "bot_incident_action_targets.v1",
                "source": "targets plus evidence_refs",
            },
            {
                "claim": "Bot/proxy provenance",
                "artifact": "bot_incident_scope.v1 / bot_incident_actors.v1",
                "source": "bot_source_mix, proxy_classification_mix, and client_ip provenance cooccurrence cells",
            },
        ],
        "raw_actor_rows": raw_actor_rows,
        "action_target_rows": action_target_rows,
        "target_evidence_available": bool(action_targets_art.get("targets")),
        "credential_evidence_rule": (
            "Credential-access findings require auth endpoint, failure pattern, "
            "account/user identifiers, or SIEM/auth correlation. Without those, "
            "T1110/T1110.004 remain investigation leads."
        ),
    }


def _build_method_block(actors_art: dict, actor_rankings: list[dict]) -> dict:
    return {
        "schema_version": SCHEMA,
        "comparison_type": "previous_window",
        "baseline_note": "Previous-window comparison unless the artifact records a different baseline strategy.",
        "producer_limit": actors_art.get("top_n"),
        "result_row_count": sum(len(r.get("rows") or []) for r in actor_rankings),
        "result_truncated": False,
        "scoring_thresholds": [
            "Action targets are sorted by heuristic severity, then observed request volume.",
            "Raw actor rows are sorted by raw request volume within the actor ranking artifact.",
            "ATT&CK credential-access mappings are investigation leads unless auth-specific evidence is present.",
        ],
        "interpretation_constraints": [
            "mechanical_features_only",
            "no_causal_claim",
            "no_malicious_intent_claim",
        ],
    }
