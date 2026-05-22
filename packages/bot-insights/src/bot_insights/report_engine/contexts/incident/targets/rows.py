"""Suspicious-target row projection and view builder."""

from __future__ import annotations

from .attack import _attack_mapping_class
from .edge_actions import (
    _compute_edge_action_for_indicator,
    _edge_action_display_fields,
)
from .provenance import _compute_provenance_for_indicator
from .reasons import _operational_reason_labels
from ..formatters import _format_count, _format_int, _format_pct, _safe_number
from ..labels import (
    ACTION_CLASS_LABELS,
    ACTION_CLASS_TONE,
    REASON_FLAG_LABELS,
    SEVERITY_TONE,
    TARGET_TYPE_LABELS,
)
from ..risk import _SEVERITY_ORDER


def _target_sort_key(row: dict) -> tuple[int, float]:
    severity = row.get("severity") or "review"
    severity_rank = _SEVERITY_ORDER.get(severity, 99)
    requests = _safe_number((row.get("supporting") or {}).get("requests")) or 0
    return (severity_rank, -float(requests))


def _project_supporting_metrics(supporting: dict) -> dict:
    """Flatten the ``supporting`` dict's numeric fields into display-ready keys."""
    return {
        "requests": _safe_number(supporting.get("requests")),
        "requests_display": _format_count(supporting.get("requests")),
        "share_pct": _safe_number(supporting.get("share_pct")),
        "share_pct_display": _format_pct(supporting.get("share_pct")),
        "req_429": _safe_number(supporting.get("req_429")),
        "req_429_display": _format_count(supporting.get("req_429")),
        "req_429_share_pct": _safe_number(supporting.get("req_429_share_pct")),
        "req_429_share_display": _format_pct(supporting.get("req_429_share_pct")),
        "distinct_paths": _safe_number(supporting.get("distinct_paths")),
        "distinct_paths_display": _format_int(supporting.get("distinct_paths")),
        # Pass the raw supporting dict through (including
        # supporting_extras keys like asn_cluster_id /
        # asn_cluster_org / botnet_cluster_share_pct) so downstream
        # helpers like _finding_entity can annotate entities with
        # cluster context without re-flattening the whole shape into
        # top-level keys.
        "supporting": dict(supporting),
    }


def _target_classification_fields(row: dict) -> dict:
    """Project the classification fields (target type / severity / kind /
    action class) into renderer-ready key+label pairs."""
    target_type = row.get("target_type") or ""
    severity = row.get("severity") or "review"
    kind = row.get("kind") or "actor"
    action_class = row.get("action_class") or "watch"
    return {
        "target_type": target_type,
        "target_type_label": TARGET_TYPE_LABELS.get(
            target_type, target_type.replace("_", " ").title()
        ),
        "kind": kind,
        "kind_label": kind.title(),
        "action_class": action_class,
        "action_class_label": ACTION_CLASS_LABELS.get(
            action_class, action_class.replace("-", " ").title()
        ),
        "action_class_tone": ACTION_CLASS_TONE.get(action_class, "watch"),
        "severity": severity,
        "severity_tone": SEVERITY_TONE.get(severity, "observe"),
        "severity_label": severity.title(),
    }


def _target_flag_fields(row: dict) -> dict:
    """Project the reason-flag / attack-technique lists into renderer-ready shape."""
    flags = list(row.get("reason_flags") or [])
    labels = [
        REASON_FLAG_LABELS.get(f, f.replace("_", " ")) for f in flags
    ]
    attack_techniques = list(row.get("attack_techniques") or [])
    summary_parts = []
    for technique in attack_techniques:
        tid = technique.get("id", "")
        if not tid:
            continue
        if _attack_mapping_class(tid) == "possible investigation lead":
            summary_parts.append(f"{tid} (lead)")
        else:
            summary_parts.append(tid)
    return {
        "reason_flags": flags,
        "reason_flag_labels": labels,
        "display_reason_labels": _operational_reason_labels(labels),
        "attack_techniques": attack_techniques,
        "attack_techniques_summary": ", ".join(summary_parts) or "—",
    }


def _suspicious_target_row(row: dict, actors_artifact: dict | None) -> dict:
    """Project one raw action-target row into the renderer's display shape."""
    edge_action = _compute_edge_action_for_indicator(row, actors_artifact)
    provenance = _compute_provenance_for_indicator(row, actors_artifact)
    top_label, top_share_display = _edge_action_display_fields(edge_action)
    confidence = row.get("confidence") or ""
    evidence_refs = list(row.get("evidence_refs") or [])
    classes = _target_classification_fields(row)
    return {
        **classes,
        "target_value": str(row.get("target_value") or ""),
        "edge_action": edge_action,
        "provenance": provenance,
        "provenance_lines": (provenance or {}).get("display_lines") or [],
        "provenance_display": (provenance or {}).get("display"),
        "edge_action_top_label": top_label,
        "edge_action_top_share_display": top_share_display,
        **_target_flag_fields(row),
        "confidence": confidence,
        "confidence_label": confidence.title(),
        "why_ranked_here": (
            f"{classes['severity_label']} severity; "
            f"{classes['action_class_label']} action class; "
            f"{confidence.title() if confidence else 'No'} confidence."
        ),
        "suggested_action_hint": row.get("suggested_action_hint") or "review",
        "evidence_refs": evidence_refs,
        "evidence_refs_display": "; ".join(
            f"{ref.get('artifact', 'artifact')} {ref.get('json_pointer', '')}".strip()
            for ref in evidence_refs
        ) or "—",
        **_project_supporting_metrics(row.get("supporting") or {}),
    }


def _suspicious_targets_view(
    action_targets_art: dict,
    actors_artifact: dict | None = None,
) -> list[dict]:
    """Order action-target rows for rendering: severity desc, then requests desc.

    When ``actors_artifact`` is supplied and carries
    ``actor_cooccurrence["client_ip__action_applied"]`` cells, each
    client_ip row is annotated with an ``edge_action`` payload plus
    display-ready ``edge_action_top_label`` /
    ``edge_action_top_share_display`` fields so the template can stack
    a mute "95% Denied" sub-line under the action chip without redoing
    the share math.
    """
    rows = list(action_targets_art.get("targets") or [])
    return [
        _suspicious_target_row(row, actors_artifact)
        for row in sorted(rows, key=_target_sort_key)
    ]
