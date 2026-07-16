"""Final target projection helpers for suspicious-target rows."""

from __future__ import annotations

from heuristics import (
    _SUSPICIOUS_CONCENTRATION_FLAGS,
    _SUSPICIOUS_QUANT_FLAGS,
)
from producers.suspicious_targets.taxonomy import (
    _TARGET_KIND_BY_TYPE,
    _attack_techniques_for_flags,
    _suspicious_action_class,
)


def _assign_severity(
    flag_set: set[str],
    *,
    cross_field_corroboration: bool,
) -> tuple[str, str]:
    """Tier mapping -> ``(severity, confidence)``. Anomaly is a
    baseline-corroborated signal so it counts as 2 toward the
    effective flag count: an anomaly-alone finding reaches
    ``severity: high``, share-based singles stay at ``medium``.
    ``critical`` additionally requires one flag from each of
    (quantitative) AND (concentration in shape) so a single-dimension
    actor never reaches the top tier.
    """
    flag_count = len(flag_set)
    effective_flag_count = flag_count + (1 if "anomaly" in flag_set else 0)
    if (
        effective_flag_count >= 3
        and bool(flag_set & _SUSPICIOUS_QUANT_FLAGS)
        and bool(flag_set & _SUSPICIOUS_CONCENTRATION_FLAGS)
    ):
        return "critical", "high" if cross_field_corroboration else "medium"
    if effective_flag_count >= 2:
        return "high", "high" if cross_field_corroboration else "medium"
    if flag_set & _SUSPICIOUS_QUANT_FLAGS:
        return "medium", "low"
    return "low", "low"


def _build_target_entry(row: dict, field_appearance: dict[str, int]) -> dict:
    """Project an ``intermediate`` row into a final
    ``bot_incident_action_targets.v1`` ``targets`` entry -- tier
    assignment, supporting payload, evidence_refs, and the
    descriptive (not prescriptive) action_class.
    """
    flag_set = set(row["flags"])
    cross_field_corroboration = field_appearance.get(row["value"], 0) >= 2
    severity, confidence = _assign_severity(
        flag_set, cross_field_corroboration=cross_field_corroboration,
    )
    supporting = {
        "requests": int(row["requests"]),
        "share_pct": row["share_pct"],
        "req_429": int(row["req_429"]),
        "req_429_share_pct": row["req_429_share_pct"],
        "distinct_paths": row["distinct_paths"],
    }
    supporting.update(row.get("supporting_extras") or {})
    return {
        "target_type": row["target_type"],
        "target_value": row["value"],
        "kind": _TARGET_KIND_BY_TYPE.get(row["target_type"], "actor"),
        "action_class": _suspicious_action_class(
            row["target_type"], severity, row["flags"],
        ),
        "reason_flags": list(row["flags"]),
        "attack_techniques": _attack_techniques_for_flags(row["flags"]),
        "severity": severity,
        "supporting": supporting,
        "suggested_action_hint": "review",
        "confidence": confidence,
        "evidence_refs": [
            {
                "artifact": "bot_incident_actors.v1",
                "json_pointer": (
                    f"/actor_rankings/{row['ranking_idx']}/rows/"
                    f"{row['row_idx']}"
                ),
            }
        ],
    }
