"""Heuristic-ladder evaluators for the incident_report suspicious-target list.

Split across two sub-modules:

  - ``taxonomy``: the lookup tables that pin a flag-firing row to a
    target type, an ATT&CK mapping, a target ``kind`` (actor vs.
    target), and the descriptive ``action_class`` a downstream WAF /
    SOAR consumer would route the indicator to. These are contract
    surfaces — changing an entry is a downstream-consumer break, not
    a calibration change.
  - ``ladder``: the per-row primitive evaluators (share-based,
    novelty, anomaly) and the orchestrator
    (``_compute_suspicious_targets``) that walks every actor ranking.
  - ``clusters``: cross-row ASN cluster pivots.
  - ``targets``: tier assignment and final
    ``bot_incident_action_targets.v1`` ``targets`` projection.

Calibration constants (threshold floors, automation UA pattern,
severity rank) still live in the top-level ``heuristics`` module
(Phase 1 lift) — the ladder imports from there.
"""

from producers.suspicious_targets.ladder import (  # noqa: F401
    _apply_asn_grouped_pivots,
    _apply_cluster_pivots,
    _apply_unverified_cluster_pivots,
    _assign_severity,
    _build_target_entry,
    _compute_suspicious_targets,
    _evaluate_all_rankings,
    _evaluate_anomaly,
    _evaluate_novelty_flags,
    _evaluate_ranking_row,
    _evaluate_share_flags,
)
from producers.suspicious_targets.taxonomy import (  # noqa: F401
    _INDIVIDUAL_ENTITY_FIELDS,
    _PRIMITIVE_ATTACK_TECHNIQUES,
    _SUSPICIOUS_TARGET_TYPE_BY_FIELD,
    _TARGET_KIND_BY_TYPE,
    _attack_techniques_for_flags,
    _suspicious_action_class,
)
