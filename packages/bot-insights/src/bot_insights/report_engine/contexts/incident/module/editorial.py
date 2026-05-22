"""Editorial extension assembly for incident reports."""

from __future__ import annotations

from ..actions import _recommended_actions_view
from ..cohorts import _compute_actor_cohort_overlap
from ..findings import _incident_findings
from ..iocs import _ioc_json_text, _ioc_view
from ..narrative import (
    _analyst_assessment_fallback,
    _behavior_clusters_view,
    _coordination_signals,
    _entity_clusters_view,
    _mitigation_coverage_view,
    _observed_inferred_taxonomy,
    _primary_concern_view,
    _stood_out_bullets,
    _temporal_progression_view,
)
from ..risk import _risk_score, _severity_ladder
from ..targets import _attack_aggregation


def _build_editorial_extensions(
    scope_art: dict,
    actors_art: dict,
    action_targets_art: dict,
    scope_meta: dict,
    suspicious_targets: list[dict],
    deterministic_summary: dict,
    scope_rows: dict,
) -> dict:
    """Editorial extensions (Phase 1 deterministic-only).

    Phase 2 will let analyst notes override `incident_findings` and
    `recommended_actions`; the deterministic generators here are the
    always-on fallback. The IOC export reads ``cohort_overlap`` and
    ``actors_art`` (for the actor_cooccurrence cells) so it can embed
    cohort_topology and project per-indicator seen_at / seen_with
    scope qualifiers.
    """
    spike_flags = list(
        (scope_art.get("window_confirmation") or {}).get("spike_flags") or []
    )
    cohort_overlap = _compute_actor_cohort_overlap(suspicious_targets, actors_art)
    incident_findings = _incident_findings(
        suspicious_targets, deterministic_summary, spike_flags,
        cohort_overlap=cohort_overlap,
    )
    iocs = _ioc_view(
        action_targets_art, scope_meta,
        actors_artifact=actors_art, cohort_overlap=cohort_overlap,
    )
    return {
        "risk_score": _risk_score(deterministic_summary, suspicious_targets),
        "severity_ladder": _severity_ladder(deterministic_summary["level"]),
        "attack_aggregation": _attack_aggregation(suspicious_targets),
        "iocs": iocs,
        "iocs_json_text": _ioc_json_text(iocs),
        "incident_findings": incident_findings,
        "recommended_actions": _recommended_actions_view(
            suspicious_targets, scope_art.get("dashboard_url") or "", None
        ),
        "analyst_assessment": _analyst_assessment_fallback(
            deterministic_summary,
            incident_findings,
            scope_rows.get("cohort_mix_rows") or [],
            scope_rows.get("path_pattern_rows") or [],
            scope_rows.get("edge_action_mix_rows") or [],
            spike_flags,
        ),
        "primary_concern": _primary_concern_view(
            suspicious_targets,
            scope_rows.get("cohort_mix_rows") or [],
        ),
        "stood_out_bullets": _stood_out_bullets(
            suspicious_targets,
            scope_rows.get("cohort_mix_rows") or [],
            scope_rows.get("path_pattern_rows") or [],
            scope_rows.get("edge_action_mix_rows") or [],
            scope_rows.get("top_raw_paths_rows") or [],
            spike_flags,
            cohort_overlap,
        ),
        "observed_inferred": _observed_inferred_taxonomy(),
        "coordination_signals": _coordination_signals(
            suspicious_targets,
            scope_rows.get("top_raw_paths_rows") or [],
            scope_rows.get("edge_action_mix_rows") or [],
            cohort_overlap,
            action_targets_art.get("target_evidence") or {},
            action_targets_art.get("behavior_clusters") or [],
        ),
        "temporal_progression": _temporal_progression_view(scope_art),
        "entity_clusters": _entity_clusters_view(action_targets_art),
        "behavior_clusters": _behavior_clusters_view(action_targets_art),
        "mitigation_coverage": _mitigation_coverage_view(scope_art),
    }
