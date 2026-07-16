"""IOC export view for the incident-report SOAR handoff."""

from __future__ import annotations

from .cohorts import _compute_actor_cohort_topology
from .labels import IOC_TYPE_MAP
from .targets import _scope_views_for_indicator

__all__ = [
    '_ioc_view',
    '_ioc_json_text',
]


_OPTIONAL_SCOPE_KEYS = ("seen_at", "seen_with", "edge_action")


def _build_indicator(
    target: dict, scope_meta: dict, actors_artifact: dict
) -> dict:
    """Project one suspicious target into an IOC export indicator dict."""
    target_type = target.get("target_type") or ""
    indicator: dict = {
        "type": IOC_TYPE_MAP.get(target_type, target_type),
        "value": target.get("target_value"),
        "kind": target.get("kind") or "actor",
        "severity": target.get("severity"),
        "confidence": target.get("confidence"),
        "first_observed": scope_meta.get("start"),
        "last_observed": scope_meta.get("end"),
        "reason_flags": list(target.get("reason_flags") or []),
        "attack_techniques": list(target.get("attack_techniques") or []),
        "supporting": target.get("supporting") or {},
        "suggested_action_hint": target.get("suggested_action_hint") or "review",
        "action_class": target.get("action_class") or "watch",
    }
    scope_views = _scope_views_for_indicator(target, actors_artifact)
    for key in _OPTIONAL_SCOPE_KEYS:
        if scope_views.get(key):
            indicator[key] = scope_views[key]
    return indicator


def _build_ioc_scope(scope_meta: dict) -> dict:
    return {
        "cluster": scope_meta.get("cluster") or "",
        "host": scope_meta.get("host"),
        "asn": scope_meta.get("asn"),
        "path_pattern": scope_meta.get("path_pattern"),
        "window_start": scope_meta.get("start"),
        "window_end": scope_meta.get("end"),
        "baseline_start": scope_meta.get("baseline_start"),
        "baseline_end": scope_meta.get("baseline_end"),
    }


def _ioc_view(
    action_targets_art: dict,
    scope_meta: dict,
    actors_artifact: dict | None = None,
    cohort_overlap: dict | None = None,
) -> dict:
    """Project action-targets into a SIEM-ingestion-ready IOC export.

    Wraps the suspicious-target rows in a ``bot_incident_iocs.v1`` shape
    designed for downstream SOC tooling: schema header, scope context,
    optional ``cohort_topology`` describing actor sub-population
    overlap, and a flat ``indicators`` array. Each indicator carries
    its IOC type (using SOC vocabulary, not the report-internal
    target_type), severity, confidence, the analyst window as
    first/last observed timestamps, reason flags, ATT&CK techniques,
    supporting evidence, and (when the actor_cooccurrence payload is
    present) ``seen_at`` / ``seen_with`` scope qualifiers — top
    counterparties so a SOAR consumer can compose path-scoped
    blocks instead of site-wide ones.

    The export is *additive* — the same underlying data lives in
    bot_incident_action_targets.v1; this view is the read model SOC
    automation consumes.
    """
    actors = actors_artifact or {}
    indicators = [
        _build_indicator(t, scope_meta, actors)
        for t in action_targets_art.get("targets") or []
    ]
    view: dict = {
        "schema": "bot_incident_iocs.v1",
        "scope": _build_ioc_scope(scope_meta),
        "source_artifact": "bot_incident_action_targets.v1",
        "heuristic_version": action_targets_art.get("heuristic_version"),
        "indicators": indicators,
    }
    topology = _compute_actor_cohort_topology(cohort_overlap)
    if topology:
        view["cohort_topology"] = topology
    return view


def _ioc_json_text(ioc_view: dict) -> str:
    """Serialize the IOC view as indented JSON for the report's IOC appendix.

    Keys are not sorted — preserving the structured ordering keeps the
    schema/scope/indicators flow obvious to a reader scanning the
    rendered code block.
    """
    import json

    return json.dumps(ioc_view, indent=2)
