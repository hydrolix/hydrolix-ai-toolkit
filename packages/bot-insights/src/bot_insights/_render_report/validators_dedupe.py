"""Duplicate artifact body safeguards."""

from __future__ import annotations

from typing import Any

from .constants import (
    CONTROL_SCHEMA,
    INCIDENT_ACTION_TARGETS_SCHEMA,
    INCIDENT_ACTORS_SCHEMA,
    INCIDENT_SCOPE_SCHEMA,
    INDEX_SCHEMA,
    MOVER_SCHEMA,
    POSTURE_SCHEMA,
    SCORECARD_SCHEMA,
)
from .errors import ReportContext, ReportError
from .validators_normalization import duplicate_body_fingerprint, schema_of


def cited_artifact_selectors(
    notes: list[dict[str, Any]],
) -> tuple[set[str], set[str]]:
    artifact_ids: set[str] = set()
    schema_only: set[str] = set()
    for note in notes:
        data_sources = note.get("data_sources") or []
        if not isinstance(data_sources, list):
            continue
        for source in data_sources:
            if not isinstance(source, dict):
                continue
            artifact_id = source.get("artifact_id")
            schema = source.get("schema_version")
            if isinstance(artifact_id, str):
                artifact_ids.add(artifact_id)
            elif isinstance(schema, str):
                schema_only.add(schema)
    return artifact_ids, schema_only


def duplicate_dedupe_risk(
    schema: str,
    report_type: str,
) -> str | None:
    selection_sensitive_schemas = {
        "executive_posture": {POSTURE_SCHEMA, INDEX_SCHEMA, MOVER_SCHEMA},
        "soc_triage": {
            INDEX_SCHEMA,
            SCORECARD_SCHEMA,
            POSTURE_SCHEMA,
            MOVER_SCHEMA,
        },
        "control_review": {CONTROL_SCHEMA, POSTURE_SCHEMA, MOVER_SCHEMA},
        "scorecard_brief": {SCORECARD_SCHEMA, INDEX_SCHEMA},
        "crawler_governance": {
            SCORECARD_SCHEMA,
            INDEX_SCHEMA,
            POSTURE_SCHEMA,
            MOVER_SCHEMA,
        },
        "edge_ops_impact": {
            SCORECARD_SCHEMA,
            INDEX_SCHEMA,
            POSTURE_SCHEMA,
            MOVER_SCHEMA,
        },
        "incident_report": {
            INCIDENT_SCOPE_SCHEMA,
            INCIDENT_ACTORS_SCHEMA,
            INCIDENT_ACTION_TARGETS_SCHEMA,
        },
        "incident_executive_view": {
            INCIDENT_SCOPE_SCHEMA,
            INCIDENT_ACTORS_SCHEMA,
            INCIDENT_ACTION_TARGETS_SCHEMA,
        },
        "incident_soc_action_packet": {
            INCIDENT_SCOPE_SCHEMA,
            INCIDENT_ACTORS_SCHEMA,
            INCIDENT_ACTION_TARGETS_SCHEMA,
        },
        "incident_edge_platform_brief": {
            INCIDENT_SCOPE_SCHEMA,
            INCIDENT_ACTORS_SCHEMA,
            INCIDENT_ACTION_TARGETS_SCHEMA,
        },
        "incident_detection_engineering": {
            INCIDENT_SCOPE_SCHEMA,
            INCIDENT_ACTORS_SCHEMA,
            INCIDENT_ACTION_TARGETS_SCHEMA,
        },
    }
    if schema in selection_sensitive_schemas.get(report_type, set()):
        if schema == SCORECARD_SCHEMA and report_type in {
            "soc_triage",
            "crawler_governance",
            "edge_ops_impact",
        }:
            return "duplicates could affect scorecard input order or rendered rows"
        return "duplicates could affect report artifact selection"
    return None


def dedupe_artifact_bodies(
    artifacts: list[dict[str, Any]],
    notes: list[dict[str, Any]],
    report_type: str,
    ctx: ReportContext,
) -> list[dict[str, Any]]:
    groups: dict[str, list[dict[str, Any]]] = {}
    for artifact in artifacts:
        groups.setdefault(duplicate_body_fingerprint(artifact), []).append(artifact)

    cited_ids, schema_only_citations = cited_artifact_selectors(notes)
    dropped_ids: set[str] = set()
    for group in groups.values():
        if len(group) < 2:
            continue
        kept = group[0]
        duplicate_ids = [str(artifact["artifact_id"]) for artifact in group]
        schema = schema_of(kept)
        if any(
            ctx.artifact_id_explicit.get(artifact_id) for artifact_id in duplicate_ids
        ):
            raise ReportError(
                "Artifact bodies for "
                + ", ".join(duplicate_ids)
                + " are identical; duplicates with explicit artifact IDs cannot be deduplicated safely."
            )
        if cited_ids.intersection(duplicate_ids) or schema in schema_only_citations:
            raise ReportError(
                "Artifact bodies for "
                + ", ".join(duplicate_ids)
                + " are identical; analyst-note citations make deduplication ambiguous."
            )
        risk = duplicate_dedupe_risk(schema, report_type)
        if risk:
            raise ReportError(
                "Artifact bodies for "
                + ", ".join(duplicate_ids)
                + f" are identical; {risk}."
            )
        dropped = duplicate_ids[1:]
        dropped_ids.update(dropped)
        ctx.warn(
            "Ignored duplicate artifact bodies for "
            + ", ".join(dropped)
            + f"; kept {kept['artifact_id']}."
        )

    if not dropped_ids:
        return artifacts
    return [
        artifact
        for artifact in artifacts
        if str(artifact.get("artifact_id")) not in dropped_ids
    ]
