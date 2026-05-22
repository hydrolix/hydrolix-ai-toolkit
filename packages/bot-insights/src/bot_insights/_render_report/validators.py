"""Wrapper validation / artifact normalization / schema routing."""

from __future__ import annotations

import argparse
import copy
import json
from typing import Any
from report_engine.contexts._shared import companion_compatible
from report_engine.contexts._shared import known

from .constants import (
    CONTROL_EXPECTED_BASES,
    CONTROL_SCHEMA,
    INCIDENT_ACTION_TARGETS_SCHEMA,
    INCIDENT_ACTORS_SCHEMA,
    INCIDENT_SCOPE_SCHEMA,
    INDEX_SCHEMA,
    KNOWN_UNSUPPORTED_SCHEMAS,
    MOVER_SCHEMA,
    POSTURE_SCHEMA,
    REPORT_TYPES,
    RESERVED_CHILD_ID,
    SCORECARD_PACKET_SCHEMA,
    SCORECARD_SCHEMA,
    SUPPORTED_SCHEMAS,
    THREAT_HUNT_SCHEMA,
    WRAPPER_SCHEMA,
)
from .errors import (
    ReportContext,
    ReportError,
)
from .formatters import slug_title

__all__ = [
    'json_fingerprint',
    'duplicate_body_fingerprint',
    'reserved_artifact_id',
    'schema_of',
    'validate_artifact_schema',
    'artifact_with_id',
    'normalize_artifacts',
    'load_report_input',
    'infer_report_type',
    'resolve_options',
    'default_limit',
    'generated_title',
    'by_schema',
    'cited_artifact_selectors',
    'duplicate_dedupe_risk',
    'dedupe_artifact_bodies',
    'require_one',
    'filter_compatible_companion',
    'validate_report_artifacts',
    'same_packet',
    'shared_metadata_matches',
    'compatible_scorecards_for_index_with_order_status',
    'compatible_scorecards_for_index',
    'first_or_warn',
    'scan_metadata_warnings',
]


def json_fingerprint(value: Any) -> str:
    sanitized = copy.deepcopy(value)
    if isinstance(sanitized, dict):
        sanitized.pop("artifact_id", None)
    return json.dumps(sanitized, sort_keys=True, separators=(",", ":"))


def duplicate_body_fingerprint(artifact: dict[str, Any]) -> str:
    sanitized = copy.deepcopy(artifact)
    for key in ("artifact_id", "parent_artifact_id", "parent_json_pointer"):
        sanitized.pop(key, None)
    return json.dumps(sanitized, sort_keys=True, separators=(",", ":"))


def reserved_artifact_id(artifact_id: str) -> bool:
    return RESERVED_CHILD_ID.search(artifact_id) is not None


def schema_of(artifact: Any) -> str:
    if isinstance(artifact, dict):
        return str(artifact.get("schema_version", ""))
    return ""


def validate_artifact_schema(
    artifact: Any, allow_unknown: bool, ctx: ReportContext
) -> bool:
    if not isinstance(artifact, dict):
        raise ReportError("Artifact entries must be JSON objects.")
    schema = schema_of(artifact)
    if not schema:
        raise ReportError("Artifact object is missing schema_version.")
    if schema in KNOWN_UNSUPPORTED_SCHEMAS:
        raise ReportError(
            f"{schema} is a known future schema but is unsupported by the MVP renderer."
        )
    if schema in SUPPORTED_SCHEMAS:
        return True
    if allow_unknown:
        ctx.warn(f"Skipped unknown artifact schema {schema}.")
        return False
    raise ReportError(f"Unknown artifact schema {schema}.")


def artifact_with_id(
    artifact: dict[str, Any],
    artifact_id: str,
    *,
    parent_id: str | None = None,
    parent_pointer: str | None = None,
) -> dict[str, Any]:
    copied = copy.deepcopy(artifact)
    copied["artifact_id"] = artifact_id
    if parent_id is not None:
        copied["parent_artifact_id"] = parent_id
    if parent_pointer is not None:
        copied["parent_json_pointer"] = parent_pointer
    return copied


def normalize_artifacts(
    artifacts: list[dict[str, Any]],
    *,
    allow_unknown: bool,
    ctx: ReportContext,
) -> list[dict[str, Any]]:
    all_ids: set[str] = set()
    explicit_input_ids: set[str] = set()
    normalized: list[dict[str, Any]] = []

    for index, raw in enumerate(artifacts, start=1):
        if not validate_artifact_schema(raw, allow_unknown, ctx):
            continue
        artifact_id, had_explicit = _normalized_artifact_id(
            raw, index, explicit_input_ids
        )
        parent = artifact_with_id(raw, artifact_id)
        _append_normalized_artifact(parent, all_ids, normalized, ctx, had_explicit)
        _append_scorecard_packet_children(raw, artifact_id, all_ids, normalized, ctx)
    return normalized


def _normalized_artifact_id(
    raw: dict[str, Any], index: int, explicit_input_ids: set[str]
) -> tuple[str, bool]:
    had_explicit = "artifact_id" in raw and raw.get("artifact_id") is not None
    if had_explicit and (
        not isinstance(raw["artifact_id"], str) or not raw["artifact_id"].strip()
    ):
        raise ReportError("Explicit artifact_id must be a non-empty string.")
    artifact_id = raw["artifact_id"] if had_explicit else f"artifact-{index}"
    if reserved_artifact_id(artifact_id):
        raise ReportError(
            f"Artifact ID {artifact_id} uses a reserved generated child suffix."
        )
    if had_explicit:
        if artifact_id in explicit_input_ids:
            raise ReportError(f"Duplicate artifact_id {artifact_id}.")
        explicit_input_ids.add(artifact_id)
    return artifact_id, had_explicit


def _append_normalized_artifact(
    artifact: dict[str, Any],
    all_ids: set[str],
    normalized: list[dict[str, Any]],
    ctx: ReportContext,
    explicit_id: bool,
    generated_parent_id: str | None = None,
) -> None:
    artifact_id = str(artifact["artifact_id"])
    if artifact_id in all_ids:
        raise ReportError(f"Duplicate normalized artifact_id {artifact_id}.")
    all_ids.add(artifact_id)
    ctx.artifact_id_explicit[artifact_id] = explicit_id
    if generated_parent_id is not None:
        ctx.generated_child_parent[artifact_id] = generated_parent_id
    normalized.append(artifact)


def _append_scorecard_packet_children(
    raw: dict[str, Any],
    artifact_id: str,
    all_ids: set[str],
    normalized: list[dict[str, Any]],
    ctx: ReportContext,
) -> None:
    if schema_of(raw) != SCORECARD_PACKET_SCHEMA:
        return
    _append_packet_index_child(raw, artifact_id, all_ids, normalized, ctx)
    scorecards = raw.get("scorecards")
    if not isinstance(scorecards, list):
        return
    for child_index, scorecard in enumerate(scorecards, start=1):
        _append_packet_scorecard_child(
            scorecard, child_index, artifact_id, all_ids, normalized, ctx
        )


def _append_packet_index_child(
    raw: dict[str, Any],
    artifact_id: str,
    all_ids: set[str],
    normalized: list[dict[str, Any]],
    ctx: ReportContext,
) -> None:
    packet_index = raw.get("index")
    if not isinstance(packet_index, dict) or schema_of(packet_index) != INDEX_SCHEMA:
        return
    child = artifact_with_id(
        copy.deepcopy(packet_index),
        f"{artifact_id}#index",
        parent_id=artifact_id,
        parent_pointer="/index",
    )
    _append_normalized_artifact(child, all_ids, normalized, ctx, False, artifact_id)


def _append_packet_scorecard_child(
    scorecard: Any,
    child_index: int,
    artifact_id: str,
    all_ids: set[str],
    normalized: list[dict[str, Any]],
    ctx: ReportContext,
) -> None:
    if not isinstance(scorecard, dict) or schema_of(scorecard) != SCORECARD_SCHEMA:
        return
    child = artifact_with_id(
        copy.deepcopy(scorecard),
        f"{artifact_id}#scorecard-{child_index}",
        parent_id=artifact_id,
        parent_pointer=f"/scorecards/{child_index - 1}",
    )
    _append_normalized_artifact(child, all_ids, normalized, ctx, False, artifact_id)


def load_report_input(
    value: Any,
    args: argparse.Namespace,
    ctx: ReportContext,
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    str | None,
    str | None,
    int | None,
    str | None,
    str | None,
]:
    (
        raw_artifacts,
        notes,
        wrapper_report_type,
        wrapper_title,
        wrapper_limit,
        scope_label,
        raw_mode,
    ) = _raw_report_input(value, args)

    if not all(isinstance(artifact, dict) for artifact in raw_artifacts):
        raise ReportError("All artifacts must be JSON objects.")

    normalized = normalize_artifacts(
        raw_artifacts,
        allow_unknown=bool(args.allow_unknown),
        ctx=ctx,
    )
    if not normalized:
        raise ReportError("No supported artifacts were available after normalization.")
    return (
        normalized,
        notes,
        wrapper_report_type,
        wrapper_title,
        wrapper_limit,
        scope_label,
        raw_mode,
    )


def _raw_report_input(
    value: Any, args: argparse.Namespace
) -> tuple[
    list[Any],
    list[dict[str, Any]],
    str | None,
    str | None,
    int | None,
    str | None,
    str | None,
]:
    if isinstance(value, dict) and value.get("schema_version") == WRAPPER_SCHEMA:
        return _wrapper_report_input(value)
    if isinstance(value, dict) and "schema_version" in value:
        return [value], [], None, None, None, None, "single"
    if isinstance(value, list):
        if not value:
            raise ReportError("Raw artifact array input must be non-empty.")
        if args.report_type is None:
            raise ReportError("Raw artifact array input requires --report-type.")
        return value, [], None, None, None, None, "array"
    if isinstance(value, dict):
        raise ReportError("Raw artifact object input is missing schema_version.")
    raise ReportError(
        "Input must be a known artifact object, a non-empty artifact array, or a bot_report_input.v1 wrapper."
    )


def _wrapper_report_input(
    value: dict[str, Any],
) -> tuple[
    list[Any],
    list[dict[str, Any]],
    str | None,
    str | None,
    int | None,
    str | None,
    str | None,
]:
    wrapper_report_type = _wrapper_report_type(value)
    wrapper_title = _wrapper_title(value)
    wrapper_limit = _wrapper_limit(value)
    scope_label = _wrapper_scope_label(value)
    notes = _wrapper_notes(value)
    raw_artifacts = value.get("artifacts")
    if not isinstance(raw_artifacts, list) or not raw_artifacts:
        raise ReportError("Wrapper artifacts must be a non-empty array.")
    return (
        raw_artifacts,
        notes,
        wrapper_report_type,
        wrapper_title,
        wrapper_limit,
        scope_label,
        None,
    )


def _wrapper_report_type(value: dict[str, Any]) -> str | None:
    wrapper_report_type = value.get("report_type")
    if wrapper_report_type is not None and not isinstance(wrapper_report_type, str):
        raise ReportError("Wrapper report_type must be a string.")
    if wrapper_report_type is not None and wrapper_report_type not in REPORT_TYPES:
        raise ReportError(f"Unsupported wrapper report_type {wrapper_report_type}.")
    return wrapper_report_type


def _wrapper_title(value: dict[str, Any]) -> str | None:
    wrapper_title = value.get("title")
    if wrapper_title is not None and not isinstance(wrapper_title, str):
        raise ReportError("Wrapper title must be a string.")
    return wrapper_title


def _wrapper_limit(value: dict[str, Any]) -> int | None:
    wrapper_limit = value.get("limit")
    if wrapper_limit is not None and (
        not isinstance(wrapper_limit, int)
        or isinstance(wrapper_limit, bool)
        or wrapper_limit <= 0
    ):
        raise ReportError("Wrapper limit must be a positive integer.")
    return wrapper_limit


def _wrapper_scope_label(value: dict[str, Any]) -> str | None:
    scope_label = value.get("scope_label")
    if scope_label is not None and (
        not isinstance(scope_label, str) or not scope_label.strip()
    ):
        raise ReportError("Wrapper scope_label must be a non-empty string.")
    return scope_label


def _wrapper_notes(value: dict[str, Any]) -> list[dict[str, Any]]:
    raw_notes = value.get("analyst_notes", [])
    if raw_notes is None:
        raw_notes = []
    if not isinstance(raw_notes, list) or not all(
        isinstance(note, dict) for note in raw_notes
    ):
        raise ReportError("Wrapper analyst_notes must be an array of objects.")
    return raw_notes


def infer_report_type(
    artifacts: list[dict[str, Any]], raw_hint: str | None
) -> str | None:
    if raw_hint != "single":
        return None
    raw_schema = schema_of(artifacts[0]) if artifacts else ""
    mapping = {
        POSTURE_SCHEMA: "executive_posture",
        CONTROL_SCHEMA: "control_review",
        INDEX_SCHEMA: "soc_triage",
    }
    return mapping.get(raw_schema)


def resolve_options(
    artifacts: list[dict[str, Any]],
    *,
    wrapper_report_type: str | None,
    wrapper_title: str | None,
    wrapper_limit: int | None,
    scope_label: str | None,
    raw_mode: str | None,
    args: argparse.Namespace,
    ctx: ReportContext,
) -> tuple[str, str, int, str | None]:
    cli_report_type = args.report_type
    if (
        wrapper_report_type
        and cli_report_type
        and wrapper_report_type != cli_report_type
    ):
        raise ReportError(
            f"Wrapper report_type {wrapper_report_type} conflicts with CLI --report-type {cli_report_type}."
        )
    report_type = wrapper_report_type or cli_report_type
    if report_type is None:
        report_type = infer_report_type(artifacts, raw_mode)
    if report_type is None:
        raise ReportError(
            "Missing or ambiguous report intent; supply --report-type or wrapper report_type."
        )

    if args.title is not None and not isinstance(args.title, str):
        raise ReportError("--title must be a string.")
    if (
        args.title is not None
        and wrapper_title is not None
        and args.title != wrapper_title
    ):
        ctx.warn("CLI --title overrides wrapper title.")
    title = (
        args.title
        or wrapper_title
        or generated_title(report_type, artifacts, scope_label)
    )

    if args.limit is not None:
        if (
            not isinstance(args.limit, int)
            or isinstance(args.limit, bool)
            or args.limit <= 0
        ):
            raise ReportError("--limit must be a positive integer.")
    if (
        args.limit is not None
        and wrapper_limit is not None
        and args.limit != wrapper_limit
    ):
        ctx.warn("CLI --limit overrides wrapper limit.")
    limit = args.limit or wrapper_limit or default_limit(report_type)
    return report_type, title, limit, scope_label


def default_limit(report_type: str) -> int:
    if report_type == "scorecard_brief":
        return 20
    return 10


def generated_title(
    report_type: str, artifacts: list[dict[str, Any]], scope_label: str | None
) -> str:
    scope = scope_label
    if not scope:
        for artifact in artifacts:
            scope_value = artifact.get("scope")
            if isinstance(scope_value, dict) and scope_value:
                scope = ", ".join(
                    f"{key}={value}" for key, value in sorted(scope_value.items())
                )
                break
    if scope:
        return f"{slug_title(report_type)} - {scope}"
    return slug_title(report_type)


def by_schema(artifacts: list[dict[str, Any]], schema: str) -> list[dict[str, Any]]:
    return [artifact for artifact in artifacts if schema_of(artifact) == schema]


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


def require_one(
    artifacts: list[dict[str, Any]], schema: str, report_type: str
) -> dict[str, Any]:
    matches = by_schema(artifacts, schema)
    if not matches:
        raise ReportError(f"{report_type} requires {schema}.")
    if len(matches) > 1:
        raise ReportError(f"{report_type} requires one {schema}; found {len(matches)}.")
    return matches[0]


def filter_compatible_companion(
    primary: dict[str, Any] | None,
    companion: dict[str, Any] | None,
    label: str,
    ctx: ReportContext,
) -> dict[str, Any] | None:
    if companion is None:
        return None
    ok, reason = companion_compatible(primary, companion)
    if ok:
        return companion
    ctx.warn(
        f"Omitting optional {label} {companion.get('artifact_id')} from combined sections: {reason}."
    )
    return None


def validate_report_artifacts(
    report_type: str,
    artifacts: list[dict[str, Any]],
    ctx: ReportContext,
) -> dict[str, Any]:
    if report_type in _REPORT_VALIDATORS:
        return _REPORT_VALIDATORS[report_type](artifacts, report_type, ctx)
    if report_type in {
        "incident_report",
        "incident_executive_view",
        "incident_soc_action_packet",
        "incident_edge_platform_brief",
        "incident_detection_engineering",
    }:
        scope = require_one(artifacts, INCIDENT_SCOPE_SCHEMA, report_type)
        actors = require_one(artifacts, INCIDENT_ACTORS_SCHEMA, report_type)
        action_targets = require_one(
            artifacts, INCIDENT_ACTION_TARGETS_SCHEMA, report_type
        )
        return {
            "scope": scope,
            "actors": actors,
            "action_targets": action_targets,
        }
    if report_type == "threat_hunt":
        threat_hunt = require_one(artifacts, THREAT_HUNT_SCHEMA, report_type)
        return {"threat_hunt": threat_hunt}
    raise ReportError(f"Unsupported report type {report_type}.")


def _validate_executive_posture(
    artifacts: list[dict[str, Any]], report_type: str, ctx: ReportContext
) -> dict[str, Any]:
    posture = require_one(artifacts, POSTURE_SCHEMA, report_type)
    index = first_or_warn(artifacts, INDEX_SCHEMA, report_type, ctx)
    mover = first_or_warn(artifacts, MOVER_SCHEMA, report_type, ctx)
    index = filter_compatible_companion(posture, index, "index", ctx)
    scorecards: list[dict[str, Any]] = []
    if index:
        scorecards = compatible_scorecards_for_index(
            index, by_schema(artifacts, SCORECARD_SCHEMA), ctx, required=False
        )
    return {
        "posture": posture,
        "index": index,
        "scorecards": scorecards,
        "mover": filter_compatible_companion(posture, mover, "mover", ctx),
    }


def _validate_soc_triage(
    artifacts: list[dict[str, Any]], report_type: str, ctx: ReportContext
) -> dict[str, Any]:
    index = require_one(artifacts, INDEX_SCHEMA, report_type)
    scorecards = compatible_scorecards_for_index(
        index, by_schema(artifacts, SCORECARD_SCHEMA), ctx,
        required=bool(by_schema(artifacts, SCORECARD_SCHEMA)),
    )
    if not scorecards:
        ctx.warn(
            "SOC triage has only bot_scorecard_index.v1 and renders a degraded ranking-only report."
        )
    posture = first_or_warn(artifacts, POSTURE_SCHEMA, report_type, ctx)
    mover = first_or_warn(artifacts, MOVER_SCHEMA, report_type, ctx)
    return {
        "index": index,
        "scorecards": scorecards,
        "posture": filter_compatible_companion(index, posture, "posture", ctx),
        "mover": filter_compatible_companion(index, mover, "mover", ctx),
    }


def _validate_control_review(
    artifacts: list[dict[str, Any]], report_type: str, ctx: ReportContext
) -> dict[str, Any]:
    control = require_one(artifacts, CONTROL_SCHEMA, report_type)
    posture = first_or_warn(artifacts, POSTURE_SCHEMA, report_type, ctx)
    mover = first_or_warn(artifacts, MOVER_SCHEMA, report_type, ctx)
    return {
        "control": control,
        "posture": filter_compatible_companion(control, posture, "posture", ctx),
        "mover": filter_compatible_companion(control, mover, "mover", ctx),
    }


def _validate_scorecard_brief(
    artifacts: list[dict[str, Any]], report_type: str, ctx: ReportContext
) -> dict[str, Any]:
    scorecards = _require_scorecards(artifacts, report_type)
    index = first_or_warn(artifacts, INDEX_SCHEMA, report_type, ctx)
    index_order_usable = False
    if index:
        scorecards, index_order_usable = compatible_scorecards_for_index_with_order_status(
            index, scorecards, ctx, required=True
        )
    return {
        "scorecard": scorecards[0],
        "scorecards": scorecards,
        "index": index,
        "index_order_usable": index_order_usable,
        "is_fleet": bool(index or len(scorecards) > 1),
    }


def _validate_scorecard_family(
    artifacts: list[dict[str, Any]], report_type: str, ctx: ReportContext
) -> dict[str, Any]:
    scorecards = _require_scorecards(artifacts, report_type)
    index = first_or_warn(artifacts, INDEX_SCHEMA, report_type, ctx)
    index_order_usable = False
    if index:
        scorecards, index_order_usable = compatible_scorecards_for_index_with_order_status(
            index, scorecards, ctx, required=False
        )
    reference = index or (scorecards[0] if scorecards else None)
    posture = first_or_warn(artifacts, POSTURE_SCHEMA, report_type, ctx)
    mover = first_or_warn(artifacts, MOVER_SCHEMA, report_type, ctx)
    return {
        "scorecards": scorecards,
        "index": index,
        "index_order_usable": index_order_usable,
        "posture": filter_compatible_companion(reference, posture, "posture", ctx),
        "mover": filter_compatible_companion(reference, mover, "mover", ctx),
    }


def _require_scorecards(
    artifacts: list[dict[str, Any]], report_type: str
) -> list[dict[str, Any]]:
    scorecards = by_schema(artifacts, SCORECARD_SCHEMA)
    if scorecards:
        return scorecards
    if report_type == "scorecard_brief":
        raise ReportError(f"{report_type} requires {SCORECARD_SCHEMA}.")
    raise ReportError(
        f"{report_type} requires bot_entity_scorecard.v1 artifacts or a scorecard packet."
    )


_REPORT_VALIDATORS = {
    "executive_posture": _validate_executive_posture,
    "soc_triage": _validate_soc_triage,
    "control_review": _validate_control_review,
    "scorecard_brief": _validate_scorecard_brief,
    "crawler_governance": _validate_scorecard_family,
    "edge_ops_impact": _validate_scorecard_family,
}


def same_packet(
    left: dict[str, Any], right: dict[str, Any], ctx: ReportContext
) -> bool:
    left_parent = ctx.generated_child_parent.get(str(left.get("artifact_id")))
    right_parent = ctx.generated_child_parent.get(str(right.get("artifact_id")))
    return bool(left_parent and left_parent == right_parent)


def shared_metadata_matches(
    index: dict[str, Any], scorecard: dict[str, Any], ctx: ReportContext
) -> bool:
    if same_packet(index, scorecard, ctx):
        for field in (
            "scope",
            "current_window",
            "baseline_windows",
            "table_used",
            "comparison_type",
        ):
            left = index.get(field)
            right = scorecard.get(field)
            if known(left) and known(right) and left != right:
                raise ReportError(
                    f"Same-packet scorecard metadata mismatch for {field}."
                )
            if not known(left) or not known(right):
                ctx.warn(
                    f"{scorecard.get('artifact_id')} missing same-packet {field} metadata."
                )
        return True

    for field in ("scope", "current_window", "baseline_windows", "table_used"):
        left = index.get(field)
        right = scorecard.get(field)
        if not known(left) or not known(right):
            raise ReportError(
                f"Standalone scorecard pairing requires known {field} metadata."
            )
        if left != right:
            raise ReportError(f"Scorecard metadata mismatch for {field}.")

    left_comparison = index.get("comparison_type")
    right_comparison = scorecard.get("comparison_type")
    if known(left_comparison) != known(right_comparison):
        raise ReportError(
            "Standalone scorecard pairing requires matching comparison_type metadata when present."
        )
    if known(left_comparison) and left_comparison != right_comparison:
        raise ReportError("Scorecard metadata mismatch for comparison_type.")
    return True


def compatible_scorecards_for_index_with_order_status(
    index: dict[str, Any],
    scorecards: list[dict[str, Any]],
    ctx: ReportContext,
    *,
    required: bool,
) -> tuple[list[dict[str, Any]], bool]:
    by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for card in scorecards:
        if not known(card.get("entity_type")) or not known(card.get("entity")):
            continue
        key = (str(card.get("entity_type")), str(card.get("entity")))
        existing = by_key.get(key)
        if existing is not None:
            raise ReportError(
                "Multiple scorecards share entity_type/entity "
                f"{key[0]}={key[1]}; pairing with an index would be ambiguous."
            )
        by_key[key] = card
    compatible: list[dict[str, Any]] = []
    for row in index.get("ranked_entities", []):
        key = (str(row.get("entity_type")), str(row.get("entity")))
        card = by_key.get(key)
        if not card:
            continue
        if shared_metadata_matches(index, card, ctx):
            compatible.append(card)
    if required and scorecards and not compatible:
        raise ReportError("No scorecards are compatible with the selected index.")
    if scorecards and not compatible:
        ctx.warn(
            "No scorecards were compatible with the selected index; using input order."
        )
        return scorecards, False
    return compatible, bool(compatible)


def compatible_scorecards_for_index(
    index: dict[str, Any],
    scorecards: list[dict[str, Any]],
    ctx: ReportContext,
    *,
    required: bool,
) -> list[dict[str, Any]]:
    compatible, _ = compatible_scorecards_for_index_with_order_status(
        index, scorecards, ctx, required=required
    )
    return compatible


def first_or_warn(
    artifacts: list[dict[str, Any]],
    schema: str,
    report_type: str,
    ctx: ReportContext,
) -> dict[str, Any] | None:
    matches = by_schema(artifacts, schema)
    if len(matches) > 1:
        raise ReportError(
            f"{report_type} cannot select between multiple {schema} artifacts."
        )
    return matches[0] if matches else None


def scan_metadata_warnings(artifacts: list[dict[str, Any]], ctx: ReportContext) -> None:
    for artifact in artifacts:
        schema = schema_of(artifact)
        aid = artifact.get("artifact_id")
        if schema in {POSTURE_SCHEMA, SCORECARD_SCHEMA, INDEX_SCHEMA}:
            _scan_window_metadata(artifact, aid, ctx)
        elif schema == CONTROL_SCHEMA:
            _scan_control_metadata(artifact, aid, ctx)
        elif schema == MOVER_SCHEMA:
            _scan_mover_metadata(artifact, aid, ctx)


def _scan_window_metadata(
    artifact: dict[str, Any], aid: Any, ctx: ReportContext
) -> None:
    if not artifact.get("current_window"):
        ctx.warn(f"{aid} missing current_window metadata.")
    if not artifact.get("baseline_windows"):
        ctx.warn(f"{aid} missing baseline_windows metadata.")


def _scan_control_metadata(
    artifact: dict[str, Any], aid: Any, ctx: ReportContext
) -> None:
    if not artifact.get("before_window"):
        ctx.warn(f"{aid} missing before_window metadata.")
    if not artifact.get("after_window"):
        ctx.warn(f"{aid} missing after_window metadata.")
    basis = artifact.get("expected_basis")
    if _control_has_expected_effects(artifact) and (
        not isinstance(basis, str) or basis not in CONTROL_EXPECTED_BASES
    ):
        ctx.warn(f"{aid} missing or unknown expected_basis with expected target effects.")
    if basis in {"before_window", "external_model"} and not artifact.get(
        "expected_window"
    ):
        ctx.warn(f"{aid} missing expected_window metadata for expected_basis {basis}.")


def _control_has_expected_effects(artifact: dict[str, Any]) -> bool:
    effects = artifact.get("target_effects") or []
    return any(
        isinstance(effect, dict)
        and "expected" in effect
        and effect.get("expected") is not None
        for effect in effects
    )


def _scan_mover_metadata(
    artifact: dict[str, Any], aid: Any, ctx: ReportContext
) -> None:
    if not artifact.get("dimension"):
        ctx.warn(f"{aid} missing mover dimension metadata.")
    if not artifact.get("metric"):
        ctx.warn(f"{aid} missing mover metric metadata.")
