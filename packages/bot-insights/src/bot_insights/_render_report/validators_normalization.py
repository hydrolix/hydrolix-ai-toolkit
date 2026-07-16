"""Artifact schema validation and normalization helpers."""

from __future__ import annotations

import copy
import json
from typing import Any

from .constants import (
    INDEX_SCHEMA,
    KNOWN_UNSUPPORTED_SCHEMAS,
    RESERVED_CHILD_ID,
    SCORECARD_PACKET_SCHEMA,
    SCORECARD_SCHEMA,
    SUPPORTED_SCHEMAS,
)
from .errors import ReportContext, ReportError


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


def by_schema(artifacts: list[dict[str, Any]], schema: str) -> list[dict[str, Any]]:
    return [artifact for artifact in artifacts if schema_of(artifact) == schema]


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
