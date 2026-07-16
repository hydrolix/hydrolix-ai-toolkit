"""JSON-pointer-based artifact citation resolution."""

from __future__ import annotations

import re
from typing import Any

from .errors import ReportError

__all__ = [
    'json_pointer_get',
    '_encode_pointer_token',
    '_list_index_from_token',
    'json_pointer_resolve',
    'resolve_citation',
]


def json_pointer_get(value: Any, pointer: str) -> Any:
    return json_pointer_resolve(value, pointer)[1]


def _encode_pointer_token(token: str) -> str:
    return token.replace("~", "~0").replace("/", "~1")


def _list_index_from_token(token: str, length: int) -> int:
    if re.fullmatch(r"0|[1-9][0-9]*", token):
        index = int(token)
    else:
        raise KeyError(token)
    if index < 0 or index >= length:
        raise KeyError(token)
    return index


def json_pointer_resolve(value: Any, pointer: str) -> tuple[str, Any]:
    if pointer == "":
        return "", value
    if not pointer.startswith("/") or re.search(r"~(?![01])", pointer):
        raise KeyError(pointer)
    current = value
    normalized_tokens: list[str] = []
    for raw_token in pointer.split("/")[1:]:
        token = raw_token.replace("~1", "/").replace("~0", "~")
        if isinstance(current, list):
            index = _list_index_from_token(token, len(current))
            normalized_tokens.append(str(index))
            current = current[index]
        elif isinstance(current, dict):
            current = current[token]
            normalized_tokens.append(_encode_pointer_token(token))
        else:
            raise KeyError(pointer)
    return "/" + "/".join(normalized_tokens), current


def _validate_citation_source(source: dict[str, Any]) -> tuple[str | None, str | None]:
    artifact_id = source.get("artifact_id")
    schema = source.get("schema_version")
    if artifact_id is not None and not isinstance(artifact_id, str):
        raise ReportError("Analyst-note citation artifact_id must be a string.")
    if schema is not None and not isinstance(schema, str):
        raise ReportError("Analyst-note citation schema_version must be a string.")
    label = source.get("label")
    if label is not None and not isinstance(label, str):
        raise ReportError("Analyst-note citation label must be a string.")
    return artifact_id, schema


def _artifact_by_id(
    artifact_id: str,
    schema: str | None,
    artifacts: list[dict[str, Any]],
) -> dict[str, Any]:
    candidates = [
        artifact
        for artifact in artifacts
        if artifact.get("artifact_id") == artifact_id
    ]
    if not candidates:
        raise ReportError(
            f"Analyst-note citation artifact_id {artifact_id} cannot be resolved."
        )
    artifact = candidates[0]
    if schema and artifact.get("schema_version") != schema:
        raise ReportError(
            f"Analyst-note citation {artifact_id} schema mismatch: expected {schema}."
        )
    return artifact


def _artifact_by_schema(
    schema: str,
    artifacts: list[dict[str, Any]],
) -> dict[str, Any]:
    candidates = [
        artifact
        for artifact in artifacts
        if artifact.get("schema_version") == schema
    ]
    if len(candidates) != 1:
        raise ReportError(
            f"Analyst-note schema-only citation {schema} is ambiguous or missing."
        )
    return candidates[0]


def _citation_artifact(
    artifact_id: str | None,
    schema: str | None,
    artifacts: list[dict[str, Any]],
) -> dict[str, Any]:
    if artifact_id:
        return _artifact_by_id(artifact_id, schema, artifacts)
    if schema:
        return _artifact_by_schema(schema, artifacts)
    raise ReportError(
        "Analyst-note citation requires artifact_id or schema_version."
    )


def resolve_citation(
    source: dict[str, Any],
    artifacts: list[dict[str, Any]],
) -> tuple[dict[str, Any], str, Any]:
    artifact_id, schema = _validate_citation_source(source)
    artifact = _citation_artifact(artifact_id, schema, artifacts)

    pointer = source.get("json_pointer")
    if not isinstance(pointer, str):
        raise ReportError("Analyst-note citation is missing json_pointer.")
    try:
        normalized_pointer, resolved = json_pointer_resolve(artifact, pointer)
        return artifact, normalized_pointer, resolved
    except (KeyError, IndexError, ValueError, TypeError):
        raise ReportError(
            f"Analyst-note citation pointer {pointer} cannot be resolved."
        )
