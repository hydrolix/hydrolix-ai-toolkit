from __future__ import annotations

import hashlib
from typing import Any

from .constants import SHA256_RE
from .numeric import canonical_json_bytes
from .options import parse_dimensions
from .rows import column_names


def column_identity(column: Any) -> dict[str, Any]:
    if isinstance(column, str):
        return {"name": column}
    if not isinstance(column, dict):
        return {"name": str(column)}

    name = column.get("name", column.get("column", column.get("column_name", "")))
    identity = {"name": str(name)}
    for source_key, target_key in (
        ("type", "type"),
        ("data_type", "type"),
        ("column_type", "type"),
        ("column_category", "column_category"),
        ("base_function", "base_function"),
        ("merge_function", "merge_function"),
        ("default_expr", "default_expr"),
    ):
        if source_key in column and target_key not in identity:
            identity[target_key] = column[source_key]
    return identity


def table_metadata_columns(table_metadata: dict[str, Any]) -> list[dict[str, Any]]:
    raw_columns = table_metadata.get("columns", [])
    if not isinstance(raw_columns, list):
        raw_columns = []
    return sorted(
        (column_identity(column) for column in raw_columns),
        key=lambda column: column.get("name", ""),
    )


def metadata_fingerprint_payload(
    table_metadata: dict[str, Any],
    *,
    selected_columns: Any = None,
    metadata_retrieval_identity: str | None = None,
    metadata_fixture_identity: str | None = None,
) -> dict[str, Any]:
    columns = table_metadata_columns(table_metadata)
    column_names = [column["name"] for column in columns if column.get("name")]
    selected = parse_dimensions(selected_columns) if selected_columns is not None else column_names
    source_identity = metadata_retrieval_identity or metadata_fixture_identity
    return {
        "table": table_metadata.get("table")
        or table_metadata.get("table_name")
        or table_metadata.get("name"),
        "database": table_metadata.get("database"),
        "is_summary_table": bool(table_metadata.get("is_summary_table", False)),
        "selected_columns": sorted(selected),
        "columns": columns,
        "metadata_retrieval_identity": metadata_retrieval_identity,
        "metadata_fixture_identity": metadata_fixture_identity,
        "metadata_source_identity": source_identity,
    }


def metadata_fingerprint(
    table_metadata: dict[str, Any],
    *,
    selected_columns: Any = None,
    metadata_retrieval_identity: str | None = None,
    metadata_fixture_identity: str | None = None,
) -> str:
    payload = metadata_fingerprint_payload(
        table_metadata,
        selected_columns=selected_columns,
        metadata_retrieval_identity=metadata_retrieval_identity,
        metadata_fixture_identity=metadata_fixture_identity,
    )
    return "sha256:" + hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def sha256_payload_digest(payload: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def is_sha256_digest(value: Any) -> bool:
    return isinstance(value, str) and SHA256_RE.match(value) is not None
