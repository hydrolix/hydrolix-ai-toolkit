from __future__ import annotations

from ._shared import *
from .part_01 import *
from .part_02 import *

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

def decimal_value(value: Any, *, path: str) -> Decimal:
    if isinstance(value, bool) or value is None:
        raise_invalid(
            "non_finite_digest_value",
            "Digest numeric fields must be finite decimal values.",
            path=path,
        )
    if isinstance(value, float) and not math.isfinite(value):
        raise_invalid(
            "non_finite_digest_value",
            "Digest numeric fields must be finite decimal values.",
            path=path,
        )
    try:
        number = Decimal(str(value))
    except (InvalidOperation, ValueError):
        raise_invalid(
            "non_finite_digest_value",
            "Digest numeric fields must be finite decimal values.",
            path=path,
        )
    if not number.is_finite():
        raise_invalid(
            "non_finite_digest_value",
            "Digest numeric fields must be finite decimal values.",
            path=path,
        )
    if number == Decimal("-0"):
        return Decimal("0")
    return number

def digest_decimal(
    value: Any,
    *,
    path: str,
    places: int = 6,
) -> str:
    number = decimal_value(value, path=path)
    quant = Decimal("1").scaleb(-places)
    rounded = number.quantize(quant, rounding=ROUND_HALF_UP)
    if rounded == Decimal("-0").quantize(quant):
        rounded = Decimal("0").quantize(quant)
    return f"{rounded:.{places}f}"

def digest_support_value(value: Any, *, path: str) -> int | str:
    number = decimal_value(value, path=path)
    if number < 0:
        raise_invalid(
            "non_finite_digest_value",
            "Digest support counts must be non-negative.",
            path=path,
        )
    if number == number.to_integral_value():
        return int(number)
    return digest_decimal(number, path=path)

def digest_percentage(value: Any, *, path: str) -> str:
    return digest_decimal(value, path=path, places=2)

def normalize_digest_timestamp(value: Any, *, path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise_invalid(
            "timestamp_invalid",
            "Digest timestamps must be RFC 3339 strings with a timezone.",
            path=path,
        )
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        raise_invalid(
            "timestamp_invalid",
            "Digest timestamps must be RFC 3339 strings with a timezone.",
            path=path,
        )
    if parsed.tzinfo is None:
        raise_invalid(
            "timestamp_invalid",
            "Digest timestamps must include a deterministic timezone.",
            path=path,
        )
    return parsed.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")

def normalize_digest_window(value: Any, *, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise_invalid(
            "window_invalid",
            "Digest window fields must be objects with start and end.",
            path=path,
        )
    normalized = {
        "start": normalize_digest_timestamp(value.get("start"), path=f"{path}.start"),
        "end": normalize_digest_timestamp(value.get("end"), path=f"{path}.end"),
    }
    if "label" in value:
        normalized["label"] = None if value["label"] is None else str(value["label"])
    return normalized

def normalize_digest_value(value: Any, *, path: str) -> Any:
    if isinstance(value, dict):
        return {
            str(key): normalize_digest_value(value[key], path=f"{path}.{key}")
            for key in sorted(value)
        }
    if isinstance(value, list):
        return [
            normalize_digest_value(item, path=f"{path}[{index}]")
            for index, item in enumerate(value)
        ]
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return value
    if isinstance(value, (int, float, Decimal)):
        return digest_decimal(value, path=path)
    return str(value)

def collect_trust_metadata(payload: Any, metadata: dict[str, Any]) -> dict[str, Any]:
    trust_metadata: dict[str, Any] = {}
    for key in TRUST_METADATA_FIELDS:
        value = resolve_value(payload, metadata, key)
        if value is not None:
            trust_metadata[key] = value
    return trust_metadata

def canonical_digest_row(
    row: dict[str, Any],
    dimensions: list[str],
    *,
    path: str,
) -> dict[str, Any]:
    digest_row: dict[str, Any] = {
        "dimensions": {
            dimension: row["dimensions"].get(dimension)
            for dimension in dimensions
        },
        "current": None
        if row.get("current") is None
        else digest_decimal(row["current"], path=f"{path}.current"),
        "baseline": None
        if row.get("baseline") is None
        else digest_decimal(row["baseline"], path=f"{path}.baseline"),
    }
    for key in (
        "current_support_raw",
        "baseline_support_raw",
        "baseline_support_normalized",
    ):
        if key in row and row[key] is not None:
            digest_row[key] = digest_support_value(row[key], path=f"{path}.{key}")
    for key in (
        "baseline_raw",
        "absolute_delta",
        "abs_delta",
        "complete_scope_total_abs_delta",
        "baseline_normalization_factor",
    ):
        if key in row:
            digest_row[key] = None if row[key] is None else digest_decimal(row[key], path=f"{path}.{key}")
    for key in ("pct_change", "contribution_pct"):
        if key in row:
            digest_row[key] = None if row[key] is None else digest_percentage(row[key], path=f"{path}.{key}")
    return digest_row

def canonical_row_sort_key(row: dict[str, Any], dimensions: list[str]) -> tuple[Any, ...]:
    dimension_key = tuple(
        (row["dimensions"].get(dimension) is None, "" if row["dimensions"].get(dimension) is None else str(row["dimensions"].get(dimension)))
        for dimension in dimensions
    )
    return dimension_key + (canonical_json_bytes(row).decode("utf-8"),)

def digest_payload_v1_from_normalized(
    normalized: dict[str, Any],
    *,
    options: Any = None,
) -> dict[str, Any]:
    opts = normalize_options(options)
    limit_value = opts.get("limit")
    limit = int(limit_value) if limit_value is not None else 0
    report_metadata = normalized.get("report_metadata", {})
    trust_metadata = normalized.get("trust_metadata", {})
    rows = [
        canonical_digest_row(row, normalized["dimensions"], path=f"$.canonical_rows[{index}]")
        for index, row in enumerate(normalized["canonical_rows"])
    ]
    rows.sort(key=lambda row: canonical_row_sort_key(row, normalized["dimensions"]))

    payload: dict[str, Any] = {
        "digest_schema_version": DIGEST_SCHEMA_VERSION,
        "metric": normalized["metric"],
        "metric_kind": normalized["metric_kind"],
        "dimensions": list(normalized["dimensions"]),
        "row_shape": normalized["row_shape"],
        "rowset_complete": False,
        "contribution_basis": "none",
        "source_limit_applied": bool(report_metadata.get("source_limit_applied", False)),
        "output_limit": limit,
        "output_limit_applied": bool(limit > 0 and len(rows) > limit),
        "mapped_rows": rows,
    }
    input_assertions = normalized.get("input_assertions", {})
    if "complete_scope_total_abs_delta" in input_assertions:
        value = input_assertions["complete_scope_total_abs_delta"]
        payload["complete_scope_total_abs_delta"] = (
            None
            if value is None
            else digest_decimal(value, path="$.complete_scope_total_abs_delta")
        )
    for key in (
        "scope",
        "filters",
        "applied_scope_filters",
        "granularity",
        "comparison_type",
    ):
        if key in report_metadata:
            payload[key] = normalize_digest_value(report_metadata[key], path=f"$.{key}")
    if "current_window" in report_metadata:
        payload["current_window"] = normalize_digest_window(
            report_metadata["current_window"],
            path="$.current_window",
        )
    if "baseline_windows" in normalized:
        payload["baseline_windows"] = [
            normalize_digest_window(window, path=f"$.baseline_windows[{index}]")
            for index, window in enumerate(normalized["baseline_windows"])
        ]
    if "baseline_method" in normalized:
        payload["baseline_method"] = normalized["baseline_method"]
    if "baseline_value_semantic" in normalized:
        payload["baseline_value_semantic"] = normalized["baseline_value_semantic"]
    if "baseline_normalization" in trust_metadata:
        payload["baseline_normalization"] = normalize_digest_value(
            trust_metadata["baseline_normalization"],
            path="$.baseline_normalization",
        )
    for source_key, target_key in (
        ("table_used", "selected_table"),
        ("selected_table", "selected_table"),
        ("selected_columns", "selected_columns"),
        ("metadata_origin", "metadata_origin"),
        ("metadata_fingerprint", "metadata_fingerprint"),
        ("metadata_retrieval_identity", "metadata_retrieval_identity"),
        ("metadata_fixture_identity", "metadata_fixture_identity"),
        ("merge_expressions", "merge_expressions"),
        ("limit_stage", "limit_stage"),
        ("source_limit_stage", "source_limit_stage"),
        ("query_fingerprint", "query_fingerprint"),
        ("template_id", "template_id"),
    ):
        source = report_metadata if source_key == "table_used" else trust_metadata
        if source_key in source and source[source_key] is not None:
            payload[target_key] = normalize_digest_value(
                source[source_key],
                path=f"$.{target_key}",
            )
    return payload

def result_digest_v1(input_doc: Any, *, options: Any = None) -> str:
    normalized = normalize_input_rows(input_doc, options=options)
    return sha256_payload_digest(digest_payload_v1_from_normalized(normalized, options=options))

TRUSTED_EVIDENCE_TYPES = {
    "complete_scope_pre_limit_evidence",
    "zero_fill_evidence",
    "provided_contribution_evidence",
    "complete_rowset_evidence",
    "request_level_coverage_evidence",
    "duplicate_aggregation_evidence",
}

def normalized_contract_for_trust(
    normalized: dict[str, Any],
    digest_payload: dict[str, Any],
) -> dict[str, Any]:
    contract = {
        "metric": normalized["metric"],
        "dimensions": list(normalized["dimensions"]),
        "grouped_dimensions": list(normalized["dimensions"]),
        "scope": digest_payload.get("scope", {}),
        "applied_scope_filters": digest_payload.get("applied_scope_filters"),
        "current_window": digest_payload.get("current_window"),
        "baseline_windows": digest_payload.get("baseline_windows"),
        "baseline_method": digest_payload.get("baseline_method"),
        "baseline_value_semantic": digest_payload.get("baseline_value_semantic"),
        "baseline_normalization": digest_payload.get("baseline_normalization"),
        "selected_table": digest_payload.get("selected_table"),
        "selected_columns": digest_payload.get("selected_columns"),
        "metadata_origin": digest_payload.get("metadata_origin"),
        "metadata_fingerprint": digest_payload.get("metadata_fingerprint"),
        "metadata_retrieval_identity": digest_payload.get("metadata_retrieval_identity"),
        "merge_expressions": digest_payload.get("merge_expressions"),
        "limit_stage": digest_payload.get("limit_stage"),
        "template_id": digest_payload.get("template_id", SQL_TEMPLATE_ID),
        "query_fingerprint": digest_payload.get("query_fingerprint"),
    }
    return {key: value for key, value in contract.items() if value is not None}

REQUIRED_TRUST_CONTRACT_FIELDS = (
    "metric",
    "dimensions",
    "grouped_dimensions",
    "scope",
    "current_window",
    "baseline_windows",
    "baseline_method",
    "baseline_value_semantic",
    "baseline_normalization",
    "selected_table",
    "selected_columns",
    "metadata_origin",
    "metadata_fingerprint",
    "metadata_retrieval_identity",
    "merge_expressions",
    "limit_stage",
    "template_id",
    "query_fingerprint",
)

__all__ = [name for name in globals() if not name.startswith("__")]
