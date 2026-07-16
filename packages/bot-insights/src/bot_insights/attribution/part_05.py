from __future__ import annotations

from ._shared import *
from .part_01 import *
from .part_02 import *
from .part_03 import *
from .part_04 import *

def validate_trusted_context(
    trusted_context: Any,
    normalized: dict[str, Any],
    digest_payload: dict[str, Any],
    recomputed_digest: str,
) -> dict[str, Any]:
    reasons: list[str] = []
    evidence_types: list[str] = []
    if trusted_context is None:
        return {
            "valid": False,
            "trusted": False,
            "result_digest": recomputed_digest,
            "reasons": ["trusted_context_missing"],
            "evidence_types": evidence_types,
        }
    if not isinstance(trusted_context, dict):
        return {
            "valid": False,
            "trusted": False,
            "result_digest": recomputed_digest,
            "reasons": ["trusted_context_invalid", "trusted_wrapper_unavailable"],
            "evidence_types": evidence_types,
        }

    context = trusted_context
    for key in ("query_fingerprint", "result_digest"):
        if not is_sha256_digest(context.get(key)):
            append_once(reasons, f"{key}_missing")
    if is_sha256_digest(context.get("result_digest")) and context["result_digest"] != recomputed_digest:
        append_once(reasons, "trusted_context_digest_mismatch")

    required_text_fields = (
        "generator_name",
        "generator_version",
        "wrapper_name",
        "wrapper_version",
        "template_id",
        "result_origin",
        "metadata_origin",
        "selected_table",
        "metadata_fingerprint",
        "metadata_retrieval_identity",
    )
    for key in required_text_fields:
        if not isinstance(context.get(key), str) or not context.get(key).strip():
            append_once(reasons, "trusted_context_invalid")
    if context.get("trusted_generator_invocation") is not True:
        append_once(reasons, "trusted_context_invalid")
    if context.get("generator_name") != SQL_GENERATOR_NAME:
        append_once(reasons, "trusted_context_invalid")
    if context.get("generator_version") != SQL_GENERATOR_VERSION:
        append_once(reasons, "trusted_context_invalid")
    if context.get("wrapper_name") != TRUSTED_WRAPPER_NAME:
        append_once(reasons, "trusted_context_invalid")
    if context.get("wrapper_version") != TRUSTED_WRAPPER_VERSION:
        append_once(reasons, "trusted_context_invalid")
    if context.get("result_origin") != TRUSTED_RESULT_ORIGIN:
        append_once(reasons, "trusted_context_invalid")
    if context.get("metadata_origin") != TRUSTED_METADATA_ORIGIN:
        append_once(reasons, "trusted_context_invalid")
    expected_template = digest_payload.get("template_id", SQL_TEMPLATE_ID)
    if context.get("template_id") != expected_template:
        append_once(reasons, "trusted_context_invalid")
    if not isinstance(context.get("selected_columns"), list) or not context.get("selected_columns"):
        append_once(reasons, "trusted_context_invalid")
    if not isinstance(context.get("merge_expressions"), dict):
        append_once(reasons, "trusted_context_invalid")

    contract = normalized_contract_for_trust(normalized, digest_payload)
    for key in REQUIRED_TRUST_CONTRACT_FIELDS:
        if key not in contract:
            append_once(reasons, "trusted_context_invalid")
    for key in (
        "selected_table",
        "selected_columns",
        "metadata_origin",
        "metadata_fingerprint",
        "metadata_retrieval_identity",
        "merge_expressions",
        "query_fingerprint",
        "template_id",
    ):
        if key in contract and (key not in context or not values_match(context[key], contract[key])):
            append_once(reasons, "trusted_context_invalid")

    trusted_evidence = context.get("trusted_evidence")
    if not isinstance(trusted_evidence, list):
        append_once(reasons, "trusted_evidence_missing")
        trusted_evidence = []
    elif not trusted_evidence:
        append_once(reasons, "trusted_evidence_missing")

    seen_ids: set[str] = set()
    valid_evidence_count = 0
    for item in trusted_evidence:
        if not isinstance(item, dict):
            append_once(reasons, "trusted_evidence_mismatch")
            continue
        evidence_id = item.get("evidence_id")
        if not isinstance(evidence_id, str) or not evidence_id.strip():
            append_once(reasons, "trusted_evidence_mismatch")
        elif evidence_id in seen_ids:
            append_once(reasons, "trusted_evidence_mismatch")
        else:
            seen_ids.add(evidence_id)
        evidence_type = item.get("evidence_type")
        if evidence_type not in TRUSTED_EVIDENCE_TYPES:
            append_once(reasons, "trusted_evidence_mismatch")
            continue
        evidence_types.append(str(evidence_type))
        common_valid = validate_common_evidence_fields(
            item,
            context=context,
            normalized=normalized,
            contract=contract,
            reasons=reasons,
        )
        specific_valid = validate_specific_evidence_fields(item, normalized=normalized, reasons=reasons)
        if common_valid and specific_valid:
            valid_evidence_count += 1

    context_valid = not any(
        reason
        in {
            "trusted_context_invalid",
            "trusted_context_digest_mismatch",
            "query_fingerprint_missing",
            "result_digest_missing",
        }
        for reason in reasons
    )
    evidence_valid = valid_evidence_count > 0 and not {
        "trusted_evidence_mismatch",
        "provided_contribution_inconsistent",
    }.intersection(reasons)
    if not TRUSTED_WRAPPER_AVAILABLE:
        append_once(reasons, "trusted_wrapper_unavailable")
    if "duplicate_aggregation_evidence" in evidence_types and not TRUSTED_WRAPPER_AVAILABLE:
        append_once(reasons, "duplicate_aggregation_not_trusted")
    return {
        "valid": bool(context_valid and evidence_valid),
        "trusted": bool(context_valid and evidence_valid and TRUSTED_WRAPPER_AVAILABLE),
        "result_digest": recomputed_digest,
        "reasons": reasons,
        "evidence_types": sorted(set(evidence_types)),
    }

def normalize_metric_name(name: str) -> str | None:
    text = str(name).strip()
    if not text:
        return None
    return METRIC_ALIAS_TO_CANONICAL.get(text)

def metric_entry(metric_name: str) -> dict[str, Any]:
    canonical = normalize_metric_name(metric_name)
    if canonical is None:
        raise_invalid(
            "unsupported_metric",
            f"Metric '{metric_name}' is not in the reviewed v1 allowlist.",
            details={"metric": metric_name},
        )
    entry = dict(METRIC_ALLOWLIST[canonical])
    entry["name"] = canonical
    return entry

def metric_aliases(metric_name: str) -> tuple[str, ...]:
    entry = metric_entry(metric_name)
    aliases = [entry["name"], *entry["aliases"]]
    return tuple(dict.fromkeys(alias for alias in aliases if alias))

def current_metric_keys(metric_name: str) -> tuple[str, ...]:
    keys = ["current"]
    for alias in metric_aliases(metric_name):
        keys.extend((f"current_{alias}", f"{alias}_current", f"current.{alias}"))
    return tuple(dict.fromkeys(keys))

def baseline_metric_keys(metric_name: str) -> tuple[str, ...]:
    keys = ["baseline"]
    for alias in metric_aliases(metric_name):
        keys.extend((f"baseline_{alias}", f"{alias}_baseline", f"baseline.{alias}"))
    return tuple(dict.fromkeys(keys))

def period_metric_keys(metric_name: str) -> tuple[str, ...]:
    return tuple(
        alias
        for alias in metric_aliases(metric_name)
        if not alias.startswith(("current_", "baseline_"))
        and not alias.endswith(("_current", "_baseline"))
    )

def sql_identifier(name: str) -> str:
    return "`" + str(name).replace("`", "``") + "`"

def sql_string_literal(value: Any) -> str:
    return "'" + str(value).replace("'", "''") + "'"

def sql_literal(value: Any) -> str:
    if value is None:
        return "NULL"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    return sql_string_literal(value)

def sql_table_name(table_metadata: dict[str, Any]) -> str:
    table = table_metadata.get("table") or table_metadata.get("table_name") or table_metadata.get("name")
    if not isinstance(table, str) or not table.strip():
        raise_invalid(
            "table_metadata_missing_table",
            "Selected table metadata must include a non-blank table name.",
        )
    database = table_metadata.get("database")
    if isinstance(database, str) and database.strip():
        return f"{sql_identifier(database.strip())}.{sql_identifier(table.strip())}"
    return sql_identifier(table.strip())

def table_metadata_table_name(table_metadata: dict[str, Any]) -> str:
    table = table_metadata.get("table") or table_metadata.get("table_name") or table_metadata.get("name")
    if not isinstance(table, str) or not table.strip():
        raise_invalid(
            "table_metadata_missing_table",
            "Selected table metadata must include a non-blank table name.",
        )
    return table.strip()

def column_lookup(table_metadata: dict[str, Any]) -> dict[str, dict[str, Any]]:
    lookup: dict[str, dict[str, Any]] = {}
    for column in table_metadata_columns(table_metadata):
        name = column.get("name")
        if not isinstance(name, str) or not name:
            continue
        lookup[name] = column
        lookup.setdefault(name.lower(), column)
    return lookup

def metric_column_candidates(metric_name: str) -> list[str]:
    candidates: list[str] = []
    for alias in metric_aliases(metric_name):
        candidates.extend(
            (
                alias,
                f"sum({alias})",
                f"sumIf({alias})",
                f"count({alias})",
            )
        )
    if normalize_metric_name(metric_name) == "requests":
        candidates.extend(("count()", "count"))
    return unique_strings(candidates)

def support_column_candidates(metric_name: str) -> list[str]:
    if metric_support_uses_metric_value(metric_entry(metric_name)["metric_kind"]):
        return metric_column_candidates(metric_name)
    return metric_column_candidates("requests")

def find_metadata_column(
    table_metadata: dict[str, Any],
    candidates: Iterable[str],
    *,
    purpose: str,
) -> dict[str, Any]:
    lookup = column_lookup(table_metadata)
    for candidate in candidates:
        column = lookup.get(candidate) or lookup.get(candidate.lower())
        if column is not None:
            return column
    raise_invalid(
        "metadata_column_missing",
        f"Hydrolix metadata does not expose a reviewed {purpose} column.",
        details={"purpose": purpose, "candidates": list(candidates)},
    )

def aggregate_sql_expression(column: dict[str, Any]) -> str:
    name = str(column.get("name", "")).strip()
    if not name:
        raise_invalid("metadata_column_missing", "Hydrolix metadata column name is blank.")
    category = column.get("column_category")
    if category == "AggregateColumn":
        merge_function = column.get("merge_function")
        if not isinstance(merge_function, str) or not merge_function.strip():
            raise_invalid(
                "metadata_merge_function_missing",
                f"Aggregate-state column '{name}' is missing merge_function metadata.",
                details={"column": name},
            )
        return f"{merge_function.strip()}({sql_identifier(name)})"
    if category == "SummaryColumn":
        return sql_identifier(name)
    return f"sum({sql_identifier(name)})"

def merge_expression_map(columns: Iterable[dict[str, Any]]) -> dict[str, str]:
    expressions: dict[str, str] = {}
    for column in columns:
        if column.get("column_category") != "AggregateColumn":
            continue
        name = str(column.get("name", "")).strip()
        if not name:
            continue
        expressions[name] = aggregate_sql_expression(column)
    return expressions

def required_metadata_column(
    table_metadata: dict[str, Any],
    column_name: str,
    *,
    purpose: str,
) -> dict[str, Any]:
    return find_metadata_column(table_metadata, [column_name], purpose=purpose)

def metadata_column_aliases(column_name: str) -> list[str]:
    aliases = FIELD_NAME_ALIASES.get(column_name, (column_name,))
    return unique_strings([column_name, *aliases])

def resolved_metadata_column(
    table_metadata: dict[str, Any],
    column_name: str,
    *,
    purpose: str,
) -> dict[str, Any]:
    return find_metadata_column(table_metadata, metadata_column_aliases(column_name), purpose=purpose)

def resolved_column_name(
    table_metadata: dict[str, Any],
    column_name: str,
    *,
    purpose: str,
) -> str:
    return str(resolved_metadata_column(table_metadata, column_name, purpose=purpose)["name"])

def normalize_window(window: Any, *, path: str) -> dict[str, Any]:
    if not isinstance(window, dict):
        raise_invalid(
            "window_invalid",
            "SQL template windows must be objects with start and end.",
            path=path,
        )
    start = window.get("start")
    end = window.get("end")
    if not isinstance(start, str) or not start.strip() or not isinstance(end, str) or not end.strip():
        raise_invalid(
            "window_invalid",
            "SQL template windows must include non-blank start and end strings.",
            path=path,
        )
    normalized = {"start": start.strip(), "end": end.strip()}
    if "label" in window and window["label"] is not None:
        normalized["label"] = str(window["label"])
    return normalized

def normalize_baseline_windows(windows: Any) -> list[dict[str, Any]]:
    if not isinstance(windows, list) or not windows:
        raise_invalid(
            "baseline_windows_invalid",
            "SQL template rendering requires at least one baseline window.",
            path="$.baseline_windows",
        )
    return [normalize_window(window, path=f"$.baseline_windows[{index}]") for index, window in enumerate(windows)]

def normalized_predicate_value(value: Any) -> Any:
    if isinstance(value, (list, tuple)):
        return sorted(
            (normalize_digest_value(item, path="$.predicate") for item in value),
            key=lambda item: canonical_json_bytes(item).decode("utf-8"),
        )
    return normalize_digest_value(value, path="$.predicate")

__all__ = [name for name in globals() if not name.startswith("__")]
