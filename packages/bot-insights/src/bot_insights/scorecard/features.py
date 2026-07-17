from __future__ import annotations

from typing import Any

from .constants import DOMAINS, METADATA_KEYS, PROVENANCE_KEYS, SUPPORTED_ENTITY_TYPES
from .numeric import clean_number, json_safe
from .rows import (
    baseline_number,
    current_number,
    entity_value,
    infer_entity_type,
    merge_period_metadata,
    result_rows,
)


def combine_period_rows(
    rows: list[dict[str, Any]], entity_type: str
) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    saw_period = False
    saw_non_period = False

    for row in rows:
        period = str(row.get("period", "")).lower()
        if period not in {"current", "baseline", "after", "before"}:
            saw_non_period = True
            continue
        saw_period = True
        normalized_period = (
            "current"
            if period == "after"
            else "baseline"
            if period == "before"
            else period
        )
        row_entity_type = infer_entity_type(
            row, entity_type if entity_type != "value" else None
        )
        entity = entity_value(row, row_entity_type)
        key = (row_entity_type, entity)
        combined = grouped.setdefault(key, {row_entity_type: entity})
        for field, value in row.items():
            if field in METADATA_KEYS or field in SUPPORTED_ENTITY_TYPES:
                continue
            if field in PROVENANCE_KEYS:
                merge_period_metadata(
                    combined,
                    field,
                    value,
                    entity_type=row_entity_type,
                    entity=entity,
                )
                continue
            combined[f"{normalized_period}_{field}"] = value

    if not saw_period:
        return rows
    if saw_non_period:
        raise ValueError(
            "Input rows must not mix period-split rows with already-combined "
            "entity rows. Normalize or join rows before running scorecard.py."
        )
    return list(grouped.values())


def metadata_from(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    metadata = dict(
        value.get("confidence_context", {})
        if isinstance(value.get("confidence_context"), dict)
        else {}
    )
    for key in (
        "scope",
        "comparison_type",
        "granularity",
        "table_used",
        "current_window",
        "baseline_windows",
        "summary_table_used",
        "source_coverage_caveat",
        "source_caveats",
        "rowset_complete",
        "contribution_basis",
        "rowset_scope",
        "feature_provenance",
        "analysis_domains",
    ):
        if key in value:
            metadata[key] = value[key]
    return json_safe(metadata)


def normalize_analysis_domains(value: Any) -> tuple[str, ...]:
    if value is None or value == "":
        return tuple(DOMAINS)
    if isinstance(value, str):
        candidates = [item.strip() for item in value.split(",")]
    elif isinstance(value, list):
        candidates = [str(item).strip() for item in value]
    elif isinstance(value, tuple):
        candidates = [str(item).strip() for item in value]
    else:
        raise ValueError("analysis_domains must be a list or comma-separated string.")

    domains = tuple(dict.fromkeys(item for item in candidates if item))
    invalid = [domain for domain in domains if domain not in DOMAINS]
    if invalid:
        raise ValueError(
            "analysis_domains contains unsupported domains: "
            + ", ".join(invalid)
            + ". Supported domains: "
            + ", ".join(DOMAINS)
        )
    return domains or tuple(DOMAINS)


def prepared_rows(
    value: Any, entity_type: str | None = None
) -> tuple[list[dict[str, Any]], str]:
    rows = result_rows(value)
    if not rows and isinstance(value, dict):
        rows = [value]

    requested = entity_type
    if requested is None and isinstance(value, dict):
        candidate = value.get("entity_type") or value.get("dimension")
        if str(candidate) in SUPPORTED_ENTITY_TYPES:
            requested = str(candidate)

    inferred = requested or (infer_entity_type(rows[0]) if rows else "value")
    rows = combine_period_rows(rows, inferred)
    if rows and inferred == "value":
        inferred = infer_entity_type(rows[0])
    return rows, inferred


def metric_values(
    row: dict[str, Any], metric: tuple[str, ...]
) -> tuple[float | None, float | None]:
    return current_number(row, *metric), baseline_number(row, *metric)


def make_feature(
    name: str,
    domain: str,
    points: int,
    evidence: str,
    *,
    current: float | None = None,
    baseline: float | None = None,
    threshold: float | None = None,
    supporting_metrics: dict[str, Any] | None = None,
) -> dict[str, Any]:
    feature: dict[str, Any] = {
        "name": name,
        "domain": domain,
        "points": points,
        "evidence": evidence,
    }
    if current is not None:
        feature["current"] = clean_number(current)
    if baseline is not None:
        feature["baseline"] = clean_number(baseline)
    if threshold is not None:
        feature["threshold"] = clean_number(threshold)
    if supporting_metrics:
        feature["supporting_metrics"] = supporting_metrics
    return feature


def evaluated_zero_feature(
    name: str,
    domain: str,
    *,
    current: float | None = None,
    baseline: float | None = None,
    threshold: float | None = None,
    supporting_metrics: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return make_feature(
        name,
        domain,
        0,
        "Rule evaluated below threshold.",
        current=current,
        baseline=baseline,
        threshold=threshold,
        supporting_metrics=supporting_metrics,
    )


def missing_feature(
    name: str, domain: str, missing_inputs: list[str]
) -> dict[str, Any]:
    return {
        "name": name,
        "domain": domain,
        "missing_inputs": sorted(set(missing_inputs)),
        "reason": "feature_input_missing",
    }
