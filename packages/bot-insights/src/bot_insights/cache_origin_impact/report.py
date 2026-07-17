from __future__ import annotations

from typing import Any

from .confidence import (
    _candidate_count_confidence_reasons,
    _candidate_limitations,
    _confidence_label,
    _lowest_confidence,
    _response_bytes_optional_metadata,
    _summary_context_metadata,
    _table_confidence_reasons,
    _trusted_context_complete,
)
from .constants import ANALYSIS_TYPE, INTERPRETATION_CONSTRAINTS, REPORT_SCHEMA
from .contribution import _derive_share_and_contribution_metrics
from .features import (
    _candidate_sort_key,
    _detector_not_evaluated_entries,
    _finding_types,
    _score_features,
)
from .helpers import _clean_metric_map, _require_mapping
from .metrics import (
    _baseline_normalization,
    _delta_metrics,
    _derive_period_metrics,
    _metric_rows,
    _normalize_baseline_metrics,
    _not_evaluated_entries,
)
from .validation import (
    _validate_current_window,
    _validate_dimensions,
    _validate_metric_or_analysis_type,
    _validate_metric_semantics,
    _validate_rows,
    _validated_rows,
)


def _derive_candidates(
    rows: list[dict[str, Any]],
    dimensions: list[str],
    scope: dict[str, Any],
    metric_semantics: dict[str, Any],
    normalization: dict[str, Any],
    data: dict[str, Any],
    *,
    trusted_context_complete: bool,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    candidates: list[dict[str, Any]] = []
    not_evaluated: list[dict[str, Any]] = []
    confidence_reasons: list[str] = []
    base_confidence_reasons = _table_confidence_reasons(
        data,
        dimensions,
        normalization,
    )
    if trusted_context_complete:
        base_confidence_reasons.append("direct_mcp_trusted_context")
    summary_context_metadata = _summary_context_metadata(data)

    metric_rows = _metric_rows(rows, dimensions, scope)

    derived_rows: list[dict[str, Any]] = []
    for metric_row in metric_rows:
        current, current_reasons = _derive_period_metrics(
            metric_row["current"],
            metric_semantics,
        )
        normalized_baseline = _normalize_baseline_metrics(
            metric_row["baseline"],
            normalization,
        )
        baseline, baseline_reasons = _derive_period_metrics(
            normalized_baseline,
            metric_semantics,
        )
        deltas = _delta_metrics(current, baseline)
        derived_rows.append(
            {
                "metric_row": metric_row,
                "current": current,
                "current_reasons": current_reasons,
                "baseline": baseline,
                "baseline_reasons": baseline_reasons,
                "deltas": deltas,
            }
        )

    contribution_totals: dict[str, float] = {}
    if data.get("rowset_complete") is True:
        cache_miss_values = [
            row["current"].get("cache_misses")
            for row in derived_rows
            if row["current"].get("cache_misses") is not None
        ]
        origin_pressure_values = [
            row["current"].get("origin_pressure_score")
            for row in derived_rows
            if row["current"].get("origin_pressure_score") is not None
        ]
        if cache_miss_values:
            contribution_totals["cache_misses"] = sum(cache_miss_values)
        if origin_pressure_values:
            contribution_totals["origin_pressure_score"] = sum(origin_pressure_values)

    for derived_row in derived_rows:
        metric_row = derived_row["metric_row"]
        source_row = metric_row.get("source_row", {})
        entity = metric_row["entity"]
        current = derived_row["current"]
        current_reasons = derived_row["current_reasons"]
        baseline = derived_row["baseline"]
        baseline_reasons = derived_row["baseline_reasons"]
        deltas = derived_row["deltas"]
        share_denominators, share_not_evaluated, share_confidence_reasons = (
            _derive_share_and_contribution_metrics(
                source_row,
                current,
                deltas,
                data=data,
                metric_semantics=metric_semantics,
                scope=scope,
                entity=entity,
                contribution_totals=contribution_totals,
            )
        )
        candidate_not_evaluated = _not_evaluated_entries(
            entity,
            current,
            baseline,
            deltas,
        )
        candidate_not_evaluated.extend(share_not_evaluated)
        candidate_not_evaluated.extend(
            _detector_not_evaluated_entries(entity, current, baseline, deltas)
        )
        features, score, band = _score_features(current, deltas)
        optional_metadata: dict[str, Any] = {
            "response_bytes": _response_bytes_optional_metadata(current, baseline),
        }
        if summary_context_metadata is not None:
            optional_metadata["summary_context"] = summary_context_metadata
        candidate_reasons = sorted(
            set(
                base_confidence_reasons
                + current_reasons
                + baseline_reasons
                + share_confidence_reasons
                + _candidate_count_confidence_reasons(current, baseline)
            )
        )
        limitations = _candidate_limitations(
            candidate_reasons,
            candidate_not_evaluated,
            optional_metadata,
            data,
        )
        confidence = _confidence_label(
            candidate_reasons,
            limitations,
            trusted_context_complete=trusted_context_complete,
        )

        candidate: dict[str, Any] = {
            "entity": entity,
            "current": _clean_metric_map(current),
            "baseline": _clean_metric_map(baseline),
            "deltas": _clean_metric_map(deltas),
            "candidate_score": score,
            "candidate_band": band,
            "features": features,
            "finding_types": _finding_types(current),
            "not_evaluated": candidate_not_evaluated,
            "confidence": confidence,
            "confidence_reasons": candidate_reasons,
            "limitations": limitations,
            "optional_metadata": optional_metadata,
        }
        if share_denominators:
            candidate["share_denominators"] = share_denominators
        confidence_reasons.extend(candidate_reasons)
        candidates.append(candidate)
        not_evaluated.extend(candidate_not_evaluated)

    candidates.sort(key=_candidate_sort_key)
    for rank, candidate in enumerate(candidates, start=1):
        candidate["rank"] = rank

    return candidates, not_evaluated, sorted(set(confidence_reasons))


def build_report(
    value: Any,
    trusted_context: dict[str, Any] | None = None,
    *,
    limit: int | None = None,
) -> dict[str, Any]:
    data = _require_mapping(value)
    _validate_metric_or_analysis_type(data)
    dimensions = _validate_dimensions(data)
    rows = _validated_rows(data)
    current_window = _validate_current_window(data)
    scope = _validate_rows(data, dimensions, rows)
    metric_semantics = _validate_metric_semantics(data, rows)

    if limit is not None and limit < 0:
        raise ValueError("limit must be non-negative.")
    baseline_normalization = _baseline_normalization(
        data,
        current_window,
        rows,
    )
    trusted_context_is_complete = _trusted_context_complete(trusted_context, dimensions)
    candidates, not_evaluated, _derivation_confidence_reasons = _derive_candidates(
        rows,
        dimensions,
        scope,
        metric_semantics,
        baseline_normalization,
        data,
        trusted_context_complete=trusted_context_is_complete,
    )
    if limit is not None:
        candidates = candidates[:limit]
        for rank, candidate in enumerate(candidates, start=1):
            candidate["rank"] = rank
        emitted_entities = {tuple(sorted(candidate["entity"].items())) for candidate in candidates}
        not_evaluated = [
            entry
            for entry in not_evaluated
            if tuple(sorted(entry.get("entity", {}).items())) in emitted_entities
        ]

    confidence_reasons = sorted(
        {
            reason
            for candidate in candidates
            for reason in candidate.get("confidence_reasons", [])
        }
    )
    limitations = sorted(
        {
            limitation
            for candidate in candidates
            for limitation in candidate.get("limitations", [])
        }
    )
    optional_metadata: dict[str, Any] = {}
    summary_context_metadata = _summary_context_metadata(data)
    if summary_context_metadata is not None:
        optional_metadata["summary_context"] = summary_context_metadata

    report_metric_semantics = {
        "origin_pressure_score": "proxy_misses_times_origin_p95_seconds",
        **metric_semantics,
    }
    report: dict[str, Any] = {
        "schema_version": REPORT_SCHEMA,
        "analysis_type": ANALYSIS_TYPE,
        "source_skill": data.get("source_skill", "bot-insights"),
        "comparison_type": data.get(
            "comparison_type",
            "current_only" if not data.get("baseline_windows") else "unspecified",
        ),
        "granularity": data.get("granularity"),
        "table_used": data.get("table_used"),
        "summary_table_used": data.get("summary_table_used"),
        "scope": scope,
        "dimensions": dimensions,
        "current_window": current_window,
        "baseline_windows": data.get("baseline_windows", []),
        "baseline_normalization": baseline_normalization,
        "metric_semantics": report_metric_semantics,
        "candidates": candidates,
        "not_evaluated": not_evaluated,
        "interpretation_constraints": INTERPRETATION_CONSTRAINTS,
        "confidence": _lowest_confidence(
            [candidate.get("confidence", "medium") for candidate in candidates]
        ),
        "confidence_reasons": sorted(set(confidence_reasons)),
        "limitations": limitations,
    }
    if optional_metadata:
        report["optional_metadata"] = optional_metadata
    return report
