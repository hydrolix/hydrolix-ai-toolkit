from __future__ import annotations

from typing import Any

from .constants import (
    ADDITIVE_BASELINE_METRICS,
    DERIVED_METRIC_INPUTS,
    PERIOD_ALIASES,
    SEMANTIC_REQUIREMENT_KEYS,
)
from .contribution import _semantic_basis
from .helpers import (
    _canonical_for_key,
    _is_blank,
    _qs_ratio,
    _ratio,
    _row_has_period,
    _value_at_path,
    _window_duration_seconds,
    clean_number,
    pct_delta,
    to_number,
)


def _baseline_duration_seconds(value: dict[str, Any]) -> float | None:
    baseline_windows = value.get("baseline_windows")
    if isinstance(baseline_windows, dict):
        baseline_windows = [baseline_windows]
    if not isinstance(baseline_windows, list) or not baseline_windows:
        return None

    total = 0.0
    for window in baseline_windows:
        duration = _window_duration_seconds(window)
        if duration is not None:
            total += duration
    return total if total > 0 else None


def _baseline_normalization(
    value: dict[str, Any],
    current_window: dict[str, Any],
    rows: list[dict[str, Any]],
) -> dict[str, Any]:
    current_duration = _window_duration_seconds(current_window)
    baseline_duration = _baseline_duration_seconds(value)
    if current_duration is None or baseline_duration is None:
        return {
            "method": "missing_or_current_only",
            "factor": None,
            "applies_to": [],
        }

    factor = current_duration / baseline_duration
    if abs(factor - 1.0) < 0.000001:
        return {
            "method": "none_equal_duration_windows",
            "factor": 1.0,
            "applies_to": [],
        }

    affected = sorted(_baseline_additive_metrics(rows))
    return {
        "method": "duration_normalized_additive_metrics",
        "factor": clean_number(factor),
        "applies_to": affected,
    }


def _baseline_additive_metrics(rows: list[dict[str, Any]]) -> set[str]:
    affected: set[str] = set()
    for row in rows:
        row_period = PERIOD_ALIASES.get(str(row.get("period", "")).lower())
        for key in row:
            canonical = _canonical_for_key(key)
            if canonical is None:
                continue
            period, canonical_name = canonical
            if canonical_name not in ADDITIVE_BASELINE_METRICS:
                continue
            if period == "baseline" or (period == "row" and row_period == "baseline"):
                affected.add(canonical_name)
    return affected


def _entity_from_row(
    row: dict[str, Any],
    dimensions: list[str],
    scope: dict[str, Any],
) -> dict[str, Any]:
    entity: dict[str, Any] = {}
    scoped_host = scope.get("request_host")
    if _is_blank(scoped_host) and not _is_blank(row.get("request_host")):
        entity["request_host"] = row["request_host"]

    for dimension in dimensions:
        if dimension == "request_host" and not _is_blank(scoped_host):
            continue
        value = row.get(dimension)
        if not _is_blank(value):
            entity[dimension] = value
    return entity


def _entity_key(entity: dict[str, Any], dimensions: list[str]) -> tuple[Any, ...]:
    key_dimensions = list(dimensions)
    if "request_host" in entity and "request_host" not in key_dimensions:
        key_dimensions = ["request_host", *key_dimensions]
    return tuple(entity.get(dimension) for dimension in key_dimensions)


def _collect_metrics(
    row: dict[str, Any],
    *,
    period_override: str | None = None,
) -> dict[str, dict[str, float]]:
    periods: dict[str, dict[str, float]] = {"current": {}, "baseline": {}}
    for key, value in row.items():
        canonical = _canonical_for_key(key)
        if canonical is None:
            continue
        period, canonical_name = canonical
        normalized_period = period_override or PERIOD_ALIASES.get(period)
        if normalized_period is None and period == "row":
            normalized_period = "current"
        if normalized_period not in periods:
            continue
        number = to_number(value)
        if number is not None:
            periods[normalized_period][canonical_name] = number
    return periods


def _metric_rows(
    rows: list[dict[str, Any]],
    dimensions: list[str],
    scope: dict[str, Any],
) -> list[dict[str, Any]]:
    if not any(_row_has_period(row) for row in rows):
        return [
            {
                "entity": _entity_from_row(row, dimensions, scope),
                "source_row": row,
                **_collect_metrics(row),
            }
            for row in rows
        ]

    grouped: dict[tuple[Any, ...], dict[str, Any]] = {}
    order: list[tuple[Any, ...]] = []
    for row in rows:
        row_period = PERIOD_ALIASES.get(str(row.get("period", "")).lower())
        if row_period is None:
            continue
        entity = _entity_from_row(row, dimensions, scope)
        key = _entity_key(entity, dimensions)
        if key not in grouped:
            grouped[key] = {
                "entity": entity,
                "source_row": {},
                "current": {},
                "baseline": {},
            }
            order.append(key)
        if row_period == "current":
            grouped[key]["source_row"] = row
        elif not grouped[key]["source_row"]:
            grouped[key]["source_row"] = row
        collected = _collect_metrics(row, period_override=row_period)
        grouped[key][row_period].update(collected[row_period])
    return [grouped[key] for key in order]


def _origin_pressure(metrics: dict[str, float]) -> float | None:
    cache_misses = metrics.get("cache_misses")
    origin_p95_ms = metrics.get("origin_p95_ms")
    if cache_misses is None or origin_p95_ms is None:
        return None
    return cache_misses * max(origin_p95_ms, 1.0) / 1000.0


def _derive_period_metrics(
    metrics: dict[str, float],
    metric_semantics: dict[str, Any],
) -> tuple[dict[str, float], list[str]]:
    derived = dict(metrics)
    reasons: list[str] = []

    miss_rate = _ratio(derived.get("cache_misses"), derived.get("requests"), 100.0)
    if miss_rate is not None:
        derived["miss_rate_pct"] = miss_rate

    if "unique_query_strings" in derived:
        unique_semantics = _semantic_basis(
            metric_semantics,
            *SEMANTIC_REQUIREMENT_KEYS["unique_query_strings"],
        )
        exact_period_unique = unique_semantics == "exact_period_unique"
        qs_ratio = _qs_ratio(derived, exact_period_unique=exact_period_unique)
        if qs_ratio is not None:
            derived["qs_diversity_ratio"] = qs_ratio
        if exact_period_unique:
            reasons.append("query_string_cardinality_exact")
        else:
            reasons.append("query_string_cardinality_approximate")

    if "origin_p95_ms" in derived or "origin_p99_ms" in derived:
        latency_semantics = _semantic_basis(
            metric_semantics,
            *SEMANTIC_REQUIREMENT_KEYS["origin_p95_ms"],
            *SEMANTIC_REQUIREMENT_KEYS["origin_p99_ms"],
        )
        latency_semantics_text = str(latency_semantics or "").lower()
        if latency_semantics_text in {
            "metadata_merged_quantile",
            "merged_quantile",
            "exact_merge",
            "merge_exact",
        }:
            reasons.append("origin_latency_merge_exact")
        elif "worst" in latency_semantics_text or "bucket" in latency_semantics_text:
            reasons.append("origin_latency_worst_bucket")

    origin_pressure = _origin_pressure(derived)
    if origin_pressure is not None:
        derived["origin_pressure_score"] = origin_pressure

    return derived, reasons


def _normalize_baseline_metrics(
    metrics: dict[str, float],
    normalization: dict[str, Any],
) -> dict[str, float]:
    normalized = dict(metrics)
    if normalization.get("method") != "duration_normalized_additive_metrics":
        return normalized
    factor = to_number(normalization.get("factor"))
    if factor is None:
        return normalized
    for metric in ADDITIVE_BASELINE_METRICS:
        if metric in normalized:
            normalized[metric] *= factor
    return normalized


def _delta_metrics(
    current: dict[str, float],
    baseline: dict[str, float],
) -> dict[str, float]:
    deltas: dict[str, float] = {}
    delta_pairs = {
        "requests": ("requests", "requests"),
        "cache_misses": ("cache_misses", "cache_misses"),
        "miss_rate_delta_pp": ("miss_rate_pct", "miss_rate_pct"),
        "qs_diversity_delta": ("qs_diversity_ratio", "qs_diversity_ratio"),
        "origin_p95_delta_ms": ("origin_p95_ms", "origin_p95_ms"),
        "origin_p99_delta_ms": ("origin_p99_ms", "origin_p99_ms"),
        "origin_pressure_delta": (
            "origin_pressure_score",
            "origin_pressure_score",
        ),
    }
    for output_name, (current_name, baseline_name) in delta_pairs.items():
        current_value = current.get(current_name)
        baseline_value = baseline.get(baseline_name)
        if current_value is not None and baseline_value is not None:
            deltas[output_name] = current_value - baseline_value

    cache_misses = current.get("cache_misses")
    baseline_cache_misses = baseline.get("cache_misses")
    if cache_misses is not None and baseline_cache_misses is not None:
        deltas["cache_miss_pct_change"] = pct_delta(cache_misses, baseline_cache_misses)

    origin_p95 = current.get("origin_p95_ms")
    baseline_origin_p95 = baseline.get("origin_p95_ms")
    if origin_p95 is not None and baseline_origin_p95 is not None:
        deltas["origin_p95_pct_change"] = pct_delta(origin_p95, baseline_origin_p95)
    return deltas


def _missing_inputs(
    current: dict[str, float],
    baseline: dict[str, float],
    inputs: tuple[str, ...],
    *,
    default_scope: str,
) -> list[str]:
    missing: list[str] = []
    for input_name in inputs:
        if "." in input_name:
            if _value_at_path(current, baseline, input_name) is None:
                missing.append(input_name)
        elif default_scope == "baseline":
            if input_name not in baseline:
                missing.append(f"baseline.{input_name}")
        elif input_name not in current:
            missing.append(f"current.{input_name}")
    return missing


def _not_evaluated_entries(
    entity: dict[str, Any],
    current: dict[str, float],
    baseline: dict[str, float],
    deltas: dict[str, float],
) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    available = {
        "current_miss_rate_pct": current.get("miss_rate_pct"),
        "baseline_miss_rate_pct": baseline.get("miss_rate_pct"),
        "current_qs_diversity_ratio": current.get("qs_diversity_ratio"),
        "baseline_qs_diversity_ratio": baseline.get("qs_diversity_ratio"),
        "current_origin_pressure_score": current.get("origin_pressure_score"),
        "baseline_origin_pressure_score": baseline.get("origin_pressure_score"),
        "request_delta": deltas.get("requests"),
        "cache_miss_delta": deltas.get("cache_misses"),
        "miss_rate_delta_pp": deltas.get("miss_rate_delta_pp"),
        "qs_diversity_delta": deltas.get("qs_diversity_delta"),
        "origin_p95_delta_ms": deltas.get("origin_p95_delta_ms"),
        "origin_p99_delta_ms": deltas.get("origin_p99_delta_ms"),
        "cache_miss_pct_change": deltas.get("cache_miss_pct_change"),
        "origin_p95_pct_change": deltas.get("origin_p95_pct_change"),
        "origin_pressure_delta": deltas.get("origin_pressure_delta"),
    }
    for name, (default_scope, inputs) in DERIVED_METRIC_INPUTS.items():
        if available.get(name) is not None:
            continue
        missing_inputs = _missing_inputs(
            current,
            baseline,
            inputs,
            default_scope=default_scope,
        )
        entries.append(
            {
                "entity": entity,
                "name": name,
                "reason": "missing_optional_metric_input"
                if missing_inputs
                else "not_computable_from_supplied_inputs",
                "missing_inputs": missing_inputs,
            }
        )
    return entries
