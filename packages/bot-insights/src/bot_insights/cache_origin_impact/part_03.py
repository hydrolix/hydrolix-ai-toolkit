from __future__ import annotations

from ._shared import *
from .part_01 import *
from .part_02 import *

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

def _ratio(numerator: float | None, denominator: float | None, multiplier: float = 1.0) -> float | None:
    if numerator is None or denominator is None or denominator <= 0:
        return None
    return numerator / denominator * multiplier

def _qs_ratio(
    metrics: dict[str, float],
    *,
    exact_period_unique: bool,
) -> float | None:
    ratio = _ratio(metrics.get("unique_query_strings"), metrics.get("requests"))
    if ratio is None:
        return None
    if exact_period_unique:
        return min(max(ratio, 0.0), 1.0)
    return ratio

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

def _value_at_path(
    current: dict[str, float],
    baseline: dict[str, float],
    path: str,
) -> float | None:
    container_name, metric = path.split(".", 1)
    container = current if container_name == "current" else baseline
    return container.get(metric)

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

def _clean_metric_map(metrics: dict[str, float]) -> dict[str, float | int]:
    return {
        key: clean_number(value)
        for key, value in metrics.items()
        if value is not None
    }

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

def _row_number(row: dict[str, Any], *keys: str) -> float | None:
    for key in keys:
        number = to_number(row.get(key))
        if number is not None:
            return number
    return None

def _pct_from_parts(numerator: float | None, denominator: float | None) -> float | None:
    return _ratio(numerator, denominator, 100.0)

def _semantic_basis(metric_semantics: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in metric_semantics:
            return metric_semantics[key]
    return None

def _contribution_basis(
    data: dict[str, Any],
    metric_semantics: dict[str, Any],
) -> str | None:
    basis = data.get("contribution_basis")
    if basis is None:
        basis = _semantic_basis(
            metric_semantics,
            "contribution_fields",
            "cache_miss_contribution_pct",
            "origin_pressure_contribution_pct",
        )
    return str(basis) if basis is not None else None

def _complete_scope_contribution_available(
    data: dict[str, Any],
    metric_semantics: dict[str, Any],
) -> bool:
    basis = _contribution_basis(data, metric_semantics)
    if basis in COMPLETE_SCOPE_BASIS_VALUES:
        return True
    if basis in SOURCE_LIMITED_BASIS_VALUES:
        return False
    return data.get("rowset_complete") is True

def _contribution_withheld(
    row: dict[str, Any],
    data: dict[str, Any],
    metric_semantics: dict[str, Any],
) -> bool:
    if _complete_scope_contribution_available(data, metric_semantics):
        return False
    contribution_keys = (
        "cache_miss_contribution_pct",
        "current_cache_miss_contribution_pct",
        "origin_pressure_contribution_pct",
        "current_origin_pressure_contribution_pct",
        "current_total_cache_misses_for_contribution",
        "current_total_origin_pressure_score",
        "current_total_origin_pressure_for_contribution",
    )
    return any(_row_number(row, key) is not None for key in contribution_keys)

def _selected_bot_classes(scope: dict[str, Any], entity: dict[str, Any]) -> list[str]:
    selected = scope.get("selected_bot_classes")
    if isinstance(selected, list):
        return [str(value) for value in selected if not _is_blank(value)]
    if not _is_blank(entity.get("bot_class")):
        return [str(entity["bot_class"])]
    return []

def _derive_share_and_contribution_metrics(
    row: dict[str, Any],
    current: dict[str, float],
    deltas: dict[str, float],
    *,
    data: dict[str, Any],
    metric_semantics: dict[str, Any],
    scope: dict[str, Any],
    entity: dict[str, Any],
    contribution_totals: dict[str, float],
) -> tuple[dict[str, Any], list[dict[str, Any]], list[str]]:
    share_denominators: dict[str, Any] = {}
    not_evaluated: list[dict[str, Any]] = []
    confidence_reasons: list[str] = []
    complete_contribution = _complete_scope_contribution_available(
        data,
        metric_semantics,
    )
    _derive_bot_share_metrics(row, current, share_denominators, scope, entity)

    contribution_basis = _contribution_basis(data, metric_semantics)
    if contribution_basis is None and data.get("rowset_complete") is True:
        contribution_basis = "rowset_complete"
    _derive_contribution_metrics(
        row,
        current,
        deltas,
        data=data,
        metric_semantics=metric_semantics,
        entity=entity,
        contribution_totals=contribution_totals,
        contribution_basis=contribution_basis,
        complete_contribution=complete_contribution,
        share_denominators=share_denominators,
        not_evaluated=not_evaluated,
        confidence_reasons=confidence_reasons,
    )

    return share_denominators, not_evaluated, confidence_reasons

def _derive_bot_share_metrics(
    row: dict[str, Any],
    current: dict[str, float],
    share_denominators: dict[str, Any],
    scope: dict[str, Any],
    entity: dict[str, Any],
) -> None:
    selected_bot_classes = _selected_bot_classes(scope, entity)
    if selected_bot_classes:
        share_denominators["selected_bot_classes"] = selected_bot_classes
    _derive_cache_miss_share(row, current, share_denominators)
    _derive_origin_pressure_share(row, current, share_denominators)

def _derive_cache_miss_share(
    row: dict[str, Any],
    current: dict[str, float],
    share_denominators: dict[str, Any],
) -> None:
    total_share_misses = _row_number(row, "current_total_cache_misses_for_share")
    selected_share_misses = _row_number(
        row, "current_selected_bot_class_cache_misses_for_share"
    )
    _store_denominator(
        share_denominators, "current_total_cache_misses_for_share", total_share_misses
    )
    _store_denominator(
        share_denominators,
        "current_selected_bot_class_cache_misses_for_share",
        selected_share_misses,
    )
    bot_miss_share = _row_number(row, "bot_miss_share_pct", "current_bot_miss_share_pct")
    if bot_miss_share is None:
        bot_miss_share = _pct_from_parts(selected_share_misses, total_share_misses)
    if bot_miss_share is not None:
        current["bot_miss_share_pct"] = bot_miss_share
        if total_share_misses is not None or selected_share_misses is not None:
            share_denominators[
                "bot_miss_share_basis"
            ] = "selected_bot_classes_over_path_all_bot_classes_and_asn_types"

__all__ = [name for name in globals() if not name.startswith("__")]
