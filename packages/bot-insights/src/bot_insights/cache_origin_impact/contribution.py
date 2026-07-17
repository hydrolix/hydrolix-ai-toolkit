from __future__ import annotations

from typing import Any

from .constants import COMPLETE_SCOPE_BASIS_VALUES, SOURCE_LIMITED_BASIS_VALUES
from .helpers import _is_blank, _pct_from_parts, _row_number, clean_number


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


def _derive_origin_pressure_share(
    row: dict[str, Any],
    current: dict[str, float],
    share_denominators: dict[str, Any],
) -> None:
    total_path_pressure = _row_number(row, "current_total_origin_pressure_for_path")
    selected_path_pressure = _row_number(
        row, "current_selected_bot_class_origin_pressure_for_path"
    )
    _store_denominator(
        share_denominators, "current_total_origin_pressure_for_path", total_path_pressure
    )
    _store_denominator(
        share_denominators,
        "current_selected_bot_class_origin_pressure_for_path",
        selected_path_pressure,
    )
    bot_pressure_share = _row_number(
        row, "bot_origin_pressure_share_pct", "current_bot_origin_pressure_share_pct"
    )
    if bot_pressure_share is None:
        bot_pressure_share = _pct_from_parts(selected_path_pressure, total_path_pressure)
    if bot_pressure_share is not None:
        current["bot_origin_pressure_share_pct"] = bot_pressure_share
        if total_path_pressure is not None or selected_path_pressure is not None:
            share_denominators[
                "bot_origin_pressure_share_basis"
            ] = "selected_bot_classes_over_path_all_bot_classes_and_asn_types"


def _store_denominator(
    share_denominators: dict[str, Any], key: str, value: float | None
) -> None:
    if value is not None:
        share_denominators[key] = clean_number(value)


def _derive_contribution_metrics(
    row: dict[str, Any],
    current: dict[str, float],
    deltas: dict[str, float],
    *,
    data: dict[str, Any],
    metric_semantics: dict[str, Any],
    entity: dict[str, Any],
    contribution_totals: dict[str, float],
    contribution_basis: str | None,
    complete_contribution: bool,
    share_denominators: dict[str, Any],
    not_evaluated: list[dict[str, Any]],
    confidence_reasons: list[str],
) -> None:
    if contribution_basis is not None:
        share_denominators["cache_miss_contribution_basis"] = contribution_basis
        share_denominators["origin_pressure_contribution_basis"] = contribution_basis
    if complete_contribution:
        _derive_complete_contributions(
            row, current, deltas, data, contribution_totals, share_denominators
        )
        confidence_reasons.append("complete_scope_contribution")
    elif _contribution_withheld(row, data, metric_semantics):
        _append_withheld_contributions(not_evaluated, entity)
        confidence_reasons.append("contribution_withheld_source_limited")
    elif contribution_basis in SOURCE_LIMITED_BASIS_VALUES:
        confidence_reasons.append("contribution_withheld_source_limited")


def _derive_complete_contributions(
    row: dict[str, Any],
    current: dict[str, float],
    deltas: dict[str, float],
    data: dict[str, Any],
    contribution_totals: dict[str, float],
    share_denominators: dict[str, Any],
) -> None:
    total_misses = _contribution_denominator(
        row,
        data,
        contribution_totals,
        "current_total_cache_misses_for_contribution",
        "cache_misses",
    )
    _store_denominator(
        share_denominators, "current_total_cache_misses_for_contribution", total_misses
    )
    cache_miss_contribution = _row_number(
        row, "cache_miss_contribution_pct", "current_cache_miss_contribution_pct"
    )
    if cache_miss_contribution is None:
        cache_miss_contribution = _pct_from_parts(current.get("cache_misses"), total_misses)
    if cache_miss_contribution is not None:
        deltas["cache_miss_contribution_pct"] = cache_miss_contribution

    total_pressure = _contribution_denominator(
        row,
        data,
        contribution_totals,
        "current_total_origin_pressure_score",
        "origin_pressure_score",
        "current_total_origin_pressure_for_contribution",
    )
    _store_denominator(
        share_denominators, "current_total_origin_pressure_score", total_pressure
    )
    origin_pressure_contribution = _row_number(
        row, "origin_pressure_contribution_pct", "current_origin_pressure_contribution_pct"
    )
    if origin_pressure_contribution is None:
        origin_pressure_contribution = _pct_from_parts(
            current.get("origin_pressure_score"), total_pressure
        )
    if origin_pressure_contribution is not None:
        deltas["origin_pressure_contribution_pct"] = origin_pressure_contribution


def _contribution_denominator(
    row: dict[str, Any],
    data: dict[str, Any],
    contribution_totals: dict[str, float],
    key: str,
    total_key: str,
    *alternate_keys: str,
) -> float | None:
    value = _row_number(row, key, *alternate_keys)
    if value is None and data.get("rowset_complete") is True:
        return contribution_totals.get(total_key)
    return value


def _append_withheld_contributions(
    not_evaluated: list[dict[str, Any]], entity: dict[str, Any]
) -> None:
    for name in ("cache_miss_contribution_pct", "origin_pressure_contribution_pct"):
        not_evaluated.append(
            {
                "entity": entity,
                "name": name,
                "reason": "contribution_withheld_source_limited",
            }
        )
