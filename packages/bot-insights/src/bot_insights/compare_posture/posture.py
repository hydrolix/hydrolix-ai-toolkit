from __future__ import annotations

from typing import Any

from .constants import (
    ABSOLUTE_DELTA_DENOMINATOR_BASES,
    METADATA_KEYS,
    MOVER_CONSTRAINTS,
    MOVER_SCHEMA,
    POSTURE_CONSTRAINTS,
    POSTURE_SCHEMA,
)
from .helpers import (
    clean_number,
    confidence,
    direction,
    json_safe,
    json_safe_metadata_value,
    metadata_text,
    pct_delta,
    support_counts,
    to_number,
)
from .rows import result_rows, rows_to_periods


def metric_specs(value: dict[str, Any], current: dict[str, Any], baseline: dict[str, Any]) -> list[dict[str, Any]]:
    raw_specs = value.get("metrics")
    if isinstance(raw_specs, list) and raw_specs:
        specs: list[dict[str, Any]] = []
        for item in raw_specs:
            if isinstance(item, str):
                specs.append({"name": item})
            elif isinstance(item, dict) and "name" in item:
                specs.append(item)
        return specs

    names = sorted((set(current) & set(baseline)) - METADATA_KEYS)
    specs = []
    for name in names:
        if to_number(current.get(name)) is not None and to_number(baseline.get(name)) is not None:
            specs.append({"name": name})
    return specs


def metric_row(
    name: str,
    current: float,
    baseline: float,
    row_current: dict[str, Any],
    row_baseline: dict[str, Any],
    metadata: dict[str, Any],
    spec: dict[str, Any],
    min_count: float,
) -> dict[str, Any]:
    delta = current - baseline
    current_count, baseline_count = support_counts(
        name, current, baseline, row_current, row_baseline, metadata
    )
    label, reasons = confidence(
        table_used=metadata_text(metadata.get("table_used", "")),
        comparison_type=metadata_text(metadata.get("comparison_type", "")),
        granularity=metadata_text(metadata.get("granularity", "")),
        current_count=current_count,
        baseline_count=baseline_count,
        baseline_value=baseline,
        context=metadata,
        min_count=min_count,
    )
    row: dict[str, Any] = {
        "name": name,
        "current": clean_number(current),
        "baseline": clean_number(baseline),
        "absolute_delta": clean_number(delta),
        "pct_change": clean_number(pct_delta(current, baseline)),
        "direction": direction(delta),
        "confidence": label,
        "confidence_reasons": reasons,
    }
    if "unit" in spec:
        row["unit"] = spec["unit"]
    return row


def compare_posture(value: Any, min_count: float = 100.0) -> dict[str, Any]:
    data = value if isinstance(value, dict) else {}
    periods = rows_to_periods(value)
    current = periods["current"]
    baseline = periods["baseline"]
    metadata = dict(data.get("confidence_context", {}) if isinstance(data, dict) else {})
    for key in (
        "comparison_type",
        "granularity",
        "table_used",
        "scope",
        "current_window",
        "baseline_windows",
        "counts",
    ):
        if isinstance(data, dict) and key in data:
            metadata[key] = data[key]
    metadata = json_safe(metadata)

    metrics: list[dict[str, Any]] = []
    for spec in metric_specs(data, current, baseline):
        name = str(spec["name"])
        current_value = to_number(current.get(name))
        baseline_value = to_number(baseline.get(name))
        if current_value is None or baseline_value is None:
            continue
        metrics.append(
            metric_row(
                name,
                current_value,
                baseline_value,
                current,
                baseline,
                metadata,
                spec,
                min_count,
            )
        )

    output: dict[str, Any] = {
        "schema_version": POSTURE_SCHEMA,
        "comparison_type": json_safe_metadata_value(
            metadata, "comparison_type", "previous_window"
        ),
        "granularity": json_safe_metadata_value(metadata, "granularity", ""),
        "table_used": json_safe_metadata_value(metadata, "table_used", ""),
        "scope": json_safe_metadata_value(metadata, "scope", {}),
        "current_window": json_safe_metadata_value(metadata, "current_window", {}),
        "baseline_windows": json_safe_metadata_value(
            metadata, "baseline_windows", []
        ),
        "metrics": metrics,
        "interpretation_constraints": POSTURE_CONSTRAINTS,
    }

    movers = data.get("movers") if isinstance(data, dict) else None
    if isinstance(movers, list):
        output["movers"] = compare_movers(value, min_count)["movers"]
    return output


def mover_value(row: dict[str, Any], dimension: str) -> Any:
    if "value" in row:
        return row["value"]
    if dimension in row:
        return row[dimension]
    return ""


def compare_movers(value: Any, min_count: float = 100.0) -> dict[str, Any]:
    data = value if isinstance(value, dict) else {}
    movers_input = data.get("movers") if isinstance(data, dict) else None
    if not isinstance(movers_input, list):
        movers_input = result_rows(value)

    metadata = dict(data.get("confidence_context", {}) if isinstance(data, dict) else {})
    dimension = json_safe_metadata_value(data, "dimension", "value")
    metric = json_safe_metadata_value(data, "metric", "requests")
    table_used = json_safe_metadata_value(data, "table_used", "")
    comparison_type = json_safe_metadata_value(
        data, "comparison_type", "previous_window"
    )
    granularity = json_safe_metadata_value(data, "granularity", "")
    dimension_key = dimension if isinstance(dimension, str) and dimension else "value"
    metric_key = metric if isinstance(metric, str) and metric else "requests"
    for key in ("scope", "current_window", "baseline_windows"):
        if isinstance(data, dict) and key in data:
            metadata[key] = data[key]
    metadata.update(
        {
            "table_used": table_used,
            "comparison_type": comparison_type,
            "granularity": granularity,
        }
    )
    metadata = json_safe(metadata)

    prepared: list[tuple[dict[str, Any], float, float, float]] = []
    for row in movers_input:
        if not isinstance(row, dict):
            continue
        current = to_number(row.get("current", row.get("current_requests")))
        baseline = to_number(row.get("baseline", row.get("baseline_requests")))
        if current is None or baseline is None:
            continue
        delta = current - baseline
        prepared.append((row, current, baseline, delta))

    provided_total_delta = to_number(data.get("total_delta")) if isinstance(data, dict) else None
    provided_total_delta_basis = (
        metadata_text(data.get("total_delta_basis", "")) if isinstance(data, dict) else ""
    )
    if (
        provided_total_delta is not None
        and provided_total_delta_basis in ABSOLUTE_DELTA_DENOMINATOR_BASES
    ):
        total_delta = abs(provided_total_delta)
        total_delta_basis = provided_total_delta_basis
    else:
        total_delta = sum(abs(delta) for _, _, _, delta in prepared)
        total_delta_basis = "sum_abs_mover_delta"

    movers: list[dict[str, Any]] = []
    for row, current, baseline, delta in prepared:
        basis = abs(total_delta) if total_delta else 0.0
        contribution = abs(delta) / basis * 100.0 if basis > 0 else 0.0
        current_count, baseline_count = support_counts(
            metric_key, current, baseline, {"requests": current}, {"requests": baseline}, metadata
        )
        label, reasons = confidence(
            table_used=metadata_text(table_used),
            comparison_type=metadata_text(comparison_type),
            granularity=metadata_text(granularity),
            current_count=current_count,
            baseline_count=baseline_count,
            baseline_value=baseline,
            context=metadata,
            min_count=min_count,
        )
        movers.append(
            {
                "dimension": dimension,
                "value": json_safe(mover_value(row, dimension_key)),
                "metric": metric,
                "current": clean_number(current),
                "baseline": clean_number(baseline),
                "absolute_delta": clean_number(delta),
                "pct_change": clean_number(pct_delta(current, baseline)),
                "direction": direction(delta),
                "contribution_pct": clean_number(contribution),
                "confidence": label,
                "confidence_reasons": reasons,
            }
        )

    return {
        "schema_version": MOVER_SCHEMA,
        "comparison_type": comparison_type,
        "granularity": granularity,
        "table_used": table_used,
        "scope": json_safe_metadata_value(metadata, "scope", {}),
        "current_window": json_safe_metadata_value(metadata, "current_window", {}),
        "baseline_windows": json_safe_metadata_value(
            metadata, "baseline_windows", []
        ),
        "dimension": dimension,
        "metric": metric,
        "total_delta": clean_number(total_delta or 0.0),
        "total_delta_basis": total_delta_basis,
        "movers": movers,
        "interpretation_constraints": MOVER_CONSTRAINTS,
    }
