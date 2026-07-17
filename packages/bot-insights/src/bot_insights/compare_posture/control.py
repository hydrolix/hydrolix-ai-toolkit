from __future__ import annotations

from typing import Any

from .constants import (
    CONTROL_CONSTRAINTS,
    CONTROL_SCHEMA,
    METADATA_KEYS,
    VALID_EXPECTED_BASIS,
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
from .rows import result_rows


def control_status(
    after: float,
    expected: float,
    desired_direction: str | None = None,
    tolerance_pct: float = 5.0,
) -> str:
    delta = after - expected
    change_pct = abs(pct_delta(after, expected))
    if change_pct <= tolerance_pct:
        return "within_expected"
    actual = direction(delta)
    if desired_direction is None:
        return "increased" if actual == "increase" else "decreased"
    if actual == desired_direction:
        return "improved"
    return "review"


def control_metric_specs(data: dict[str, Any], after: dict[str, Any], expected: dict[str, Any]) -> list[dict[str, Any]]:
    raw_specs = data.get("target_metrics") or data.get("metrics")
    if isinstance(raw_specs, list) and raw_specs:
        specs: list[dict[str, Any]] = []
        for item in raw_specs:
            if isinstance(item, str):
                specs.append({"name": item})
            elif isinstance(item, dict) and "name" in item:
                specs.append(item)
        return specs
    return [{"name": name} for name in sorted((set(after) & set(expected)) - METADATA_KEYS)]


def compare_control(value: Any, min_count: float = 100.0) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("Control review input must be a JSON object.")
    data = value

    before, after, expected, expected_supplied, expected_fell_back_to_before = (
        _control_periods(data)
    )
    metadata = _control_metadata(data)
    desired = data.get("desired_directions", {})
    if not isinstance(desired, dict):
        desired = {}

    target_effects = [
        effect
        for spec in control_metric_specs(data, after, expected)
        if (
            effect := _control_target_effect(
                spec, before, after, expected, metadata, desired, data, min_count
            )
        )
        is not None
    ]
    expected_basis = _control_expected_basis(
        data, expected_supplied, expected_fell_back_to_before
    )

    output = {
        "schema_version": CONTROL_SCHEMA,
        "comparison_type": "post_change_vs_expected",
        "change_time": json_safe(data.get("change_time", "")),
        "target": json_safe(data.get("target", {})),
        "scope": json_safe(data.get("scope", {})),
        "expected_basis": expected_basis,
        "table_used": json_safe_metadata_value(metadata, "table_used", ""),
        "target_effects": target_effects,
        "collateral_checks": json_safe(data.get("collateral_checks", [])),
        "displacement_checks": json_safe(data.get("displacement_checks", [])),
        "interpretation_constraints": CONTROL_CONSTRAINTS,
    }
    for key in ("before_window", "after_window", "expected_window"):
        if key in data:
            output[key] = json_safe(data[key])
    if (
        "expected_window" not in output
        and expected_basis == "before_window"
        and "before_window" in output
    ):
        output["expected_window"] = output["before_window"]
    return output


def _control_periods(
    data: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], bool, bool]:
    before = data.get("before")
    after = data.get("after")
    expected = data.get("expected")
    if not isinstance(before, dict) or not isinstance(after, dict):
        periods = {}
        for row in result_rows(data):
            period = str(row.get("period", "")).lower()
            if period in {"before", "after"}:
                periods[period] = row
        before = periods.get("before", before)
        after = periods.get("after", after)
    if not isinstance(before, dict):
        before = {}
    if not isinstance(after, dict):
        raise ValueError("Control review input must contain after metrics.")
    expected_supplied = isinstance(expected, dict)
    if not expected_supplied:
        expected = before
    expected_fell_back_to_before = not expected_supplied and bool(before)
    return before, after, expected, expected_supplied, expected_fell_back_to_before


def _control_metadata(data: dict[str, Any]) -> dict[str, Any]:
    metadata = dict(data.get("confidence_context", {}) if isinstance(data.get("confidence_context"), dict) else {})
    for key in ("comparison_type", "granularity", "table_used", "counts"):
        if key in data:
            metadata[key] = data[key]
    metadata.setdefault("comparison_type", "post_change_vs_expected")
    return json_safe(metadata)


def _control_target_effect(
    spec: dict[str, Any],
    before: dict[str, Any],
    after: dict[str, Any],
    expected: dict[str, Any],
    metadata: dict[str, Any],
    desired: dict[str, Any],
    data: dict[str, Any],
    min_count: float,
) -> dict[str, Any] | None:
    metric = str(spec["name"])
    after_value = to_number(after.get(metric))
    expected_value = to_number(expected.get(metric))
    before_value = to_number(before.get(metric))
    if after_value is None or expected_value is None:
        return None
    delta = after_value - expected_value
    desired_direction = spec.get("desired_direction") or desired.get(metric)
    current_count, baseline_count = support_counts(
        metric,
        after_value,
        expected_value,
        after,
        expected,
        metadata,
    )
    label, reasons = confidence(
        table_used=metadata_text(metadata.get("table_used", "")),
        comparison_type="post_change_vs_expected",
        granularity=metadata_text(metadata.get("granularity", "")),
        current_count=current_count,
        baseline_count=baseline_count,
        baseline_value=expected_value,
        context=metadata,
        min_count=min_count,
    )
    return {
        "metric": metric,
        "before": clean_number(before_value) if before_value is not None else None,
        "after": clean_number(after_value),
        "expected": clean_number(expected_value),
        "absolute_delta_vs_expected": clean_number(delta),
        "pct_change_vs_expected": clean_number(pct_delta(after_value, expected_value)),
        "direction": direction(delta),
        "status": control_status(
            after_value,
            expected_value,
            desired_direction=str(desired_direction) if desired_direction else None,
            tolerance_pct=float(spec.get("tolerance_pct", data.get("tolerance_pct", 5.0))),
        ),
        "confidence": label,
        "confidence_reasons": reasons,
    }


def _control_expected_basis(
    data: dict[str, Any], expected_supplied: bool, expected_fell_back_to_before: bool
) -> str:
    raw_basis = data.get("expected_basis")
    if isinstance(raw_basis, str) and raw_basis in VALID_EXPECTED_BASIS:
        return raw_basis
    if expected_fell_back_to_before:
        return "before_window"
    if expected_supplied:
        return "explicit_target"
    return "unknown"
