from __future__ import annotations

from ._shared import *

"""Emit structured Bot Insights posture analytics from aggregate JSON.

This script does not query Hydrolix. Feed it Hydrolix MCP query results, saved
JSON, or pasted aggregate JSON that already contains current/baseline rows.
Hydrolix should do filtering, grouping, and aggregation; this script standardizes
report shape, confidence reasons, contribution math, and interpretation guards.
"""


import argparse

import importlib.util

import json

import sys

from pathlib import Path

from typing import Any

def _load_baselines_module() -> Any:
    spec = importlib.util.spec_from_file_location(
        "_bot_insights_baselines", Path(__file__).resolve().parent.parent / "baselines.py"
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("Could not load sibling baselines.py module.")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

baselines = _load_baselines_module()

clean_number = baselines.clean_number

confidence = baselines.confidence

direction = baselines.direction

json_safe = baselines.json_safe

json_safe_metadata_value = baselines.json_safe_metadata_value

metadata_text = baselines.metadata_text

pct_delta = baselines.pct_delta

support_counts = baselines.support_counts

to_number = baselines.to_number

POSTURE_SCHEMA = "bot_posture_movement.v1"

MOVER_SCHEMA = "bot_mover_attribution.v1"

CONTROL_SCHEMA = "bot_control_review.v1"

POSTURE_CONSTRAINTS = [
    "movement_only",
    "no_causal_claim",
    "llm_may_summarize_structured_evidence_only",
]

MOVER_CONSTRAINTS = [
    "attribution_from_aggregate_deltas",
    "no_causal_claim",
    "llm_may_summarize_structured_evidence_only",
]

CONTROL_CONSTRAINTS = [
    "control_effectiveness_review",
    "no_causal_claim_without_external_change_evidence",
    "llm_may_summarize_structured_evidence_only",
]

VALID_EXPECTED_BASIS = {
    "before_window",
    "explicit_target",
    "external_model",
    "unknown",
}

ABSOLUTE_DELTA_DENOMINATOR_BASES = {
    "complete_scope_abs_delta",
    "complete_scope_total_abs_delta",
    "sum_abs_delta",
    "sum_abs_mover_delta",
}

METADATA_KEYS = {
    "period",
    "timestamp",
    "time",
    "bucket",
    "window",
    "label",
    "dimension",
    "value",
    "current_count",
    "baseline_count",
    "before",
    "after",
    "expected",
}

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compute structured Bot Insights posture analytics from aggregate JSON."
    )
    parser.add_argument(
        "text",
        nargs="*",
        help="Aggregate JSON. If omitted, stdin is read.",
    )
    parser.add_argument(
        "-f",
        "--file",
        type=Path,
        help="Read aggregate JSON from a file instead of positional arguments/stdin.",
    )
    parser.add_argument(
        "--schema",
        choices=("auto", "posture", "movers", "control"),
        default="auto",
        help="Output schema to emit.",
    )
    parser.add_argument(
        "--min-count",
        type=float,
        default=100.0,
        help="Minimum current and baseline support count for high confidence.",
    )
    return parser.parse_args()

def read_input(args: argparse.Namespace) -> str:
    if args.file:
        return args.file.read_text(encoding="utf-8")
    if args.text:
        return " ".join(args.text)
    return sys.stdin.read()

def column_names(columns: list[Any]) -> list[str]:
    names: list[str] = []
    for column in columns:
        if isinstance(column, str):
            names.append(column)
        elif isinstance(column, dict):
            names.append(str(column.get("name") or column.get("column") or ""))
        else:
            names.append(str(column))
    return names

def result_rows(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [row for row in value if isinstance(row, dict)]

    if not isinstance(value, dict):
        return []

    rows = value.get("rows")
    if not isinstance(rows, list):
        rows = value.get("data")
    if not isinstance(rows, list):
        return []

    if not rows:
        return []
    if all(isinstance(row, dict) for row in rows):
        return rows

    columns = value.get("columns", [])
    if not isinstance(columns, list):
        return []
    names = column_names(columns)
    converted: list[dict[str, Any]] = []
    for row in rows:
        if isinstance(row, list):
            converted.append({name: row[index] for index, name in enumerate(names) if index < len(row)})
    return converted

def rows_to_periods(value: Any) -> dict[str, dict[str, Any]]:
    if isinstance(value, dict):
        current = value.get("current")
        baseline = value.get("baseline")
        if isinstance(current, dict) and isinstance(baseline, dict):
            return {"current": current, "baseline": baseline}

    periods: dict[str, dict[str, Any]] = {}
    for row in result_rows(value):
        period = str(row.get("period", "")).lower()
        if period in {"current", "baseline", "before", "after"}:
            periods[period] = row

    if "current" in periods and "baseline" in periods:
        return {"current": periods["current"], "baseline": periods["baseline"]}
    if "after" in periods and "before" in periods:
        return {"current": periods["after"], "baseline": periods["before"]}
    raise ValueError(
        "Input must contain current/baseline objects or period rows with current/baseline."
    )

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

__all__ = [name for name in globals() if not name.startswith("__")]
