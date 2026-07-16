from __future__ import annotations

from ._shared import *

"""Emit deterministic Bot Insights entity scorecards from aggregate JSON.

This script does not query Hydrolix. Feed it Hydrolix MCP query results, saved
JSON, or pasted aggregate JSON that already contains entity-level aggregate
rows. Hydrolix should do filtering, grouping, and aggregation; this script
standardizes rule-based scorecard shape, feature evidence, confidence reasons,
and ranked index output.
"""


import argparse

import json

import math

import sys

from pathlib import Path

from typing import Any, Callable

SCORECARD_SCHEMA = "bot_entity_scorecard.v1"

INDEX_SCHEMA = "bot_scorecard_index.v1"

ARTIFACT_SCHEMA = "bot_scorecard_artifacts.v1"

SCORECARD_ERROR_SCHEMA = "bot_scorecard_error.v1"

ADVANCED_ATTRIBUTION_SCHEMA = "bot_attribution_report.v1"

ADVANCED_SCORECARD_INPUT_SCHEMA = "bot_scorecard_input.v1"

SUPPORTED_ENTITY_TYPES = (
    "client_asn",
    "request_path_norm",
    "request_host",
    "bot_class",
    "ai_category",
)

DOMAINS = (
    "movement",
    "origin_impact",
    "cache_busting",
    "crawler_governance",
    "security_evidence",
    "signal_alignment",
    "policy_collateral",
)

INTERPRETATION_CONSTRAINTS = [
    "rule_based_scorecard",
    "mechanical_features_only",
    "no_causal_claim",
    "llm_may_summarize_structured_evidence_only",
]

METADATA_KEYS = {
    "period",
    "timestamp",
    "time",
    "bucket",
    "window",
    "label",
    "dimension",
    "value",
}

ALLOWED_POPULATIONS = ("crawler", "good_bot", "ai_crawler", "all_traffic", "unknown")

PROVENANCE_KEYS = ("rowset_scope", "feature_provenance")

SIEM_INPUTS = {
    "siem_blocked_requests",
    "cnt_blocked",
    "blocked_requests",
    "siem_auth_fail_requests",
    "cnt_auth_fail",
    "auth_fail_requests",
}

class InvalidScorecardInputError(ValueError):
    """Typed invalid-input error for scorecard library callers."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        path: str = "$",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        error = {
            "code": code,
            "message": message,
            "path": path,
        }
        if details:
            error["details"] = details
        self.document = {
            "schema_version": SCORECARD_ERROR_SCHEMA,
            "error_type": "invalid_input",
            "fatal": True,
            "errors": [error],
            "limitations": [],
        }

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compute Bot Insights scorecard artifacts from aggregate JSON."
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
        "--entity-type",
        choices=SUPPORTED_ENTITY_TYPES,
        help="Entity type to score. Defaults to metadata or inferred row columns.",
    )
    parser.add_argument(
        "--min-count",
        type=float,
        default=100.0,
        help="Minimum current and baseline support count for high confidence.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Optional maximum number of scorecards and ranked index entries.",
    )
    parser.add_argument(
        "--domains",
        help=(
            "Optional comma-separated scorecard domains to evaluate, such as "
            "security_evidence for SOC or crawler_governance for crawler reports. "
            "Defaults to all domains."
        ),
    )
    parser.add_argument(
        "--output",
        choices=("all", "scorecards", "index"),
        default="all",
        help="Artifact type to emit.",
    )
    return parser.parse_args()

def read_input(args: argparse.Namespace) -> str:
    if args.file:
        return args.file.read_text(encoding="utf-8")
    if args.text:
        return " ".join(args.text)
    return sys.stdin.read()

def validate_rowset_scope(scope: Any, context: str) -> dict[str, Any]:
    if not isinstance(scope, dict):
        raise ValueError(f"{context} must be a JSON object")
    if "population" in scope:
        population = scope["population"]
        if not isinstance(population, str) or population not in ALLOWED_POPULATIONS:
            raise ValueError(
                f"{context}.population must be one of " + ", ".join(ALLOWED_POPULATIONS)
            )
    return json_safe(scope)

def validate_feature_provenance(provenance: Any, context: str) -> dict[str, Any]:
    if not isinstance(provenance, dict):
        raise ValueError(f"{context} must be a JSON object keyed by feature name")
    for feature_name, entry in provenance.items():
        if not isinstance(feature_name, str) or not feature_name:
            raise ValueError(f"{context} keys must be non-empty feature name strings")
        entry_context = f"{context}.{feature_name}"
        if not isinstance(entry, dict):
            raise ValueError(f"{entry_context} must be a JSON object")
        if "rowset_scope" in entry:
            validate_rowset_scope(
                entry["rowset_scope"], f"{entry_context}.rowset_scope"
            )
        if "metric_inputs" in entry:
            metric_inputs = entry["metric_inputs"]
            if not isinstance(metric_inputs, list) or not all(
                isinstance(item, str) for item in metric_inputs
            ):
                raise ValueError(
                    f"{entry_context}.metric_inputs must be an array of strings"
                )
    return json_safe(provenance)

def to_number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        number = float(value)
        return number if math.isfinite(number) else None
    if isinstance(value, str):
        try:
            number = float(value)
        except ValueError:
            return None
        return number if math.isfinite(number) else None
    return None

def clean_number(value: float | int | None) -> float | int | None:
    if value is None:
        return None
    if not math.isfinite(float(value)):
        raise ValueError("Output numeric values must be finite.")
    rounded = round(float(value), 6)
    if rounded.is_integer():
        return int(rounded)
    return rounded

def json_safe(value: Any) -> Any:
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, int):
        return value
    if isinstance(value, list):
        return [json_safe(item) for item in value]
    if isinstance(value, dict):
        return {key: json_safe(item) for key, item in value.items()}
    return value

def metadata_text(value: Any, default: str = "") -> str:
    safe_value = json_safe(value)
    if safe_value is None:
        return default
    return str(safe_value)

def pct_delta(current: float, baseline: float) -> float:
    return (current - baseline) / max(baseline, 1.0) * 100.0

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
            converted.append(
                {
                    name: row[index]
                    for index, name in enumerate(names)
                    if index < len(row)
                }
            )
    return converted

def infer_entity_type(row: dict[str, Any], requested: str | None = None) -> str:
    if requested:
        return requested
    for entity_type in SUPPORTED_ENTITY_TYPES:
        if entity_type in row:
            return entity_type
    if "entity_type" in row and str(row["entity_type"]) in SUPPORTED_ENTITY_TYPES:
        return str(row["entity_type"])
    if "dimension" in row and str(row["dimension"]) in SUPPORTED_ENTITY_TYPES:
        return str(row["dimension"])
    return "value"

def entity_value(row: dict[str, Any], entity_type: str) -> str:
    if entity_type in row:
        return str(row[entity_type])
    if "entity" in row:
        return str(row["entity"])
    if "value" in row:
        return str(row["value"])
    return ""

def prefixed_keys(prefix: str, names: tuple[str, ...]) -> tuple[str, ...]:
    keys: list[str] = []
    for name in names:
        keys.extend(
            [
                f"{prefix}_{name}",
                f"{name}_{prefix}",
                f"{prefix}.{name}",
            ]
        )
    return tuple(keys)

def first_number(row: dict[str, Any], keys: tuple[str, ...]) -> float | None:
    for key in keys:
        if key in row:
            value = to_number(row[key])
            if value is not None:
                return value
    return None

def merge_period_metadata(
    combined: dict[str, Any],
    field: str,
    value: Any,
    *,
    entity_type: str,
    entity: str,
) -> None:
    if field not in combined:
        combined[field] = value
        return
    if combined[field] != value:
        raise ValueError(
            f"Period-split rows for {entity_type}={entity} must not disagree on {field}"
        )

def current_number(row: dict[str, Any], *names: str) -> float | None:
    return first_number(row, prefixed_keys("current", names) + names)

def baseline_number(row: dict[str, Any], *names: str) -> float | None:
    return first_number(row, prefixed_keys("baseline", names))

def count_values(row: dict[str, Any]) -> tuple[float | None, float | None]:
    current = first_number(
        row,
        (
            "current_count",
            "current_requests",
            "requests_current",
            "current.cnt_all",
            "current_cnt_all",
            "cnt_all_current",
            "requests",
            "cnt_all",
            "current",
        ),
    )
    baseline = first_number(
        row,
        (
            "baseline_count",
            "baseline_requests",
            "requests_baseline",
            "baseline.cnt_all",
            "baseline_cnt_all",
            "cnt_all_baseline",
            "baseline",
        ),
    )
    return current, baseline

__all__ = [name for name in globals() if not name.startswith("__")]
