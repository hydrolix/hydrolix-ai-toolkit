from __future__ import annotations

import argparse
from typing import Any

from .constants import ANALYSIS_TYPES
from .errors import raise_invalid
from .numeric import resolve_value, unique_strings


def normalize_options(options: Any) -> dict[str, Any]:
    if options is None:
        return {}
    if isinstance(options, argparse.Namespace):
        return vars(options).copy()
    if isinstance(options, dict):
        return dict(options)
    raise TypeError("options must be a dict, argparse.Namespace, or None")


def normalize_analysis_type(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if text not in ANALYSIS_TYPES:
        raise_invalid(
            "analysis_type_invalid",
            f"Unsupported analysis_type '{value}'.",
            details={"analysis_type": value, "supported_analysis_types": sorted(ANALYSIS_TYPES)},
        )
    return text


def resolve_analysis_type(payload: Any, metadata: dict[str, Any], options: dict[str, Any]) -> str:
    cli_analysis = normalize_analysis_type(options.get("analysis"))
    input_analysis = normalize_analysis_type(resolve_value(payload, metadata, "analysis_type"))
    if cli_analysis and input_analysis and cli_analysis != input_analysis:
        raise_invalid(
            "analysis_type_conflict",
            "CLI analysis conflicts with input analysis_type.",
            details={"cli_analysis": cli_analysis, "input_analysis": input_analysis},
        )
    return cli_analysis or input_analysis or "aggregate_delta_attribution"


def parse_dimensions(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return unique_strings(value.split(","))
    if isinstance(value, (list, tuple)):
        return unique_strings(value)
    return unique_strings([value])


def filter_columns(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, dict):
        return unique_strings(value.keys())
    return parse_dimensions(value)


def selected_filter_columns(*values: Any) -> list[str]:
    columns: list[str] = []
    for value in values:
        columns.extend(filter_columns(value))
    return unique_strings(columns)
