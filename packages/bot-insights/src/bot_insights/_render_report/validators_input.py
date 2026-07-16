"""Report wrapper input parsing and option resolution."""

from __future__ import annotations

import argparse
from typing import Any

from .constants import (
    CONTROL_SCHEMA,
    INDEX_SCHEMA,
    POSTURE_SCHEMA,
    REPORT_TYPES,
    WRAPPER_SCHEMA,
)
from .errors import ReportContext, ReportError
from .formatters import slug_title
from .validators_normalization import normalize_artifacts, schema_of


def load_report_input(
    value: Any,
    args: argparse.Namespace,
    ctx: ReportContext,
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    str | None,
    str | None,
    int | None,
    str | None,
    str | None,
]:
    (
        raw_artifacts,
        notes,
        wrapper_report_type,
        wrapper_title,
        wrapper_limit,
        scope_label,
        raw_mode,
    ) = _raw_report_input(value, args)

    if not all(isinstance(artifact, dict) for artifact in raw_artifacts):
        raise ReportError("All artifacts must be JSON objects.")

    normalized = normalize_artifacts(
        raw_artifacts,
        allow_unknown=bool(args.allow_unknown),
        ctx=ctx,
    )
    if not normalized:
        raise ReportError("No supported artifacts were available after normalization.")
    return (
        normalized,
        notes,
        wrapper_report_type,
        wrapper_title,
        wrapper_limit,
        scope_label,
        raw_mode,
    )


def infer_report_type(
    artifacts: list[dict[str, Any]], raw_hint: str | None
) -> str | None:
    if raw_hint != "single":
        return None
    raw_schema = schema_of(artifacts[0]) if artifacts else ""
    mapping = {
        POSTURE_SCHEMA: "executive_posture",
        CONTROL_SCHEMA: "control_review",
        INDEX_SCHEMA: "soc_triage",
    }
    return mapping.get(raw_schema)


def resolve_options(
    artifacts: list[dict[str, Any]],
    *,
    wrapper_report_type: str | None,
    wrapper_title: str | None,
    wrapper_limit: int | None,
    scope_label: str | None,
    raw_mode: str | None,
    args: argparse.Namespace,
    ctx: ReportContext,
) -> tuple[str, str, int, str | None]:
    cli_report_type = args.report_type
    if (
        wrapper_report_type
        and cli_report_type
        and wrapper_report_type != cli_report_type
    ):
        raise ReportError(
            f"Wrapper report_type {wrapper_report_type} conflicts with CLI --report-type {cli_report_type}."
        )
    report_type = wrapper_report_type or cli_report_type
    if report_type is None:
        report_type = infer_report_type(artifacts, raw_mode)
    if report_type is None:
        raise ReportError(
            "Missing or ambiguous report intent; supply --report-type or wrapper report_type."
        )

    if args.title is not None and not isinstance(args.title, str):
        raise ReportError("--title must be a string.")
    if (
        args.title is not None
        and wrapper_title is not None
        and args.title != wrapper_title
    ):
        ctx.warn("CLI --title overrides wrapper title.")
    title = (
        args.title
        or wrapper_title
        or generated_title(report_type, artifacts, scope_label)
    )

    if args.limit is not None:
        if (
            not isinstance(args.limit, int)
            or isinstance(args.limit, bool)
            or args.limit <= 0
        ):
            raise ReportError("--limit must be a positive integer.")
    if (
        args.limit is not None
        and wrapper_limit is not None
        and args.limit != wrapper_limit
    ):
        ctx.warn("CLI --limit overrides wrapper limit.")
    limit = args.limit or wrapper_limit or default_limit(report_type)
    return report_type, title, limit, scope_label


def default_limit(report_type: str) -> int:
    if report_type == "scorecard_brief":
        return 20
    return 10


def generated_title(
    report_type: str, artifacts: list[dict[str, Any]], scope_label: str | None
) -> str:
    scope = scope_label
    if not scope:
        for artifact in artifacts:
            scope_value = artifact.get("scope")
            if isinstance(scope_value, dict) and scope_value:
                scope = ", ".join(
                    f"{key}={value}" for key, value in sorted(scope_value.items())
                )
                break
    if scope:
        return f"{slug_title(report_type)} - {scope}"
    return slug_title(report_type)


def _raw_report_input(
    value: Any, args: argparse.Namespace
) -> tuple[
    list[Any],
    list[dict[str, Any]],
    str | None,
    str | None,
    int | None,
    str | None,
    str | None,
]:
    if isinstance(value, dict) and value.get("schema_version") == WRAPPER_SCHEMA:
        return _wrapper_report_input(value)
    if isinstance(value, dict) and "schema_version" in value:
        return [value], [], None, None, None, None, "single"
    if isinstance(value, list):
        if not value:
            raise ReportError("Raw artifact array input must be non-empty.")
        if args.report_type is None:
            raise ReportError("Raw artifact array input requires --report-type.")
        return value, [], None, None, None, None, "array"
    if isinstance(value, dict):
        raise ReportError("Raw artifact object input is missing schema_version.")
    raise ReportError(
        "Input must be a known artifact object, a non-empty artifact array, or a bot_report_input.v1 wrapper."
    )


def _wrapper_report_input(
    value: dict[str, Any],
) -> tuple[
    list[Any],
    list[dict[str, Any]],
    str | None,
    str | None,
    int | None,
    str | None,
    str | None,
]:
    wrapper_report_type = _wrapper_report_type(value)
    wrapper_title = _wrapper_title(value)
    wrapper_limit = _wrapper_limit(value)
    scope_label = _wrapper_scope_label(value)
    notes = _wrapper_notes(value)
    raw_artifacts = value.get("artifacts")
    if not isinstance(raw_artifacts, list) or not raw_artifacts:
        raise ReportError("Wrapper artifacts must be a non-empty array.")
    return (
        raw_artifacts,
        notes,
        wrapper_report_type,
        wrapper_title,
        wrapper_limit,
        scope_label,
        None,
    )


def _wrapper_report_type(value: dict[str, Any]) -> str | None:
    wrapper_report_type = value.get("report_type")
    if wrapper_report_type is not None and not isinstance(wrapper_report_type, str):
        raise ReportError("Wrapper report_type must be a string.")
    if wrapper_report_type is not None and wrapper_report_type not in REPORT_TYPES:
        raise ReportError(f"Unsupported wrapper report_type {wrapper_report_type}.")
    return wrapper_report_type


def _wrapper_title(value: dict[str, Any]) -> str | None:
    wrapper_title = value.get("title")
    if wrapper_title is not None and not isinstance(wrapper_title, str):
        raise ReportError("Wrapper title must be a string.")
    return wrapper_title


def _wrapper_limit(value: dict[str, Any]) -> int | None:
    wrapper_limit = value.get("limit")
    if wrapper_limit is not None and (
        not isinstance(wrapper_limit, int)
        or isinstance(wrapper_limit, bool)
        or wrapper_limit <= 0
    ):
        raise ReportError("Wrapper limit must be a positive integer.")
    return wrapper_limit


def _wrapper_scope_label(value: dict[str, Any]) -> str | None:
    scope_label = value.get("scope_label")
    if scope_label is not None and (
        not isinstance(scope_label, str) or not scope_label.strip()
    ):
        raise ReportError("Wrapper scope_label must be a non-empty string.")
    return scope_label


def _wrapper_notes(value: dict[str, Any]) -> list[dict[str, Any]]:
    raw_notes = value.get("analyst_notes", [])
    if raw_notes is None:
        raw_notes = []
    if not isinstance(raw_notes, list) or not all(
        isinstance(note, dict) for note in raw_notes
    ):
        raise ReportError("Wrapper analyst_notes must be an array of objects.")
    return raw_notes
