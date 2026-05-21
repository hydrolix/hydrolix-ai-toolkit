"""Table / window / scope display helpers shared by md + html."""

from __future__ import annotations

import json
from typing import Any
from report_engine.humanize import stringify

from .constants import (
    POSTURE_SCHEMA,
    TIMESERIES_SCHEMA,
)
from .errors import ReportContext
from .formatters import (
    human_window_range,
    md_escape,
)

__all__ = [
    'md_table',
    'limited_rows',
    'window_text',
    'evidence_window_summary',
    'artifact_display_name',
    'selected_artifacts',
    'format_artifact_scope',
    'resolve_scope_display',
]


def md_table(headers: list[str], rows: list[list[Any]]) -> str:
    output = [
        "| " + " | ".join(md_escape(header) for header in headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for row in rows:
        output.append("| " + " | ".join(md_escape(cell) for cell in row) + " |")
    return "\n".join(output)


def limited_rows(
    rows: list[Any], limit: int, label: str, ctx: ReportContext
) -> list[Any]:
    if limit > 0 and len(rows) > limit:
        ctx.warn(
            f"Showing {limit} of {len(rows)} available {label}; display limit omitted {len(rows) - limit}."
        )
        return rows[:limit]
    return rows


def window_text(artifact: dict[str, Any]) -> str:
    parts = []
    labels = {
        "current_window": "current",
        "before_window": "before",
        "after_window": "after",
        "expected_window": "expected",
    }
    for key in ("current_window", "before_window", "after_window", "expected_window"):
        value = artifact.get(key)
        if isinstance(value, dict):
            parts.append(f"{labels[key]} {human_window_range(value)}")
        elif value:
            parts.append(f"{labels[key]} {stringify(value)}")
    baselines = artifact.get("baseline_windows")
    if isinstance(baselines, list) and baselines and isinstance(baselines[0], dict):
        parts.append(f"baseline {human_window_range(baselines[0])}")
    elif baselines:
        parts.append(f"baseline {stringify(baselines)}")
    return "; ".join(parts) if parts else "unavailable"


def evidence_window_summary(artifact: dict[str, Any]) -> str:
    current = artifact.get("current_window")
    baselines = artifact.get("baseline_windows")
    parts: list[str] = []
    if isinstance(current, dict):
        parts.append(f"current window {human_window_range(current)}")
    if isinstance(baselines, list) and baselines and isinstance(baselines[0], dict):
        parts.append(f"baseline window {human_window_range(baselines[0])}")
    return "; ".join(parts) if parts else "unavailable"


def artifact_display_name(artifact: dict[str, Any]) -> str:
    title = artifact.get("title")
    if isinstance(title, str) and title.strip():
        return title
    schema = artifact.get("schema_version")
    if schema == POSTURE_SCHEMA:
        return "Posture movement"
    if schema == TIMESERIES_SCHEMA:
        return "Hourly trend evidence"
    return str(artifact.get("artifact_id") or "Artifact")


def selected_artifacts(selected: dict[str, Any]) -> list[dict[str, Any]]:
    collected: list[dict[str, Any]] = []
    for value in selected.values():
        if value is None:
            continue
        if isinstance(value, list):
            collected.extend(item for item in value if isinstance(item, dict))
        elif isinstance(value, dict):
            collected.append(value)
    return collected


def format_artifact_scope(scope: dict[str, Any]) -> str:
    return ", ".join(f"{key}={value}" for key, value in sorted(scope.items()))


def resolve_scope_display(
    scope_label: str | None,
    selected: dict[str, Any],
    ctx: ReportContext,
) -> str:
    if scope_label:
        return str(scope_label)
    unique: list[dict[str, Any]] = []
    seen: set[str] = set()
    for artifact in selected_artifacts(selected):
        scope = artifact.get("scope")
        if not isinstance(scope, dict) or not scope:
            continue
        fingerprint = json.dumps(scope, sort_keys=True, separators=(",", ":"))
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        unique.append(scope)
    if not unique:
        ctx.warn(
            "Scope unavailable: no wrapper scope_label and no selected artifact carries scope metadata."
        )
        return "unavailable"
    if len(unique) > 1:
        ctx.warn(
            "Scope mixed: selected artifacts disagree on scope metadata; rendered as mixed."
        )
        return "mixed"
    return format_artifact_scope(unique[0])
