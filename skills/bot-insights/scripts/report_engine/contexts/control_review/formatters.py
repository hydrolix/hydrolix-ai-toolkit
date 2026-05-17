"""Tiny formatters / scope helpers."""

from __future__ import annotations

from ...humanize import cluster_display

__all__ = [
    '_maybe_float',
    '_short_window',
    '_cluster_label',
    '_target_descriptor',
]


def _maybe_float(value: object) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return float(int(value))
    try:
        return float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _short_window(window: dict) -> str:
    """``2026-04-08 → 2026-04-15`` from ``{start, end}`` ISO timestamps.

    Mirrors ``executive_posture._short_window`` so cross-report headlines
    read consistently.
    """
    if not window:
        return "n/a"
    start = window.get("start") or ""
    end = window.get("end") or ""

    def _date(value: str) -> str:
        if "T" in value:
            return value.split("T", 1)[0]
        return value

    return f"{_date(start)} → {_date(end)}".strip(" →")


def _cluster_label(scope: dict) -> str:
    """Display-friendly cluster name for the H1. Mirrors
    ``executive_posture._cluster_label``."""
    cluster = scope.get("cluster")
    if cluster:
        return cluster_display(cluster)
    host = scope.get("request_host") or scope.get("entity") or ""
    return host or ""


def _target_descriptor(target: dict) -> str:
    """Best-effort human descriptor for the target of the control.

    Tries common identifier fields in priority order. Falls back to a
    deterministic ``key=value`` join so a producer that emits a new key
    still produces something readable.
    """
    if not isinstance(target, dict):
        return ""
    for key in ("policy_id", "feature", "rule_id", "name", "identifier"):
        value = target.get(key)
        if value:
            return str(value)
    parts = [f"{k}={v}" for k, v in sorted(target.items()) if v not in (None, "")]
    return ", ".join(parts)
