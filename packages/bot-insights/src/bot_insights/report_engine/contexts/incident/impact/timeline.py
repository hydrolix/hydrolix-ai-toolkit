"""Timeline projection helpers for incident impact context."""

from __future__ import annotations

from datetime import datetime

from ..formatters import _short_iso

__all__ = ['_window_timeline_view']


def _timeline_dt(value: str) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def _window_timeline_view(scope_art: dict) -> dict | None:
    """Project baseline/current windows into a compact print timeline."""
    scope_meta = scope_art.get("scope") or {}
    baseline_start = scope_meta.get("baseline_start") or ""
    baseline_end = scope_meta.get("baseline_end") or ""
    current_start = scope_meta.get("start") or ""
    current_end = scope_meta.get("end") or ""
    points = {
        "baseline_start": _timeline_dt(baseline_start),
        "baseline_end": _timeline_dt(baseline_end),
        "current_start": _timeline_dt(current_start),
        "current_end": _timeline_dt(current_end),
    }
    if not all(points.values()):
        return None

    min_start = min(points.values())
    max_end = max(points.values())
    total_seconds = max((max_end - min_start).total_seconds(), 1.0)

    def segment(start: datetime, end: datetime, label: str) -> dict:
        left = ((start - min_start).total_seconds() / total_seconds) * 100.0
        width = max(((end - start).total_seconds() / total_seconds) * 100.0, 1.0)
        return {
            "label": label,
            "left_pct": f"{left:.3f}%",
            "width_pct": f"{width:.3f}%",
            "start_label": _short_iso(start.isoformat().replace("+00:00", "Z")),
            "end_label": _short_iso(end.isoformat().replace("+00:00", "Z")),
        }

    return {
        "start_label": _short_iso(min_start.isoformat().replace("+00:00", "Z")),
        "end_label": _short_iso(max_end.isoformat().replace("+00:00", "Z")),
        "segments": [
            segment(points["baseline_start"], points["baseline_end"], "Baseline"),
            segment(points["current_start"], points["current_end"], "Current"),
        ],
    }
