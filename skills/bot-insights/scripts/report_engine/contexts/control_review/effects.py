"""Effect-row + bar-row + check-row builders."""

from __future__ import annotations

from ...humanize import human_metric_name

from .formatters import _maybe_float
from .labels import (
    _status_label,
    _status_tone,
)

__all__ = [
    '_effect_row',
    '_bar_row',
    '_check_rows',
]


def _effect_row(effect: dict) -> dict:
    """Project a ``target_effects`` entry into the row shape the template
    consumes. Keeps every numeric value as the producer emitted it so
    ``|pct2`` / ``|signed_pp`` filters can format consistently.
    """
    metric = effect.get("metric")
    return {
        "metric": metric,
        "metric_label": human_metric_name(metric),
        "before": _maybe_float(effect.get("before")),
        "after": _maybe_float(effect.get("after")),
        "expected": _maybe_float(effect.get("expected")),
        "absolute_delta_vs_expected": _maybe_float(
            effect.get("absolute_delta_vs_expected")
        ),
        "pct_change_vs_expected": _maybe_float(effect.get("pct_change_vs_expected")),
        "status": effect.get("status"),
        "status_label": _status_label(effect.get("status")),
        "status_tone": _status_tone(effect.get("status")),
        "confidence": effect.get("confidence") or "",
        "direction": effect.get("direction"),
    }


def _bar_row(row: dict) -> dict | None:
    """Project an effect row into the input the control_bars macro
    consumes. Returns ``None`` if every numeric value is missing so the
    macro can skip the row outright (matches legacy ``html_control_bars``
    behavior at ``render_report.py:3461``).
    """
    values = (row["before"], row["after"], row["expected"])
    if all(v is None for v in values):
        return None
    return {
        "metric": row["metric"],
        "metric_label": row["metric_label"],
        "before": row["before"],
        "after": row["after"],
        "expected": row["expected"],
        "status": row["status"],
        "status_label": row["status_label"],
        "confidence": row["confidence"],
    }


def _check_rows(checks: list[dict]) -> list[dict]:
    rows = []
    for check in checks:
        if not isinstance(check, dict):
            continue
        metric = check.get("metric") or check.get("name")
        rows.append(
            {
                "metric": metric,
                "metric_label": human_metric_name(metric) if metric else "",
                "before": _maybe_float(check.get("before")),
                "after": _maybe_float(check.get("after")),
                "delta": _maybe_float(
                    check.get("absolute_delta") or check.get("delta")
                ),
                "pct_change": _maybe_float(check.get("pct_change")),
                "status": check.get("status"),
                "status_label": _status_label(check.get("status")),
                "status_tone": _status_tone(check.get("status")),
                "confidence": check.get("confidence") or "",
            }
        )
    return rows
