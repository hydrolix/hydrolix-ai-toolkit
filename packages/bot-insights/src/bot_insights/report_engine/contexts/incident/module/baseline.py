"""Baseline strategy and current-versus-baseline metric rows."""

from __future__ import annotations

from datetime import datetime

from ..formatters import _format_count, _format_signed_pct

from .scope import _build_windows_block, _sum_numeric


def _baseline_strategy(scope_meta: dict) -> str:
    start = scope_meta.get("start") or ""
    end = scope_meta.get("end") or ""
    baseline_start = scope_meta.get("baseline_start") or ""
    baseline_end = scope_meta.get("baseline_end") or ""
    try:
        start_dt = datetime.fromisoformat(start.replace("Z", "+00:00"))
        end_dt = datetime.fromisoformat(end.replace("Z", "+00:00"))
        base_start_dt = datetime.fromisoformat(baseline_start.replace("Z", "+00:00"))
        base_end_dt = datetime.fromisoformat(baseline_end.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        return "Baseline comparison window is recorded in the artifact; strategy could not be inferred."
    if base_end_dt == start_dt and (end_dt - start_dt) == (base_end_dt - base_start_dt):
        return "Trailing equal-length prior window."
    if (start_dt - base_start_dt).days == 1 and start_dt.time() == base_start_dt.time():
        return "Same-hour prior-day comparison window."
    return "Artifact-supplied comparison window."


def _series_current_baseline_rows(scope_art: dict) -> list[dict]:
    rows: list[dict] = []
    series = ((scope_art.get("volume_timeseries") or {}).get("series") or {})
    for key, payload in series.items():
        current = _sum_numeric(payload.get("current") or [])
        baseline = _sum_numeric(payload.get("baseline") or [])
        delta = ((current - baseline) / max(baseline, 1.0)) * 100.0
        rows.append(
            {
                "metric": payload.get("label") or key.replace("_", " ").title(),
                "current": current,
                "current_display": _format_count(current),
                "baseline": baseline,
                "baseline_display": _format_count(baseline),
                "delta_pct": round(delta, 2),
                "delta_display": _format_signed_pct(delta),
                "source": "bot_incident_scope.v1 / volume_timeseries",
            }
        )
    return rows


def _build_baseline_context(scope_art: dict, scope_meta: dict) -> dict:
    return {
        "current_window": _build_windows_block(scope_meta)["current"],
        "baseline_window": _build_windows_block(scope_meta)["baseline"],
        "strategy": _baseline_strategy(scope_meta),
        "metric_rows": _series_current_baseline_rows(scope_art),
    }
