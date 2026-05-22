"""Volume chart projection helpers for incident impact context."""

from __future__ import annotations

from datetime import datetime, timedelta

from ..formatters import _format_count, _safe_number, _short_iso
from .constants import _CHART_SELECTION_REASONS, _CHART_SELECTION_RULE

__all__ = [
    '_volume_chart_view',
    '_interpolate_time_label',
    '_duration_display',
    '_select_chart_series',
]


def _resolve_chart_series_dict(ts: dict) -> dict:
    """Normalize the v1 / v2 timeseries payload shapes.

    Multi-series shape (v2): ``series`` dict keyed by metric name.
    Single-series shape (v1 back-compat): ``current`` + ``baseline``
    at top level, treated as the requests_per_minute series.
    """
    if "series" in ts:
        return ts.get("series") or {}
    if "current" in ts:
        return {
            "requests_per_minute": {
                "label": "Requests per minute",
                "spike_flag": "volume_up",
                "current": ts.get("current") or [],
                "baseline": ts.get("baseline") or [],
            }
        }
    return {}


def _clean_series_values(series: list) -> list[float]:
    out: list[float] = []
    for v in series:
        n = _safe_number(v)
        out.append(float(n) if n is not None else 0.0)
    return out


def _baseline_avg_display(baseline_values: list[float]) -> str | None:
    if not baseline_values:
        return None
    return _format_count(sum(baseline_values) / len(baseline_values))


def _chart_window_iso(
    ts: dict, scope_art: dict
) -> tuple[str, str, str, str]:
    """Resolve (start, end, scope_start, scope_end) for the chart window.

    The duration label reflects the *incident scope* window, not the
    chart's timeseries window — the chart often carries 24h of context
    for a 1h incident, and the operator-facing label should name the
    incident, not the chart's framing window.
    """
    scope_meta = scope_art.get("scope", {})
    start = ts.get("start") or scope_meta.get("start") or ""
    end = ts.get("end") or scope_meta.get("end") or ""
    scope_start = scope_meta.get("start") or ""
    scope_end = scope_meta.get("end") or ""
    return start, end, scope_start, scope_end


def _incident_window_fraction(
    chart_start_iso: str,
    chart_end_iso: str,
    scope_start_iso: str,
    scope_end_iso: str,
) -> tuple[float, float] | None:
    """Project the incident scope window onto the broader chart axis."""
    if not all((chart_start_iso, chart_end_iso, scope_start_iso, scope_end_iso)):
        return None
    try:
        chart_start = datetime.fromisoformat(chart_start_iso.replace("Z", "+00:00"))
        chart_end = datetime.fromisoformat(chart_end_iso.replace("Z", "+00:00"))
        scope_start = datetime.fromisoformat(scope_start_iso.replace("Z", "+00:00"))
        scope_end = datetime.fromisoformat(scope_end_iso.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    chart_seconds = (chart_end - chart_start).total_seconds()
    if chart_seconds <= 0 or scope_end <= chart_start or scope_start >= chart_end:
        return None
    start_f = (max(scope_start, chart_start) - chart_start).total_seconds() / chart_seconds
    end_f = (min(scope_end, chart_end) - chart_start).total_seconds() / chart_seconds
    if end_f <= start_f:
        return None
    return start_f, end_f


def _fractions_differ(
    first: tuple[float, float] | None,
    second: tuple[float, float] | None,
) -> bool:
    if first is None or second is None:
        return False
    return abs(first[0] - second[0]) > 0.001 or abs(first[1] - second[1]) > 0.001


def _build_chart_context(
    scope_art: dict,
    ts: dict,
    selected_name: str,
    selected_series: dict,
    current_values: list[float],
    baseline_values: list[float],
) -> dict:
    """Final shaping step: project the cleaned series into chart-ready dict."""
    peak_value = max(current_values)
    peak_idx = current_values.index(peak_value)
    n = len(current_values)
    start, end, scope_start, scope_end = _chart_window_iso(ts, scope_art)
    scope_fraction = _incident_window_fraction(start, end, scope_start, scope_end)
    detection = scope_art.get("incident_detection") or {}
    detected_fraction = _incident_window_fraction(
        start,
        end,
        detection.get("detected_start") or "",
        detection.get("detected_end") or "",
    )
    primary_fraction = detected_fraction or scope_fraction
    scoped_marker_fraction = (
        scope_fraction if _fractions_differ(detected_fraction, scope_fraction) else None
    )
    spike_flag = selected_series.get("spike_flag") or ""
    granularity = ts.get("granularity") or ""
    duration_display = _duration_display(scope_start, scope_end, n, granularity)
    detected_duration_display = _duration_display(
        detection.get("detected_start") or "",
        detection.get("detected_end") or "",
        n,
        granularity,
    )
    detected_label = (
        f"Detected anomaly period ({detected_duration_display})"
        if detected_duration_display else "Detected anomaly period"
    )
    return {
        "current": current_values,
        "baseline": baseline_values,
        "peak_value": peak_value,
        "peak_value_display": _format_count(peak_value),
        "peak_index": peak_idx,
        "peak_fraction": peak_idx / (n - 1) if n > 1 else 0.5,
        "peak_time_display": _interpolate_time_label(start, end, peak_idx, n),
        "duration_display": duration_display,
        "incident_window_label": (
            f"Incident window ({duration_display})" if duration_display else "Incident window"
        ),
        "detected_window_label": detected_label,
        "highlight_label": detected_label if detected_fraction else (
            f"Incident window ({duration_display})" if duration_display else "Incident window"
        ),
        "incident_highlight_start": primary_fraction[0] if primary_fraction else None,
        "incident_highlight_end": primary_fraction[1] if primary_fraction else None,
        "scoped_analysis_highlight_start": (
            scoped_marker_fraction[0] if scoped_marker_fraction else None
        ),
        "scoped_analysis_highlight_end": (
            scoped_marker_fraction[1] if scoped_marker_fraction else None
        ),
        "has_incident_detection": bool(detected_fraction),
        "left_label": _short_iso(start),
        "right_label": _short_iso(end),
        "metric_name": selected_name,
        "metric_label": selected_series.get("label") or selected_name.replace("_", " "),
        "selection_reason": _CHART_SELECTION_REASONS.get(
            spike_flag, "default — total volume tells the story"
        ),
        "baseline_avg_display": _baseline_avg_display(baseline_values),
        "granularity": granularity,
    }


def _volume_chart_view(scope_art: dict) -> dict | None:
    """Project ``volume_timeseries`` into chart-ready context, or None.

    Returns a dict the template feeds into ``incident_volume_chart()``
    plus a peak label, left/right time labels, and a textual summary.
    Returns ``None`` when the artifact does not carry timeseries data
    (e.g. degraded clusters, v1 wrappers from before this field
    existed), so the template can ``{% if impact.volume_chart %}``
    around it.

    Series selection is mechanical, driven by the dominant spike flag:
      - ``rate_429_up`` fired → plot 429s/minute (rate-limit story)
      - ``bot_share_up`` fired → plot bot-classified/minute
      - default → plot total requests/minute (volume story)
    See :func:`_select_chart_series`. Same inputs produce the same
    chart choice; the rule is unit-tested in tests/test_report_engine.py.
    """
    ts = scope_art.get("volume_timeseries") or {}
    series_dict = _resolve_chart_series_dict(ts)
    if not series_dict:
        return None

    spike_flags = list(
        (scope_art.get("window_confirmation") or {}).get("spike_flags") or []
    )
    selected_name, selected_series = _select_chart_series(series_dict, spike_flags)
    if selected_series is None:
        return None

    current_values = _clean_series_values(selected_series.get("current") or [])
    if len(current_values) < 2:
        return None
    baseline = selected_series.get("baseline") or []
    baseline_values = _clean_series_values(baseline) if len(baseline) >= 2 else []

    return _build_chart_context(
        scope_art, ts, selected_name, selected_series,
        current_values, baseline_values,
    )


def _interpolate_time_label(
    start_iso: str, end_iso: str, idx: int, n: int
) -> str:
    """Return a clock-friendly UTC label for index ``idx`` along
    [start_iso, end_iso] (n samples).

    Returns empty string when the timestamps don't parse cleanly. The
    label is intentionally clock-only (HH:MM UTC); the date is already
    in the window line above the chart.
    """
    if not start_iso or not end_iso or n <= 1:
        return ""
    try:
        start_dt = datetime.fromisoformat(start_iso.replace("Z", "+00:00"))
        end_dt = datetime.fromisoformat(end_iso.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return ""
    total = (end_dt - start_dt).total_seconds()
    if total <= 0:
        return ""
    fraction = idx / (n - 1)
    peak_seconds = total * fraction
    peak_dt = start_dt + timedelta(seconds=peak_seconds)
    return f"{peak_dt:%H:%M} UTC"


def _duration_display(
    start_iso: str, end_iso: str, n: int, granularity: str
) -> str:
    """Return a humanized duration ("1 hour", "12 hours", "45 minutes").

    Computed from the timestamp delta; granularity is accepted so the
    label can shade to the producer's sampling step when timestamps are
    coarse. Returns empty string when parsing fails.
    """
    del n, granularity  # reserved for future granularity-aware rendering
    if not start_iso or not end_iso:
        return ""
    try:
        start_dt = datetime.fromisoformat(start_iso.replace("Z", "+00:00"))
        end_dt = datetime.fromisoformat(end_iso.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return ""
    seconds = int((end_dt - start_dt).total_seconds())
    if seconds <= 0:
        return ""
    if seconds % 3600 == 0:
        hours = seconds // 3600
        return f"{hours} hour" if hours == 1 else f"{hours} hours"
    if seconds >= 3600:
        hours = seconds / 3600
        return f"{hours:.1f} hours"
    minutes = max(1, seconds // 60)
    return f"{minutes} minute" if minutes == 1 else f"{minutes} minutes"


def _select_chart_series(
    series_dict: dict, spike_flags: list[str]
) -> tuple[str, dict | None]:
    """Mechanical chart-series selection from the dominant spike flag.

    Walks :data:`_CHART_SELECTION_RULE` in order; the first rule where
    (a) the spike flag is in ``spike_flags`` AND (b) the series is
    present in ``series_dict`` wins. Falls back to whatever's first in
    ``series_dict`` if nothing matches — common case is volume_up
    being the only fired flag, and ``requests_per_minute`` is the
    natural default series.

    Returns ``(metric_name, series_dict_entry)``. The entry is
    ``None`` only when ``series_dict`` is empty.
    """
    if not series_dict:
        return "", None
    spike_set = set(spike_flags)
    for spike_flag, metric_name in _CHART_SELECTION_RULE:
        if spike_flag in spike_set and metric_name in series_dict:
            return metric_name, series_dict[metric_name]
    # Fallback: first key in insertion order. Python dicts preserve
    # insertion order since 3.7, so this is deterministic.
    fallback_name = next(iter(series_dict))
    return fallback_name, series_dict[fallback_name]
