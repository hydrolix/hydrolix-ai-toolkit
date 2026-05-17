"""Top-of-report Impact strip and the per-bucket volume chart view."""

from __future__ import annotations

from datetime import datetime, timezone
from datetime import timedelta

from .formatters import (
    _format_count,
    _format_int,
    _format_pct,
    _format_signed_pct,
    _safe_number,
    _short_iso,
    _top_delta,
)

__all__ = [
    '_CHART_SELECTION_RULE',
    '_CHART_SELECTION_REASONS',
    '_impact_view',
    '_volume_chart_view',
    '_interpolate_time_label',
    '_duration_display',
    '_select_chart_series',
]


_CHART_SELECTION_RULE = [
    ("rate_429_up", "req_429_per_minute"),
    ("bot_share_up", "bot_like_requests_per_minute"),
    ("volume_up", "requests_per_minute"),
]


_CHART_SELECTION_REASONS = {
    "rate_429_up": (
        "rate_429_up was the most specific spike flag — the rate-limit "
        "pressure curve is the lede"
    ),
    "bot_share_up": (
        "bot_share_up was the most specific spike flag — the automation "
        "wave shape is the lede"
    ),
    "volume_up": (
        "volume_up was the dominant spike — total request volume is the lede"
    ),
}


def _edge_blocks_tile(requests: float, blocked_share: object) -> dict:
    """Edge-blocks tile, with em-dash fallback when no edge-block data
    is available (neither SIEM actionClass share nor action_applied
    share from raw akamai.logs)."""
    if blocked_share is None:
        return {"label": "Edge blocks", "value": "—", "sub": "no edge block data"}
    blocked = float(blocked_share or 0)
    req_blocks = int(requests * blocked / 100.0) if requests else 0
    return {
        "label": "Edge blocks",
        "value": _format_count(req_blocks),
        "sub": _format_pct(blocked_share) + " of window",
    }


def _top_path_share_tile(paths_rows: list[dict]) -> dict:
    """Top-path-share tile (briefing.html v2). Falls back to em-dashes
    when the path_pattern_rows are empty so the strip never collapses."""
    top_path_row = paths_rows[0] if paths_rows else None
    if not top_path_row:
        return {"label": "Top path share", "value": "—", "sub": "no path data"}
    path_label = str(top_path_row.get("value") or "")
    delta_display = _format_signed_pct(top_path_row.get("delta_vs_baseline_pct"))
    if path_label and delta_display != "—":
        sub = f"{path_label} · {delta_display}"
    elif path_label:
        sub = path_label
    else:
        sub = delta_display
    return {
        "label": "Top path share",
        "value": _format_pct(top_path_row.get("share_pct")),
        "sub": sub,
    }


def _requests_tile(requests: float, hosts_rows: list[dict]) -> dict:
    return {
        "label": "Requests",
        "value": _format_count(requests),
        "sub": _format_signed_pct(_top_delta(hosts_rows)),
    }


def _served_rate_tile(label: str, requests: float, rate_pct: float) -> dict:
    """Build a "X served" KPI tile (e.g. 429s, 5xx) from total + percentage."""
    served = int(requests * (rate_pct or 0) / 100.0) if requests else 0
    return {
        "label": label,
        "value": _format_count(served),
        "sub": _format_pct(rate_pct) + " of window",
    }


def _build_impact_tiles(scope_art: dict, window: dict) -> list[dict]:
    """Build the ordered KPI tiles for the Impact strip."""
    requests = _safe_number(window.get("requests")) or 0
    hosts_rows = scope_art.get("top_targeted_hosts") or []
    paths_rows = scope_art.get("top_targeted_path_patterns") or []
    hosts_affected = sum(
        1 for row in hosts_rows if (_safe_number(row.get("requests")) or 0) > 0
    )

    return [
        _requests_tile(requests, hosts_rows),
        _served_rate_tile("429s served", requests, window.get("rate_429_pct") or 0),
        _served_rate_tile("5xx served", requests, window.get("rate_5xx_pct") or 0),
        _edge_blocks_tile(requests, window.get("blocked_share_pct")),
        {
            "label": "Hosts affected",
            "value": _format_int(hosts_affected),
            "sub": "in window",
        },
        _top_path_share_tile(paths_rows),
    ]


def _top_affected_view(scope_art: dict) -> dict | None:
    """Compose the "top affected" sentence projection, or None when
    there isn't both a top host and a top path."""
    hosts_rows = scope_art.get("top_targeted_hosts") or []
    paths_rows = scope_art.get("top_targeted_path_patterns") or []
    top_host = hosts_rows[0] if hosts_rows else None
    top_path = paths_rows[0] if paths_rows else None
    if not (top_host and top_path):
        return None
    return {
        "host": str(top_host.get("value") or ""),
        "path_pattern": str(top_path.get("value") or ""),
        "requests": _safe_number(top_path.get("requests")),
        "requests_display": _format_count(top_path.get("requests")),
        "share_pct": _safe_number(top_path.get("share_pct")),
        "share_pct_display": _format_pct(top_path.get("share_pct")),
        "delta_pct": _safe_number(top_path.get("delta_vs_baseline_pct")),
        "delta_pct_display": _format_signed_pct(
            top_path.get("delta_vs_baseline_pct")
        ),
    }


def _impact_view(scope_art: dict) -> dict:
    """Build the top-of-report Impact strip + 'top affected' sentence.

    Six tiles in v2 (Peak/minute is deferred to Phase 3):
    Requests, 429s, 5xx, Edge blocks, Hosts affected, Top path share.
    Edge-blocks tile renders an em-dash placeholder when the producer
    could derive neither a SIEM-table actionClass share nor an
    action_applied share from raw ``akamai.logs``.

    Also projects a ``volume_chart`` block when the scope artifact
    carries a ``volume_timeseries`` field (per-minute or per-bucket
    request counts for current and baseline). Renders as a SVG chart
    above the KPI tiles; gracefully absent when the artifact has no
    timeseries data.
    """
    window = scope_art.get("window_confirmation") or {}
    return {
        "tiles": _build_impact_tiles(scope_art, window),
        "top_affected": _top_affected_view(scope_art),
        "volume_chart": _volume_chart_view(scope_art),
    }


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
    spike_flag = selected_series.get("spike_flag") or ""
    granularity = ts.get("granularity") or ""
    return {
        "current": current_values,
        "baseline": baseline_values,
        "peak_value": peak_value,
        "peak_value_display": _format_count(peak_value),
        "peak_index": peak_idx,
        "peak_fraction": peak_idx / (n - 1) if n > 1 else 0.5,
        "peak_time_display": _interpolate_time_label(start, end, peak_idx, n),
        "duration_display": _duration_display(scope_start, scope_end, n, granularity),
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
    from datetime import timedelta

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
