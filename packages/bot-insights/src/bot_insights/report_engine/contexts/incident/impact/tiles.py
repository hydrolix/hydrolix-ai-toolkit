"""KPI tile and impact view helpers for incident impact context."""

from __future__ import annotations

from ..formatters import (
    _format_count,
    _format_int,
    _format_pct,
    _format_signed_pct,
    _safe_number,
    _top_delta,
)
from .constants import _HOST_AFFECTED_CAP, _HOST_AFFECTED_SHARE_THRESHOLD
from .timeline import _window_timeline_view
from .volume import _volume_chart_view

__all__ = ['_impact_view']


def _edge_blocks_tile(requests: float, blocked_share: object) -> dict:
    """Edge-blocks tile, with em-dash fallback when no edge-block data
    is available (neither SIEM actionClass share nor action_applied
    share from raw akamai.logs)."""
    if blocked_share is None:
        return {
            "label": "Edge blocks",
            "value": "—",
            "sub": "no edge block data",
            "rank_score": 0,
        }
    blocked = float(blocked_share or 0)
    req_blocks = int(requests * blocked / 100.0) if requests else 0
    return {
        "label": "Edge blocks",
        "value": _format_count(req_blocks),
        "sub": _format_pct(blocked_share) + " of window",
        "rank_score": blocked,
    }


def _top_path_share_tile(paths_rows: list[dict]) -> dict:
    """Top-path-share tile (briefing.html v2). Falls back to em-dashes
    when the path_pattern_rows are empty so the strip never collapses."""
    top_path_row = paths_rows[0] if paths_rows else None
    if not top_path_row:
        return {
            "label": "Top path share",
            "value": "—",
            "sub": "no path data",
            "rank_score": 0,
        }
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
        "rank_score": abs(
            float(_safe_number(top_path_row.get("delta_vs_baseline_pct")) or 0)
        ) or float(_safe_number(top_path_row.get("share_pct")) or 0),
    }


def _requests_tile(requests: float, hosts_rows: list[dict]) -> dict:
    delta = _top_delta(hosts_rows)
    return {
        "label": "Requests",
        "value": _format_count(requests),
        "sub": _format_signed_pct(delta),
        "rank_score": abs(float(_safe_number(delta) or 0)),
    }


def _served_rate_tile(label: str, requests: float, rate_pct: float) -> dict:
    """Build a "X served" KPI tile (e.g. 429s, 5xx) from total + percentage."""
    served = int(requests * (rate_pct or 0) / 100.0) if requests else 0
    return {
        "label": label,
        "value": _format_count(served),
        "sub": _format_pct(rate_pct) + " of window",
        "rank_score": float(_safe_number(rate_pct) or 0),
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
            "rank_score": float(hosts_affected),
        },
        _top_path_share_tile(paths_rows),
    ]


def _projected_host_row(row: dict) -> dict:
    return {
        "value": str(row.get("value") or ""),
        "requests": _safe_number(row.get("requests")),
        "requests_display": _format_count(row.get("requests")),
        "share_pct": _safe_number(row.get("share_pct")),
        "share_pct_display": _format_pct(row.get("share_pct")),
        "delta_pct": _safe_number(row.get("delta_vs_baseline_pct")),
        "delta_pct_display": _format_signed_pct(
            row.get("delta_vs_baseline_pct")
        ),
    }


def _top_affected_hosts_view(scope_art: dict) -> dict | None:
    """Project the list of meaningfully-affected hosts for the
    "top affected" sentence.

    Returns a dict ``{hosts, cumulative_share_pct_display, is_fallback}``
    or None when no host data is present. ``hosts`` is the list of
    rows above the share threshold (capped at ``_HOST_AFFECTED_CAP``).
    ``is_fallback`` is True when no host crossed the threshold and the
    projection collapsed to the single top-ranked host.
    """
    hosts_rows = scope_art.get("top_targeted_hosts") or []
    if not hosts_rows:
        return None
    above = [
        row for row in hosts_rows
        if (row.get("share_pct") or 0) >= _HOST_AFFECTED_SHARE_THRESHOLD
    ]
    if above:
        selected = above[:_HOST_AFFECTED_CAP]
        is_fallback = False
    else:
        selected = hosts_rows[:1]
        is_fallback = True
    projected = [_projected_host_row(row) for row in selected]
    cumulative = sum(row.get("share_pct") or 0 for row in selected)
    return {
        "hosts": projected,
        "cumulative_share_pct_display": _format_pct(cumulative),
        "is_fallback": is_fallback,
    }


def _top_path_pattern_view(scope_art: dict) -> dict | None:
    """Project the single top-ranked path-pattern row for the
    "top path pattern" sentence. Returns None when no rows exist."""
    paths_rows = scope_art.get("top_targeted_path_patterns") or []
    if not paths_rows:
        return None
    top_path = paths_rows[0]
    return {
        "value": str(top_path.get("value") or ""),
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
        "top_affected_hosts": _top_affected_hosts_view(scope_art),
        "top_path_pattern": _top_path_pattern_view(scope_art),
        "window_timeline": _window_timeline_view(scope_art),
        "volume_chart": _volume_chart_view(scope_art),
    }
