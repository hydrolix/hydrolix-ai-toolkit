"""Window-confirmation block + scope-filter / short-window helpers."""

from __future__ import annotations

from datetime import datetime, timezone

from .formatters import (
    _format_count,
    _format_pct,
    _safe_number,
)
from .labels import SPIKE_FLAG_LABELS

__all__ = [
    '_window_confirmation_view',
    '_scope_filters',
    '_short_window',
]


def _window_confirmation_view(window: dict) -> dict:
    spike_flags = window.get("spike_flags") or []
    blocked_share = window.get("blocked_share_pct")
    tiles = [
        {
            "label": "Requests",
            "value": _format_count(window.get("requests")),
            "raw": _safe_number(window.get("requests")),
        },
        {
            "label": "Bot share",
            "value": _format_pct(window.get("bot_share_pct")),
            "raw": _safe_number(window.get("bot_share_pct")),
        },
        {
            "label": "429 rate",
            "value": _format_pct(window.get("rate_429_pct")),
            "raw": _safe_number(window.get("rate_429_pct")),
        },
        {
            "label": "5xx rate",
            "value": _format_pct(window.get("rate_5xx_pct")),
            "raw": _safe_number(window.get("rate_5xx_pct")),
        },
    ]
    if blocked_share is not None:
        tiles.append(
            {
                "label": "Edge blocked share",
                "value": _format_pct(blocked_share),
                "raw": _safe_number(blocked_share),
            }
        )
    return {
        "tiles": tiles,
        "spike_flags": [
            {
                "name": flag,
                "label": SPIKE_FLAG_LABELS.get(
                    flag, flag.replace("_", " ").capitalize()
                ),
            }
            for flag in spike_flags
        ],
    }


def _scope_filters(
    host: str | None, asn: str | int | None, path_pattern: str | None
) -> list[dict]:
    parts: list[dict] = []
    if host:
        parts.append({"label": "Host", "value": host})
    if asn not in (None, ""):
        parts.append({"label": "ASN", "value": str(asn)})
    if path_pattern:
        parts.append({"label": "Path pattern", "value": path_pattern})
    return parts


def _short_window(scope_meta: dict) -> str:
    """Render a scope window as a compact headline label.

    Same-day windows collapse to 'YYYY-MM-DD HH:MM-HH:MM UTC' (the
    common case for incident reports — a 3-hour spike inside one day).
    Cross-day windows fall back to a date range. Malformed timestamps
    drop through to a string-only fallback.
    """
    start = scope_meta.get("start") or ""
    end = scope_meta.get("end") or ""

    if not start and not end:
        return ""

    try:
        start_dt = datetime.fromisoformat(start.replace("Z", "+00:00"))
        end_dt = datetime.fromisoformat(end.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        # Date-only fallback for non-ISO inputs.
        def _date(v: str) -> str:
            return v.split("T", 1)[0] if "T" in v else v

        return f"{_date(start)} → {_date(end)}"

    if start_dt.date() == end_dt.date():
        return f"{start_dt:%Y-%m-%d %H:%M}-{end_dt:%H:%M} UTC"
    return f"{start_dt:%Y-%m-%d} → {end_dt:%Y-%m-%d}"
