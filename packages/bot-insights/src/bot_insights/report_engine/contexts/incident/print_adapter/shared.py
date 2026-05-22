"""Shared helpers for incident print-report context adaptation."""

from __future__ import annotations

import html
from datetime import datetime
from typing import Any

def _text(value: Any, default: str = "") -> str:
    if value is None:
        return default
    return str(value)

def _clean_print_claim_language(value: str) -> str:
    return value.replace("root cause", "causal attribution").replace(
        "Root cause", "Causal attribution"
    )

def _fmt_dt(value: str, fmt: str) -> str:
    if not value:
        return ""
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return value
    return parsed.strftime(fmt)

def _parse_dt(value: str) -> datetime | None:
    if not value:
        return None
    normalized = value.replace("Z", "+00:00")
    for fmt in ("%Y-%m-%d %H:%M%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return datetime.strptime(normalized, fmt)
        except ValueError:
            pass
    try:
        return datetime.fromisoformat(normalized)
    except ValueError:
        return None

def _window(ctx: dict[str, Any]) -> dict[str, str]:
    current = (ctx.get("windows") or {}).get("current") or {}
    start = _text(current.get("start"))
    end = _text(current.get("end"))
    return {
        "date": _fmt_dt(start, "%b %d, %Y") or "Incident window",
        "start": _fmt_dt(start, "%H:%M") or start,
        "end": _fmt_dt(end, "%H:%M") or end,
        "tz": "UTC",
        "duration_short": "current window",
    }

def _compact(value: float | int | None) -> str:
    value = float(value or 0)
    if value >= 1_000_000:
        return f"{value / 1_000_000:.1f}M"
    if value >= 1_000:
        return f"{value / 1_000:.1f}K"
    return str(int(round(value)))

def _html(value: Any) -> str:
    return html.escape(_clean_print_claim_language(_text(value)))

def _prose(value: Any) -> str:
    text = _clean_print_claim_language(_text(value))
    try:
        from ...markdown import render_safe

        return str(render_safe(text))
    except ModuleNotFoundError:
        escaped = html.escape(text)
        escaped = escaped.replace("**", "")
        return f"<p>{escaped}</p>" if escaped else ""

def _join_phrase(items: list[str]) -> str:
    if len(items) <= 1:
        return "".join(items)
    return ", ".join(items[:-1]) + f" and {items[-1]}"

def _first_sentence(value: Any) -> str:
    text = " ".join(_text(value).split())
    if not text:
        return ""
    sentence, sep, _rest = text.partition(". ")
    return f"{sentence}." if sep else text

def _short_user_agent(value: Any, limit: int = 74) -> str:
    text = " ".join(_text(value).split())
    if len(text) <= limit:
        return text
    return f"{text[: max(0, limit - 3)].rstrip()}..."
