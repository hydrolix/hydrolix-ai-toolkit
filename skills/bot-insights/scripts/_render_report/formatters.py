"""Number / time / markdown / html string formatters + slug helpers."""

from __future__ import annotations

import html
import re
from datetime import datetime, timezone
from typing import Any
from report_engine.humanize import stringify

__all__ = [
    'human_number',
    'human_delta',
    'human_window_range',
    'compact_window_range',
    'human_timestamp',
    'parse_utc_timestamp',
    'human_windows',
    'to_float',
    'clean_display',
    '_MD_BACKSLASH_CHARS',
    'md_escape',
    '_demd',
    '_is_escaped_marker',
    '_find_unescaped',
    'h_escape',
    'slug_title',
]


def human_number(value: Any, *, percent: bool = False) -> str:
    number = to_float(value)
    if number is None:
        return stringify(value)
    abs_number = abs(number)
    if percent:
        return f"{number:+.1f}%"
    if abs_number >= 1_000_000_000:
        return f"{number / 1_000_000_000:.2f}B"
    if abs_number >= 1_000_000:
        return f"{number / 1_000_000:.2f}M"
    if abs_number >= 1_000:
        return f"{number / 1_000:.2f}K"
    if float(number).is_integer():
        return f"{int(number):,}"
    return f"{number:,.2f}"


def human_delta(value: Any) -> str:
    number = to_float(value)
    if number is None:
        return stringify(value)
    sign = "+" if number > 0 else ""
    return sign + human_number(number)


def human_window_range(window: Any) -> str:
    if not isinstance(window, dict):
        return stringify(window)
    start = human_timestamp(window.get("start") or "unknown")
    end = human_timestamp(window.get("end") or "unknown")
    return f"{start} to {end}"


def compact_window_range(window: Any) -> str:
    if not isinstance(window, dict):
        return stringify(window)
    start = parse_utc_timestamp(window.get("start"))
    end = parse_utc_timestamp(window.get("end"))
    if start is None or end is None:
        return human_window_range(window)
    start_date = start.strftime("%b %-d, %Y")
    start_time = start.strftime("%H:%M")
    end_time = end.strftime("%H:%M")
    if end.date() == start.date():
        return f"{start_date}, {start_time}-{end_time} UTC"
    if (end - start).total_seconds() == 86400 and end_time == "00:00":
        return f"{start_date}, {start_time}-24:00 UTC"
    end_date = end.strftime("%b %-d, %Y")
    return f"{start_date} {start_time} - {end_date} {end_time} UTC"


def human_timestamp(value: Any) -> str:
    if not isinstance(value, str):
        return stringify(value)
    match = re.fullmatch(
        r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::\d{2})?Z",
        value,
    )
    if not match:
        return value
    year, month, day, hour, minute = match.groups()
    return f"{year}-{month}-{day} {hour}:{minute} UTC"


def parse_utc_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
            return datetime.fromisoformat(value).replace(tzinfo=timezone.utc)
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except ValueError:
        return None


def human_windows(artifact: dict[str, Any]) -> str:
    current = artifact.get("current_window")
    baselines = artifact.get("baseline_windows")
    parts: list[str] = []
    if current:
        parts.append(f"current {human_window_range(current)}")
    if isinstance(baselines, list) and baselines:
        parts.append(f"baseline {human_window_range(baselines[0])}")
    return "; ".join(parts) if parts else "unavailable"


def to_float(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None


def clean_display(value: float) -> int | float:
    if value.is_integer():
        return int(value)
    return round(value, 6)


_MD_BACKSLASH_CHARS = "`*_{}[]()#+-.!"


def md_escape(value: Any) -> str:
    text = stringify(value)
    text = text.replace("\r\n", " ").replace("\n", " ").replace("\r", " ")
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    text = text.replace("\\", "\\\\")
    text = text.replace("|", "\\|")
    out_chars: list[str] = []
    for ch in text:
        if ch in _MD_BACKSLASH_CHARS:
            out_chars.append("\\" + ch)
        else:
            out_chars.append(ch)
    return "".join(out_chars)


def _demd(text: str) -> str:
    return re.sub(r"\\([\\`*_{}\[\]()#+\-.!|])", r"\1", text)


def _is_escaped_marker(text: str, index: int) -> bool:
    slash_count = 0
    cursor = index - 1
    while cursor >= 0 and text[cursor] == "\\":
        slash_count += 1
        cursor -= 1
    return slash_count % 2 == 1


def _find_unescaped(text: str, marker: str, start: int = 0) -> int:
    cursor = start
    while True:
        index = text.find(marker, cursor)
        if index == -1:
            return -1
        if not _is_escaped_marker(text, index):
            return index
        cursor = index + 1


def h_escape(value: Any) -> str:
    return html.escape(html.unescape(stringify(value)), quote=True)


def slug_title(report_type: str) -> str:
    return report_type.replace("_", " ").title()
