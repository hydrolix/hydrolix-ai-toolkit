"""String/number/date formatters exposed to Jinja templates."""

from __future__ import annotations

import re
from datetime import datetime


def window_fmt(window: dict) -> str:
    """Format a {start,end} ISO window.

    Same-day windows collapse to 'YYYY-MM-DD HH:MM-HH:MM UTC' so the
    date doesn't repeat. Cross-day windows keep the full both-ends
    form 'YYYY-MM-DD HH:MM → YYYY-MM-DD HH:MM UTC'.
    """
    start = datetime.fromisoformat(window["start"].replace("Z", "+00:00"))
    end = datetime.fromisoformat(window["end"].replace("Z", "+00:00"))
    if start.date() == end.date():
        return f"{start:%Y-%m-%d %H:%M}-{end:%H:%M} UTC"
    return f"{start:%Y-%m-%d %H:%M} → {end:%Y-%m-%d %H:%M} UTC"


def _date_long(dt: datetime) -> str:
    """Long-form date suitable for editorial headlines: ``Apr 19, 2026``.

    Avoids ``%-d``/``%#d`` for portability — manually composes the
    day-of-month without the platform-dependent strftime modifier.
    """
    return f"{dt:%b} {dt.day}, {dt.year}"


def _hm_24(dt: datetime) -> str:
    return f"{dt:%H:%M}"


def _hm_12(dt: datetime) -> str:
    hour = dt.hour % 12 or 12
    return f"{hour}:{dt:%M}"


def _period_12(dt: datetime) -> str:
    return "AM" if dt.hour < 12 else "PM"


def headline_window_fmt(window: dict, clock: str = "12") -> str:
    """Format a ``{start, end}`` window for inclusion inside an editorial
    H1 headline.

    Produces a compact, human-readable rendering for the incident
    report's H1 parenthetical, e.g. ``"Apr 19, 2026 · 3:00–4:00 PM
    UTC"`` for the 12-hour clock or ``"Apr 19, 2026 · 15:00–16:00
    UTC"`` for the 24-hour clock. The 12-hour form omits a repeated
    period (PM/AM) when both endpoints fall in the same half.
    """
    start = datetime.fromisoformat(window["start"].replace("Z", "+00:00"))
    end = datetime.fromisoformat(window["end"].replace("Z", "+00:00"))

    if clock == "24":
        if start.date() == end.date():
            return (
                f"{_date_long(start)} · "
                f"{_hm_24(start)}–{_hm_24(end)} UTC"
            )
        return (
            f"{_date_long(start)} {_hm_24(start)} → "
            f"{_date_long(end)} {_hm_24(end)} UTC"
        )

    # 12-hour clock
    if start.date() == end.date():
        if _period_12(start) == _period_12(end):
            return (
                f"{_date_long(start)} · "
                f"{_hm_12(start)}–{_hm_12(end)} {_period_12(end)} UTC"
            )
        return (
            f"{_date_long(start)} · "
            f"{_hm_12(start)} {_period_12(start)}–"
            f"{_hm_12(end)} {_period_12(end)} UTC"
        )
    return (
        f"{_date_long(start)} {_hm_12(start)} {_period_12(start)} → "
        f"{_date_long(end)} {_hm_12(end)} {_period_12(end)} UTC"
    )


def big_number(value: float | int) -> str:
    """Compact human-readable number: 11.81B, 662.43M, 23.33K, 999."""
    n = float(value)
    sign = "-" if n < 0 else ""
    n = abs(n)
    for divisor, suffix in ((1e9, "B"), (1e6, "M"), (1e3, "K")):
        if n >= divisor:
            return f"{sign}{n / divisor:.2f}{suffix}"
    if n >= 1:
        return f"{sign}{n:.0f}"
    return f"{sign}{n:.2f}"


def signed_pct(value: float, digits: int = 1) -> str:
    """Format a percentage with explicit sign: +12.3%, -0.4%, ±0.0%."""
    if abs(value) < 10**-digits / 2:
        return f"±0.{'0' * digits}%"
    sign = "+" if value > 0 else ""
    return f"{sign}{value:.{digits}f}%"


def signed_pp(value: float, digits: int = 1) -> str:
    """Same as signed_pct but reads as percentage points (no % suffix)."""
    if abs(value) < 10**-digits / 2:
        return f"±0.{'0' * digits}pp"
    sign = "+" if value > 0 else ""
    return f"{sign}{value:.{digits}f}pp"


def format_share_pct(pct: float) -> str:
    """Format a fleet-share percent — drop trailing zero, preserve precision
    near 100% so a 99.97% reading doesn't round to a clean 100%."""
    if pct >= 99 and pct < 100:
        return f"{pct:.2f}%"
    if abs(pct - round(pct)) < 0.05:
        return f"{int(round(pct))}%"
    return f"{pct:.1f}%"


def pct2(value: float) -> str:
    """Format a number as a 2-decimal percent: 5 → '5.00%', 0.5 → '0.50%'.

    Reader-facing convention across this engine: any percentage uses two
    decimals.
    """
    return f"{value:.2f}%"


_PERCENT_RE = re.compile(r"(-?\d+(?:\.\d+)?)\s*%")


def normalize_percents(text: str) -> str:
    """Reformat any percentage embedded in a string to 2 decimals.

    Producer-supplied evidence sentences may carry full instrument precision
    (e.g. ``"Cache miss rate is 99.992029%."``). This filter normalizes
    embedded percentages to ``"99.99%"`` without disturbing surrounding
    prose. Safe to apply to arbitrary strings; no-op when no percentage
    pattern is present.
    """
    if not text:
        return text

    def _fix(match: re.Match[str]) -> str:
        return f"{float(match.group(1)):.2f}%"

    return _PERCENT_RE.sub(_fix, text)
