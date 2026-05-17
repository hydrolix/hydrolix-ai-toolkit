"""Number / time formatters used across the incident-report views."""

from __future__ import annotations

from ...formatters import big_number
import baselines as baselines_mod  # type: ignore

__all__ = [
    '_safe_number',
    '_format_count',
    '_format_int',
    '_format_pct',
    '_format_signed_pct',
    '_top_delta',
    '_short_iso',
]


def _safe_number(value: object) -> float | int | None:
    number = baselines_mod.to_number(value)
    if number is None:
        return None
    try:
        return baselines_mod.clean_number(number)
    except ValueError:
        return None


def _format_count(value: object) -> str:
    number = baselines_mod.to_number(value)
    if number is None:
        return "—"
    try:
        return big_number(number)
    except Exception:
        return f"{int(number):,}"


def _format_int(value: object) -> str:
    number = baselines_mod.to_number(value)
    if number is None:
        return "—"
    return f"{int(number):,}"


def _format_pct(value: object) -> str:
    number = baselines_mod.to_number(value)
    if number is None:
        return "—"
    if abs(number) >= 100:
        return f"{number:.0f}%"
    if abs(number) >= 10:
        return f"{number:.1f}%"
    return f"{number:.2f}%"


def _format_signed_pct(value: object) -> str:
    number = baselines_mod.to_number(value)
    if number is None:
        return "—"
    sign = "+" if number > 0 else ""
    if abs(number) >= 100:
        return f"{sign}{number:.0f}%"
    if abs(number) >= 10:
        return f"{sign}{number:.1f}%"
    return f"{sign}{number:.2f}%"


def _top_delta(rows: list[dict]) -> object:
    """Pull the top-row delta-vs-baseline for the requests tile subscript."""
    if not rows:
        return None
    return rows[0].get("delta_vs_baseline_pct")


def _short_iso(value: str) -> str:
    """Render an ISO timestamp as a chart axis label (HH:MM UTC)."""
    if not value or "T" not in value:
        return value or ""
    try:
        date_part, rest = value.split("T", 1)
        hhmm = rest[:5]
        return f"{date_part} {hhmm}Z"
    except ValueError:
        return value
