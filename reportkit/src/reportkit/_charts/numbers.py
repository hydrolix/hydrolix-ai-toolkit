"""Numeric formatting helpers for chart labels."""

from __future__ import annotations


def _fmt_compact(value: float) -> str:
    """Compact-format a numeric for chart axis labels (1.2M, 340K, etc.)."""
    n = float(value)
    abs_n = abs(n)
    if abs_n >= 1_000_000_000:
        return f"{n / 1_000_000_000:.1f}B"
    if abs_n >= 1_000_000:
        return f"{n / 1_000_000:.1f}M"
    if abs_n >= 1_000:
        return f"{n / 1_000:.0f}K"
    if abs_n >= 100:
        return f"{n:.0f}"
    return f"{n:.1f}"
