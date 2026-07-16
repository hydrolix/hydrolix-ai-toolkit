"""Stateless formatters used across the producer orchestrator.

Number coercion (``as_number``), reader-facing rendering
(``human_number``, ``pct``, ``pct_change``, ``label_change``), time-
window helpers (``parse_time``, ``sql_ts``, ``choose_granularity``),
and SQL-literal escapers (``sql_literal``, ``bucket_expr``). Every
helper is pure; none touch the network, disk, or environment.

These were originally module-level helpers on
``bot_insights_report.py``. Lifted here so per-report orchestrators
(soon to live under ``producers/orchestrators/``) and per-report SQL
builders (``producers/sql/``) can import them without dragging in the
4000-line orchestrator monolith.
"""

from __future__ import annotations

from datetime import datetime, timezone


def parse_time(value: str, label: str) -> datetime:
    """ISO-8601 → tz-aware ``datetime``, normalized to UTC.

    Accepts trailing ``Z`` for compatibility with the CLI surface
    every report's ``--start`` / ``--end`` / ``--baseline-start``
    flag exposes. ``label`` is interpolated into the error message
    so the caller doesn't have to wrap the call.
    """
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise SystemExit(
            f"--{label} must be ISO-8601, for example 2026-05-08T00:00:00Z"
        ) from exc
    if parsed.tzinfo is None:
        raise SystemExit(
            f"--{label} must include a timezone, for example 2026-05-08T00:00:00Z"
        )
    return parsed.astimezone(timezone.utc)


def sql_ts(value: datetime) -> str:
    """Render a ``datetime`` as ``YYYY-MM-DD HH:MM:SS`` for SQL literals."""
    return value.strftime("%Y-%m-%d %H:%M:%S")


def as_number(value):
    """Best-effort numeric coercion. Booleans are rejected (they
    coerce to int in Python but aren't honest numbers in evidence
    packets). Returns ``None`` for everything else that can't parse.
    """
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


def human_number(value, *, percent: bool = False, signed: bool = False) -> str:
    """Reader-facing rendering of a quantity.

    Returns ``"unavailable"`` when ``value is None``; the source
    string when value can't be coerced (so the renderer can still
    show what was there). Percentages get a fixed-precision ``%``
    suffix; magnitudes scale to ``K`` / ``M`` / ``B``. ``signed``
    forces a leading ``+`` on positives so deltas read consistently
    with their negative counterparts.
    """
    number = as_number(value)
    if number is None:
        return "unavailable" if value is None else str(value)
    sign = "+" if signed and number > 0 else ""
    if percent:
        return f"{sign}{number:.1f}%"
    abs_number = abs(number)
    if abs_number >= 1_000_000_000:
        return f"{sign}{number / 1_000_000_000:.2f}B"
    if abs_number >= 1_000_000:
        return f"{sign}{number / 1_000_000:.2f}M"
    if abs_number >= 1_000:
        return f"{sign}{number / 1_000:.2f}K"
    if number.is_integer():
        return f"{sign}{int(number):,}"
    return f"{sign}{number:,.2f}"


def pct(numerator, denominator):
    """Numerator / denominator as a percentage, or ``None`` when
    either side is missing or the denominator is zero. The
    denominator-zero guard matters because share-of-window math
    routinely divides by counters that can collapse to zero on
    quiet baselines."""
    numerator = as_number(numerator)
    denominator = as_number(denominator)
    if numerator is None or denominator in (None, 0):
        return None
    return numerator / denominator * 100


def pct_change(current, baseline):
    """``(current - baseline) / max(baseline, 1) * 100``. The
    ``max(baseline, 1)`` floor prevents divide-by-zero on quiet
    baselines and pegs the percent change to the absolute delta in
    that degenerate case (which reads as ``+N%`` rather than
    infinity).
    """
    current = as_number(current)
    baseline = as_number(baseline)
    if current is None or baseline is None:
        return None
    return (current - baseline) / max(baseline, 1) * 100


def label_change(value) -> str:
    """Qualitative banding of a percent change. Bands are
    ``flat`` / ``minor`` / ``moderate`` / ``material``; sign
    decides ``increase`` vs ``decrease``. Used wherever the
    renderer needs a verbal hint alongside the raw number."""
    number = as_number(value)
    if number is None:
        return "not evaluated"
    abs_number = abs(number)
    if abs_number < 1:
        return "flat"
    if abs_number < 10:
        return "minor increase" if number > 0 else "minor decrease"
    if abs_number < 50:
        return "moderate increase" if number > 0 else "moderate decrease"
    return "material increase" if number > 0 else "material decrease"


def choose_granularity(start: datetime, end: datetime) -> str:
    """Pick a summary-table granularity (``minute``/``hour``/``day``)
    for a given window. Boundaries are 180 minutes (= 3h) for
    minute → hour, and 2880 minutes (= 48h) for hour → day. Matches
    the ``bi_summary_<granularity>`` summary-table naming so the
    caller can compose the table name directly."""
    minutes = (end - start).total_seconds() / 60
    if minutes <= 0:
        raise SystemExit("--end must be later than --start")
    if minutes < 180:
        return "minute"
    if minutes < 2880:
        return "hour"
    return "day"


def sql_literal(value: str) -> str:
    """Single-quoted SQL string literal with backslash + single-quote
    escaping. The only quoting helper the orchestrator uses — every
    user-derived value (cluster name, host, asn, path pattern, table
    name, etc.) must route through this when interpolated into SQL.
    """
    return "'" + value.replace("\\", "\\\\").replace("'", "''") + "'"


def bucket_expr(column: str, granularity: str) -> str:
    """``toStartOf<Granularity>(column)`` for ClickHouse time bucketing."""
    if granularity == "minute":
        return f"toStartOfMinute({column})"
    if granularity == "hour":
        return f"toStartOfHour({column})"
    return f"toStartOfDay({column})"
