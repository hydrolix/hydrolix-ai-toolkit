"""Temporal progression projection for incident narrative context."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from ..formatters import _format_count


def _largest_series_delta(points: list[dict]) -> str | None:
    totals: dict[str, int] = {}
    for point in points:
        value = str(point.get("value") or "")
        if value:
            totals[value] = totals.get(value, 0) + int(float(point.get("requests") or 0))
    if len(totals) < 2:
        return None
    top = sorted(totals.items(), key=lambda kv: -kv[1])[:2]
    return f"{top[0][0]} led the mix ahead of {top[1][0]}."


def _parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def _format_ts(value: datetime) -> str:
    normalized = value.astimezone(timezone.utc)
    return normalized.strftime("%Y-%m-%d %H:%M UTC")


def _granularity_delta(granularity: str | None) -> timedelta | None:
    text = str(granularity or "").lower()
    if text == "minute":
        return timedelta(minutes=1)
    if text == "hour":
        return timedelta(hours=1)
    if text == "day":
        return timedelta(days=1)
    return None


def _duration_phrase(bucket_count: int, step: timedelta | None) -> str | None:
    if bucket_count <= 0 or step is None:
        return None
    seconds = int(bucket_count * step.total_seconds())
    if seconds < 3600:
        minutes = max(1, round(seconds / 60))
        return f"{minutes} minute{'s' if minutes != 1 else ''}"
    if seconds < 86400:
        hours = round(seconds / 3600, 1)
        hours_text = str(int(hours)) if hours.is_integer() else str(hours)
        return f"{hours_text} hour{'s' if hours != 1 else ''}"
    days = round(seconds / 86400, 1)
    days_text = str(int(days)) if days.is_integer() else str(days)
    return f"{days_text} day{'s' if days != 1 else ''}"


def _bucket_time(
    start: datetime | None,
    step: timedelta | None,
    index: int,
) -> datetime | None:
    if start is None or step is None:
        return None
    return start + (step * index)


def _temporal_progression_view(scope_art: dict) -> dict:
    volume = scope_art.get("volume_timeseries") or {}
    series = (volume.get("series") or {}).get("requests_per_minute") or {}
    current = [int(float(v or 0)) for v in (series.get("current") or [])]
    evidence_ts = scope_art.get("evidence_timeseries") or {}
    if not current and not any(evidence_ts.values()):
        return {
            "available": False,
            "summary": "Temporal progression is not available in this artifact.",
            "bullets": [],
        }

    bullets: list[str] = []
    if current:
        bullets.extend(_volume_progression_bullets(current, volume, scope_art))

    for key, label in (
        ("cohorts", "Cohort mix"),
        ("paths", "Path mix"),
        ("edge_actions", "Edge action mix"),
    ):
        block = evidence_ts.get(key) or {}
        delta = _largest_series_delta(block.get("points") or [])
        if delta:
            bullets.append(f"{label}: {delta}")

    return {
        "available": True,
        "summary": "Temporal progression is derived from bucketed producer evidence.",
        "bullets": bullets[:6],
    }


def _volume_progression_bullets(
    current: list[int],
    volume: dict,
    scope_art: dict,
) -> list[str]:
    scope = scope_art.get("scope") or {}
    start = _parse_ts(volume.get("start") or scope.get("start"))
    end = _parse_ts(volume.get("end") or scope.get("end"))
    step = _granularity_delta(volume.get("granularity") or scope.get("granularity"))
    peak_value = max(current)
    peak_index = current.index(peak_value)
    first_nonzero = next((i for i, v in enumerate(current) if v > 0), 0)
    last_nonzero = len(current) - 1 - next(
        (i for i, v in enumerate(reversed(current)) if v > 0),
        0,
    )
    peak_time = _bucket_time(start, step, peak_index)
    bullets = _ramp_and_peak_bullets(
        first_nonzero, peak_index, peak_value, peak_time, start, step, volume
    )
    bullets.extend(_sustain_and_taper_bullets(
        current, last_nonzero, peak_index, peak_value, peak_time, start, step, end
    ))
    return bullets


def _ramp_and_peak_bullets(
    first_nonzero: int,
    peak_index: int,
    peak_value: int,
    peak_time: datetime | None,
    start: datetime | None,
    step: timedelta | None,
    volume: dict,
) -> list[str]:
    bullets: list[str] = []
    first_time = _bucket_time(start, step, first_nonzero)
    if first_nonzero < peak_index:
        duration = _duration_phrase(peak_index - first_nonzero, step)
        if first_time and peak_time and duration:
            bullets.append(
                f"Ramp built for {duration}, from {_format_ts(first_time)} to the peak at {_format_ts(peak_time)}."
            )
        else:
            bullets.append("Ramp was visible before the peak bucket.")
    if peak_time:
        bullets.append(
            f"Peak arrived at {_format_ts(peak_time)} with {_format_count(peak_value)} requests in the {volume.get('granularity') or 'bucket'} bucket."
        )
    else:
        bullets.append(
            f"Peak bucket was bucket {peak_index + 1} with {_format_count(peak_value)} requests."
        )
    return bullets


def _sustain_and_taper_bullets(
    current: list[int],
    last_nonzero: int,
    peak_index: int,
    peak_value: int,
    peak_time: datetime | None,
    start: datetime | None,
    step: timedelta | None,
    end: datetime | None,
) -> list[str]:
    bullets: list[str] = []
    last_time = _bucket_time(start, step, last_nonzero)
    if last_nonzero > peak_index:
        duration = _duration_phrase(last_nonzero - peak_index, step)
        if peak_time and last_time and duration:
            bullets.append(
                f"Sustained pressure continued for {duration} after peak, through {_format_ts(last_time)}."
            )
        else:
            bullets.append("Sustained pressure continued after the peak bucket.")
    if current[-1] < peak_value:
        if end:
            bullets.append(
                f"Taper or recovery was visible by the window close at {_format_ts(end)}."
            )
        else:
            bullets.append("Taper or recovery was visible by the final bucket.")
    return bullets
