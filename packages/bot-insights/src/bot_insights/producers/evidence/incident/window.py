"""Incident window and volume-timeseries evidence shaping."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

def _incident_split_period_rows(rows: list[dict], *, source: str) -> dict:
    """Bucket UNION-ALL rows by ``period`` for a given ``source`` tag."""
    out: dict[str, dict] = {"current": {}, "baseline": {}}
    for row in rows:
        if row.get("source") != source:
            continue
        period = row.get("period")
        if period in out:
            out[period] = row
    return out
def _incident_compute_window_confirmation(
    rows: list[dict], siem_available: bool
) -> tuple[dict, dict]:
    """Return ``(window_confirmation, baseline_stats)`` from the phase-1 rows."""
    import baselines as baselines_mod

    summary = _incident_split_period_rows(rows, source="summary")
    current = summary.get("current") or {}
    baseline = summary.get("baseline") or {}

    def _num(row: dict, key: str) -> float:
        n = baselines_mod.to_number(row.get(key))
        return float(n) if n is not None else 0.0

    raw = _incident_split_period_rows(rows, source="raw")
    raw_current = raw.get("current") or {}
    raw_baseline = raw.get("baseline") or {}
    source = "summary"

    if _num(current, "requests") <= 0 and _num(raw_current, "requests") > 0:
        current = raw_current
        baseline = raw_baseline
        source = "raw"

    requests_current = _num(current, "requests")
    requests_baseline = _num(baseline, "requests")
    bot_current = _num(current, "bot_like_requests")
    bot_baseline = _num(baseline, "bot_like_requests")
    req_429_current = _num(current, "req_429")
    req_429_baseline = _num(baseline, "req_429")
    req_5xx_current = _num(current, "req_5xx")
    req_5xx_baseline = _num(baseline, "req_5xx")

    def _share(num: float, denom: float) -> float:
        return 100.0 * num / denom if denom > 0 else 0.0

    bot_share = _share(bot_current, requests_current)
    rate_429 = _share(req_429_current, requests_current)
    rate_5xx = _share(req_5xx_current, requests_current)
    blocked_share = _incident_blocked_share(
        rows, raw_current, siem_available, _num, _share
    )
    spike_flags = _incident_spike_flags(
        requests_current,
        requests_baseline,
        bot_current,
        bot_baseline,
        req_429_current,
        req_429_baseline,
        req_5xx_current,
        req_5xx_baseline,
    )

    window_confirmation = {
        "requests": int(requests_current),
        "bot_share_pct": baselines_mod.clean_number(round(bot_share, 2)),
        "rate_429_pct": baselines_mod.clean_number(round(rate_429, 2)),
        "rate_5xx_pct": baselines_mod.clean_number(round(rate_5xx, 2)),
        "blocked_share_pct": (
            baselines_mod.clean_number(round(blocked_share, 2))
            if blocked_share is not None
            else None
        ),
        "spike_flags": spike_flags,
        "source": source,
    }
    baseline_stats = {
        "requests": int(requests_baseline),
        "bot_like_requests": int(bot_baseline),
        "req_429": int(req_429_baseline),
        "req_5xx": int(req_5xx_baseline),
    }
    return window_confirmation, baseline_stats
def _incident_blocked_share(
    rows: list[dict],
    raw_current: dict,
    siem_available: bool,
    num,
    share,
) -> float | None:
    if siem_available:
        siem = _incident_split_period_rows(rows, source="siem")
        siem_current = siem.get("current") or {}
        siem_requests = num(siem_current, "requests")
        siem_blocked = num(siem_current, "blocked")
        return share(siem_blocked, siem_requests) if siem_requests > 0 else 0.0
    raw_requests = num(raw_current, "requests")
    denied = num(raw_current, "denied_requests")
    monitored = num(raw_current, "monitored_requests")
    if raw_requests > 0:
        return share(denied + monitored, raw_requests)
    return None
def _incident_spike_flags(
    requests_current: float,
    requests_baseline: float,
    bot_current: float,
    bot_baseline: float,
    req_429_current: float,
    req_429_baseline: float,
    req_5xx_current: float,
    req_5xx_baseline: float,
) -> list[str]:
    import baselines as baselines_mod

    checks = [
        ("volume_up", requests_current, requests_baseline),
        ("bot_share_up", bot_current, bot_baseline),
        ("rate_429_up", req_429_current, req_429_baseline),
        ("rate_5xx_up", req_5xx_current, req_5xx_baseline),
    ]
    return [
        flag
        for flag, current, baseline in checks
        if baselines_mod.pct_delta(current, baseline) >= 25
    ]
_INCIDENT_GRANULARITY_DELTA = {
    "minute": timedelta(minutes=1),
    "hour": timedelta(hours=1),
    "day": timedelta(days=1),
}
def _incident_compute_timeseries(
    rows: list[dict],
    *,
    granularity: str,
    current_start: datetime,
    current_end: datetime,
    baseline_start: datetime,
    baseline_end: datetime,
) -> dict | None:
    """Reshape per-bucket timeseries rows into the artifact's volume_timeseries field.

    Fills missing buckets with 0 so the chart's polyline does not get
    short-circuited by holes (a quiet baseline minute is still a
    legitimate data point). Returns ``None`` if no rows came back; the
    renderer then omits the chart instead of rendering an empty box.

    Series keys are stable identifiers (``requests_per_minute`` etc.)
    regardless of actual granularity — the chart-series selection rule
    in ``contexts/incident_report.py`` switches on these names. The
    bucket size is carried separately in the ``granularity`` field and
    used to humanize the chart labels.
    """
    import baselines as baselines_mod

    if not rows:
        return None

    bucket_delta = _INCIDENT_GRANULARITY_DELTA.get(
        granularity, timedelta(minutes=1)
    )

    indexed: dict[tuple[str, datetime], dict] = {}
    for r in rows:
        period = r.get("period")
        bucket = _incident_bucket_datetime(r.get("bucket"))
        if period in ("current", "baseline") and bucket is not None:
            indexed[(period, bucket)] = r

    granularity_label = granularity if granularity in ("minute", "hour", "day") else "minute"

    return {
        "granularity": granularity_label,
        "start": current_start.isoformat().replace("+00:00", "Z"),
        "end": current_end.isoformat().replace("+00:00", "Z"),
        "baseline_start": baseline_start.isoformat().replace("+00:00", "Z"),
        "baseline_end": baseline_end.isoformat().replace("+00:00", "Z"),
        "series": {
            "requests_per_minute": {
                "label": f"Requests per {granularity_label}",
                "spike_flag": "volume_up",
                "current": _incident_series_for(
                    indexed, bucket_delta, "current", current_start, current_end, "requests"
                ),
                "baseline": _incident_series_for(
                    indexed, bucket_delta, "baseline", baseline_start, baseline_end, "requests"
                ),
            },
            "req_429_per_minute": {
                "label": f"429s per {granularity_label}",
                "spike_flag": "rate_429_up",
                "current": _incident_series_for(
                    indexed, bucket_delta, "current", current_start, current_end, "req_429"
                ),
                "baseline": _incident_series_for(
                    indexed, bucket_delta, "baseline", baseline_start, baseline_end, "req_429"
                ),
            },
            "bot_like_requests_per_minute": {
                "label": f"Bot-classified requests per {granularity_label}",
                "spike_flag": "bot_share_up",
                "current": _incident_series_for(
                    indexed, bucket_delta, "current", current_start, current_end, "bot_like_requests"
                ),
                "baseline": _incident_series_for(
                    indexed, bucket_delta, "baseline", baseline_start, baseline_end, "bot_like_requests"
                ),
            },
        },
    }
def _incident_bucket_datetime(value: object) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(
                timezone.utc
            )
        except ValueError:
            return None
    return None
def _incident_bucketize(
    start: datetime, end: datetime, bucket_delta: timedelta
) -> list[datetime]:
    out: list[datetime] = []
    t = start
    while t < end:
        out.append(t)
        t += bucket_delta
    return out
def _incident_series_for(
    indexed: dict[tuple[str, datetime], dict],
    bucket_delta: timedelta,
    period: str,
    start: datetime,
    end: datetime,
    key: str,
) -> list[int]:
    import baselines as baselines_mod

    out: list[int] = []
    for bucket in _incident_bucketize(start, end, bucket_delta):
        row = indexed.get((period, bucket))
        value = 0 if row is None else baselines_mod.to_number(row.get(key)) or 0
        out.append(int(value))
    return out
