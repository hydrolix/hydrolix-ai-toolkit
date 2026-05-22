from __future__ import annotations

from ._shared import *

def _timestamp_seconds(value: Any) -> float | None:
    if value in (None, ""):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    raw = str(value).strip()
    if not raw:
        return None
    try:
        return float(raw)
    except ValueError:
        pass
    normalized = raw.replace("Z", "+00:00")
    if " " in normalized and "T" not in normalized:
        normalized = normalized.replace(" ", "T", 1)
    try:
        dt = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)  # type: ignore[name-defined]
    return dt.timestamp()

def _median(values: list[float]) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    mid = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[mid]
    return (ordered[mid - 1] + ordered[mid]) / 2.0

def _percentile(values: list[float], percentile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * percentile
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[int(position)]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)

def _entropy(counter: Counter[int]) -> float | None:
    total = sum(counter.values())
    if total <= 0:
        return None
    entropy = 0.0
    for count in counter.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy

def _lag1_autocorrelation(values: list[float]) -> float | None:
    if len(values) < 3:
        return None
    left = values[:-1]
    right = values[1:]
    left_mean = sum(left) / len(left)
    right_mean = sum(right) / len(right)
    numerator = sum((a - left_mean) * (b - right_mean) for a, b in zip(left, right))
    left_den = math.sqrt(sum((a - left_mean) ** 2 for a in left))
    right_den = math.sqrt(sum((b - right_mean) ** 2 for b in right))
    if left_den <= 0 or right_den <= 0:
        return None
    return numerator / (left_den * right_den)

def _spectral_peak_ratio(values: list[float]) -> float | None:
    if len(values) < 8:
        return None
    sample = values[: min(len(values), 128)]
    mean = sum(sample) / len(sample)
    centered = [value - mean for value in sample]
    if not any(abs(value) > 1e-9 for value in centered):
        return None
    powers = []
    max_k = min(len(centered) // 2, 24)
    for k in range(1, max_k + 1):
        real = 0.0
        imag = 0.0
        for index, value in enumerate(centered):
            angle = 2.0 * math.pi * k * index / len(centered)
            real += value * math.cos(angle)
            imag -= value * math.sin(angle)
        powers.append(real * real + imag * imag)
    if not powers:
        return None
    average = sum(powers) / len(powers)
    if average <= 0:
        return None
    return max(powers) / average

def _lz_complexity_ratio(values: list[float]) -> float | None:
    if len(values) < 2:
        return None
    median = _median(values)
    if median is None:
        return None
    sequence = "".join("1" if value > median else "0" for value in values)
    phrases: set[str] = set()
    index = 0
    while index < len(sequence):
        end = index + 1
        while end <= len(sequence) and sequence[index:end] in phrases:
            end += 1
        phrases.add(sequence[index:end])
        index = end
    return len(phrases) / len(sequence)

def _bimodality(values: list[float]) -> tuple[bool, float | None]:
    if len(values) < 20:
        return False, None
    median = _median(values)
    if median is None or median <= 0:
        return False, None
    lower = [value for value in values if value <= median]
    upper = [value for value in values if value > median]
    if len(lower) < max(5, len(values) * 0.2) or len(upper) < max(5, len(values) * 0.2):
        return False, None
    low_med = _median(lower)
    high_med = _median(upper)
    if low_med is None or high_med is None or low_med <= 0:
        return False, None
    separation = high_med / low_med
    return separation >= 2.0, separation

def _iat_deltas(rows: list[dict[str, Any]], *, user_agent: str, client_ip: str | None = None) -> list[float]:
    timestamps = []
    for row in rows:
        if row.get("user_agent") != user_agent:
            continue
        if client_ip is not None and row.get("client_ip") != client_ip:
            continue
        seconds = _timestamp_seconds(row.get("timestamp"))
        if seconds is not None:
            timestamps.append(seconds)
    timestamps.sort()
    return [
        later - earlier
        for earlier, later in zip(timestamps, timestamps[1:])
        if later > earlier
    ]

def _iat_metrics(deltas: list[float]) -> dict[str, Any] | None:
    if len(deltas) < 50:
        return None
    mean = sum(deltas) / len(deltas)
    median = _median(deltas)
    stddev = math.sqrt(sum((value - mean) ** 2 for value in deltas) / len(deltas))
    p10 = _percentile(deltas, 0.10)
    p90 = _percentile(deltas, 0.90)
    mad = _median([abs(value - (median or 0.0)) for value in deltas])
    bins = Counter(max(0, int(math.floor(math.log2(max(value, 1e-9))))) for value in deltas)
    dominant = max(bins.values()) / len(deltas) if bins else None
    bimodal, separation = _bimodality(deltas)
    return {
        "count": len(deltas),
        "sample_size": len(deltas),
        "mean_iat_sec": mean,
        "median_iat_sec": median,
        "stddev_iat_sec": stddev,
        "cv": stddev / mean if mean > 0 else None,
        "normalized_mad": (mad / median) if median and median > 0 and mad is not None else None,
        "p10_sec": p10,
        "p90_sec": p90,
        "p10_p90_ratio": (p10 / p90) if p10 and p10 > 0 and p90 is not None and p90 > 0 else None,
        "p90_p10_ratio": (p90 / p10) if p10 and p10 > 0 and p90 is not None else None,
        "log_bucket_entropy": _entropy(bins),
        "dominant_bin_share": dominant,
        "lag1_autocorrelation": _lag1_autocorrelation(deltas),
        "spectral_peak_ratio": _spectral_peak_ratio(deltas),
        "lz_complexity_ratio": _lz_complexity_ratio(deltas),
        "bimodal": bimodal,
        "bimodal_peak_separation": separation,
    }

def _fine_archetype(metrics: dict[str, Any]) -> str | None:
    cv = metrics.get("cv")
    entropy = metrics.get("log_bucket_entropy")
    p90_p10 = metrics.get("p90_p10_ratio")
    spectral = metrics.get("spectral_peak_ratio")
    lag1 = metrics.get("lag1_autocorrelation")
    if cv is not None and cv < 0.1:
        return "metronome"
    if entropy is not None and entropy < 1.0 and _num(metrics.get("dominant_bin_share")) >= 0.9:
        return "metronome"
    if cv is not None and 0.1 <= cv < 0.35 and (p90_p10 is None or p90_p10 <= 3.0) and (entropy is None or entropy < 2.0):
        return "jittered_metronome"
    if metrics.get("bimodal") or _num(spectral) > 3.0 or abs(_num(lag1)) >= 0.45:
        return "burst_pause"
    return None

def _fine_timing_signal(metrics: dict[str, Any]) -> bool:
    return (
        _num(metrics.get("sample_size")) >= 50
        and (
            (_num(metrics.get("cv"), 999.0) < 0.3)
            or (_num(metrics.get("log_bucket_entropy"), 999.0) < 1.5)
            or (_num(metrics.get("spectral_peak_ratio")) > 3.0)
            or (_num(metrics.get("bimodal_peak_separation")) > 2.0)
            or (_num(metrics.get("lz_complexity_ratio"), 999.0) < 0.4)
        )
    )

def _hourly_counter_for_user_agent(user_agent: str, hourly_rows: list[dict[str, Any]]) -> Counter[str]:
    counter: Counter[str] = Counter()
    for row in hourly_rows:
        if row.get("user_agent") != user_agent:
            continue
        hour = str(row.get("hour") or "").strip()
        if hour:
            counter[hour] += _num(row.get("requests"))
    return counter

def _window_hour_count(start: datetime, end: datetime) -> int:
    seconds = max(0.0, (end - start).total_seconds())
    return max(1, int(math.ceil(seconds / 3600.0)))

def _hourly_timing_profile(
    user_agent: str,
    hourly_rows: list[dict[str, Any]],
    *,
    window_hour_count: int | None = None,
    source: str = "scraper_hourly",
) -> dict[str, Any]:
    counter = _hourly_counter_for_user_agent(user_agent, hourly_rows)
    active_hours = [value for value in counter.values() if value > 0]
    inferred_window = len(counter) if counter else 0
    window_hours = max(1, window_hour_count or inferred_window)
    active_count = len(active_hours)
    coverage_pct = _pct(active_count, window_hours)
    base = {
        "status": "unavailable" if not active_hours else "insufficient_coverage",
        "source": source,
        "resolution": "hourly_coarse",
        "active_hour_count": active_count,
        "window_hour_count": window_hours,
        "coverage_pct": coverage_pct,
        "hourly_request_cv": None,
        "max_min_hourly_ratio": None,
        "mean_hourly_requests": None,
        "total_profile_requests": sum(active_hours),
        "hourly_profile": [
            {"hour": hour, "requests": requests}
            for hour, requests in sorted(counter.items())
            if requests > 0
        ],
        "temporal": None,
    }
    min_active = min(6, window_hours)
    if active_count < min_active or (coverage_pct is not None and coverage_pct < 75.0):
        return base
    if not active_hours:
        return base
    mean = sum(active_hours) / len(active_hours)
    stddev = math.sqrt(sum((value - mean) ** 2 for value in active_hours) / len(active_hours))
    cv = stddev / mean if mean > 0 else None
    ratio = max(active_hours) / min(active_hours) if min(active_hours) > 0 else None
    total = sum(active_hours)
    base.update(
        {
            "status": "irregular",
            "hourly_request_cv": cv,
            "max_min_hourly_ratio": ratio,
            "mean_hourly_requests": mean,
            "total_profile_requests": total,
        }
    )
    regular = _num(cv, 999.0) <= 0.35 or (_num(ratio, 999.0) <= 3.0 and active_count >= 12)
    if not regular:
        return base
    metrics = {
        "active_hour_count": active_count,
        "window_hour_count": window_hours,
        "coverage_pct": coverage_pct,
        "hourly_request_cv": cv,
        "max_min_hourly_ratio": ratio,
        "mean_hourly_requests": mean,
        "total_profile_requests": total,
    }
    temporal = {
        "resolution": "hourly_coarse",
        "archetype": "hourly_regular",
        "sample_size": active_count,
        "active_hour_count": active_count,
        "window_hour_count": window_hours,
        "coverage_pct": coverage_pct,
        "hourly_request_cv": cv,
        "max_min_hourly_ratio": ratio,
        "mean_hourly_requests": mean,
        "total_profile_requests": total,
        "metrics": metrics,
        "top_pairs": [],
        "hourly_profile": base["hourly_profile"],
        "summary": (
            f"Hourly coarse profile shows regular request-count cadence across {active_count} "
            f"of {window_hours} report-window hours."
        ),
    }
    base["status"] = "regular"
    base["temporal"] = temporal
    return base

def _legacy_hourly_timing_profile(user_agent: str, drilldown_rows: list[dict[str, Any]]) -> dict[str, Any] | None:
    counter = _hourly_counter_for_user_agent(user_agent, drilldown_rows)
    active_hours = [value for value in counter.values() if value > 0]
    if len(active_hours) < 6:
        return None
    mean = sum(active_hours) / len(active_hours)
    stddev = math.sqrt(sum((value - mean) ** 2 for value in active_hours) / len(active_hours))
    repeated = sum(count for count in Counter(active_hours).values() if count > 1)
    metrics = {
        "active_hour_count": len(active_hours),
        "hourly_request_cv": stddev / mean if mean > 0 else None,
        "max_min_hourly_ratio": max(active_hours) / min(active_hours) if min(active_hours) > 0 else None,
        "repeated_count_share": repeated / len(active_hours) if active_hours else None,
    }
    if _num(metrics["hourly_request_cv"], 999.0) >= 0.2:
        return None
    return {
        "resolution": "hourly_coarse",
        "archetype": "hourly_regular",
        "sample_size": len(active_hours),
        "metrics": metrics,
        "top_pairs": [],
        "summary": (
            f"Hourly drilldown shows low request-count variation across {len(active_hours)} active hours."
        ),
    }

def _temporal_regularity(user_agent: str, iat_rows: list[dict[str, Any]], drilldown_rows: list[dict[str, Any]]) -> dict[str, Any] | None:
    ua_metrics = _iat_metrics(_iat_deltas(iat_rows, user_agent=user_agent))
    pair_rows = []
    for ip in sorted({str(row.get("client_ip")) for row in iat_rows if row.get("user_agent") == user_agent and row.get("client_ip")}):
        metrics = _iat_metrics(_iat_deltas(iat_rows, user_agent=user_agent, client_ip=ip))
        if not metrics:
            continue
        archetype = _fine_archetype(metrics)
        signal = archetype is not None and _fine_timing_signal(metrics)
        pair_rows.append(
            {
                "client_ip": ip,
                "archetype": archetype,
                "signal": signal,
                "sample_size": metrics["sample_size"],
                "cv": metrics.get("cv"),
                "log_bucket_entropy": metrics.get("log_bucket_entropy"),
                "spectral_peak_ratio": metrics.get("spectral_peak_ratio"),
            }
        )
    pair_signals = [row for row in pair_rows if row.get("signal")]
    ua_archetype = _fine_archetype(ua_metrics) if ua_metrics else None
    if len(pair_signals) >= 2 and ua_archetype not in {"metronome", "jittered_metronome"}:
        archetype = "rotation_mask"
        return {
            "resolution": "request_iat",
            "archetype": archetype,
            "sample_size": sum(_int(row.get("sample_size")) for row in pair_signals),
            "metrics": ua_metrics or {},
            "top_pairs": sorted(pair_signals, key=lambda row: (-_num(row.get("sample_size")), str(row.get("client_ip"))))[:5],
            "summary": (
                f"UA-level timing is not independently regular, but {len(pair_signals)} UA x IP pairs show regular timing evidence."
            ),
        }
    if ua_metrics and _fine_timing_signal(ua_metrics):
        archetype = ua_archetype or "timing_regular"
        return {
            "resolution": "request_iat",
            "archetype": archetype,
            "sample_size": ua_metrics["sample_size"],
            "metrics": ua_metrics,
            "top_pairs": sorted(pair_rows, key=lambda row: (-_num(row.get("sample_size")), str(row.get("client_ip"))))[:5],
            "summary": (
                f"Request-level inter-arrival timing matches {archetype.replace('_', ' ')} behavior in the sampled rows."
            ),
        }
    if iat_rows:
        return None
    return _legacy_hourly_timing_profile(user_agent, drilldown_rows)

__all__ = [name for name in globals() if not name.startswith("__")]
