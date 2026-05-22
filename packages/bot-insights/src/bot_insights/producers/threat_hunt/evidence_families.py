from __future__ import annotations

from ._shared import *

def _baseline_growth_family(requests: float, baseline_requests: float, request_delta: Any) -> dict[str, Any] | None:
    delta_pct = _pct(requests - baseline_requests, baseline_requests)
    if requests >= 100 and baseline_requests <= 10:
        tier = "novel"
        label = "The UA is new or near-new versus the baseline window."
    elif baseline_requests >= 1_000 and delta_pct is not None and delta_pct >= 100:
        tier = "aggressive_growth"
        label = "The UA more than doubled versus the baseline window."
    elif baseline_requests >= 1_000 and delta_pct is not None and delta_pct >= 50:
        tier = "elevated_growth"
        label = "The UA is elevated at least 1.5x versus the baseline window."
    else:
        return None
    ratio = requests / baseline_requests if baseline_requests > 0 else None
    return {
        "tier": tier,
        "requests": requests,
        "baseline_requests": baseline_requests,
        "request_delta": request_delta,
        "pct_change": delta_pct,
        "current_to_baseline_ratio": ratio,
        "label": label,
    }

def _row_evidence_families(row: dict[str, Any], *, window_end: datetime | None = None) -> set[str]:
    raw_flags = row.get("evidence_flags")
    if isinstance(raw_flags, list):
        return _explicit_evidence_families(raw_flags)
    user_agent = str(_first(row, ("user_agent", "userAgent", "UA", "ua"), ""))
    metrics = _row_evidence_metrics(row)
    families = _row_metric_families(row, metrics)
    if _automation_signature(user_agent):
        families.add("automation_signature")
    if _row_temporal_family(row):
        families.add("temporal_regularity")
    if _row_classification_gap(row):
        families.add("classification_gap")
    if _row_ua_anomaly(user_agent, metrics["unique_ips"], window_end):
        families.add("ua_anomaly")
    return families

def _row_metric_families(row: dict[str, Any], metrics: dict[str, float]) -> set[str]:
    families: set[str] = set()
    path = str(_first(row, ("request_path", "any_path", "path", "requestPath"), ""))
    if metrics["unique_ips"] >= 10 or metrics["unique_asns"] >= 2:
        families.add("ua_ip_fanout")
    if metrics["targeted"] > 0 or _path_markers(path):
        families.add("endpoint_targeting")
    if _row_baseline_growth(metrics["requests"], metrics["baseline_requests"]):
        families.add("baseline_novelty_or_growth")
    if _row_rate_pressure(metrics["requests"], metrics["status_429"], metrics["status_5xx"]):
        families.add("rate_limit_or_error_pressure")
    if metrics["unique_asns"] >= 3 or metrics["unique_countries"] >= 3:
        families.add("infrastructure_topology")
    return families

def _row_temporal_family(row: dict[str, Any]) -> bool:
    explicit_temporal = str(_first(row, ("temporal_regularity", "timing_status", "temporal_status"), "")).lower()
    return explicit_temporal in {"regular", "metronome", "jittered_metronome", "burst_pause", "rotation_mask"}

def _row_classification_gap(row: dict[str, Any]) -> bool:
    return _first(row, ("classification_gap", "coverage_gap"), None) in {True, "true", "yes", "1"}

def _row_ua_anomaly(
    user_agent: str, unique_ips: float, window_end: datetime | None
) -> bool:
    if window_end is None:
        return False
    plausibility = score_ua_plausibility(
        user_agent=user_agent,
        window_end=window_end,
        fanout_by_ua={},
        fallback_unique_ips=unique_ips,
        family_request_totals=Counter(),
        total_family_requests=0,
        browser_fingerprint_count=0,
        source="background_sample",
    )
    return bool(plausibility.get("counts_for_verdict"))

def _explicit_evidence_families(raw_flags: list[Any]) -> set[str]:
    return {str(flag) for flag in raw_flags if str(flag) in SCRAPER_EVIDENCE_FAMILIES}

def _row_evidence_metrics(row: dict[str, Any]) -> dict[str, float]:
    return {
        "requests": _num(_first(row, ("requests", "request_count", "count", "hits"))),
        "baseline_requests": _num(_first(row, ("baseline_requests", "baseline_count", "previous_requests"))),
        "unique_ips": _num(_first(row, ("unique_client_ips", "distinct_client_ips", "client_ip_count", "ips"))),
        "unique_asns": _num(_first(row, ("unique_asns", "distinct_asns", "asn_count"))),
        "unique_countries": _num(_first(row, ("unique_countries", "distinct_countries", "country_count"))),
        "targeted": _num(_first(row, ("targeted_endpoint_requests", "endpoint_target_requests", "api_requests"))),
        "status_429": _num(_first(row, ("status_429", "requests_429", "429", "req_429"))),
        "status_5xx": _num(_first(row, ("status_5xx", "requests_5xx", "5xx", "req_5xx"))),
    }

def _row_baseline_growth(requests: float, baseline_requests: float) -> bool:
    if baseline_requests <= 10 and requests >= 100:
        return True
    delta = _pct(requests - baseline_requests, baseline_requests)
    return bool(baseline_requests >= 1_000 and delta is not None and delta >= 50)

def _row_rate_pressure(requests: float, status_429: float, status_5xx: float) -> bool:
    return bool(
        requests > 0
        and any(
            (share := _pct(value, requests)) is not None and share >= 2
            for value in (status_429, status_5xx)
        )
    )

def _background_rates(
    rows: list[dict[str, Any]],
    *,
    window_end: datetime,
) -> dict[str, Any]:
    if not rows:
        return {
            "status": "unavailable",
            "sample_size": 0,
            "families": {
                family: {"triggered": 0, "sample_size": 0, "rate_pct": None, "concern": "unavailable"}
                for family in SCRAPER_EVIDENCE_FAMILIES
            },
        }
    counts: Counter[str] = Counter()
    for row in rows:
        counts.update(_row_evidence_families(row, window_end=window_end))
    sample_size = len(rows)
    families = {}
    for family in SCRAPER_EVIDENCE_FAMILIES:
        rate = _pct(counts.get(family, 0), sample_size)
        concern = "high" if _num(rate) >= 20 else "moderate" if _num(rate) >= 10 else "low"
        families[family] = {
            "triggered": counts.get(family, 0),
            "sample_size": sample_size,
            "rate_pct": rate,
            "concern": concern,
        }
    return {"status": "available", "sample_size": sample_size, "families": families}

def _baseline_significance_by_ua(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    buckets: dict[str, list[float]] = defaultdict(list)
    for row in rows:
        ua = str(_first(row, ("user_agent", "userAgent", "UA", "ua"), "")).strip()
        if not ua:
            continue
        buckets[ua].append(_num(_first(row, ("requests", "request_count", "count", "hits"))))
    out = {}
    for ua, values in buckets.items():
        mean = sum(values) / len(values) if values else 0.0
        stddev = math.sqrt(sum((value - mean) ** 2 for value in values) / len(values)) if values else 0.0
        out[ua] = {
            "status": "available" if len(values) >= 3 and stddev > 0 else "insufficient_distribution" if values else "unavailable",
            "bucket_count": len(values),
            "mean_requests": mean,
            "stddev_requests": stddev,
            "z_score": None,
        }
    return out

def _baseline_significance_for_case(
    case: dict[str, Any],
    by_ua: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    ua = str(case.get("user_agent") or "")
    base = dict(by_ua.get(ua) or {})
    if not base:
        return {"status": "unavailable", "reason": "no_per_ua_baseline_buckets"}
    if base.get("status") != "available":
        base["reason"] = "requires_at_least_three_nonflat_baseline_buckets"
        return base
    z_score = (_num(case.get("requests")) - _num(base.get("mean_requests"))) / _num(base.get("stddev_requests"), 1.0)
    base["z_score"] = z_score
    if z_score >= 5:
        base["significance"] = "very_high"
    elif z_score >= 3:
        base["significance"] = "high"
    elif z_score >= 2:
        base["significance"] = "moderate"
    else:
        base["significance"] = "low"
    return base

__all__ = [name for name in globals() if not name.startswith("__")]
