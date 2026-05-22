"""Campaign summary builders."""

from __future__ import annotations

from collections import Counter
from typing import Any

from .numbers import _num, _pct, _pearson


def _coverage_label(status_counts: Counter[str], weighted_pct: float | None, member_count: int) -> str:
    if weighted_pct is not None and weighted_pct >= 75.0:
        return "focused_api_surface"
    low_count = status_counts.get("unavailable", 0) + status_counts.get("uncharacterized", 0)
    if member_count and low_count > member_count / 2:
        return "diffuse_surface"
    return "mixed_surface"


def _campaign_drilldown_coverage_summary(members: list[str], case_by_ua: dict[str, dict[str, Any]]) -> dict[str, Any]:
    status_counts: Counter[str] = Counter()
    drilldown_requests = 0.0
    total_requests = 0.0
    for ua in members:
        coverage = case_by_ua.get(ua, {}).get("drilldown_coverage")
        if not isinstance(coverage, dict):
            coverage = {
                "status": "unavailable",
                "drilldown_requests": 0.0,
                "total_requests": _num(case_by_ua.get(ua, {}).get("requests")),
            }
        status_counts[str(coverage.get("status") or "unavailable")] += 1
        drilldown_requests += _num(coverage.get("drilldown_requests"))
        total_requests += _num(coverage.get("total_requests"))
    weighted_pct = _pct(drilldown_requests, total_requests)
    return {
        "member_count": len(members),
        "status_counts": dict(sorted(status_counts.items())),
        "drilldown_requests": drilldown_requests,
        "total_requests": total_requests,
        "weighted_coverage_pct": weighted_pct,
        "surface_label": _coverage_label(status_counts, weighted_pct, len(members)),
    }


def _campaign_timing_summary(
    members: list[str],
    case_by_ua: dict[str, dict[str, Any]],
    features: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    regular_members = []
    correlations = []
    for ua in members:
        timing = case_by_ua.get(ua, {}).get("temporal_regularity")
        if isinstance(timing, dict) and timing.get("archetype") == "hourly_regular":
            regular_members.append(ua)
    for index, left_ua in enumerate(members):
        for right_ua in members[index + 1 :]:
            corr = _pearson(features[left_ua]["hours"], features[right_ua]["hours"])
            if corr is not None:
                correlations.append(corr)
    mean_abs = (
        sum(abs(value) for value in correlations) / len(correlations)
        if correlations
        else None
    )
    max_abs = max((abs(value) for value in correlations), default=None)
    member_count = len(members)
    regular_pct = _pct(len(regular_members), member_count)
    parallel = bool(
        member_count >= 4
        and regular_pct is not None
        and regular_pct >= 50.0
        and correlations
        and _num(mean_abs, 999.0) <= 0.25
        and _num(max_abs, 999.0) <= 0.50
    )
    return {
        "member_count": member_count,
        "regular_member_count": len(regular_members),
        "regular_member_pct": regular_pct,
        "regular_members": regular_members,
        "pairwise_correlation_count": len(correlations),
        "mean_abs_pairwise_temporal_correlation": mean_abs,
        "max_abs_pairwise_temporal_correlation": max_abs,
        "parallel_independent": parallel,
        "evidence_text": (
            "linked leads independently exhibit regular hourly cadence without synchronized timing, "
            "consistent with parallel scraper workers."
        )
        if parallel
        else None,
    }


def _campaign_ua_plausibility_summary(
    members: list[str], case_by_ua: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    trigger_counts: Counter[str] = Counter()
    status_counts: Counter[str] = Counter()
    anomaly_counts: Counter[str] = Counter()
    anomalous = 0
    weak = 0
    max_score = 0.0
    for ua in members:
        plausibility = case_by_ua.get(ua, {}).get("ua_plausibility")
        if not isinstance(plausibility, dict):
            status_counts["unavailable"] += 1
            continue
        verdict = str(plausibility.get("verdict") or "unavailable")
        status_counts[verdict] += 1
        score = _num(plausibility.get("composite_score"))
        max_score = max(max_score, score)
        if plausibility.get("counts_for_verdict"):
            anomalous += 1
        elif verdict == "elevated":
            weak += 1
        trigger = str(plausibility.get("trigger_reason") or "")
        if trigger:
            trigger_counts[trigger] += 1
        signals = plausibility.get("signals") if isinstance(plausibility.get("signals"), dict) else {}
        for name, signal in signals.items():
            if isinstance(signal, dict) and _num(signal.get("score")) > 0:
                anomaly_counts[str(name)] += 1
    forged = bool(
        anomalous >= 2
        or (
            len(members) >= 3
            and status_counts.get("elevated", 0) + anomalous >= 2
            and max_score >= 0.6
        )
    )
    return {
        "member_count": len(members),
        "anomalous_member_count": anomalous,
        "weak_member_count": weak,
        "status_counts": dict(sorted(status_counts.items())),
        "top_triggers": [
            {"trigger": trigger, "count": count}
            for trigger, count in trigger_counts.most_common(5)
        ],
        "dominant_anomaly_types": [
            {"type": name, "count": count}
            for name, count in anomaly_counts.most_common(5)
        ],
        "max_score": max_score,
        "forged_ua_candidate": forged,
    }


def _campaign_fanout_summary(
    members: list[str], case_by_ua: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    source_counts: Counter[str] = Counter()
    unique_total = 0.0
    effective_total = 0.0
    available = 0
    threshold_counts: Counter[str] = Counter()
    for ua in members:
        fanout = case_by_ua.get(ua, {}).get("fanout_enrichment")
        if not isinstance(fanout, dict) or str(fanout.get("source") or "unavailable") == "unavailable":
            continue
        available += 1
        source = str(fanout.get("source") or "unknown")
        source_counts[source] += 1
        threshold_counts[str(fanout.get("threshold_class") or "unknown")] += 1
        unique_total += _num(fanout.get("unique_ips") if fanout.get("unique_ips") is not None else fanout.get("unique_client_ips"))
        effective_total += _num(fanout.get("effective_ips") or fanout.get("unique_ips") or fanout.get("unique_client_ips"))
    source = source_counts.most_common(1)[0][0] if source_counts else "unavailable"
    return {
        "member_count": len(members),
        "available_member_count": available,
        "source": source,
        "source_counts": dict(sorted(source_counts.items())),
        "threshold_counts": dict(sorted(threshold_counts.items())),
        "unique_ips_lower_bound": int(unique_total),
        "effective_ips_composite": int(effective_total),
        "line": (
            f"Composite member fan-out lower bound sums {int(unique_total):,} per-UA unique-IP observations "
            f"({int(effective_total):,} effective IPs); this is not an exact deduplicated campaign union."
        )
        if available
        else "Campaign fan-out enrichment unavailable; no exact member-union IP count is claimed.",
    }
