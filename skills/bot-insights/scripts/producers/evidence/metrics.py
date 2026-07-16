"""Shared metric helpers used by every per-report evidence builder.

The deterministic-artifact shapes (posture, control, scorecard) all
project a list of ``metrics`` cards plus a list of derived rate
rows. These helpers pair raw metric dicts with the human-readable
labels and display strings the LLM interpretation step expects.
"""

from __future__ import annotations

from producers.formatting import human_number, label_change, pct


# Display labels for the canonical metric names emitted by every
# producer summary query. Lifted here so per-report evidence
# builders can attach human strings without repeating the dict.
METRIC_LABELS = {
    "ai_requests": "AI requests",
    "bot_like_requests": "Bot-like requests",
    "cache_misses": "Cache misses",
    "error_5xx_requests": "5xx errors",
    "rate_limited_requests": "429 rate-limited requests",
    "requests": "Total requests",
    "avg_bot_score": "Average bot score",
    "siem_auth_fail_requests": "SIEM auth failures",
    "siem_blocked_requests": "SIEM blocked requests",
    "unique_client_ips": "Unique client IPs",
}


def metric_by_name(artifact: dict) -> dict[str, dict]:
    return {
        str(metric.get("name")): metric
        for metric in artifact.get("metrics", [])
        if isinstance(metric, dict) and metric.get("name")
    }


def rate_row(
    name: str, label: str, numerator: str, denominator: str, metrics: dict[str, dict]
) -> dict:
    num = metrics.get(numerator, {})
    den = metrics.get(denominator, {})
    current = pct(num.get("current"), den.get("current"))
    baseline = pct(num.get("baseline"), den.get("baseline"))
    delta_points = None if current is None or baseline is None else current - baseline
    return {
        "name": name,
        "label": label,
        "current_pct": current,
        "baseline_pct": baseline,
        "delta_points": delta_points,
        "current_display": human_number(current, percent=True)
        if current is not None
        else "unavailable",
        "baseline_display": human_number(baseline, percent=True)
        if baseline is not None
        else "unavailable",
        "delta_points_display": human_number(delta_points, percent=True, signed=True)
        if delta_points is not None
        else "unavailable",
        "change_label": label_change(delta_points),
    }


def metric_card_from_metric(metric: dict) -> dict:
    name = str(metric.get("name", ""))
    return {
        "name": name,
        "label": METRIC_LABELS.get(name, name),
        "current": metric.get("current"),
        "baseline": metric.get("baseline"),
        "absolute_delta": metric.get("absolute_delta"),
        "pct_change": metric.get("pct_change"),
        "current_display": human_number(metric.get("current")),
        "baseline_display": human_number(metric.get("baseline")),
        "absolute_delta_display": human_number(
            metric.get("absolute_delta"), signed=True
        ),
        "pct_change_display": human_number(
            metric.get("pct_change"), percent=True, signed=True
        ),
        "direction": metric.get("direction"),
        "confidence": metric.get("confidence"),
        "change_label": label_change(metric.get("pct_change")),
    }


def metric_map_from_control_effects(artifact: dict) -> dict[str, dict]:
    metrics: dict[str, dict] = {}
    for effect in artifact.get("target_effects", []):
        if not isinstance(effect, dict) or not effect.get("metric"):
            continue
        name = str(effect["metric"])
        metrics[name] = {
            "name": name,
            "current": effect.get("after"),
            "baseline": effect.get("expected"),
            "absolute_delta": effect.get("absolute_delta_vs_expected"),
            "pct_change": effect.get("pct_change_vs_expected"),
            "direction": effect.get("direction"),
            "confidence": effect.get("confidence"),
        }
    return metrics


def standard_derived_rates(metrics: dict[str, dict]) -> list[dict]:
    return [
        rate_row(
            "bot_like_share_pct",
            "Bot-like share",
            "bot_like_requests",
            "requests",
            metrics,
        ),
        rate_row("ai_share_pct", "AI share", "ai_requests", "requests", metrics),
        rate_row(
            "cache_miss_rate_pct",
            "Cache miss rate",
            "cache_misses",
            "requests",
            metrics,
        ),
        rate_row(
            "rate_limited_rate_pct",
            "429 rate-limit rate",
            "rate_limited_requests",
            "requests",
            metrics,
        ),
        rate_row(
            "error_5xx_rate_pct",
            "5xx error rate",
            "error_5xx_requests",
            "requests",
            metrics,
        ),
    ]
