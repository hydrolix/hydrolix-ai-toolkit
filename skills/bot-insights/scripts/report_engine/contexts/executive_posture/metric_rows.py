"""Per-metric row classification + recommendation builders."""

from __future__ import annotations

from .constants import (
    _STABLE_PCT,
    _VOLUME_METRICS,
    _WATCH_PCT,
)
from .formatters import (
    _confidence_chip,
    _metric_label,
    _to_float,
)

__all__ = [
    '_classify_metric',
    '_metric_recommendation',
    '_metric_row',
]


_VERDICT_INSUFFICIENT = {
    "state": "insufficient_data",
    "label": "Insufficient data",
    "tone": "neutral",
}
_VERDICT_STABLE = {"state": "stable", "label": "Stable", "tone": "observe"}
_VERDICT_INVESTIGATE = {
    "state": "investigate",
    "label": "Investigate",
    "tone": "escalate",
}
_VERDICT_WATCH = {"state": "watch", "label": "Watch", "tone": "monitor"}


def _classify_metric(metric: dict, recommendation: dict | None) -> dict:
    """Per-metric verdict — Investigate / Watch / Stable / Insufficient data.

    Mirrors the fleet brief's 4-state taxonomy so the triage strip / chip
    code paths are shared. The verdict is anchored on the operator-action
    thresholds defined in :func:`_metric_recommendation`: a metric that
    crosses an action threshold with high/medium confidence is
    Investigate. Below the action threshold but with directional movement
    above the noise floor is Watch. |pct_change| < 5% is Stable. Missing
    or unknown direction is Insufficient. Low-confidence movement does
    not demote the row to Insufficient — the coverage gap surfaces via
    the confidence chip, the same axis split the scorecard brief uses.
    """
    direction = (metric.get("direction") or "").lower()
    pct = _to_float(metric.get("pct_change"))
    if pct is None or direction in {"", "unknown"}:
        return _VERDICT_INSUFFICIENT
    abs_pct = abs(pct)
    if abs_pct < _STABLE_PCT or direction in {"flat", "no_change"}:
        return _VERDICT_STABLE
    confidence = (metric.get("confidence") or "").lower()
    if recommendation is not None and confidence in {"high", "medium"}:
        return _VERDICT_INVESTIGATE
    return _VERDICT_WATCH


_VOLUME_MOVER_RECOMMENDATION = {
    "summary": "Investigate the volume mover.",
    "detail": (
        "Break down request volume by ASN, host, and bot class for the "
        "affected window."
    ),
    "trigger": "volume mover",
}

# Per-metric recommendation table.
# Each entry: (threshold_value_from_metric, threshold_min, recommendation_dict).
_RECOMMENDATIONS_BY_METRIC: dict[str, tuple[str, float, dict]] = {
    "requests": ("pct_change", 50.0, _VOLUME_MOVER_RECOMMENDATION),
    "bot_share_pct": ("absolute_delta", 5.0, {
        "summary": "Audit the bot-share rise.",
        "detail": (
            "Compare crawler/AI populations vs. prior week; check policy surfaces."
        ),
        "trigger": "crawler shift",
    }),
    "rate_429_pct": ("absolute_delta", 1.0, {
        "summary": "Review good-crawler 429s.",
        "detail": (
            "Pull rate-limit policy for known good crawlers and check "
            "policy collateral."
        ),
        "trigger": "rate limiting",
    }),
    "error_5xx_requests": ("pct_change", 25.0, {
        "summary": "Triage 5xx exposure.",
        "detail": (
            "Group 5xx by origin path and bot class; correlate with deploys."
        ),
        "trigger": "error spike",
    }),
    "cache_misses": ("pct_change", 25.0, {
        "summary": "Audit cache-key behavior.",
        "detail": (
            "Inspect query-string diversity and cache-key composition for "
            "affected paths."
        ),
        "trigger": "cache movement",
    }),
}


def _metric_recommendation(metric: dict) -> dict | None:
    """Return ``{summary, detail}`` for a metric whose movement crossed an
    operator-action threshold. ``None`` when nothing is actionable.

    Single source of truth for action selection — both the executive
    summary and the actions section consume the same dict, so the short
    form stays consistent with the analyst-grade detail.
    """
    if (metric.get("direction") or "").lower() != "increase":
        return None
    entry = _RECOMMENDATIONS_BY_METRIC.get(metric.get("name") or "")
    if entry is None:
        return None
    metric_key, threshold, recommendation = entry
    value = _to_float(metric.get(metric_key)) or 0.0
    if metric_key == "absolute_delta":
        value = abs(value)
    return recommendation if value >= threshold else None


def _apply_mover_escalation(
    metric: dict,
    name: str,
    verdict: dict,
    recommendation: dict | None,
    top_mover: dict | None,
) -> tuple[dict, dict | None]:
    """Mover-driven escalation: when a dominant mover (≥ 50% concentration)
    attributes the move to a single dimension value, treat the metric it
    explains as Investigate and synthesize the volume-mover action — even
    if the bare pct_change is below the standard 50% threshold. The
    operator's job here is to look at the mover, not at the headline %.
    """
    if not top_mover or top_mover.get("metric_name") != name:
        return verdict, recommendation
    if (metric.get("direction") or "flat").lower() != "increase":
        return verdict, recommendation
    if (metric.get("confidence") or "low").lower() not in {"high", "medium"}:
        return verdict, recommendation
    return _VERDICT_INVESTIGATE, recommendation or _VOLUME_MOVER_RECOMMENDATION


def _metric_magnitude(name: str, metric: dict) -> float:
    """Magnitude key used to rank "largest move" — abs_delta for volume
    metrics, abs(pct_change) for share-style metrics."""
    if name in _VOLUME_METRICS:
        return abs(_to_float(metric.get("absolute_delta")) or 0.0)
    return abs(_to_float(metric.get("pct_change")) or 0.0)


def _metric_row(metric: dict, top_mover: dict | None = None) -> dict:
    """Project a producer metric into the row shape the template renders."""
    name = metric.get("name") or ""
    recommendation = _metric_recommendation(metric)
    verdict = _classify_metric(metric, recommendation)
    verdict, recommendation = _apply_mover_escalation(
        metric, name, verdict, recommendation, top_mover
    )
    return {
        "name": name,
        "label": _metric_label(name),
        "current": _to_float(metric.get("current")),
        "baseline": _to_float(metric.get("baseline")),
        "absolute_delta": _to_float(metric.get("absolute_delta")) or 0.0,
        "pct_change": _to_float(metric.get("pct_change")) or 0.0,
        "direction": (metric.get("direction") or "flat").lower(),
        "confidence": (metric.get("confidence") or "low").lower(),
        "confidence_chip": _confidence_chip(metric.get("confidence")),
        "verdict_state": verdict["state"],
        "verdict_label": verdict["label"],
        "verdict_tone": verdict["tone"],
        "is_volume": name in _VOLUME_METRICS,
        "recommendation_summary": recommendation["summary"] if recommendation else None,
        "recommendation_detail": recommendation["detail"] if recommendation else None,
        "recommendation_trigger": (
            recommendation["trigger"] if recommendation else None
        ),
        "magnitude": _metric_magnitude(name, metric),
    }
