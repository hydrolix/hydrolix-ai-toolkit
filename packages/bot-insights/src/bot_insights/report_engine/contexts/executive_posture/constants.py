"""Volume-metric filter, watch/stable thresholds, state ordering."""

from __future__ import annotations

__all__ = [
    '_VOLUME_METRICS',
    '_WATCH_PCT',
    '_STABLE_PCT',
    '_STATE_ORDER',
    '_STATE_LABELS',
    '_STATE_TONE',
]


_VOLUME_METRICS = frozenset(
    {
        "requests",
        "ai_requests",
        "bot_like_requests",
        "cache_misses",
        "error_5xx_requests",
        "rate_limited_requests",
        "siem_auth_fail_requests",
        "siem_blocked_requests",
        "unique_client_ips",
    }
)


_WATCH_PCT = 10.0


_STABLE_PCT = 5.0


_STATE_ORDER = ("investigate", "watch", "stable", "insufficient_data")


_STATE_LABELS = {
    "investigate": "Investigate",
    "watch": "Watch",
    "stable": "Stable",
    "insufficient_data": "Insufficient data",
}


_STATE_TONE = {
    "investigate": "escalate",
    "watch": "monitor",
    "stable": "observe",
    "insufficient_data": "neutral",
}
