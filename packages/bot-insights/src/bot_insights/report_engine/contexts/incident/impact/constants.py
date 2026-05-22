"""Constants for incident impact views."""

from __future__ import annotations

__all__ = [
    '_CHART_SELECTION_RULE',
    '_CHART_SELECTION_REASONS',
    '_HOST_AFFECTED_SHARE_THRESHOLD',
    '_HOST_AFFECTED_CAP',
]


_CHART_SELECTION_RULE = [
    ("rate_429_up", "req_429_per_minute"),
    ("bot_share_up", "bot_like_requests_per_minute"),
    ("volume_up", "requests_per_minute"),
]


_CHART_SELECTION_REASONS = {
    "rate_429_up": (
        "rate_429_up was the most specific spike flag — the rate-limit "
        "pressure curve is the lede"
    ),
    "bot_share_up": (
        "bot_share_up was the most specific spike flag — the automation "
        "wave shape is the lede"
    ),
    "volume_up": (
        "volume_up was the dominant spike — total request volume is the lede"
    ),
}


# Host-concentration projection thresholds. A host is named in the
# "top affected" line when its window share is at or above
# ``_HOST_AFFECTED_SHARE_THRESHOLD``; at most ``_HOST_AFFECTED_CAP``
# hosts are surfaced even if more cross the threshold. When no host
# crosses the threshold, the projection falls back to the single
# top-ranked host so the line never collapses to empty when there is
# meaningful host data.
_HOST_AFFECTED_SHARE_THRESHOLD = 10.0
_HOST_AFFECTED_CAP = 5
