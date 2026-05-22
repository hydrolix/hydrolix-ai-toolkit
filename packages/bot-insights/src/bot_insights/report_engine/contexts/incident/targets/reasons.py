"""Reason-label ordering for suspicious targets."""

from __future__ import annotations


_REASON_DISPLAY_PRIORITY = (
    "high 429 rate",
    "single path concentration",
    "high volume share",
    "high volume new actor",
    "new in window",
    "single ASN cluster",
    "automation user-agent",
    "behavioral anomaly",
)


def _operational_reason_labels(labels: list[str], limit: int = 3) -> list[str]:
    ordered: list[str] = []
    lower_to_label = {label.lower(): label for label in labels}
    for preferred in _REASON_DISPLAY_PRIORITY:
        if preferred in lower_to_label:
            ordered.append(lower_to_label[preferred])
    for label in labels:
        if label not in ordered:
            ordered.append(label)
    return ordered[:limit]
