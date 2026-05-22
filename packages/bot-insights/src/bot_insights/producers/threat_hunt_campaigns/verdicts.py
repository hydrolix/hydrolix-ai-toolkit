"""Campaign verdict helpers."""

from __future__ import annotations


def _verdict_for_family_count(count: int) -> str:
    if count >= 3:
        return "strong_lead"
    if count >= 2:
        return "lead"
    if count == 1:
        return "weak_lead"
    return "not_enough_data"
