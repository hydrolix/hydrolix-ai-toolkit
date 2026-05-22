"""Numeric helpers for campaign evidence scoring."""

from __future__ import annotations

import math
from collections import Counter
from typing import Any


def _num(value: Any, default: float = 0.0) -> float:
    if value is None or value == "":
        return default
    try:
        n = float(value)
    except (TypeError, ValueError):
        return default
    if math.isnan(n) or math.isinf(n):
        return default
    return n


def _pct(part: float, whole: float) -> float | None:
    if whole <= 0:
        return None
    return part / whole * 100.0


def _cosine(left: Counter[str], right: Counter[str]) -> float | None:
    if not left or not right:
        return None
    shared = set(left) & set(right)
    numerator = sum(left[key] * right[key] for key in shared)
    left_mag = math.sqrt(sum(value * value for value in left.values()))
    right_mag = math.sqrt(sum(value * value for value in right.values()))
    if left_mag <= 0 or right_mag <= 0:
        return None
    return numerator / (left_mag * right_mag)


def _pearson(left: Counter[str], right: Counter[str]) -> float | None:
    keys = sorted(set(left) | set(right))
    if len(keys) < 2:
        return None
    left_values = [_num(left.get(key)) for key in keys]
    right_values = [_num(right.get(key)) for key in keys]
    left_mean = sum(left_values) / len(left_values)
    right_mean = sum(right_values) / len(right_values)
    numerator = sum((a - left_mean) * (b - right_mean) for a, b in zip(left_values, right_values))
    left_den = math.sqrt(sum((a - left_mean) ** 2 for a in left_values))
    right_den = math.sqrt(sum((b - right_mean) ** 2 for b in right_values))
    if left_den <= 0 or right_den <= 0:
        return None
    return numerator / (left_den * right_den)
