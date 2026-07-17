from __future__ import annotations

import math
from typing import Any


def to_number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        number = float(value)
        return number if math.isfinite(number) else None
    if isinstance(value, str):
        try:
            number = float(value)
        except ValueError:
            return None
        return number if math.isfinite(number) else None
    return None


def clean_number(value: float | int | None) -> float | int | None:
    if value is None:
        return None
    if not math.isfinite(float(value)):
        raise ValueError("Output numeric values must be finite.")
    rounded = round(float(value), 6)
    if rounded.is_integer():
        return int(rounded)
    return rounded


def json_safe(value: Any) -> Any:
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, int):
        return value
    if isinstance(value, list):
        return [json_safe(item) for item in value]
    if isinstance(value, dict):
        return {key: json_safe(item) for key, item in value.items()}
    return value


def metadata_text(value: Any, default: str = "") -> str:
    safe_value = json_safe(value)
    if safe_value is None:
        return default
    return str(safe_value)


def pct_delta(current: float, baseline: float) -> float:
    return (current - baseline) / max(baseline, 1.0) * 100.0
