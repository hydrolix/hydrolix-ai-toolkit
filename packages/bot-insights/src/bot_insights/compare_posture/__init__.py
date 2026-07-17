"""Deterministic posture / mover / control comparison from aggregate JSON.

This package does not query Hydrolix. It compares current-vs-baseline aggregate
rows and emits posture-movement, mover-attribution, or control-review artifacts
with confidence reasoning. Hydrolix does the filtering, grouping, aggregation.
"""

from __future__ import annotations

from .cli import compare, main

__all__ = [
    "compare",
    "main",
]
