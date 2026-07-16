"""Deterministic cache-busting and origin-impact report from aggregate JSON.

This package does not query Hydrolix. It consumes aggregate rows (Hydrolix MCP
results or pasted JSON) already grouped by entity/period and derives cache-miss,
query-string, origin-pressure, and contribution features with confidence
reasoning. Hydrolix does the filtering, grouping, and aggregation.
"""

from __future__ import annotations

from .cli import main
from .helpers import result_rows
from .report import build_report

__all__ = [
    "build_report",
    "main",
    "result_rows",
]
