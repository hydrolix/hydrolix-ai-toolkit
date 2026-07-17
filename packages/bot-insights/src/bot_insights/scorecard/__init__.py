"""Deterministic Bot Insights entity scorecards from aggregate JSON.

This package does not query Hydrolix. Feed it Hydrolix MCP query results, saved
JSON, or pasted aggregate JSON that already contains entity-level aggregate
rows. Hydrolix should do filtering, grouping, and aggregation; this package
standardizes rule-based scorecard shape, feature evidence, confidence reasons,
and ranked index output.
"""

from __future__ import annotations

from .assembly import build_artifacts
from .cli import main
from .errors import InvalidScorecardInputError
from .scoring import score_band

__all__ = [
    "InvalidScorecardInputError",
    "build_artifacts",
    "main",
    "score_band",
]
