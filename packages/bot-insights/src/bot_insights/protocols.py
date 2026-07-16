"""Protocols for Bot Insights replaceable boundaries."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence


class HydrolixQueryClient(Protocol):
    """Boundary for executing validated Hydrolix SQL."""

    def run_select_query(self, *, cluster: str, query: str) -> Mapping[str, Any]:
        """Run a SELECT query and return the decoded ClickHouse/Hydrolix response."""


class CaptureClient(Protocol):
    """Boundary for guarded capture command implementations."""

    def capture(self, *, sql: str, output: Path, shape: str = "clickhouse") -> Mapping[str, Any]:
        """Capture query output to disk and return redacted run metadata."""


class ReportRendererAdapter(Protocol):
    """Boundary for deterministic report rendering."""

    def render(self, payload: Mapping[str, Any], *, output_format: str) -> str:
        """Render a wrapper or artifact to Markdown, HTML, or another supported format."""


class BotManagerRowNormalizer(Protocol):
    """Boundary for normalizing Bot Manager source rows."""

    def normalize_rows(self, rows: Sequence[Mapping[str, Any]]) -> Sequence[Mapping[str, Any]]:
        """Normalize vendor/source rows into Bot Insights enrichment records."""
