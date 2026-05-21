"""ReportError + ReportContext (shared warning collector)."""

from __future__ import annotations

__all__ = [
    'ReportError',
    'ReportContext',
]


class ReportError(ValueError):
    """Input or rendering error that should produce a CLI failure."""


class ReportContext:
    def __init__(self) -> None:
        self.warnings: list[str] = []
        self.artifact_id_explicit: dict[str, bool] = {}
        self.generated_child_parent: dict[str, str] = {}

    def warn(self, message: str) -> None:
        if message not in self.warnings:
            self.warnings.append(message)
