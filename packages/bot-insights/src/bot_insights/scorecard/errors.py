from __future__ import annotations

from typing import Any

from .constants import SCORECARD_ERROR_SCHEMA


class InvalidScorecardInputError(ValueError):
    """Typed invalid-input error for scorecard library callers."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        path: str = "$",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        error = {
            "code": code,
            "message": message,
            "path": path,
        }
        if details:
            error["details"] = details
        self.document = {
            "schema_version": SCORECARD_ERROR_SCHEMA,
            "error_type": "invalid_input",
            "fatal": True,
            "errors": [error],
            "limitations": [],
        }
