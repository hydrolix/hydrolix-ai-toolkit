from __future__ import annotations

from typing import Any

from .constants import ERROR_SCHEMA


class InvalidInputError(Exception):
    """Typed invalid-input error for CLI and library callers."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        path: str = "$",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.document = invalid_input_doc(code, message, path=path, details=details)


def invalid_input_doc(
    code: str,
    message: str,
    *,
    path: str = "$",
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    error = {
        "code": code,
        "message": message,
        "path": path,
    }
    if details:
        error["details"] = details
    return {
        "schema_version": ERROR_SCHEMA,
        "error_type": "invalid_input",
        "fatal": True,
        "errors": [error],
        "limitations": [],
    }


def raise_invalid(
    code: str,
    message: str,
    *,
    path: str = "$",
    details: dict[str, Any] | None = None,
) -> None:
    raise InvalidInputError(code, message, path=path, details=details)
