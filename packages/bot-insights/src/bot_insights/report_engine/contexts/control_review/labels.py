"""Status / expected-basis label maps + their lookup helpers."""

from __future__ import annotations

__all__ = [
    '_STATUS_LABELS',
    '_STATUS_TONES',
    '_status_label',
    '_status_tone',
    '_EXPECTED_BASIS_LABELS',
    '_expected_basis_label',
]


_STATUS_LABELS = {
    "increased": "Increased",
    "decreased": "Decreased",
    "flat": "Flat",
    "unchanged": "Unchanged",
    "improved": "Improved",
    "worsened": "Worsened",
}


_STATUS_TONES = {
    # The tone classes are styling hints, not semantic verdicts —
    # ``status`` in a control_review is an observation, not a judgment.
    "increased": "monitor",
    "improved": "observe",
    "decreased": "observe",
    "flat": "muted",
    "unchanged": "muted",
    "worsened": "escalate",
}


def _status_label(status: str | None) -> str:
    if not status:
        return ""
    return _STATUS_LABELS.get(status, status.replace("_", " ").capitalize())


def _status_tone(status: str | None) -> str:
    if not status:
        return "muted"
    return _STATUS_TONES.get(status, "muted")


_EXPECTED_BASIS_LABELS = {
    "explicit_target": "Explicit target",
    "previous_window": "Previous window",
    "rolling_baseline": "Rolling baseline",
    "external_model": "External model",
    "before_window": "Before window",
}


def _expected_basis_label(basis: str | None) -> str:
    if not basis:
        return ""
    return _EXPECTED_BASIS_LABELS.get(basis, basis.replace("_", " ").capitalize())
