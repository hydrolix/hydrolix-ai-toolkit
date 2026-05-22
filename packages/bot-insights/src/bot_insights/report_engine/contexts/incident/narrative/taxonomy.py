"""Observed/inferred taxonomy for incident narrative context."""

from __future__ import annotations


def _observed_inferred_taxonomy() -> dict:
    return {
        "observed": [
            "request concentration",
            "path concentration",
            "cohort distribution",
            "5xx/429 rates",
            "edge action mix",
        ],
        "inferred": [
            "coordinated infrastructure",
            "evasive automation",
            "application-layer flooding",
        ],
        "boundary": (
            "Inferred labels are analytic interpretations of observed log patterns; "
            "they are not attribution, root cause, or intent claims."
        ),
    }
