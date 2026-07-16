"""Detection-engineering review view for incident evidence."""

from __future__ import annotations

from .incident_stakeholder_views import SCHEMA, assemble, prepare_detection_engineering

REPORT_TYPE = "incident_detection_engineering"
TEMPLATE = "reports/incident_detection_engineering.html"
NOTE_ID_TO_SLOT = {
    "llm-calibration-calls": "calibration_calls",
}


def prepare(artifact: dict) -> dict:
    return prepare_detection_engineering(artifact)
