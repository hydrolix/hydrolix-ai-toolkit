"""CDN/edge operations view for incident evidence."""

from __future__ import annotations

from .incident_stakeholder_views import SCHEMA, assemble, prepare_edge_platform_brief

REPORT_TYPE = "incident_edge_platform_brief"
TEMPLATE = "reports/incident_edge_platform_brief.html"
NOTE_ID_TO_SLOT = {
    "llm-policy-assessment": "policy_assessment",
}


def prepare(artifact: dict) -> dict:
    return prepare_edge_platform_brief(artifact)
