"""SOC/IR handoff view for incident evidence."""

from __future__ import annotations

from .incident_stakeholder_views import SCHEMA, assemble, prepare_soc_action_packet

REPORT_TYPE = "incident_soc_action_packet"
TEMPLATE = "reports/incident_soc_action_packet.html"
NOTE_ID_TO_SLOT = {}


def prepare(artifact: dict) -> dict:
    return prepare_soc_action_packet(artifact)
