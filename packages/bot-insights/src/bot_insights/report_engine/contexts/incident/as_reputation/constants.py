"""Shared AS reputation constants."""

from __future__ import annotations


AUTHORITATIVE_SOURCE_TYPES = frozenset({"sanctions", "law_enforcement"})
QUALIFYING_SOURCE_TYPES = frozenset(
    {
        "sanctions",
        "law_enforcement",
        "threat_intelligence",
        "security_research",
        "network_intelligence",
    }
)

SPAMHAUS_ASNDROP_URL = "https://www.spamhaus.org/drop/asndrop/"

LABEL_DISPLAY = {
    "sanctioned_bulletproof_hosting": "Sanctioned bulletproof-hosting context",
    "public_threat_enabler": "Public threat-enabler context",
    "reputation_hit": "Public reputation hit",
    "no_public_bad_as_evidence": "No public bad-AS evidence",
}
