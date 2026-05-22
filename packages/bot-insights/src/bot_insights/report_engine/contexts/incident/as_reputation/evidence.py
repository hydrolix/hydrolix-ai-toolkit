"""Evidence-bar and wording helpers for AS reputation context."""

from __future__ import annotations

from .constants import AUTHORITATIVE_SOURCE_TYPES, QUALIFYING_SOURCE_TYPES
from .corpus import _format_asn


def _source_is_authoritative(source: dict) -> bool:
    return str(source.get("source_type") or "") in AUTHORITATIVE_SOURCE_TYPES


def reputation_evidence_profile(entry: dict) -> dict:
    """Return conservative source-bar metadata for a reputation entry."""
    sources = [
        source
        for source in entry.get("sources") or []
        if str(source.get("source_type") or "") in QUALIFYING_SOURCE_TYPES
        and source.get("url")
    ]
    authoritative = any(_source_is_authoritative(source) for source in sources)
    source_types = sorted({str(source.get("source_type") or "") for source in sources})
    source_count = len(sources)
    provider_snapshot = entry.get("minimum_source_bar") == "provider_snapshot"
    label = entry.get("label")
    qualifies = (
        label != "no_public_bad_as_evidence"
        and (authoritative or source_count >= 2 or provider_snapshot)
    )
    known_bad_wording_allowed = (
        label != "no_public_bad_as_evidence"
        and (authoritative or source_count >= 2)
    )
    if authoritative:
        bar = "authoritative_source"
    elif source_count >= 2:
        bar = "two_source"
    elif provider_snapshot:
        bar = "provider_snapshot"
    else:
        bar = "two_source"
    return {
        "source_count": source_count,
        "source_types": source_types,
        "has_authoritative_source": authoritative,
        "provider_snapshot": provider_snapshot,
        "qualifies": qualifies,
        "known_bad_wording_allowed": known_bad_wording_allowed,
        "bar": bar,
    }


def _external_reputation_point(asn: str, entry: dict, profile: dict) -> str:
    label = entry.get("label") or "reputation_hit"
    name = entry.get("name") or "the owning entity"
    if entry.get("provider") == "spamhaus_asndrop":
        return (
            f"Spamhaus ASN-DROP lists {_format_asn(asn)}/{name} in public "
            "routing and reputation context. This context does not imply "
            "every IP, customer, or request from the AS is malicious."
        )
    if label == "sanctioned_bulletproof_hosting":
        phrase = "sanctioned bulletproof-hosting or threat-enabling infrastructure"
    elif label == "public_threat_enabler":
        phrase = "threat-enabling infrastructure"
    else:
        phrase = "public reputation concerns"
    authoritative = bool(profile.get("has_authoritative_source"))
    source_phrase = (
        "An authoritative public source"
        if authoritative
        else "Multiple public sources"
    )
    verb = "describes" if authoritative else "describe"
    return (
        f"{source_phrase} {verb} {_format_asn(asn)}/{name} as associated "
        f"with {phrase}. This context does not imply every IP, customer, "
        f"or request from the AS is malicious."
    )
