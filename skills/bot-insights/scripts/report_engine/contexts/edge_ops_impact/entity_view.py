"""Entity-type resolution + display helpers."""

from __future__ import annotations

from ...humanize import humanize_entity_value

__all__ = [
    '_resolve_entity_type',
    '_entity_display',
]


def _resolve_entity_type(ranked_entities: list[dict], scorecards: list[dict]) -> str:
    """Pick the producer's entity_type axis. Edge producers commonly rank on
    ``client_asn`` or ``request_host``; fall back so an empty index still
    labels sensibly.
    """
    for entry in ranked_entities:
        et = entry.get("entity_type")
        if et:
            return et
    for sc in scorecards:
        et = sc.get("entity_type")
        if et:
            return et
    return "client_asn"


def _entity_display(entity: str, entity_type: str) -> str:
    """Reader-facing rendering of an entity identifier.

    For ASNs the bare number reads as a domain name; prepending the noun
    avoids that ambiguity. AI-category slugs (e.g. ``ai_training``) get
    Title Case with acronym preservation. Other entity_types render as-is.
    """
    if not entity:
        return entity
    return humanize_entity_value(entity, entity_type)
