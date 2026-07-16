"""Entity-type resolver + display label."""

from __future__ import annotations

__all__ = [
    '_resolve_entity_type',
    '_entity_display',
]


def _resolve_entity_type(ranked_entities: list[dict], scorecards: list[dict]) -> str:
    """Pick the producer's entity_type axis. All ranked rows in a single
    report share one entity_type; fall back to the first scorecard, then
    to ``client_asn`` so an empty index still labels sensibly.
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
    avoids that ambiguity ("64500" → "ASN 64500"). Hosts and IPs render
    as-is — they're already self-evident in the column. snake_case slugs
    get Title Case with acronym preservation.
    """
    from ...humanize import humanize_entity_value
    if not entity:
        return entity
    return humanize_entity_value(entity, entity_type)
