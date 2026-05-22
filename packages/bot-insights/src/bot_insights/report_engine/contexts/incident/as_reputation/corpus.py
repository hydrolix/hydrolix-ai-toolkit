"""AS reputation corpus normalization and merging."""

from __future__ import annotations


def _normalize_asn(value: object) -> str:
    text = str(value or "").strip().upper()
    if text.startswith("AS"):
        text = text[2:]
    return "".join(ch for ch in text if ch.isdigit())


def _format_asn(asn: str) -> str:
    return f"AS{asn}" if asn else "AS unknown"


def normalize_reputation_corpus(
    entries: dict[str, dict] | list[dict] | tuple[dict, ...],
) -> dict[str, dict]:
    """Return corpus entries keyed by normalized ASN.

    Accepts both the preferred list shape (``{"asns": [...]}``) and the
    legacy mapping shape used by tests or callers that already key entries
    by ASN.
    """
    if isinstance(entries, dict):
        iterable = []
        for key, value in entries.items():
            entry = dict(value)
            entry.setdefault("asns", [key])
            iterable.append(entry)
    else:
        iterable = [dict(entry) for entry in entries]

    out: dict[str, dict] = {}
    for entry in iterable:
        raw_asns = entry.get("asns") or [entry.get("asn")]
        normalized_asns = [
            asn for asn in (_normalize_asn(value) for value in raw_asns) if asn
        ]
        for asn in normalized_asns:
            stored = dict(entry)
            stored["asns"] = normalized_asns
            stored["asn"] = asn
            current = out.get(asn)
            if current is None:
                out[asn] = stored
            else:
                out[asn] = _merge_reputation_entries(current, stored)
    return out


def _merge_reputation_entries(existing: dict, incoming: dict) -> dict:
    """Merge multiple reputation providers for the same ASN.

    Provider snapshots and local overrides are corroborating evidence. If both
    mention the same ASN, preserve their source lists instead of allowing the
    later provider to hide earlier citations.
    """
    merged = dict(existing)
    for key, value in incoming.items():
        if key in {"sources", "asns"}:
            continue
        if value not in (None, ""):
            merged[key] = value
    merged["asns"] = sorted(
        {
            asn
            for value in (existing.get("asns") or []) + (incoming.get("asns") or [])
            for asn in [_normalize_asn(value)]
            if asn
        },
        key=lambda value: int(value),
    )
    if existing.get("provider") and not incoming.get("provider"):
        merged["provider"] = existing["provider"]
    merged["sources"] = _merge_sources(
        (existing.get("sources") or []) + (incoming.get("sources") or [])
    )
    return merged


def _merge_sources(sources: list[dict]) -> list[dict]:
    merged: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for source in sources:
        if not isinstance(source, dict):
            continue
        key = (str(source.get("url") or ""), str(source.get("title") or ""))
        if key in seen:
            continue
        seen.add(key)
        merged.append(source)
    return merged
