"""AS reputation provider adapters."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, Protocol

from .constants import SPAMHAUS_ASNDROP_URL
from .corpus import _normalize_asn


class AsReputationProvider(Protocol):
    """Provider interface for local AS reputation sources."""

    def entries(self) -> Iterable[dict]:
        """Return normalized-ish reputation entries."""


class SpamhausAsnDropProvider:
    """Read a local Spamhaus ASN-DROP JSON snapshot."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def entries(self) -> Iterable[dict]:
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        for record in _iter_snapshot_records(raw):
            asns = _record_asns(record)
            if not asns:
                continue
            name = (
                record.get("name")
                or record.get("as_name")
                or record.get("org")
                or record.get("organization")
                or record.get("description")
                or "Spamhaus ASN-DROP listing"
            )
            listed = (
                record.get("last_seen")
                or record.get("last_updated")
                or record.get("last_reviewed")
                or ""
            )
            yield {
                "asns": asns,
                "name": str(name),
                "label": record.get("label") or "public_threat_enabler",
                "confidence": record.get("confidence") or "medium",
                "evidence_grade": (
                    record.get("evidence_grade") or "public_routing_reputation"
                ),
                "last_reviewed": listed,
                "provider": "spamhaus_asndrop",
                "minimum_source_bar": "provider_snapshot",
                "sources": [
                    {
                        "title": "Spamhaus ASN-DROP",
                        "url": record.get("source_url") or SPAMHAUS_ASNDROP_URL,
                        "source_type": "network_intelligence",
                        "summary": (
                            "Public Spamhaus ASN-DROP routing/reputation context "
                            "for dropped or blocked autonomous systems."
                        ),
                    }
                ],
            }


class LocalAsReputationOverrideProvider:
    """Read analyst-maintained AS reputation overrides from JSON/YAML/TOML."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def entries(self) -> Iterable[dict]:
        raw = _read_structured_file(self.path)
        if isinstance(raw, dict) and "entries" in raw:
            raw = raw["entries"]
        if isinstance(raw, dict):
            for key, value in raw.items():
                entry = dict(value or {})
                entry.setdefault("asns", [key])
                yield entry
            return
        for entry in raw or []:
            yield dict(entry or {})


def _read_structured_file(path: Path):
    suffix = path.suffix.lower()
    if suffix == ".json":
        return json.loads(path.read_text(encoding="utf-8"))
    if suffix == ".toml":
        import tomllib

        with path.open("rb") as handle:
            return tomllib.load(handle)
    if suffix in (".yaml", ".yml"):
        try:
            import yaml  # type: ignore[import-not-found]
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                f"{path} requires pyyaml; use JSON/TOML or install pyyaml."
            ) from exc
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    raise ValueError(
        f"Unsupported AS reputation file extension {suffix!r}; "
        "use .json, .yaml, .yml, or .toml."
    )


def _iter_snapshot_records(raw) -> Iterable[dict]:
    if isinstance(raw, list):
        yield from _dict_items(raw)
        return
    if not isinstance(raw, dict):
        return
    for key in ("records", "entries", "asndrop", "asn_drop", "data"):
        if isinstance(raw.get(key), list):
            yield from _dict_items(raw[key])
            return
    yield from _keyed_snapshot_records(raw)


def _dict_items(items) -> Iterable[dict]:
    for item in items:
        if isinstance(item, dict):
            yield item


def _keyed_snapshot_records(raw: dict) -> Iterable[dict]:
    for key, value in raw.items():
        if isinstance(value, dict):
            record = dict(value)
            record.setdefault("asn", key)
            yield record


def _record_asns(record: dict) -> list[str]:
    raw = (
        record.get("asns")
        or record.get("asn")
        or record.get("asn_id")
        or record.get("asn_number")
        or record.get("as")
    )
    values = raw if isinstance(raw, list) else [raw]
    return [asn for asn in (_normalize_asn(value) for value in values) if asn]
