"""External AS reputation context for incident reports.

Provider output is explanatory context only: callers must not feed it into
risk scoring, confidence gates, target sorting, or incident-claim wording.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, Protocol

from .formatters import _format_count, _format_pct, _safe_number

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
        for item in raw:
            if isinstance(item, dict):
                yield item
        return
    if not isinstance(raw, dict):
        return
    for key in ("records", "entries", "asndrop", "asn_drop", "data"):
        if isinstance(raw.get(key), list):
            for item in raw[key]:
                if isinstance(item, dict):
                    yield item
            return
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


def _ranking_rows_by_asn(actors_artifact: dict) -> dict[str, dict]:
    ranking = next(
        (
            row
            for row in actors_artifact.get("actor_rankings") or []
            if row.get("field") == "asn"
        ),
        None,
    )
    out: dict[str, dict] = {}
    for row in (ranking or {}).get("rows") or []:
        asn = _normalize_asn(row.get("value"))
        if asn:
            out[asn] = row
    return out


def _target_asn(target: dict) -> str:
    if target.get("target_type") == "asn":
        return _normalize_asn(target.get("target_value"))
    supporting = target.get("supporting") or {}
    return _normalize_asn(
        supporting.get("asn_cluster_id")
        or supporting.get("asn")
    )


def _observed_asn_behavior(
    asn: str,
    actors_artifact: dict,
    suspicious_targets: list[dict],
) -> dict:
    ranking_by_asn = _ranking_rows_by_asn(actors_artifact)
    ranking_total = sum(
        float(_safe_number(row.get("requests")) or 0)
        for row in ranking_by_asn.values()
    )
    ranking_row = ranking_by_asn.get(asn) or {}
    related_targets = [
        target for target in suspicious_targets if _target_asn(target) == asn
    ]
    direct_target = next(
        (target for target in related_targets if target.get("target_type") == "asn"),
        None,
    )
    supporting = (direct_target or {}).get("supporting") or {}
    requests = (
        _safe_number(supporting.get("requests"))
        or _safe_number(ranking_row.get("requests"))
        or sum(
            float(_safe_number((target.get("supporting") or {}).get("requests")) or 0)
            for target in related_targets
        )
    )
    share_pct = _safe_number(supporting.get("share_pct"))
    share_basis = "observed incident traffic"
    if share_pct is None and ranking_total > 0 and requests is not None:
        share_pct = 100.0 * float(requests) / ranking_total
        share_basis = "observed ASN-ranked traffic"
    client_ip_targets = [
        target for target in related_targets if target.get("target_type") == "client_ip"
    ]
    flags = sorted(
        {
            flag
            for target in related_targets
            for flag in (target.get("reason_flags") or [])
        }
    )
    parts = [
        f"In this report, {_format_asn(asn)} accounted for "
        f"{_format_count(requests)} requests"
    ]
    if share_pct is not None:
        parts.append(f"/ {_format_pct(share_pct)} of {share_basis}")
    if related_targets:
        parts.append(
            f"and appeared in {len(related_targets)} flagged target"
            f"{'' if len(related_targets) == 1 else 's'}"
        )
    if client_ip_targets:
        parts.append(
            f", including {len(client_ip_targets)} client-IP cluster member"
            f"{'' if len(client_ip_targets) == 1 else 's'}"
        )
    sentence = " ".join(parts) + "."
    if flags:
        sentence += f" Observed report flags included {', '.join(flags[:4])}."
    return {
        "requests": requests,
        "requests_display": _format_count(requests),
        "share_pct": share_pct,
        "share_pct_display": _format_pct(share_pct),
        "share_basis": share_basis,
        "flagged_target_count": len(related_targets),
        "client_ip_cluster_count": len(client_ip_targets),
        "anomaly_flags": flags,
        "report_local_behavior_point": sentence,
    }


def observed_asns(
    actors_artifact: dict,
    suspicious_targets: list[dict],
) -> list[str]:
    """Return normalized ASNs observed in rankings or flagged targets."""
    asns = set(_ranking_rows_by_asn(actors_artifact))
    for target in suspicious_targets:
        asn = _target_asn(target)
        if asn:
            asns.add(asn)
    return sorted(asns, key=lambda value: int(value))


def _providers_from_active_config() -> list[AsReputationProvider]:
    try:
        from config import active_thresholds
    except ImportError:
        return []
    cfg = getattr(active_thresholds(), "as_reputation", None)
    if cfg is None or not getattr(cfg, "enabled", True):
        return []
    providers: list[AsReputationProvider] = []
    if cfg.spamhaus_asndrop_path:
        providers.append(SpamhausAsnDropProvider(cfg.spamhaus_asndrop_path))
    if cfg.local_overrides_path:
        providers.append(LocalAsReputationOverrideProvider(cfg.local_overrides_path))
    return providers


def _provider_corpus(providers: Iterable[AsReputationProvider]) -> dict[str, dict]:
    entries: list[dict] = []
    for provider in providers:
        entries.extend(provider.entries())
    return normalize_reputation_corpus(entries)


def build_as_reputation_context(
    actors_artifact: dict,
    suspicious_targets: list[dict],
    *,
    corpus: dict[str, dict] | list[dict] | tuple[dict, ...] | None = None,
    providers: Iterable[AsReputationProvider] | None = None,
) -> dict:
    """Build renderer-ready AS reputation context for observed ASNs only."""
    if corpus is not None:
        normalized_corpus = normalize_reputation_corpus(corpus)
    elif providers is not None:
        normalized_corpus = _provider_corpus(providers)
    else:
        normalized_corpus = _provider_corpus(_providers_from_active_config())

    rows: list[dict] = []
    for asn in observed_asns(actors_artifact, suspicious_targets):
        entry = normalized_corpus.get(asn)
        if not entry:
            continue
        profile = reputation_evidence_profile(entry)
        if not profile["qualifies"]:
            continue
        behavior = _observed_asn_behavior(asn, actors_artifact, suspicious_targets)
        rows.append(
            {
                "asn": asn,
                "asn_display": _format_asn(asn),
                "name": entry.get("name") or "",
                "label": entry.get("label") or "reputation_hit",
                "label_display": LABEL_DISPLAY.get(
                    entry.get("label"), LABEL_DISPLAY["reputation_hit"]
                ),
                "confidence": entry.get("confidence") or "",
                "evidence_grade": entry.get("evidence_grade") or "",
                "last_reviewed": entry.get("last_reviewed") or "",
                "external_reputation_point": _external_reputation_point(
                    asn, entry, profile
                ),
                "report_local_behavior_point": behavior[
                    "report_local_behavior_point"
                ],
                "sources": entry.get("sources") or [],
                "evidence_profile": profile,
                **behavior,
            }
        )
    return {
        "available": bool(rows),
        "rows": rows,
        "boundary": (
            "External AS reputation is corroborating context only. It does not "
            "change risk score, confidence gates, target ordering, or incident claims."
        ),
    }
