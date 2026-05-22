"""Renderer-ready AS reputation context assembly."""

from __future__ import annotations

from typing import Iterable

from .behavior import _observed_asn_behavior, observed_asns
from .constants import LABEL_DISPLAY
from .corpus import _format_asn, normalize_reputation_corpus
from .evidence import _external_reputation_point, reputation_evidence_profile
from .providers import AsReputationProvider, LocalAsReputationOverrideProvider
from .providers import SpamhausAsnDropProvider


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
