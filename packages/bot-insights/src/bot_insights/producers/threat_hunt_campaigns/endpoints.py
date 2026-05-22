"""Endpoint categorization and evidence summaries."""

from __future__ import annotations

from collections import Counter
from typing import Any
from urllib.parse import urlsplit

from .constants import _TARGET_ENDPOINT_CATEGORIES, _TRACKING_STATIC_PATHS
from .numbers import _num


def endpoint_prefix(path: str) -> str:
    """Collapse a request path to the first two stable path segments."""

    raw = str(path or "").strip()
    if not raw:
        return ""
    parsed = urlsplit(raw if "://" in raw else f"https://example.invalid{raw if raw.startswith('/') else '/' + raw}")
    segments = [segment for segment in parsed.path.split("/") if segment]
    if not segments:
        return "/"
    return "/" + "/".join(segments[:2])


def _endpoint_category(path: str) -> str:
    lowered = str(path or "").lower()
    if any(lowered.startswith(prefix) for prefix in _TRACKING_STATIC_PATHS):
        return "tracking_static_asset"
    if "graphql" in lowered or "gql" in lowered:
        return "graphql"
    if any(token in lowered for token in ("login", "auth", "token", "session", "oauth")):
        return "auth"
    if any(token in lowered for token in ("checkout", "book", "booking", "reserve", "reservation", "cart", "hold", "purchase", "payment", "order")):
        return "transaction"
    if any(token in lowered for token in ("catalog", "product", "inventory", "search", "listing")):
        return "catalog_search_product_content"
    if any(token in lowered for token in ("/api", "/v1", "/v2", "/v3")):
        return "api"
    if lowered.endswith((".css", ".js", ".ico", ".woff", ".woff2", ".ttf", ".png", ".jpg", ".jpeg", ".gif", ".svg")):
        return "static_asset"
    return "general_site"


def _campaign_endpoint_evidence_summary(
    members: list[str],
    case_by_ua: dict[str, dict[str, Any]],
    paths: Counter[str],
    coverage_summary: dict[str, Any],
) -> dict[str, Any]:
    tier_counts: Counter[str] = Counter()
    source_counts: Counter[str] = Counter()
    category_counts: Counter[str] = Counter()
    confirmed_member_count = 0
    for ua in members:
        evidence = case_by_ua.get(ua, {}).get("endpoint_evidence")
        if not isinstance(evidence, dict):
            evidence = {"tier": "not_available", "source": None, "counts_for_verdict": False}
        tier = str(evidence.get("tier") or "not_available")
        tier_counts[tier] += 1
        source = evidence.get("source")
        if source:
            source_counts[str(source)] += 1
        if evidence.get("counts_for_verdict"):
            confirmed_member_count += 1
        for category in evidence.get("categories") or []:
            if category:
                category_counts[str(category)] += 1
    for path, requests in paths.items():
        category_counts[_endpoint_category(path)] += _num(requests)
    dominant_categories = [
        {"category": category, "weight": weight}
        for category, weight in category_counts.most_common(5)
    ]
    confirmed_campaign_scoped = bool(
        _num(coverage_summary.get("weighted_coverage_pct")) >= 1.0
        and any(category in _TARGET_ENDPOINT_CATEGORIES for category in category_counts)
    )
    counts_for_verdict = confirmed_member_count > 0 or confirmed_campaign_scoped
    reason = _campaign_endpoint_reason(
        counts_for_verdict, confirmed_member_count, tier_counts
    )
    return {
        "member_count": len(members),
        "confirmed_member_count": confirmed_member_count,
        "inferred_member_count": tier_counts.get("inferred_site_context", 0),
        "unconfirmed_member_count": tier_counts.get("unconfirmed_scoped", 0),
        "not_available_member_count": tier_counts.get("not_available", 0),
        "tier_counts": dict(sorted(tier_counts.items())),
        "source_counts": dict(sorted(source_counts.items())),
        "dominant_categories": dominant_categories,
        "counts_for_verdict": counts_for_verdict,
        "reason": reason,
    }


def _campaign_endpoint_reason(
    counts_for_verdict: bool,
    confirmed_member_count: int,
    tier_counts: Counter[str],
) -> str:
    if counts_for_verdict:
        return (
            "confirmed_member_endpoint_evidence"
            if confirmed_member_count
            else "campaign_scoped_ge_1pct_target_categories"
        )
    if tier_counts.get("inferred_site_context"):
        return "members_inferred_from_site_context"
    if tier_counts.get("unconfirmed_scoped"):
        return "members_unconfirmed_scoped"
    return "no_endpoint_evidence"
