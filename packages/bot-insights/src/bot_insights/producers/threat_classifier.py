"""Evidence-bounded threat taxonomy for threat-hunt artifacts."""

from __future__ import annotations

import math
from collections import Counter
from typing import Any


CATEGORIES = {
    "scraper_catalog",
    "scraper_pricing",
    "credential_stuffing",
    "inventory_abuse",
    "rate_limit_evasion",
    "training_collection",
    "application_ddos",
    "reconnaissance",
}

_TRANSACTION_TOKENS = (
    "checkout",
    "book",
    "booking",
    "reserve",
    "reservation",
    "cart",
    "hold",
    "purchase",
    "payment",
    "order",
)
_PRICING_TOKENS = ("price", "pricing", "rate", "rates", "availability", "fare", "quote")

_MITRE = {
    "credential_stuffing": {
        "mitre_techniques": ["T1110.004"],
        "mitre_tactics": ["TA0006"],
        "hdx_techniques": ["HDX-T003"],
    },
    "application_ddos": {
        "mitre_techniques": ["T1499.003"],
        "mitre_tactics": ["TA0040"],
        "hdx_techniques": [],
    },
    "reconnaissance": {
        "mitre_techniques": ["T1595.003"],
        "mitre_tactics": ["TA0043"],
        "hdx_techniques": [],
    },
    "rate_limit_evasion": {
        "mitre_techniques": ["T1036.012", "T1562"],
        "mitre_tactics": ["TA0005"],
        "hdx_techniques": ["HDX-T002", "HDX-T006"],
    },
    "scraper_catalog": {
        "mitre_techniques": [],
        "mitre_tactics": [],
        "hdx_techniques": ["HDX-T001"],
    },
    "scraper_pricing": {
        "mitre_techniques": [],
        "mitre_tactics": [],
        "hdx_techniques": ["HDX-T001", "HDX-T004"],
    },
    "inventory_abuse": {
        "mitre_techniques": [],
        "mitre_tactics": [],
        "hdx_techniques": ["HDX-T004"],
    },
    "training_collection": {
        "mitre_techniques": [],
        "mitre_tactics": [],
        "hdx_techniques": ["HDX-T005"],
    },
}

_MODIFIERS = {
    "scraper_catalog": "Use route-scoped catalog/search challenge or rate-limit controls; validate known search, SEO, and partner traffic before enforcement.",
    "scraper_pricing": "Prioritize pricing, rate, and availability API protections with scoped throttles or challenges; monitor conversion and cache behavior after changes.",
    "credential_stuffing": "Treat auth endpoints separately: use login-specific throttling, credential-stuffing controls, and SIEM correlation before broad UA blocking.",
    "inventory_abuse": "Protect transaction and hold paths with step-up challenge or queue controls; validate checkout and booking traffic before enforcement.",
    "rate_limit_evasion": "Prefer UA-family pattern handling over one exact UA string; match rotating browser-major templates and re-check family membership before enforcement.",
    "training_collection": "Use broad crawl-governance and content-access controls before blocking; validate static asset and content fetching against known browsers and crawlers.",
    "application_ddos": "Coordinate incident-style response for expensive endpoints: rate-limit or challenge at the campaign scope and watch 5xx/origin pressure.",
    "reconnaissance": "Prefer monitoring, route hardening, and low-friction throttles; broad blocks are not recommended from breadth-only evidence.",
}

_CONSERVATIVE_RANK = {
    "reconnaissance": 0,
    "training_collection": 1,
    "scraper_catalog": 2,
    "scraper_pricing": 3,
    "inventory_abuse": 4,
    "rate_limit_evasion": 5,
    "credential_stuffing": 6,
    "application_ddos": 7,
}

_ABSENCE_ONLY_FLAGS = {
    "no_auth_endpoint_targeting",
    "missing_drilldown_coverage",
    "no_contradicting_evidence",
    "classification_gap",
}

_POSITIVE_ENDPOINT_CATEGORIES = {
    "api",
    "auth",
    "catalog_search_product_content",
    "graphql",
    "static_asset",
    "tracking_static_asset",
    "transaction",
}

_STANDALONE_MIN_CONFIDENCE = 0.60


def _num(value: Any, default: float = 0.0) -> float:
    if value is None or value == "":
        return default
    try:
        n = float(value)
    except (TypeError, ValueError):
        return default
    if math.isnan(n) or math.isinf(n):
        return default
    return n


def _pct(part: float, whole: float) -> float | None:
    if whole <= 0:
        return None
    return part / whole * 100.0


def _category_for_endpoint(row: dict[str, Any]) -> str:
    category = str(row.get("endpoint_category") or "").strip()
    if category:
        return category
    path = str(row.get("endpoint_prefix") or row.get("request_path") or row.get("value") or "").lower()
    if any(token in path for token in _TRANSACTION_TOKENS):
        return "transaction"
    if any(token in path for token in ("login", "auth", "token", "session", "oauth")):
        return "auth"
    if any(token in path for token in ("catalog", "product", "inventory", "search", "listing")):
        return "catalog_search_product_content"
    if any(token in path for token in ("graphql", "gql")):
        return "graphql"
    if any(token in path for token in ("/api", "/v1", "/v2", "/v3")):
        return "api"
    if path.endswith((".css", ".js", ".ico", ".woff", ".woff2", ".ttf", ".png", ".jpg", ".jpeg", ".gif", ".svg")):
        return "static_asset"
    return "general_site"


def _endpoint_stats(entity: dict[str, Any]) -> dict[str, Any]:
    endpoints = [row for row in entity.get("endpoint_targets") or [] if isinstance(row, dict)]
    totals: Counter[str] = Counter()
    requests_total = 0.0
    pricing_requests = 0.0
    paths: set[str] = set()
    for row in endpoints:
        requests = _num(row.get("requests"), 1.0) or 1.0
        path = str(row.get("endpoint_prefix") or row.get("request_path") or row.get("value") or "")
        category = _category_for_endpoint(row)
        totals[category] += requests
        requests_total += requests
        if path:
            paths.add(path)
            if any(token in path.lower() for token in _PRICING_TOKENS):
                pricing_requests += requests
    shares = {
        category: _pct(requests, requests_total) or 0.0
        for category, requests in totals.items()
    }
    top_three = sum(value for _category, value in totals.most_common(3))
    unique_path_count = int(_num(entity.get("unique_path_count"))) or len(paths)
    return {
        "endpoint_count": len(endpoints),
        "unique_path_count": unique_path_count,
        "requests_total": requests_total,
        "category_requests": dict(totals),
        "category_shares": shares,
        "top3_share_pct": _pct(top_three, requests_total) or 0.0,
        "pricing_share_pct": _pct(pricing_requests, requests_total) or 0.0,
    }


def _positive_evidence_families(
    entity: dict[str, Any],
    endpoint: dict[str, Any],
    *,
    entity_type: str,
) -> set[str]:
    flags = {
        str(flag)
        for flag in entity.get("evidence_flags") or []
        if str(flag) and str(flag) not in _ABSENCE_ONLY_FLAGS
    }
    categories = {
        str(category)
        for category in (endpoint.get("category_requests") or {})
        if str(category) in _POSITIVE_ENDPOINT_CATEGORIES
    }
    families = set(flags)
    if categories:
        families.add("characterized_endpoint")
    if entity_type == "ua_family" and entity.get("structural_checks"):
        families.add("ua_family_structure")
    if entity_type == "campaign" and entity.get("leads"):
        families.add("coordinated_activity")
    return families


def _has_characterized_endpoint_evidence(endpoint: dict[str, Any]) -> bool:
    return any(
        str(category) in _POSITIVE_ENDPOINT_CATEGORIES
        and _num(requests) > 0
        for category, requests in (endpoint.get("category_requests") or {}).items()
    )


def _coverage_pct(entity: dict[str, Any]) -> float | None:
    for key in ("drilldown_coverage", "drilldown_coverage_summary"):
        value = entity.get(key)
        if not isinstance(value, dict):
            continue
        raw = value.get("coverage_pct")
        if raw is None:
            raw = value.get("weighted_coverage_pct")
        if raw is not None:
            return _num(raw)
    return None


def _pressure(entity: dict[str, Any]) -> dict[str, Any]:
    requests = _num(entity.get("requests") or entity.get("total_requests"))
    status_429 = _num(entity.get("status_429") or entity.get("requests_429"))
    status_5xx = _num(entity.get("status_5xx") or entity.get("requests_5xx"))
    rate_429 = _num(entity.get("rate_429_pct"))
    rate_5xx = _num(entity.get("rate_5xx_pct"))
    if requests > 0:
        rate_429 = max(rate_429, _pct(status_429, requests) or 0.0)
        rate_5xx = max(rate_5xx, _pct(status_5xx, requests) or 0.0)
    for row in entity.get("endpoint_targets") or []:
        if not isinstance(row, dict):
            continue
        rate_429 = max(rate_429, _num(row.get("rate_429_pct")))
        rate_5xx = max(rate_5xx, _num(row.get("rate_5xx_pct")))
    flags = set(str(flag) for flag in entity.get("evidence_flags") or [])
    return {
        "rate_429_pct": rate_429,
        "rate_5xx_pct": rate_5xx,
        "has_rate_or_error_pressure": "rate_limit_or_error_pressure" in flags or rate_429 >= 2.0 or rate_5xx >= 2.0,
        "has_5xx_pressure": rate_5xx >= 2.0,
    }


def _mapping(category: str) -> dict[str, Any]:
    base = _MITRE.get(category, {})
    return {
        "mitre_techniques": list(base.get("mitre_techniques") or []),
        "mitre_tactics": list(base.get("mitre_tactics") or []),
        "hdx_techniques": list(base.get("hdx_techniques") or []),
        "mapping_note": (
            "Mappings are consistent with observed signal only; they are not attribution, "
            "operator identity, intent, or proof of a named ATT&CK procedure."
        ),
    }


def _hypothesis(category: str, score: float, evidence: list[str], signals: list[str]) -> dict[str, Any]:
    return {
        "category": category,
        "confidence": round(max(0.0, min(score, 1.0)), 3),
        "trigger_evidence": evidence[:6],
        "distinguishing_signals": signals[:6],
        "recommended_action_modifier": _MODIFIERS.get(category),
        "attack_mapping": _mapping(category),
    }


def classify_entity(entity: dict[str, Any], *, entity_type: str) -> dict[str, Any]:
    if entity.get("known_traffic"):
        return {"primary": None, "secondary": [], "ambiguity_note": None}
    endpoint = _endpoint_stats(entity)
    shares = endpoint["category_shares"]
    pressure = _pressure(entity)
    flags = set(str(flag) for flag in entity.get("evidence_flags") or [])
    coverage = _coverage_pct(entity)
    surface_label = str((entity.get("drilldown_coverage_summary") or {}).get("surface_label") or "")
    diffuse = surface_label == "diffuse_surface" or (coverage is not None and coverage < 5.0)
    coordinated = entity_type == "campaign" or "coordinated_activity" in flags
    timing_regular = bool(entity.get("temporal_regularity")) or any(
        str(flag) == "temporal_regularity" for flag in flags
    )
    unique_paths = endpoint["unique_path_count"]
    requests = _num(entity.get("requests") or entity.get("total_requests"))
    requests_per_path = requests / unique_paths if unique_paths else requests
    unique_ips = _num(entity.get("unique_client_ips"))
    member_count = _num(entity.get("member_count"))
    request_cv = _num(entity.get("request_volume_cv"), 999.0)
    structural = set(str(item) for item in entity.get("structural_checks") or [])
    positive_families = _positive_evidence_families(entity, endpoint, entity_type=entity_type)
    characterized_endpoint = _has_characterized_endpoint_evidence(endpoint)

    scored: list[dict[str, Any]] = []

    def add(category: str, score: float, evidence: list[str], signals: list[str]) -> None:
        if score > 0.3:
            scored.append(_hypothesis(category, score, evidence, signals))

    catalog_share = shares.get("catalog_search_product_content", 0.0)
    api_share = shares.get("api", 0.0) + shares.get("graphql", 0.0)
    auth_share = shares.get("auth", 0.0)
    transaction_share = shares.get("transaction", 0.0)
    asset_share = shares.get("static_asset", 0.0) + shares.get("tracking_static_asset", 0.0)

    add(
        "scraper_catalog",
        min(0.9, 0.25 + catalog_share / 100.0 * 0.65 + (0.1 if timing_regular else 0.0)),
        [f"Catalog/search/product endpoints represent {catalog_share:.1f}% of scoped endpoint requests."],
        ["catalog/search/product concentration", "timing regularity present" if timing_regular else "endpoint evidence only"],
    )
    add(
        "scraper_pricing",
        min(0.9, 0.15 + endpoint["pricing_share_pct"] / 100.0 * 0.65 + (0.12 if timing_regular else 0.0) + (0.08 if api_share >= 40 else 0.0)),
        [f"Pricing/rate/availability paths represent {endpoint['pricing_share_pct']:.1f}% of scoped endpoint requests."],
        ["narrow pricing or availability API focus", "regular timing" if timing_regular else "timing not established"],
    )
    add(
        "credential_stuffing",
        min(0.95, 0.1 + auth_share / 100.0 * 0.55 + (0.18 if pressure["has_rate_or_error_pressure"] else 0.0) + (0.12 if unique_ips >= 10 else 0.0)),
        [f"Auth endpoints represent {auth_share:.1f}% of endpoint requests.", f"429/5xx pressure present: {pressure['has_rate_or_error_pressure']}."],
        ["auth concentration", "fan-out" if unique_ips >= 10 else "fan-out not established", "429/5xx pressure" if pressure["has_rate_or_error_pressure"] else "pressure not established"],
    )
    add(
        "inventory_abuse",
        min(0.9, 0.18 + transaction_share / 100.0 * 0.68 + (0.08 if pressure["has_rate_or_error_pressure"] else 0.0)),
        [f"Transaction endpoints represent {transaction_share:.1f}% of endpoint requests."],
        ["checkout/booking/cart/hold path concentration", "pressure present" if pressure["has_rate_or_error_pressure"] else "pressure not established"],
    )
    add(
        "rate_limit_evasion",
        min(0.95, (0.45 if entity_type == "ua_family" else 0.25 if entity.get("ua_family_id") else 0.0) + (0.20 if member_count >= 3 else 0.0) + (0.18 if request_cv <= 0.2 else 0.0) + (0.12 if structural else 0.0) + (0.1 if pressure["has_rate_or_error_pressure"] else 0.0)),
        ["UA family version rotation is present.", f"Request volume CV is {request_cv:.2f}."],
        ["browser-major template rotation", "uniform request volume" if request_cv <= 0.2 else "request volume not uniform", "structural zero-point checks" if structural else "structural checks absent"],
    )
    training_positive = asset_share > 0 and (coordinated or diffuse or catalog_share + api_share >= 20)
    if training_positive:
        add(
            "training_collection",
            min(0.88, 0.12 + (0.28 if diffuse else 0.0) + asset_share / 100.0 * 0.35 + (0.14 if catalog_share + api_share >= 20 else 0.0)),
            [f"Diffuse surface: {diffuse}.", f"Static/tracking asset share is {asset_share:.1f}%."],
            ["diffuse crawl surface", "asset fetching", "content/API mix" if catalog_share + api_share >= 20 else "content/API mix not established"],
        )
    add(
        "application_ddos",
        min(0.92, 0.12 + (0.22 if coordinated else 0.0) + (0.22 if pressure["has_5xx_pressure"] else 0.0) + (0.18 if api_share + auth_share + transaction_share >= 40 else 0.0) + (0.12 if requests >= 10_000 else 0.0)),
        [f"Coordinated activity: {coordinated}.", f"5xx pressure present: {pressure['has_5xx_pressure']}."],
        ["coordinated high-volume pressure", "expensive endpoint mix" if api_share + auth_share + transaction_share >= 40 else "expensive endpoint mix not established", "5xx pressure" if pressure["has_5xx_pressure"] else "5xx not established"],
    )
    add(
        "reconnaissance",
        min(0.86, 0.12 + (0.30 if unique_paths >= 20 else 0.0) + (0.18 if diffuse else 0.0) + (0.16 if unique_paths and requests_per_path <= 25 else 0.0)),
        [f"Unique path count lower bound is {unique_paths}.", f"Requests per path lower bound is {requests_per_path:.1f}."],
        ["high path breadth", "low requests per path" if unique_paths and requests_per_path <= 25 else "requests per path not low", "diffuse surface" if diffuse else "surface not diffuse"],
    )

    parsed = ((entity.get("ua_plausibility") or {}).get("parsed") or {})
    if not scored and parsed.get("ua_class") == "first_party_native_app":
        scored.append(
            _hypothesis(
                "scraper_catalog",
                0.31,
                ["First-party native-app traffic retained as low-confidence catalog scraper hypothesis because no stronger category fit."],
                ["native-app distribution evidence only"],
            )
        )

    if not positive_families:
        scored = []
    if entity_type == "lead" and not characterized_endpoint:
        scored = [
            item
            for item in scored
            if item.get("category") == "rate_limit_evasion"
        ]
    if entity_type == "lead":
        scored = [
            item
            for item in scored
            if _num(item.get("confidence")) >= _STANDALONE_MIN_CONFIDENCE
        ]

    scored.sort(key=lambda item: (-_num(item.get("confidence")), str(item.get("category"))))
    primary = scored[0] if scored else None
    secondary = scored[1:]
    ambiguity_note = None
    if len(scored) >= 2 and _num(scored[0].get("confidence")) - _num(scored[1].get("confidence")) <= 0.15:
        ambiguity_note = (
            f"Primary {scored[0]['category']} is close to {scored[1]['category']}; "
            "treat classification as a conservative hypothesis until route-specific validation is complete."
        )
    return {
        "primary": primary,
        "secondary": secondary,
        "ambiguity_note": ambiguity_note,
    }


def conservative_modifier(classification: dict[str, Any]) -> str | None:
    hypotheses = [
        item
        for item in [classification.get("primary"), *(classification.get("secondary") or [])]
        if isinstance(item, dict)
    ]
    if not hypotheses:
        return None
    primary_score = _num(hypotheses[0].get("confidence"))
    close = [
        item
        for item in hypotheses
        if primary_score - _num(item.get("confidence")) <= 0.15
    ]
    selected = min(
        close or hypotheses[:1],
        key=lambda item: _CONSERVATIVE_RANK.get(str(item.get("category")), 99),
    )
    return selected.get("recommended_action_modifier")


def attach_classifications(
    *,
    scraper_cases: list[dict[str, Any]],
    campaigns: list[dict[str, Any]],
    ua_families: list[dict[str, Any]],
) -> None:
    by_ua = {str(case.get("user_agent")): case for case in scraper_cases if case.get("user_agent")}
    for family in ua_families:
        family["threat_classification"] = classify_entity(family, entity_type="ua_family")
    family_by_id = {str(family.get("family_id")): family for family in ua_families}
    for campaign in campaigns:
        campaign["threat_classification"] = classify_entity(campaign, entity_type="campaign")
    for case in scraper_cases:
        classification = classify_entity(case, entity_type="lead")
        family = family_by_id.get(str(case.get("ua_family_id") or ""))
        if isinstance(family, dict):
            family_primary = (family.get("threat_classification") or {}).get("primary")
            if isinstance(family_primary, dict) and family_primary.get("category") == "rate_limit_evasion":
                classification = {
                    "primary": family_primary,
                    "secondary": [
                        item
                        for item in [classification.get("primary"), *(classification.get("secondary") or [])]
                        if isinstance(item, dict) and item.get("category") != "rate_limit_evasion"
                    ],
                    "ambiguity_note": classification.get("ambiguity_note"),
                }
        case["threat_classification"] = classification
    for campaign in campaigns:
        for ua in campaign.get("leads") or []:
            member = by_ua.get(str(ua))
            if member and not campaign.get("threat_classification", {}).get("primary"):
                campaign["threat_classification"] = member.get("threat_classification") or {}
