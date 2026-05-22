"""Static campaign detector constants."""

from __future__ import annotations

VERDICT_ORDER = {
    "strong_lead": 0,
    "lead": 1,
    "weak_lead": 2,
    "not_enough_data": 3,
}

_TRACKING_STATIC_PATHS = (
    "/cl/2x2.json",
    "/travel-pixel-js",
    "/egds/fonts",
    "/favicon.ico",
    "/landing-pwa/css",
)

_TARGET_ENDPOINT_CATEGORIES = {"api", "graphql", "catalog_search_product_content", "auth"}
