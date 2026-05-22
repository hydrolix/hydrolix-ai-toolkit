"""Local-input producer for ``bot_threat_hunt.v3`` artifacts."""
from __future__ import annotations
import csv
import glob
import ipaddress
import json
import math
import os
import re
import shutil
import subprocess
import tempfile
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable
from producers.formatting import parse_time, sql_literal, sql_ts
from producers.runtime import result_rows
from producers.threat_classifier import attach_classifications, conservative_modifier
from producers.threat_hunt_campaigns import attach_campaigns
from producers.threat_hunt_ua_plausibility import parse_user_agent, score_ua_plausibility
SCHEMA = "bot_threat_hunt.v3"
HUNT_IMPACT_INCLUDED_CONFIDENCE_QUALIFIERS = ("high", "partial")
HUNT_IMPACT_EXCLUDED_CONFIDENCE_QUALIFIERS = ("low", "unavailable")
HUNT_IMPACT_SCOPE_NOTE = (
    "Impact rows are scoped to high and partial confidence threat-hunt leads only; "
    "low-confidence and unavailable-confidence leads are excluded from impact totals."
)
RAW_COOCCURRENCE_MAX_SECONDS = 21_600
RAW_ACTOR_MAX_SECONDS = 3_600
RAW_ACTOR_HASH_BUCKETS = 16
RAW_ACTOR_TOPK_CANDIDATE_MULTIPLIER = 5
DEFAULT_COOCCURRENCE_TOP_N = 50
DEFAULT_MUX_PROJECT = Path.home() / "src/mcp-hydrolix-mux"
IMPACT_LANE_TOTAL_SCOPES = ("current_total", "baseline_total")
IMPACT_LANE_SCOPED_HUNT_SCOPES = ("current_high_partial", "baseline_high_partial")
IMPACT_LANE_REQUIRED_FIELDS = (
    "scope",
    "requests",
    "response_body_bytes",
    "akamai_billed_bytes",
)
_PATH_MARKERS = {
    "api": ("/api", "/v1", "/v2", "/v3"),
    "catalog": ("catalog", "product", "inventory", "search", "listing"),
    "graphql": ("graphql", "gql"),
    "auth": ("login", "auth", "token", "session", "oauth"),
    "transaction": (
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
    ),
}
_TRACKING_STATIC_PATHS = (
    "/cl/2x2.json",
    "/travel-pixel-js",
    "/egds/fonts",
    "/favicon.ico",
    "/landing-pwa/css",
)
_ENDPOINT_TARGETING_MARKERS = {"api", "catalog", "graphql", "auth"}
_CONFIRMED_ENDPOINT_COVERAGE_PCT = 1.0
_AUTOMATION_UA_MARKERS = (
    "bot",
    "crawl",
    "scrap",
    "spider",
    "python",
    "curl",
    "wget",
    "httpclient",
    "go-http-client",
    "aiohttp",
    "okhttp",
    "java/",
    "headless",
    "playwright",
    "selenium",
)
_KNOWN_INFRASTRUCTURE_UA_PATTERNS = (
    "akamaiimageserver",
    "akamaiimageuploader",
    "velocitudemp",
)
_KNOWN_CRAWLER_UA_PATTERNS = (
    "gsa/",
    "googlebot",
    "adidxbot",
    "bingbot",
    "adsbot-google",
    "mediapartners-google",
)
SCRAPER_EVIDENCE_FAMILIES = (
    "ua_ip_fanout",
    "ua_anomaly",
    "endpoint_targeting",
    "temporal_regularity",
    "baseline_novelty_or_growth",
    "automation_signature",
    "rate_limit_or_error_pressure",
    "infrastructure_topology",
    "classification_gap",
    "coordinated_activity",
)
@dataclass(frozen=True)
class Windows:
    start: str
    end: str
    baseline_start: str
    baseline_end: str

__all__ = [name for name in globals() if not name.startswith("__")]
