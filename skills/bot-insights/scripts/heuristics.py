"""Heuristic-ladder constants for the incident-report suspicious-target flow.

Calibration constants for the rule set that promotes actor-ranking rows to
``bot_incident_action_targets.v1`` entries. Lifted to their own module so
operator calibration against real incidents is a focused one-file change
and so the same thresholds can be referenced from both the producer
orchestrator (``bot_insights_report.py``) and any renderer-side
explainers that want to show "we flagged this because share >= 5%".

Every constant carries the rationale for its current value; see
``references/incident-analysis.md`` for the full calibration narrative.
Treat these as load-bearing — the conservative-by-design contract spelled
out in ``references/pitfalls.md`` rests on them.
"""

from __future__ import annotations

import re


# ---------------------------------------------------------------------------
# Share / volume floors. Promote a ranking row from "observed" to "flagged".
# Tuned to surface genuine outliers without firing on background traffic.
# ---------------------------------------------------------------------------

_SUSPICIOUS_VOLUME_SHARE_MIN = 0.05  # 5% of in-window requests
_SUSPICIOUS_RATE_429_SHARE_MIN = 0.10  # 10% of in-window 429s
_SUSPICIOUS_RATE_429_TOTAL_MIN = 100  # de-noise tiny windows
_SUSPICIOUS_SINGLE_PATH_REQUESTS_MIN = 1000  # floor on single-path concentration
_SUSPICIOUS_ASN_CLUSTER_MIN_IPS = 3  # cluster requires >= 3 flagged IPs

# Fleet-level volume floor for the ``botnet_member`` cross-row flag.
# Individual IPs in a botnet fan-out attack rarely cross the
# ``high_volume_share`` 5% bar — share is split across thousands of
# nodes. The cluster's *combined* share is the honest quant signal at
# the fleet level. Calibrated against the Expedia 2026-04-19 incident:
# the AS24940 Hetzner cluster of 3 flagged IPs ran at 0.70% of the
# window with verified ASN attribution — clearly malicious, but a 1%
# floor missed it. 0.5% catches genuine ~3-IP VPS clusters without
# tripping on noise (a 50M-req cluster in a 10B-req window is real).
_SUSPICIOUS_BOTNET_CLUSTER_SHARE_MIN = 0.005

# Magnitude floor for the ``high_volume_new_actor`` flag on lone
# (non-clustered) new client IPs. ``new_in_window`` alone is a
# categorical signal — a brand-new IP doing 1 request and one doing
# 30M requests both get the same flag, leaving high-volume singletons
# stuck at severity:low. The cluster pivots (``single_asn_cluster``,
# ``botnet_member``) only fire when >=3 flagged peers share an ASN;
# lone high-volume IPs across distinct ASNs slip through.
#
# Calibrated against the Expedia 2026-04-19 incident: 8 lone-ASN
# new-in-window IPs at 24-30M reqs each in a 10.9B-req window
# (0.22-0.27% share) carried real signal but stayed at severity:low,
# action_class:monitor, invisible in the editorial top-10. 0.1% share
# captures them; the absolute floor (1M reqs) prevents false fires
# on tiny windows where share% spikes are noise.
_SUSPICIOUS_NEW_ACTOR_VOLUME_SHARE_MIN = 0.001
_SUSPICIOUS_NEW_ACTOR_REQUESTS_MIN = 1_000_000


# ---------------------------------------------------------------------------
# Identification patterns.
# ---------------------------------------------------------------------------

# Common scripted-client UA tokens. Hits trigger ``automation_user_agent``.
_AUTOMATION_UA_PATTERN = re.compile(
    r"\b(curl|python-requests|Go-http-client|wget|libwww|httpx|aiohttp)\b",
    re.IGNORECASE,
)

# CMS / SPA routing tables typically collapse high-cardinality URL
# spaces (every article, every product page, every hotel listing) into
# a single templated pattern that begins with a placeholder segment
# like ``/:slug``, ``/:locale/:slug``, or ``/:id``. When the upstream
# capture aggregates by ``requestPathPattern``, that single bucket
# inevitably accumulates the highest volume share — but it represents
# millions of distinct underlying URLs, not a real focal point.
#
# Treat any request_path target whose value starts with a placeholder
# segment as a catch-all bucket: it can still be flagged via volume
# and 429 primitives, but ``single_path_concentration`` is
# tautologically true for any ``GROUP BY request_path`` row and gives
# a false-positive critical-tier flag here. Suppressing it lets real,
# specific endpoints (``/graphql``, ``/api/v1/auth/login``,
# ``/login/submit``) keep their critical tier while CMS buckets fall
# to high — visible, but no longer dominating the ranking.
_TEMPLATED_CATCHALL_PATH_PATTERN = re.compile(r"^/:[A-Za-z_][\w]*")


def _is_templated_catchall_path(value: str) -> bool:
    """Return True if ``value`` is a CMS-bucket templated path pattern
    whose leading segment is a placeholder (``/:slug``, ``/:locale``,
    ``/:id/...``). Used by the suspicious-target heuristic to suppress
    the tautological ``single_path_concentration`` flag for such
    patterns."""
    return bool(_TEMPLATED_CATCHALL_PATH_PATTERN.match(value or ""))


# ---------------------------------------------------------------------------
# Anomaly primitive. An actor's current-window error rate
# (req_429+req_5xx)/requests is at least N× its own baseline error rate,
# with absolute floors to de-noise the long tail. Applies across all
# entity types (cohort, IP, ASN, UA, path, country) — wherever a baseline
# error rate is known.
# ---------------------------------------------------------------------------

_ANOMALY_ERROR_RATE_RATIO_MIN = 3.0   # current >= 3× baseline
_ANOMALY_CURRENT_ERROR_RATE_MIN = 0.05  # current rate >= 5%
_ANOMALY_MIN_REQUESTS = 1000  # de-noise tiny actors


# ---------------------------------------------------------------------------
# Severity tiering. Ranks order rows in the canonical sort; flag-set
# partitions feed the critical-tier rule (quant AND concentration).
# ---------------------------------------------------------------------------

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# Quantitative flags — concentration in *amount* (volume or 429 share),
# distinct from concentration in *shape* (single path, single ASN cluster)
# and from identification signals (automation_user_agent, new_in_window).
# ``critical`` requires one flag from each of (quantitative) AND
# (concentration in shape), so a single-dimension actor never gets the
# top tier.
_SUSPICIOUS_QUANT_FLAGS = frozenset(
    {
        "high_volume_share",
        "high_rate_429_share",
        "botnet_member",
        "high_volume_new_actor",
    }
)

_SUSPICIOUS_CONCENTRATION_FLAGS = frozenset(
    {"single_path_concentration", "single_asn_cluster"}
)
