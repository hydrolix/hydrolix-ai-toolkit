"""Contract-level lookup tables for the suspicious-target heuristic.

Pins each ranking field (``client_ip``, ``asn``, ``request_path``, ...)
to a target type, maps each primitive flag to one or more MITRE ATT&CK
techniques, classifies target types as ``actor`` vs ``target``, and
derives a descriptive (not prescriptive) ``action_class`` that
downstream SOAR / WAF playbooks can bucket on.

These are contract surfaces: changing a target-type label or
flag-to-technique mapping breaks downstream consumers that already
read these IDs out of the ``bot_incident_action_targets.v1``
artifact. Calibration knobs (threshold floors, anomaly rates) live
elsewhere; see the top-level ``heuristics`` module.
"""

from __future__ import annotations


_SUSPICIOUS_TARGET_TYPE_BY_FIELD = {
    "client_ip": "client_ip",
    "asn": "asn",
    "user_agent": "user_agent",
    "request_path": "request_path",
    "country": "country",
    "trafficCohort": "cohort",
}

# Individual-entity fields enumerate many distinct values, most of which
# are a small share of the window. Share-based primitives
# (high_volume_share, high_rate_429_share, single_path_concentration,
# etc.) are meaningful here because a 5% share IS an outlier.
#
# Aggregate fields (cohort, country, status_code) enumerate a small
# fixed set of values, most of which are large shares of the window by
# construction. Share-based primitives would fire on every major value
# and produce noise. Only baseline-relative primitives — anomaly,
# new_in_window — fire on these fields.
_INDIVIDUAL_ENTITY_FIELDS = frozenset(
    {"client_ip", "asn", "user_agent", "request_path"}
)

# Role taxonomy. An ``actor`` is the WHO of the attack — the entity
# originating traffic. A ``target`` is the WHAT — the resource being
# hit. Same heuristic ladder catches both; the distinction matters for
# downstream SOC action because the action class differs by role even
# at the same severity tier.
_TARGET_KIND_BY_TYPE = {
    "client_ip":    "actor",
    "asn":          "actor",
    "user_agent":   "actor",
    "cohort":       "actor",
    "country":      "actor",   # source country = who hit you
    "request_path": "target",
}

# MITRE ATT&CK technique mapping per primitive.
#
# Each heuristic primitive maps to one or more techniques *consistent with*
# its signal. This is deliberately not "evidence of" — a single primitive
# alone is rarely conclusive, and the LLM contract forbids causal claims.
# The framing carried through to the rendered report is "techniques
# consistent with this signal," not "techniques used by this actor."
#
# Update with care: the technique IDs ship in the artifact and are
# consumed by downstream WAF / SOC tooling. Changing an ID is a
# breaking change for those consumers.
_PRIMITIVE_ATTACK_TECHNIQUES: dict[str, list[dict]] = {
    "high_volume_share": [
        {"id": "T1498", "name": "Network Denial of Service", "tactic": "Impact"},
    ],
    "high_rate_429_share": [
        {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
    ],
    "single_path_concentration": [
        {
            "id": "T1110.004",
            "name": "Credential Stuffing",
            "tactic": "Credential Access",
        },
    ],
    "single_asn_cluster": [
        {
            "id": "T1583.003",
            "name": "Acquire Infrastructure: Virtual Private Server",
            "tactic": "Resource Development",
        },
    ],
    "botnet_member": [
        {"id": "T1498", "name": "Network Denial of Service", "tactic": "Impact"},
    ],
    "high_volume_new_actor": [
        {"id": "T1498", "name": "Network Denial of Service", "tactic": "Impact"},
        {
            "id": "T1583.003",
            "name": "Acquire Infrastructure: Virtual Private Server",
            "tactic": "Resource Development",
        },
    ],
    "automation_user_agent": [
        {
            "id": "T1071.001",
            "name": "Application Layer Protocol: Web Protocols",
            "tactic": "Command and Control",
        },
    ],
    "anomaly": [
        {"id": "T1036", "name": "Masquerading", "tactic": "Defense Evasion"},
    ],
    # `new_in_window` intentionally has no mapping — novelty isn't a technique.
}


def _attack_techniques_for_flags(flags: list[str]) -> list[dict]:
    """Union of ATT&CK techniques from a target's reason_flags, deduped by id.

    Order preserved from flag order so the rendered output reflects the
    investigative narrative (volume → rate → concentration → infra → UA).
    """
    out: list[dict] = []
    seen_ids: set[str] = set()
    for flag in flags:
        for tech in _PRIMITIVE_ATTACK_TECHNIQUES.get(flag, []):
            tech_id = tech["id"]
            if tech_id not in seen_ids:
                seen_ids.add(tech_id)
                out.append(dict(tech))
    return out


def _client_ip_action_class(severity: str, flags: set[str]) -> str:
    if severity == "critical":
        return "block"
    if severity == "high":
        # Volume / cluster signals are confidence-grade enough for
        # challenge friction. Anomaly-only highs are weaker — watch.
        if flags & {
            "high_volume_share", "high_rate_429_share",
            "botnet_member", "high_volume_new_actor",
        }:
            return "challenge"
        return "watch"
    return "monitor"


def _user_agent_action_class(severity: str, flags: set[str]) -> str:
    # Automation UAs (curl, python-requests, etc.) are narrowly
    # attributed to scripted clients — blockable.
    if "automation_user_agent" in flags:
        return "block" if severity in ("critical", "high") else "challenge"
    # Real-browser strings caught by volume / share alone — never
    # block UA-only, that drops genuine users. Watch and pair with
    # other signals before acting.
    return "watch"


def _path_action_class(severity: str) -> str:
    if severity in ("critical", "high"):
        return "rate-limit"
    return "monitor"


def _suspicious_action_class(
    target_type: str,
    severity: str,
    reason_flags: list[str] | set[str],
) -> str:
    """Descriptive (not prescriptive) action class for an indicator.

    Names the *kind* of mitigation the signal is typically actioned
    with at a WAF / SIEM consumer — so a downstream SOAR playbook can
    bucket indicators by mitigation pathway without each consumer
    re-deriving the same logic. **Not** a directive: the report still
    sets ``suggested_action_hint = "review"`` on every indicator. A
    consumer is expected to read this as "this indicator belongs in
    the block-list workflow if you have one" rather than "block this".

    Action classes:
      - ``block``: hard-deny at the edge. Used only when the entity is
        narrowly attributed (a verified-cluster IP, an automation UA
        like curl / python-requests). Low false-positive risk.
      - ``challenge``: graceful friction (JS / CAPTCHA / fingerprint).
        Right for high-confidence-but-not-conclusive actor signals —
        a singleton high-volume new IP, a UA caught by volume alone.
      - ``rate-limit``: path-scoped throttle. The natural mitigation
        for a target (endpoint) finding — protects the resource
        without per-actor identification.
      - ``watch``: surface in analyst review, no automatic edge
        action. Right for real-browser UA strings, ASN-level findings
        (too broad to block), low-severity actors with weak signals.
      - ``monitor``: track over time, no immediate action expected.
        Right for cohort-level findings and low-severity tail.
    """
    flags = set(reason_flags or [])
    if target_type == "client_ip":
        return _client_ip_action_class(severity, flags)
    if target_type == "user_agent":
        return _user_agent_action_class(severity, flags)
    if target_type == "request_path":
        return _path_action_class(severity)
    if target_type == "asn":
        # ASN-level block is too broad — would drop legitimate
        # self-hosting customers, scrapers, etc. Watch only.
        return "watch"
    if target_type == "country":
        # Geo-rate-limit or watch — default watch.
        return "watch"
    if target_type == "cohort":
        # Behavioral grouping, not directly actionable.
        return "monitor"
    return "monitor"
