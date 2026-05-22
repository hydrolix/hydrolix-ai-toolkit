"""Contracts and shared context for the incident-report orchestrator."""

from __future__ import annotations

from dataclasses import dataclass, field


INCIDENT_INTERPRETATION_CONTRACT: dict[str, list[str]] = {
    "allowed": [
        "Lead the executive_summary slot with separate confidence statements "
        "for: traffic anomaly, targeted-automation hypothesis, operational "
        "impact, credential-access hypothesis, and attribution/intent. Make "
        "clear which confidence applies to which claim.",
        "Explain *why* the evidence reads that way - which combination of "
        "spike flags, suspicious-target reason flags, and SIEM signals "
        "is driving the call. State this as an opinion grounded in the "
        "named evidence, not a generic narration.",
        "Format the executive_summary as a hybrid when there are 3+ "
        "distinct parallel signals (different evidence sources concurring): "
        "a 1-sentence prose lead naming the pattern, a bulleted reasoning "
        "trail with one bullet per signal, then an optional 1-sentence "
        "closing interpretation. With 1-2 tightly-coupled signals or when "
        "reasoning interweaves with limitations, prefer integrated prose. "
        "Do not pad prose with inline (1)(2)(3) numbered reasons - use "
        "Markdown bullets instead. The colored criticality + confidence "
        "pills render above the slot already; do not restate them inside "
        "the prose.",
        "Summarize the incident's shape from the scope-confirmation evidence: "
        "request volume, 429 rate, 5xx rate, bot share, SIEM-blocked share.",
        "Describe actor concentration using the top rows in the actors section.",
        "When describing infrastructure topology, count the distinct ASN or "
        "ASN-organization values present in the evidence. Say 'single-ASN' "
        "only when every named actor in the claim has the same ASN. Otherwise "
        "use wording such as 'across N hosting ASN clusters' and name the "
        "ASNs only when they are present in the evidence.",
        "Reference evidence with human-readable labels (Client IP, Client ASN, "
        "Request Path, User Agent, Country, Request host, Status code).",
        "State limitations explicitly when the actors section is empty, only a "
        "single prior-day or prior-window baseline exists, auth telemetry is "
        "missing, or SIEM evidence is missing - including how that affects "
        "confidence in targeted-automation and credential-access hypotheses.",
        "Name the top 1-3 suspicious targets explicitly using their "
        "human-readable label (Client IP `203.0.113.10`, Client ASN 64500, "
        "User Agent `python-requests/2.31`).",
        "Cite the reason flags that promoted each target - for example "
        "'flagged for high volume share and single-path concentration'.",
        "When the `anomaly` primitive fires on a target, name the "
        "baseline-relative magnitude explicitly (e.g. 'Browser cohort "
        "error rate climbed to X% vs ~Y% baseline, an N× departure'). "
        "The anomaly flag carries baseline corroboration the share-based "
        "primitives don't, so it warrants a sentence in the lede when "
        "present.",
        "Reference at least one target from the action-targets artifact in "
        "the next-steps slot.",
        "Frame authentication-abuse labels as evidence-bounded investigation "
        "leads. Credential-access mappings without auth-specific telemetry "
        "must be called a 'possible investigation lead', not credential "
        "stuffing or brute force.",
        "Say 'human-classified anomalous traffic' when a Human/Browser cohort "
        "is anomalous. Do not call it a Human-cohort attack or a proven "
        "Human-cohort anomaly unless classifier-validation evidence is present.",
    ],
    "forbidden": [
        "Do not name internal tables (akamai.logs, bi_summary_*, "
        "bi_siem_policy_summary_*) — refer to 'this report's evidence' or to "
        "the report type by name.",
        "Do not claim malicious intent, abuse, attack causality, actor intent, "
        "or root cause.",
        "Do not use targeted, attack, credential stuffing, brute force, botnet, "
        "actor intent, or root cause as firm claims unless the evidence packet "
        "contains the required corroborating fields. Targeted automation "
        "requires multi-signal actor/path evidence and a rolling or multi-day "
        "baseline before it can be high confidence. Credential access requires "
        "an auth endpoint plus auth outcomes, account identifiers, or explicit "
        "auth/SIEM correlation.",
        "Do not invent metrics, rankings, share percentages, deltas, severity "
        "labels, or dashboard URLs.",
        "Do not invent business or customer-impact facts such as revenue, "
        "booking failures, checkout errors, funnel completion, customer "
        "reports, or latency. Those require explicit supplied evidence; log "
        "volume, status, and actor data are not enough.",
        "Do not invent response-timeline facts such as WAF push time, deny-list "
        "updates, rate-limit changes, post-push drops, threat-intel tickets, "
        "or prior incident waves. Only mention them when they are explicit "
        "fields in the evidence packet or quoted user-supplied context.",
        "Do not convert edge-action evidence into configuration certainty. "
        "No Action / Monitor / Deny shares may support 'edge enforcement was "
        "limited in this window'; they do not prove a rule was absent, a "
        "specific IP was not on a list, or a policy was misconfigured.",
        "Do not collapse multiple ASN clusters into a single-ASN claim. If "
        "the evidence names multiple ASN values or organizations, preserve "
        "that plurality.",
        "Do not query Hydrolix from the interpretation step.",
        "Do not emit final HTML or Markdown layout.",
        "Do not write an executive_summary that only restates the Impact "
        "tiles - the slot must carry a criticality call and reasoning the "
        "tiles do not already convey.",
        "Do not summarize actor concentration in generic terms ('a small "
        "number of actors covered most traffic') without naming the specific "
        "top targets and their reason flags.",
        "Do not propose a specific mitigation action (block, rate-limit, "
        "challenge) - `suggested_action_hint` is mechanical and the LLM's "
        "job is to describe evidence, not propose enforcement.",
        "Do not modify the action-targets list or invent targets, reason "
        "flags, severities, or confidence labels.",
    ],
}




class _IncidentHandoff(Exception):
    """Propagate a capture MCP handoff packet out of nested helpers."""

    def __init__(self, packet: dict, label: str) -> None:
        super().__init__(label)
        self.packet = packet
        self.label = label

@dataclass
class _IncidentCtx:
    """Accumulated state threaded through the incident-report phase functions."""

    granularity: str
    summary_table: str
    raw_drilldown_available: bool = False
    siem_available: bool = False
    siem_table: str | None = None
    logs_columns: set[str] = field(default_factory=set)
    summary_columns: set[str] = field(default_factory=set)
    summary_time_column: str = "reqTimeSec"
    summary_count_column: str = "count()"
    summary_status_column: str = "statusCode"
    summary_cohort_column: str = "trafficCohort"
    summary_path_pattern_column: str = "requestPathPattern"
    fields_resolved: list[str] = field(default_factory=list)
    fields_unresolved: list[str] = field(default_factory=list)
    raw_column_by_field: dict[str, str] = field(default_factory=dict)
    raw_path_column: str = "request_path"
    raw_bytes_column: str = "bytesOut"
    bot_source_columns: set[str] = field(default_factory=set)
    proxy_classification_columns: set[str] = field(default_factory=set)
    top_n: int = 10
    limitations_scope: list[str] = field(default_factory=list)
    limitations_actors: list[str] = field(default_factory=list)
    window_confirmation: dict = field(default_factory=dict)
    volume_timeseries: dict | None = None
    scope_meta: dict = field(default_factory=dict)
    scope_artifact: dict = field(default_factory=dict)
    actors_artifact: dict = field(default_factory=dict)
    action_targets_artifact: dict = field(default_factory=dict)
    action_targets_limitations: list[str] = field(default_factory=list)
    suspicious_targets: list[dict] = field(default_factory=list)
    target_evidence: dict[str, dict] = field(default_factory=dict)
    behavior_clusters: list[dict] = field(default_factory=list)
    entity_clusters: list[dict] = field(default_factory=list)
    flagged_client_ip_timeseries: list[dict] = field(default_factory=list)
    detection_source: str = "summary"
    raw_fallback_used: bool = False
