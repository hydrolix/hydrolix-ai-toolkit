"""Label / tone constants for the incident-report context."""

from __future__ import annotations

__all__ = [
    'SPIKE_FLAG_LABELS',
    'REASON_FLAG_LABELS',
    'TARGET_TYPE_LABELS',
    'ACTION_CLASS_LABELS',
    'ACTION_CLASS_TONE',
    'SEVERITY_TONE',
    'CRITICALITY_TONE',
    'IOC_TYPE_MAP',
    '_DEFAULT_FIELD_LABELS',
    '_default_field_label',
    '_EDGE_ACTION_LABELS',
]


SPIKE_FLAG_LABELS = {
    "volume_up": "Volume up",
    "volume_down": "Volume down",
    "rate_429_up": "429 rate up",
    "rate_429_down": "429 rate down",
    "rate_5xx_up": "5xx rate up",
    "rate_5xx_down": "5xx rate down",
    "bot_share_up": "Bot share up",
    "bot_share_down": "Bot share down",
    "blocked_share_up": "SIEM blocked share up",
    "blocked_share_down": "SIEM blocked share down",
}


REASON_FLAG_LABELS = {
    "high_volume_share": "high volume share",
    "high_rate_429_share": "high 429 share",
    "single_path_concentration": "single-path concentration",
    "new_in_window": "new in window",
    "single_asn_cluster": "single-ASN cluster",
    "botnet_member": "coordinated infrastructure cluster",
    "high_volume_new_actor": "high-volume new actor",
    "automation_user_agent": "automation user agent",
    "anomaly": "behavioral anomaly",
}


TARGET_TYPE_LABELS = {
    "client_ip": "Client IP",
    "asn": "Client ASN",
    "user_agent": "User Agent",
    "request_path": "Request Path",
    "country": "Country",
    "cohort": "Traffic cohort",
}


ACTION_CLASS_LABELS = {
    "block":      "Block",
    "challenge":  "Challenge",
    "rate-limit": "Rate-limit",
    "watch":      "Watch",
    "monitor":    "Monitor",
}


ACTION_CLASS_TONE = {
    "block":      "critical",
    "challenge":  "escalate",
    "rate-limit": "escalate",
    "watch":      "monitor",
    "monitor":    "observe",
}


SEVERITY_TONE = {
    "critical": "critical",
    "high": "escalate",
    "medium": "monitor",
    "low": "observe",
    # ``review`` is the v1 vocabulary — kept here so wrappers produced
    # by the older orchestrator continue to render until they are
    # regenerated. v2 emits ``medium`` / ``low`` instead.
    "review": "monitor",
}


CRITICALITY_TONE = {
    "critical": "critical",
    "high": "escalate",
    "elevated": "elevated",
    "medium": "monitor",
    "low": "observe",
}


IOC_TYPE_MAP = {
    "client_ip": "ip",
    "asn": "asn",
    "user_agent": "user_agent",
    "request_path": "url_path",
    "country": "country",
    "cohort": "cohort",
}


_DEFAULT_FIELD_LABELS = {
    "client_ip": "Client IP",
    "asn": "Client ASN",
    "request_path": "Request Path",
    "user_agent": "User Agent",
    "country": "Country",
    "status_code": "Status Code",
    "request_method": "Request Method",
    "trafficCohort": "Traffic cohort",
}


def _default_field_label(field: str) -> str:
    if not field:
        return ""
    if field in _DEFAULT_FIELD_LABELS:
        return _DEFAULT_FIELD_LABELS[field]
    return field.replace("_", " ").title()


_EDGE_ACTION_LABELS = {
    "Deny": "Denied",
    "Monitor": "Monitored",
    "Allow": "Passed",
    "Tarpit": "Tarpitted",
}
