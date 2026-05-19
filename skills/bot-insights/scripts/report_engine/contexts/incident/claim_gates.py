"""Conservative claim gates for incident-report language."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from .formatters import _format_count

__all__ = ["build_claim_profile"]


_AUTH_PATH_MARKERS = (
    "/auth",
    "/login",
    "/signin",
    "/sign-in",
    "/oauth",
    "/sso",
    "/token",
    "/session",
    "credential",
)

_AUTH_TELEMETRY_MARKERS = (
    "auth_outcome",
    "authentication_outcome",
    "login_outcome",
    "failure_reason",
    "account_id",
    "user_id",
    "username",
    "email",
    "siem_auth",
)

_BLOCKED_FIRM_PHRASES = [
    "targeted surge",
    "attack",
    "credential stuffing",
    "brute force",
    "botnet",
    "intent",
    "root cause",
]

_APPROVED_PHRASES = [
    "traffic anomaly",
    "observed automation indicators",
    "targeted automation hypothesis",
    "credential-access investigation lead",
    "human-classified anomalous traffic",
]


def _parse_dt(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _baseline_strength(scope_meta: dict[str, Any]) -> str:
    start = _parse_dt(scope_meta.get("start"))
    end = _parse_dt(scope_meta.get("end"))
    baseline_start = _parse_dt(scope_meta.get("baseline_start"))
    baseline_end = _parse_dt(scope_meta.get("baseline_end"))
    if not all((start, end, baseline_start, baseline_end)):
        return "unavailable"
    assert start is not None
    assert end is not None
    assert baseline_start is not None
    assert baseline_end is not None
    current_duration = end - start
    baseline_duration = baseline_end - baseline_start
    if current_duration.total_seconds() <= 0 or baseline_duration.total_seconds() <= 0:
        return "unavailable"
    if (
        (start - baseline_start).total_seconds() == 86_400
        and current_duration == baseline_duration
    ):
        return "single_prior_day"
    if baseline_duration >= (current_duration * 2):
        return "rolling_multi_day"
    if baseline_end == start and baseline_duration == current_duration:
        return "trailing_prior_window"
    return "trailing_prior_window"


def _series_totals(scope_art: dict[str, Any]) -> tuple[float, float]:
    current_total = 0.0
    baseline_total = 0.0
    series = ((scope_art.get("volume_timeseries") or {}).get("series") or {})
    for payload in series.values():
        current_total += sum(float(value or 0) for value in payload.get("current") or [])
        baseline_total += sum(float(value or 0) for value in payload.get("baseline") or [])
    if current_total <= 0:
        current_total = float((scope_art.get("window_confirmation") or {}).get("requests") or 0)
    return current_total, baseline_total


def _traffic_anomaly_confidence(
    scope_art: dict[str, Any],
    actors_art: dict[str, Any],
    baseline_strength: str,
) -> str:
    window = scope_art.get("window_confirmation") or {}
    spike_flags = set(window.get("spike_flags") or [])
    current_total, baseline_total = _series_totals(scope_art)
    raw_available = bool(actors_art.get("raw_drilldown_available"))
    edge_available = window.get("blocked_share_pct") is not None
    has_volume_evidence = bool(spike_flags) or (
        current_total > 0 and current_total >= max(baseline_total * 1.5, baseline_total + 1)
    )
    if not has_volume_evidence:
        return "low"
    if raw_available and edge_available and baseline_strength != "unavailable":
        return "high"
    if raw_available or edge_available:
        return "medium"
    return "low"


def _target_flags(targets: list[dict[str, Any]]) -> set[str]:
    flags: set[str] = set()
    for target in targets:
        flags.update(str(flag) for flag in target.get("reason_flags") or [])
    return flags


def _has_raw_actor_path_concentration(
    actors_art: dict[str, Any],
    targets: list[dict[str, Any]],
    top_raw_paths: list[dict[str, Any]],
) -> bool:
    if not actors_art.get("raw_drilldown_available"):
        return False
    flags = _target_flags(targets)
    has_actor = any(
        target.get("target_type") in {"client_ip", "asn", "user_agent"}
        and target.get("severity") in {"critical", "high"}
        for target in targets
    )
    has_path = bool({"single_path_concentration", "path_concentration"} & flags) or any(
        float(row.get("share_pct") or 0) >= 20.0 for row in top_raw_paths
    )
    return has_actor and has_path


def _has_multi_signal_actor_path_evidence(
    actors_art: dict[str, Any],
    targets: list[dict[str, Any]],
    top_raw_paths: list[dict[str, Any]],
) -> bool:
    if not _has_raw_actor_path_concentration(actors_art, targets, top_raw_paths):
        return False
    types = {str(target.get("target_type") or "") for target in targets}
    flags = _target_flags(targets)
    shared_path = any(float(row.get("distinct_actors") or 0) >= 2 for row in top_raw_paths)
    automation_signal = bool({"automation_user_agent", "anomaly", "single_asn_cluster"} & flags)
    return shared_path or automation_signal or len(types & {"client_ip", "asn", "user_agent", "cohort"}) >= 2


def _targeted_automation_confidence(
    actors_art: dict[str, Any],
    targets: list[dict[str, Any]],
    top_raw_paths: list[dict[str, Any]],
    baseline_strength: str,
) -> str:
    if not _has_raw_actor_path_concentration(actors_art, targets, top_raw_paths):
        return "low"
    if (
        baseline_strength == "rolling_multi_day"
        and _has_multi_signal_actor_path_evidence(actors_art, targets, top_raw_paths)
    ):
        return "high"
    return "medium"


def _walk_values(value: Any) -> list[str]:
    out: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            out.append(str(key))
            out.extend(_walk_values(child))
    elif isinstance(value, list):
        for child in value:
            out.extend(_walk_values(child))
    elif value is not None:
        out.append(str(value))
    return out


def _has_auth_endpoint(scope_art: dict[str, Any], actors_art: dict[str, Any]) -> bool:
    haystack = " ".join(
        _walk_values(scope_art.get("top_targeted_path_patterns") or [])
        + _walk_values(scope_art.get("top_raw_paths") or [])
        + _walk_values(actors_art.get("actor_rankings") or [])
    ).lower()
    return any(marker in haystack for marker in _AUTH_PATH_MARKERS)


def _has_auth_specific_telemetry(*artifacts: dict[str, Any]) -> bool:
    haystack = " ".join(_walk_values(list(artifacts))).lower()
    return any(marker in haystack for marker in _AUTH_TELEMETRY_MARKERS)


def _build_hero_summary(
    scope_art: dict[str, Any],
    claim_profile: dict[str, Any],
) -> str:
    scope = scope_art.get("scope") or {}
    customer = scope.get("host") or scope.get("cluster") or "the monitored property"
    hosts = scope_art.get("top_targeted_hosts") or []
    lead_host = next((row.get("value") for row in hosts if row.get("value")), "")
    target = f"{customer}, led by {lead_host}" if lead_host and lead_host != customer else customer
    traffic_conf = str(claim_profile["traffic_anomaly_confidence"]).title()
    automation_conf = str(claim_profile["targeted_automation_confidence"]).lower()
    if automation_conf == "high":
        tail = "Targeted automation is supported by multi-signal actor/path evidence and rolling baseline validation."
    elif automation_conf == "medium":
        tail = (
            "Targeted automation remains a medium-confidence hypothesis pending "
            "rolling baseline, auth, and SIEM validation."
        )
    else:
        tail = "Targeted automation remains a low-confidence hypothesis pending corroborating actor/path evidence."
    return f"{traffic_conf}-confidence traffic anomaly across {target}. {tail}"


def build_claim_profile(
    scope_art: dict[str, Any],
    actors_art: dict[str, Any],
    action_targets_art: dict[str, Any],
    suspicious_targets: list[dict[str, Any]],
) -> dict[str, Any]:
    """Return deterministic confidence gates for incident-report prose.

    The profile controls renderer language only; it does not mutate the
    persisted incident artifacts and does not change risk scoring.
    """
    baseline_strength = _baseline_strength(scope_art.get("scope") or {})
    top_raw_paths = scope_art.get("top_raw_paths") or []
    profile: dict[str, Any] = {
        "baseline_strength": baseline_strength,
        "traffic_anomaly_confidence": _traffic_anomaly_confidence(
            scope_art, actors_art, baseline_strength
        ),
        "targeted_automation_confidence": _targeted_automation_confidence(
            actors_art, suspicious_targets, top_raw_paths, baseline_strength
        ),
        "credential_access_allowed": (
            _has_auth_endpoint(scope_art, actors_art)
            and _has_auth_specific_telemetry(scope_art, actors_art, action_targets_art)
        ),
        "language_rules": {
            "approved_phrases": list(_APPROVED_PHRASES),
            "blocked_firm_phrases": list(_BLOCKED_FIRM_PHRASES),
        },
    }
    profile["traffic_anomaly_confidence_label"] = (
        f"{str(profile['traffic_anomaly_confidence']).title()} traffic-anomaly confidence"
    )
    profile["targeted_automation_confidence_label"] = (
        f"{str(profile['targeted_automation_confidence']).title()} targeted-automation hypothesis confidence"
    )
    current_total, baseline_total = _series_totals(scope_art)
    profile["volume_evidence"] = {
        "current": current_total,
        "current_display": _format_count(current_total),
        "baseline": baseline_total,
        "baseline_display": _format_count(baseline_total),
    }
    profile["hero_summary"] = _build_hero_summary(scope_art, profile)
    return profile
