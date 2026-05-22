from __future__ import annotations

from ._shared import *

def _fmt_float(value: Any) -> str:
    if value is None:
        return "unavailable"
    try:
        return f"{float(value):.2f}"
    except (TypeError, ValueError):
        return "unavailable"

def _fmt_dt(value: Any, fmt: str) -> str:
    if not value:
        return ""
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return str(value)
    return parsed.strftime(fmt)

def _count_label(count: int, singular: str, plural: str | None = None) -> str:
    return f"{count} {singular if count == 1 else (plural or singular + 's')}"

def _highest_verdict(campaigns: list[dict[str, Any]], cases: list[dict[str, Any]]) -> str:
    weights = {
        "confirmed": 6,
        "strong_lead": 5,
        "likely": 4,
        "lead": 3,
        "possible": 2,
        "weak_lead": 1,
        "not_enough_data": 0,
    }
    verdicts = [
        str(item.get("verdict", "not_enough_data"))
        for item in [*campaigns, *cases]
        if isinstance(item, dict)
    ]
    return max(verdicts or ["not_enough_data"], key=lambda v: weights.get(v, 0))

def _summary_level(verdict: str) -> tuple[str, str]:
    return {
        "confirmed": ("Confirmed scraper evidence", "critical"),
        "strong_lead": ("Strong scraper lead", "high"),
        "likely": ("Likely scraper evidence", "high"),
        "lead": ("Scraper lead", "monitor"),
        "possible": ("Possible scraper evidence", "observe"),
        "weak_lead": ("Weak scraper lead", "observe"),
        "not_enough_data": ("Insufficient evidence", "neutral"),
    }.get(verdict, ("Insufficient evidence", "neutral"))

def _severity_level(verdict: str) -> str:
    return {
        "confirmed": "critical",
        "strong_lead": "high",
        "likely": "high",
        "lead": "medium",
        "possible": "low",
        "weak_lead": "low",
        "not_enough_data": "low",
    }.get(verdict, "low")

def _severity_ladder(level: str) -> list[dict[str, Any]]:
    steps = [
        ("low", "Observe", "var(--sev-observe)"),
        ("medium", "Monitor", "var(--sev-monitor)"),
        ("elevated", "Elevated", "var(--sev-elevated)"),
        ("high", "High", "var(--sev-high)"),
        ("critical", "Critical", "var(--sev-critical)"),
    ]
    keys = [key for key, _label_text, _color in steps]
    cutoff = keys.index(level) if level in keys else 0
    return [
        {
            "key": key,
            "label": label,
            "bar_color": color,
            "on": idx <= cutoff,
            "current": idx == cutoff,
        }
        for idx, (key, label, color) in enumerate(steps)
    ]

def _first_endpoint_label(artifact: dict[str, Any], campaigns: list[dict[str, Any]], cases: list[dict[str, Any]]) -> str:
    for campaign in campaigns:
        label = _campaign_endpoint_label(campaign)
        if label:
            return label
    for case in cases:
        label = _case_endpoint_label(case)
        if label:
            return label
    return ""

def _campaign_endpoint_label(campaign: dict[str, Any]) -> str:
    evidence = campaign.get("endpoint_evidence_summary") or {}
    source_text = (
        "confirmed campaign endpoint evidence"
        if evidence.get("counts_for_verdict")
        else "campaign endpoint context"
    )
    for row in campaign.get("endpoint_targets") or []:
        if isinstance(row, dict) and row.get("endpoint_prefix"):
            share = _fmt_pct(row.get("share_pct"))
            return f"{row.get('endpoint_prefix')} ({share} of campaign traffic; {source_text})"
    return ""

def _case_endpoint_label(case: dict[str, Any]) -> str:
    evidence = case.get("endpoint_evidence") or {}
    source_text = (
        "confirmed scoped endpoint targeting"
        if evidence.get("counts_for_verdict")
        else "endpoint context"
    )
    for row in case.get("endpoint_targets") or []:
        if not isinstance(row, dict):
            continue
        value = row.get("request_path") or row.get("value")
        if value:
            share = row.get("share_pct")
            if share is None:
                share = row.get("request_share_pct")
            return f"{value} ({_fmt_pct(share)} of lead traffic; {source_text})"
    return ""
    for row in artifact.get("endpoints") or []:
        if isinstance(row, dict) and row.get("value"):
            return f"{row.get('value')} ({_fmt_pct(row.get('request_share_pct'))} of site-level endpoint context)"
    return "No endpoint concentration supplied"

def _request_total(campaigns: list[dict[str, Any]], cases: list[dict[str, Any]], artifact: dict[str, Any]) -> Any:
    if campaigns:
        return sum(float(c.get("total_requests") or 0) for c in campaigns if isinstance(c, dict))
    if cases:
        return sum(float(c.get("requests") or 0) for c in cases if isinstance(c, dict))
    for row in (artifact.get("baseline_movement") or {}).get("metric_deltas") or []:
        if isinstance(row, dict) and row.get("metric") in {"requests", "total_requests"}:
            return row.get("current")
    return None

def _confidence_label(artifact: dict[str, Any], campaigns: list[dict[str, Any]], cases: list[dict[str, Any]]) -> str:
    has_campaign = bool(campaigns)
    has_timing = any(isinstance(c, dict) and c.get("temporal_regularity") for c in cases)
    has_drilldown = any(
        isinstance(c, dict) and (c.get("endpoint_targets") or c.get("hourly_bursts"))
        for c in cases
    )
    if has_campaign and has_timing and has_drilldown:
        return "Conservative confidence"
    if cases and (has_timing or has_drilldown or has_campaign):
        return "Partial confidence"
    if artifact.get("module_scorecards") or cases:
        return "Limited confidence"
    return "Insufficient evidence"

def _build_drivers(
    artifact: dict[str, Any], campaigns: list[dict[str, Any]], cases: list[dict[str, Any]]
) -> list[str]:
    drivers: list[str] = []
    if campaigns:
        top = campaigns[0]
        drivers.append(
            f"{_count_label(len(campaigns), 'campaign')} linked multiple scraper leads; top campaign carries {_fmt_num(top.get('total_requests'))} requests."
        )
    if cases:
        top_case = cases[0]
        flags = [_label(str(flag)) for flag in top_case.get("evidence_flags") or []]
        flag_text = ", ".join(flags[:3]) if flags else "no named evidence flags"
        drivers.append(
            f"{_count_label(len(cases), 'scraper lead')} assembled; strongest lead shows {flag_text}."
        )
    ua_confirmed = sum(
        1
        for case in cases
        if isinstance(case.get("ua_plausibility"), dict)
        and case["ua_plausibility"].get("counts_for_verdict")
    )
    if ua_confirmed:
        drivers.append(f"{_count_label(ua_confirmed, 'lead')} has verdict-driving UA plausibility anomaly evidence.")
    top_endpoint = _first_endpoint_label(artifact, campaigns, cases)
    if not top_endpoint.startswith("No endpoint"):
        drivers.append(f"Endpoint context is visible at {top_endpoint}.")
    if not any(isinstance(c, dict) and c.get("temporal_regularity") for c in cases):
        drivers.append("Request-level timing evidence was not supplied for the visible leads.")
    return drivers[:3] or ["No campaign or scraper-lead evidence cleared the supplied thresholds."]

def _build_deterministic_summary(
    artifact: dict[str, Any], campaigns: list[dict[str, Any]], cases: list[dict[str, Any]]
) -> dict[str, Any]:
    verdict = _highest_verdict(campaigns, cases)
    level_label, tone = _summary_level(verdict)
    severity = _severity_level(verdict)
    drivers = _build_drivers(artifact, campaigns, cases)
    return {
        "level": verdict,
        "severity_level": severity,
        "level_label": level_label,
        "level_tone": tone,
        "confidence_label": _confidence_label(artifact, campaigns, cases),
        "summary": drivers[0],
        "reasons": drivers,
    }

__all__ = [name for name in globals() if not name.startswith("__")]
