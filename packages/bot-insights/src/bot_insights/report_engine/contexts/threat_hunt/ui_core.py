from __future__ import annotations

from ._shared import *

def _window_pretty(window: Any) -> str:
    if not isinstance(window, dict):
        return "window unavailable"
    start = window.get("start") or window.get("from")
    end = window.get("end") or window.get("to")
    if start and end:
        return f"{start} to {end}"
    return str(window.get("pretty") or window.get("label") or "window unavailable")

def _add_unique(values: list[str], value: Any) -> None:
    text = str(value or "").strip()
    if text and text not in values:
        values.append(text)

def _target_values(action: dict[str, Any]) -> dict[str, Any]:
    targets = action.get("target_values") if isinstance(action.get("target_values"), dict) else {}
    return targets

def _action_primary_target(action: dict[str, Any]) -> tuple[str, str]:
    targets = _target_values(action)
    if targets.get("campaign_id"):
        return "Campaign ID", str(targets["campaign_id"])
    if targets.get("ua_family_id"):
        return "UA family", str(targets["ua_family_id"])
    if targets.get("ua_family_template"):
        return "UA family", str(targets["ua_family_template"])
    uas = targets.get("user_agents") or []
    if uas:
        return "User agent", str(uas[0])
    endpoints = targets.get("endpoint_prefixes") or []
    if endpoints:
        return "Endpoint", str(endpoints[0])
    return _label(str(action.get("scope") or "target")), "selected target"

def _action_secondary_targets(action: dict[str, Any]) -> list[dict[str, str]]:
    targets = _target_values(action)
    rows: list[dict[str, str]] = []
    primary_kind, primary_value = _action_primary_target(action)
    for ua in targets.get("user_agents") or []:
        if primary_kind == "User agent" and str(ua) == primary_value:
            continue
        rows.append({"kind": "User agent", "value": str(ua)})
    for endpoint in targets.get("endpoint_prefixes") or []:
        if primary_kind == "Endpoint" and str(endpoint) == primary_value:
            continue
        rows.append({"kind": "Endpoint", "value": str(endpoint)})
    return rows[:6]

def _attack_labels(source: dict[str, Any]) -> list[str]:
    classification = source.get("threat_classification") or {}
    primary = classification.get("primary") if isinstance(classification, dict) else {}
    mapping = primary.get("attack_mapping") if isinstance(primary, dict) else {}
    if not isinstance(mapping, dict):
        return []
    labels = [
        *(str(value) for value in mapping.get("mitre_techniques") or []),
        *(str(value) for value in mapping.get("hdx_techniques") or []),
    ]
    out: list[str] = []
    for label in labels:
        _add_unique(out, label)
    return out

def _classification_label(source: dict[str, Any]) -> str | None:
    classification = source.get("threat_classification") or {}
    primary = classification.get("primary") if isinstance(classification, dict) else {}
    if not isinstance(primary, dict):
        return None
    category = primary.get("category_label") or _label(str(primary.get("category") or "evidence_bounded"))
    confidence = primary.get("confidence_display")
    if confidence and confidence != "unavailable":
        return f"{category} · {confidence}"
    return category

def _lead_ui(case: dict[str, Any]) -> dict[str, Any]:
    impact = case.get("impact_assessment") or {}
    ua = str(case.get("user_agent") or "unknown UA")
    baseline = case.get("baseline_comparison") or _baseline_comparison(case)
    timing = case.get("timing") or {}
    ua_view = case.get("ua_plausibility") or {}
    return {
        "user_agent": ua,
        "verdict_label": case.get("verdict_label") or "Lead",
        "tone": case.get("tone") or "observe",
        "requests": case.get("requests_display") or _fmt_num(case.get("requests")),
        "baseline": case.get("baseline_display") or _fmt_num(case.get("baseline_requests")),
        "delta": baseline.get("display") or "unavailable",
        "delta_signed": baseline.get("delta_display") or "unavailable",
        "delta_dir": "up" if (_to_float(baseline.get("delta")) or 0) >= 0 else "down",
        "share": impact.get("request_share_display") or "unavailable",
        "bytes": impact.get("bytes_display") or case.get("bytes_display") or "unavailable",
        "campaign": case.get("campaign_id"),
        "ua_anomaly": f"{ua_view.get('verdict_label') or 'Unavailable'} · {ua_view.get('reason') or ua_view.get('trigger_reason') or 'no trigger'}",
        "ua_anomaly_tone": "escalate"
        if ua_view.get("verdict") == "confirmed"
        else "monitor"
        if ua_view.get("verdict") == "elevated"
        else "low",
        "timing": timing.get("metric_line") or timing.get("summary") or "Timing unavailable",
        "timing_tone": "monitor" if timing.get("status") == "regular" else "low",
        "classification": _classification_label(case),
        "attack": (_attack_labels(case) or [None])[0],
        "evidence": case.get("evidence_flag_labels") or [],
    }

def _endpoint_path(row: dict[str, Any]) -> str | None:
    value = row.get("endpoint_prefix") or row.get("request_path") or row.get("path") or row.get("value")
    return str(value) if value else None

def _campaign_ui(campaigns: list[dict[str, Any]]) -> dict[str, Any]:
    campaign = campaigns[0] if campaigns else {}
    endpoints = []
    for row in campaign.get("endpoint_targets") or []:
        if not isinstance(row, dict):
            continue
        path = _endpoint_path(row)
        if not path:
            continue
        endpoints.append(
            {
                "path": path,
                "category": row.get("category") or ",".join(row.get("markers") or []) or "endpoint",
                "requests": _fmt_num(row.get("requests")),
                "share": _fmt_pct(row.get("share_pct") if row.get("share_pct") is not None else row.get("request_share_pct")),
            }
        )
    ua_summary = campaign.get("ua_plausibility_summary") or {}
    endpoint_summary = campaign.get("endpoint_evidence_summary") or {}
    attack = _attack_labels(campaign)
    return {
        "id": str(campaign.get("campaign_id") or "No linked campaign"),
        "verdict_label": campaign.get("verdict_label") or "Evidence bounded",
        "tone": campaign.get("tone") or "observe",
        "sophistication": _label(str(campaign.get("sophistication") or "not_established")),
        "pattern": campaign.get("temporal_pattern_label") or _label(str(campaign.get("temporal_pattern") or "not_established")),
        "requests": campaign.get("total_requests_display") or _fmt_num(campaign.get("total_requests")),
        "baseline": campaign.get("baseline_requests_display") or _fmt_num(campaign.get("baseline_requests")),
        "delta": campaign.get("baseline_delta_display") or "unavailable",
        "members": len(campaign.get("leads") or []),
        "ips": campaign.get("unique_client_ips") or 0,
        "asns": campaign.get("unique_asns") or 0,
        "countries": campaign.get("unique_countries") or 0,
        "ua_confirmed": ua_summary.get("confirmed_count") or 0,
        "ua_elevated": ua_summary.get("elevated_count") or 0,
        "confirmed_endpoint_members": endpoint_summary.get("confirmed_member_count") or 0,
        "unconfirmed_endpoint_members": endpoint_summary.get("unconfirmed_member_count") or 0,
        "forged_ua_candidate": bool(campaign.get("forged_ua_candidate") or ua_summary.get("confirmed_count")),
        "classification": _classification_label(campaign) or "Evidence bounded",
        "attack": attack or ["Technique unavailable"],
        "endpoint_targets": endpoints,
        "ua_members": [str(value) for value in campaign.get("leads") or []],
    }

def _impact_tiles_ui(ctx: dict[str, Any]) -> list[dict[str, str]]:
    tiles = []
    for tile in ctx.get("impact_tiles") or []:
        tiles.append(
            {
                "label": str(tile.get("label") or ""),
                "value": str(tile.get("value") or ""),
                "delta": str(tile.get("caption") or tile.get("delta") or ""),
                "tone": str(tile.get("tone") or "observe"),
            }
        )
    return tiles

def _impact_rows_ui(ctx: dict[str, Any]) -> list[dict[str, str]]:
    assessment = ctx.get("impact_assessment") if isinstance(ctx.get("impact_assessment"), dict) else {}
    hunt = assessment.get("hunt") if isinstance(assessment.get("hunt"), dict) else {}
    if not hunt:
        return []
    return _explicit_impact_rows(hunt)

__all__ = [name for name in globals() if not name.startswith("__")]
