from __future__ import annotations

from ._shared import *

def _iocs_from_context(ctx: dict[str, Any]) -> dict[str, list[str]]:
    uas: list[str] = []
    endpoints: list[str] = []
    ips: list[str] = []
    asns: list[str] = []

    for action in ctx.get("recommended_actions") or []:
        _collect_action_iocs(action, uas, endpoints)
    for campaign in ctx.get("campaigns") or []:
        _collect_actor_iocs(campaign, uas, endpoints, ips, asns, ua_key="leads")
    for case in ctx.get("scraper_cases") or []:
        _collect_actor_iocs(case, uas, endpoints, ips, asns, ua_key="user_agent")
    for row in (ctx.get("infrastructure") or {}).get("asn_rollups") or []:
        if not isinstance(row, dict):
            continue
        _add_unique(asns, row.get("asn") or row.get("autonomous_system_number"))
    return {
        "user_agents": uas,
        "endpoints": endpoints,
        "client_ips": ips,
        "asns": asns,
    }

def _collect_action_iocs(
    action: dict[str, Any], uas: list[str], endpoints: list[str]
) -> None:
    targets = _target_values(action)
    for ua in targets.get("user_agents") or []:
        _add_unique(uas, ua)
    for endpoint in targets.get("endpoint_prefixes") or []:
        _add_unique(endpoints, endpoint)

def _collect_actor_iocs(
    actor: dict[str, Any],
    uas: list[str],
    endpoints: list[str],
    ips: list[str],
    asns: list[str],
    *,
    ua_key: str,
) -> None:
    values = actor.get(ua_key) if ua_key == "leads" else [actor.get(ua_key)]
    for ua in values or []:
        _add_unique(uas, ua)
    for row in actor.get("endpoint_targets") or []:
        if isinstance(row, dict):
            _add_unique(endpoints, _endpoint_path(row))
    for key in ("client_ips", "ip_samples", "shared_ip_samples"):
        for ip in actor.get(key) or []:
            _add_unique(ips, ip)
    if actor.get("asn"):
        _add_unique(asns, actor.get("asn"))

def _exports_for_ui(data: dict[str, Any]) -> dict[str, str]:
    artifact_metadata = (
        data.get("artifact_metadata")
        if isinstance(data.get("artifact_metadata"), dict)
        else {}
    )
    payload = {
        "report": "threat_hunt",
        "schema_version": data["meta"]["schema"],
        "window": data["meta"]["window_current"],
        "verdict": {
            "level": data["verdict"]["level"],
            "confidence": data["verdict"]["confidence"],
        },
        "campaign": {
            "id": data["campaign"]["id"],
            "classification": data["campaign"]["classification"],
            "attack": data["campaign"]["attack"],
        },
        "iocs": data["iocs"],
    }
    source: dict[str, Any] = {}
    if isinstance(artifact_metadata.get("input_manifest"), dict):
        source["input_manifest"] = artifact_metadata["input_manifest"]
    if source:
        payload["source"] = source
    if isinstance(artifact_metadata.get("harvest_plan"), dict):
        payload["harvest_plan"] = artifact_metadata["harvest_plan"]
    if isinstance(artifact_metadata.get("replay_policy"), dict):
        payload["replay_policy"] = artifact_metadata["replay_policy"]
    ua_expr = [f'(http.user_agent eq "{ua}")' for ua in data["iocs"]["user_agents"][:8]]
    endpoint_lines = [f'    "{path}",' for path in data["iocs"]["endpoints"]]
    waf_snippet = (
        "# WAF expression - block-or-challenge candidates\n"
        "# Generated from bot_threat_hunt.v3\n\n"
        + "\nor ".join(ua_expr)
    )
    if endpoint_lines:
        waf_snippet += (
            "\nor (\n  http.request.uri.path in {\n"
            + "\n".join(endpoint_lines)
            + "\n  }\n  and cf.bot_management.score < 30\n)\n"
        )
    return {
        "json": json.dumps(payload, indent=2, sort_keys=True),
        "ua_list": "\n".join(data["iocs"]["user_agents"]),
        "endpoint_list": "\n".join(data["iocs"]["endpoints"]),
        "waf_snippet": waf_snippet,
    }

def _action_source_confidence(action: dict[str, Any], ctx: dict[str, Any]) -> dict[str, str]:
    targets = action.get("target_values") if isinstance(action.get("target_values"), dict) else {}
    qualifiers: list[str] = []

    if action.get("scope") == "campaign" and targets.get("campaign_id"):
        campaign_id = str(targets["campaign_id"])
        campaign = next(
            (
                row
                for row in ctx.get("campaigns") or []
                if str(row.get("campaign_id") or "") == campaign_id
            ),
            {},
        )
        member_set = {str(ua) for ua in campaign.get("leads") or []}
        qualifiers = [
            str(((case.get("confidence_assessment") or {}).get("qualifier") or "unavailable"))
            for case in ctx.get("scraper_cases") or []
            if str(case.get("user_agent") or "") in member_set
        ]
    elif action.get("scope") == "ua_family":
        members = {str(ua) for ua in targets.get("user_agents") or []}
        qualifiers = [
            str(((case.get("confidence_assessment") or {}).get("qualifier") or "unavailable"))
            for case in ctx.get("scraper_cases") or []
            if str(case.get("user_agent") or "") in members
        ]
    else:
        uas = {str(ua) for ua in targets.get("user_agents") or []}
        qualifiers = [
            str(((case.get("confidence_assessment") or {}).get("qualifier") or "unavailable"))
            for case in ctx.get("scraper_cases") or []
            if str(case.get("user_agent") or "") in uas
        ]

    high_partial = sum(1 for qualifier in qualifiers if qualifier in {"high", "partial"})
    low_unavailable = sum(1 for qualifier in qualifiers if qualifier not in {"high", "partial"})
    if high_partial and low_unavailable:
        label = f"mixed confidence: {high_partial} high/partial, {low_unavailable} validate first"
        bucket = "response" if action.get("tier") != "tier_4" else "validate"
    elif high_partial:
        label = "high/partial confidence"
        bucket = "response" if action.get("tier") != "tier_4" else "validate"
    elif qualifiers:
        label = "low/unavailable confidence - validate first"
        bucket = "validate"
    else:
        label = "scope-level action - validate current membership"
        bucket = "validate"
    return {"label": label, "bucket": bucket}

def _action_groups(actions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    response = [action for action in actions if action.get("confidence_bucket") == "response"]
    validate = [action for action in actions if action.get("confidence_bucket") != "response"]
    groups = []
    if response:
        groups.append(
            {
                "title": "Impact-backed response candidates",
                "lede": (
                    "These actions are tied to high/partial confidence evidence. Validate current membership "
                    "before enforcement; Hunt impact totals use the same confidence boundary."
                ),
                "actions": response,
            }
        )
    if validate:
        groups.append(
            {
                "title": "Monitor / validate before enforcement",
                "lede": (
                    "These lower-confidence or mixed-scope items stay in the queue for revalidation, watchlisting, "
                    "or challenge-first handling. Do not treat them as part of the Hunt impact total."
                ),
                "actions": validate,
            }
        )
    return groups

def _topline_lede(data: dict[str, Any]) -> list[dict[str, str]]:
    hunt_impact = data.get("hunt_impact") if isinstance(data.get("hunt_impact"), dict) else {}
    rows = {
        str(row.get("label") or ""): row
        for row in hunt_impact.get("rows") or []
        if isinstance(row, dict)
    }
    hits = rows.get("Hits") or {}
    hydrolix = rows.get("Hydrolix log ingest") or {}
    akamai = rows.get("Akamai-billed") or {}
    impact_parts = []
    if hits.get("value"):
        impact_parts.append(
            f"{hits['value']} hits"
            + (f" ({hits['share']} of window HTTP requests)" if hits.get("share") else "")
        )
    if hydrolix.get("value") and hydrolix.get("value") != "unavailable":
        impact_parts.append(
            f"{hydrolix['value']} Hydrolix log ingest"
            + (f" ({hydrolix['share']} of customer log volume)" if hydrolix.get("share") else "")
        )
    if akamai.get("value") and akamai.get("value") != "unavailable":
        impact_parts.append(
            f"{akamai['value']} Akamai-billed bandwidth"
            + (f" ({akamai['share']} of CDN billed bandwidth)" if akamai.get("share") else "")
        )
    impact = (
        "Hunt-scoped findings account for " + "; ".join(impact_parts) + "."
        if impact_parts
        else "Impact is bounded to the supplied threat-hunt evidence."
    )

    response_count = sum(
        len(group.get("actions") or [])
        for group in data.get("action_groups") or []
        if group.get("title") == "Impact-backed response candidates"
    )
    validate_count = sum(
        len(group.get("actions") or [])
        for group in data.get("action_groups") or []
        if group.get("title") == "Monitor / validate before enforcement"
    )
    first_response = next(
        (
            action
            for group in data.get("action_groups") or []
            if group.get("title") == "Impact-backed response candidates"
            for action in group.get("actions") or []
            if isinstance(action, dict)
        ),
        None,
    )
    action_parts = []
    if response_count:
        action_parts.append(f"{response_count} impact-backed response candidates")
    if validate_count:
        action_parts.append(f"{validate_count} validation-first items")
    actions = (
        "Recommended queue: " + " and ".join(action_parts) + "."
        if action_parts
        else "No recommended actions were generated from the supplied evidence."
    )
    if first_response:
        target = first_response.get("target_value") or first_response.get("scope_label") or "top target"
        actions += f" Start with {first_response.get('action_type') or 'Monitor'} for {target}."

    return [
        {
            "label": "What the hunt found",
            "body": data["verdict"]["summary"],
        },
        {
            "label": "Impact of those findings",
            "body": impact,
        },
        {
            "label": "Recommended actions",
            "body": actions,
        },
    ]

__all__ = [name for name in globals() if not name.startswith("__")]
