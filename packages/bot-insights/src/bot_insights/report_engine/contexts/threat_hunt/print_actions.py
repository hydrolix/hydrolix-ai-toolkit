from __future__ import annotations

from ._shared import *

def _action_target_label(action: dict[str, Any]) -> str:
    targets = action.get("target_values") if isinstance(action.get("target_values"), dict) else {}
    group_size = int(_to_float(action.get("print_group_size")) or 0)
    if group_size > 1:
        return _count_label(group_size, "lead target")
    if targets.get("campaign_id"):
        return str(targets["campaign_id"])
    if targets.get("ua_family_id"):
        return str(targets["ua_family_id"])
    uas = targets.get("user_agents") or []
    if uas:
        return _short_ua_label(uas[0])
    if targets.get("endpoint_prefixes"):
        return str(targets["endpoint_prefixes"][0])
    return "selected lead"

def _action_endpoint_label(action: dict[str, Any]) -> str:
    targets = action.get("target_values") if isinstance(action.get("target_values"), dict) else {}
    endpoints = targets.get("endpoint_prefixes") or []
    if endpoints:
        return str(endpoints[0])
    return "Revalidate current endpoint focus before enforcement"

def _action_classification(action: dict[str, Any]) -> tuple[str, str]:
    category = action.get("threat_category_label") or _label(str(action.get("threat_category") or "unclassified"))
    confidence = action.get("threat_confidence_display") or "unavailable"
    if confidence == "unavailable":
        return category, "classification confidence unavailable"
    return category, f"confidence {confidence}"

def _merge_print_action_group(base: dict[str, Any], action: dict[str, Any]) -> None:
    base_targets = base.setdefault("target_values", {})
    targets = action.get("target_values") if isinstance(action.get("target_values"), dict) else {}
    base_targets["user_agents"] = [
        *base_targets.get("user_agents", []),
        *(targets.get("user_agents") or []),
    ]
    base["print_group_size"] = int(base.get("print_group_size") or 1) + 1
    base_impact = (
        base.get("estimated_observed_window_impact")
        if isinstance(base.get("estimated_observed_window_impact"), dict)
        else {}
    )
    impact = (
        action.get("estimated_observed_window_impact")
        if isinstance(action.get("estimated_observed_window_impact"), dict)
        else {}
    )
    base["estimated_observed_window_impact"] = {
        "requests": (_to_float(base_impact.get("requests")) or 0.0)
        + (_to_float(impact.get("requests")) or 0.0),
        "bytes": (_to_float(base_impact.get("bytes")) or 0.0)
        + (_to_float(impact.get("bytes")) or 0.0),
        "request_share": (_to_float(base_impact.get("request_share")) or 0.0)
        + (_to_float(impact.get("request_share")) or 0.0),
        "byte_share": (_to_float(base_impact.get("byte_share")) or 0.0)
        + (_to_float(impact.get("byte_share")) or 0.0),
    }
    seen = set(base.get("supporting_evidence") or [])
    for flag in action.get("supporting_evidence") or []:
        if flag not in seen:
            seen.add(flag)
            base.setdefault("supporting_evidence", []).append(flag)
    base["threat_category"] = base.get("threat_category") or action.get("threat_category")
    base["threat_category_label"] = _label(str(base.get("threat_category") or "unclassified"))
    confidence_values = [
        value
        for value in [
            _to_float(base.get("threat_confidence")),
            _to_float(action.get("threat_confidence")),
        ]
        if value is not None
    ]
    if confidence_values:
        base["threat_confidence"] = max(confidence_values)
        base["threat_confidence_display"] = f"{base['threat_confidence']:.2f}"

def _group_print_actions(actions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: list[dict[str, Any]] = []
    by_key: dict[tuple[Any, ...], dict[str, Any]] = {}
    for action in actions:
        targets = action.get("target_values") if isinstance(action.get("target_values"), dict) else {}
        endpoints = tuple(targets.get("endpoint_prefixes") or [])
        if action.get("scope") != "lead" or not endpoints:
            grouped.append(action)
            continue
        key = (
            action.get("tier"),
            action.get("action_type"),
            endpoints,
            action.get("enforcement_wording"),
        )
        if key not in by_key:
            copy = {
                **action,
                "target_values": {**targets, "user_agents": list(targets.get("user_agents") or [])},
                "supporting_evidence": list(action.get("supporting_evidence") or []),
                "print_group_size": 1,
            }
            by_key[key] = copy
            grouped.append(copy)
            continue
        _merge_print_action_group(by_key[key], action)
    return grouped

def _print_actions(actions: list[dict[str, Any]], limit: int = 4) -> list[dict[str, Any]]:
    severity_by_tier = {
        "tier_1": "critical",
        "tier_2": "high",
        "tier_3": "monitor",
        "tier_4": "observe",
    }
    rows = []
    for idx, action in enumerate(_group_print_actions(actions)[:limit], start=1):
        impact = (
            action.get("estimated_observed_window_impact")
            if isinstance(action.get("estimated_observed_window_impact"), dict)
            else {}
        )
        evidence = [
            _label(str(flag))
            for flag in (action.get("supporting_evidence") or [])[:4]
            if str(flag)
        ]
        category, confidence = _action_classification(action)
        group_size = int(_to_float(action.get("print_group_size")) or 1)
        action_text = action.get("threat_action_modifier")
        if group_size > 1:
            action_text = (
                f"Apply {_label(str(action.get('enforcement_wording') or 'challenge_first')).lower()} "
                f"handling to {_count_label(group_size, 'lead target')} after validating each UA and endpoint match."
            )
        rows.append(
            {
                "n": f"{idx:02d}",
                "severity": severity_by_tier.get(str(action.get("tier")), "monitor"),
                "chip_text": _label(str(action.get("tier") or "tier_4")),
                "scope_label": _label(str(action.get("scope") or "lead")),
                "target_html": f"<code>{_action_target_label(action)}</code>",
                "action_label": _label(str(action.get("action_type") or "monitor")),
                "classification_label": category,
                "confidence_label": confidence,
                "impact_html": _impact_action_text(impact),
                "endpoint_html": _action_endpoint_label(action),
                "evidence_tags": evidence,
                "action_text": action_text
                or f"Use {_label(str(action.get('enforcement_wording') or 'challenge_first')).lower()} handling for this target candidate.",
            }
        )
    return rows

def _print_impact_block(impact: dict[str, Any] | None) -> list[dict[str, str]]:
    view = _impact_view(impact)
    byte_label = "Response body" if impact and impact.get("response_body_bytes") is not None else "Legacy bytes"
    byte_value = (
        view["response_body_bytes_display"]
        if byte_label == "Response body"
        else view["bytes_display"]
    )
    share_label = (
        "Response byte share"
        if impact and impact.get("response_body_byte_share") is not None
        else "Legacy byte share"
    )
    share_value = (
        view["response_body_byte_share_display"]
        if share_label == "Response byte share"
        else view["byte_share_display"]
    )
    rows = [
        {"label": "Requests", "value": view["requests_display"]},
        {"label": "Share of total", "value": view["request_share_display"]},
        {"label": byte_label, "value": byte_value},
        {"label": share_label, "value": share_value},
        {"label": "Trend", "value": view["trend_severity_label"]},
    ]
    if view.get("cost_range_display"):
        rows.append({"label": "Cost range", "value": view["cost_range_display"]})
    if view.get("interpretation"):
        rows.append({"label": "Readout", "value": str(view["interpretation"])})
    return rows

def _print_impact_rows(impact_assessment: dict[str, Any]) -> list[dict[str, str]]:
    if not isinstance(impact_assessment, dict):
        return []
    rows = []
    hunt = impact_assessment.get("hunt")
    if isinstance(hunt, dict):
        view = _impact_view(hunt)
        rows.extend(_explicit_impact_rows(view))
    return rows

def _explicit_impact_rows(view: dict[str, Any]) -> list[dict[str, str]]:
    if "requests_display" not in view:
        view = _impact_view(view)
    return [
        {
            "label": "Hits",
            "value": f"{view['requests_display']} ({view['request_share_display']} of window)",
            "detail": "HTTP requests attributed to this hunt scope.",
        },
        {
            "label": "Hydrolix log ingest",
            "value": (
                f"{view['hydrolix_log_ingest_bytes_display']} "
                f"({view['hydrolix_log_ingest_byte_share_display']} of customer log volume)"
            ),
            "detail": "Hydrolix bill driver",
        },
        {
            "label": "Response body",
            "value": (
                f"{view['response_body_bytes_display']} "
                f"({view['response_body_byte_share_display']} of response bytes)"
            ),
            "detail": "response data copied to scrapers",
        },
        {
            "label": "Akamai-billed",
            "value": (
                f"{view['akamai_billed_bytes_display']} "
                f"({view['akamai_billed_byte_share_display']} of CDN billed bandwidth)"
            ),
            "detail": "CDN bandwidth Akamai billed",
        },
    ]

def _hydrolix_ingest_note(impact_assessment: dict[str, Any] | None) -> str | None:
    if not isinstance(impact_assessment, dict):
        return None
    notes = []
    hunt = impact_assessment.get("hunt")
    if isinstance(hunt, dict) and hunt.get("impact_scope_note"):
        notes.append(str(hunt["impact_scope_note"]))
    metadata = impact_assessment.get("hydrolix_log_ingest_metadata")
    if (
        isinstance(metadata, dict)
        and metadata.get("source") == "hydro.logs usagemeter"
        and metadata.get("availability") == "available"
    ):
        notes.append(
            "Hydrolix log ingest is estimated from Hydrolix usagemeter billing bytes per row "
            "for the Akamai logs table."
        )
    return " ".join(notes) if notes else None

def _impact_share_relationship(impact: dict[str, Any]) -> str | None:
    request_share = _to_float(impact.get("request_share"))
    byte_share = _to_float(impact.get("response_body_byte_share"))
    if byte_share is None:
        byte_share = _to_float(impact.get("byte_share"))
    if request_share in (None, 0) or byte_share is None:
        return None
    ratio = byte_share / request_share
    if ratio <= 0.75:
        return (
            "Byte share is materially lower than request share, so this looks like many lighter requests "
            "rather than byte-heavy transfer."
        )
    if ratio >= 1.25:
        return (
            "Byte share is higher than request share, so the finding carries disproportionate transfer volume "
            "relative to its request count."
        )
    return "Byte share is broadly in line with request share, so transfer volume tracks request volume."

def _impact_trajectory_sentence(impact: dict[str, Any]) -> str:
    view = _impact_view(impact)
    direction = str(impact.get("share_direction") or "")
    if direction == "shrinking_share":
        return (
            f"Trajectory: traffic share is down from {view['baseline_request_share_display']} in baseline, "
            f"but still represents {view['request_share_display']} of current-window traffic."
        )
    if direction == "growing_share":
        return (
            f"Trajectory: traffic share rose from {view['baseline_request_share_display']} in baseline "
            f"to {view['request_share_display']} in the current window."
        )
    if direction == "new_entrant":
        return (
            f"Trajectory: this finding is newly visible against baseline and now represents "
            f"{view['request_share_display']} of current-window traffic."
        )
    return (
        f"Trajectory: traffic share is broadly stable versus the {view['baseline_request_share_display']} "
        "baseline share."
    )

def _print_source_labels(note: dict[str, Any]) -> str:
    links = note.get("links") if isinstance(note.get("links"), list) else []
    return "; ".join(
        f"{link.get('label')}: {link.get('url')}"
        for link in links
        if isinstance(link, dict) and link.get("label") and link.get("url")
    )

def _print_pattern_notes(notes: list[dict[str, Any]], limit: int = 3) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for note in notes[:limit]:
        if not isinstance(note, dict):
            continue
        rows.append(
            {
                "title": str(note.get("title") or "Pattern context"),
                "text": str(note.get("text") or ""),
                "basis": "; ".join(str(item) for item in note.get("evidence_basis") or []),
                "boundary": str(note.get("confidence_boundary") or ""),
                "sources": _print_source_labels(note),
            }
        )
    return rows

def _print_impact_story(
    impact_assessment: dict[str, Any], customer: str, pattern_notes: list[dict[str, Any]] | None = None
) -> dict[str, Any] | None:
    if not isinstance(impact_assessment, dict):
        return None
    hunt = impact_assessment.get("hunt")
    if not isinstance(hunt, dict):
        return None
    view = _impact_view(hunt)
    if view["requests_display"] == "unavailable" and view["request_share_display"] == "unavailable":
        return None
    lines = [
        (
            f"Bottom line: the threat-hunt findings account for {view['requests_display']} requests "
            f"({view['request_share_display']} of all {customer} traffic), "
            f"{view['response_body_bytes_display']} response-body bytes "
            f"({view['response_body_byte_share_display']} of response bytes), and "
            f"{view['akamai_billed_bytes_display']} Akamai-billed bytes "
            f"({view['akamai_billed_byte_share_display']} of CDN billed bandwidth) in this window."
        ),
        _impact_trajectory_sentence(hunt),
    ]
    relationship = _impact_share_relationship(hunt)
    if relationship:
        lines.append(relationship)
    hydrolix_note = _hydrolix_ingest_note(impact_assessment)
    if hydrolix_note:
        lines.append(hydrolix_note)
    if view.get("cost_range_display"):
        basis = view.get("cost_basis_label") or "configured basis"
        disclaimer = view.get("cost_disclaimer") or "estimate only"
        lines.append(f"Cost estimate: {view['cost_range_display']} on {basis}; {disclaimer}.")
    else:
        lines.append(
            "No dollar, origin-capacity, or cache-hit impact is shown because no cost config or grounded origin/cache fields were supplied."
        )
    for note in (pattern_notes or [])[:1]:
        lines.append(f"Pattern context: {note.get('title')}: {note.get('text')}")
    return {"lines": lines}

def _cover_impact_metric(label: str, impact: dict[str, Any], *, include_bytes: bool = False) -> dict[str, str]:
    parts = [
        f"{_fmt_share(impact.get('request_share'))}",
        f"{_fmt_num(impact.get('requests'))} requests",
    ]
    if include_bytes:
        response_bytes = impact.get("response_body_bytes")
        if response_bytes is None:
            response_bytes = impact.get("bytes")
        if response_bytes is not None:
            parts.append(f"{_fmt_bytes_long(response_bytes)} response body")
    return {"label": label, "value": " · ".join(parts)}

def _cover_impact_panel(
    impact_assessment: dict[str, Any],
    campaigns: list[dict[str, Any]],
    ua_families: list[dict[str, Any]],
    cases: list[dict[str, Any]],
) -> dict[str, Any] | None:
    if not isinstance(impact_assessment, dict):
        return None
    hunt = impact_assessment.get("hunt")
    if not isinstance(hunt, dict) or hunt.get("request_share") is None:
        return None
    rows = [
        {
            "label": "Finding share",
            "value": f"{_fmt_share(hunt.get('request_share'))} of window traffic",
            "emphasis": True,
        }
    ]
    if campaigns:
        campaign = campaigns[0]
        rows.append(
            _cover_impact_metric(
                str(campaign.get("campaign_id") or "Campaign"),
                campaign.get("impact_assessment") or {},
                include_bytes=True,
            )
        )
    if ua_families:
        family = sorted(ua_families, key=lambda row: _to_float(row.get("total_requests")) or 0.0, reverse=True)[0]
        rows.append(_cover_impact_metric("UA family", family.get("impact_assessment") or {}))
    independent = [
        case
        for case in cases
        if not case.get("campaign_id")
        and not case.get("ua_family_id")
        and case.get("tone") in {"escalate", "monitor", "observe"}
    ]
    if independent:
        rows.append(
            _cover_impact_metric(
                "Independent leads",
                {
                    "requests": sum(_to_float(case.get("requests")) or 0.0 for case in independent),
                    "request_share": sum(
                        _to_float((case.get("impact_assessment") or {}).get("request_share")) or 0.0
                        for case in independent
                    ),
                },
            )
        )
    return {
        "eyebrow": "Hunt Impact",
        "rows": rows,
        "footnote": "Shares use total window traffic as the denominator. Bytes are shown where they materially clarify transfer impact.",
    }

__all__ = [name for name in globals() if not name.startswith("__")]
