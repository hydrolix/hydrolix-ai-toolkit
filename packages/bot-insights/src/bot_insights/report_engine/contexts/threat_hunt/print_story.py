from __future__ import annotations

from ._shared import *

def _print_known_traffic(rows: list[dict[str, Any]], limit: int = 3) -> list[dict[str, str]]:
    return [
        {
            "label": _label(str(row.get("disposition") or "known_traffic")),
            "target_html": f"<code>{_short_ua_label(row.get('user_agent'))}</code>",
            "detail_html": (
                f"{_fmt_num(row.get('requests'))} observed requests. "
                f"{row.get('reason') or 'Known crawler or infrastructure traffic.'}"
            ),
        }
        for row in rows[:limit]
    ]

def _story_classification(source: dict[str, Any] | None) -> dict[str, str]:
    classification = (source or {}).get("threat_classification") or {}
    primary = classification.get("primary") if isinstance(classification, dict) else None
    if not isinstance(primary, dict):
        return {
            "category": "Evidence bounded",
            "confidence": "confidence unavailable",
            "summary": "Evidence bounded; confidence unavailable",
        }
    category = primary.get("category_label") or _label(str(primary.get("category") or "evidence_bounded"))
    confidence = primary.get("confidence_display")
    if not confidence or confidence == "unavailable":
        confidence = "confidence unavailable"
    else:
        confidence = f"confidence {confidence}"
    return {
        "category": category,
        "confidence": confidence,
        "summary": f"{category}; {confidence}",
    }

def _story_fanout_lower_bound(cases: list[dict[str, Any]]) -> str:
    values = []
    for case in cases:
        fanout = case.get("fanout_enrichment") or {}
        value = _to_float(fanout.get("effective_ips"))
        if value is None:
            value = _to_float(fanout.get("unique_ips"))
        if value is not None:
            values.append(value)
    if not values:
        return "Not established"
    return f">= {_fmt_num(max(values))} effective IPs"

def _story_ua_mix(cases: list[dict[str, Any]], campaign: dict[str, Any] | None = None) -> str:
    if campaign:
        campaign_id = campaign.get("campaign_id")
        member_set = set(str(value) for value in campaign.get("leads") or [])
        rows = [
            case
            for case in cases
            if case.get("campaign_id") == campaign_id or str(case.get("user_agent") or "") in member_set
        ]
    else:
        rows = cases
    if not rows:
        return "UA mix not established"
    counts: dict[str, int] = {}
    for case in rows:
        parsed = (case.get("ua_plausibility") or {}).get("parsed") or {}
        browser = parsed.get("browser_family")
        if browser and str(browser).lower() not in {"unknown", "other"}:
            label = str(browser)
        else:
            label = _parsed_ua_label(case).split("/", 1)[0]
        counts[label] = counts.get(label, 0) + 1
    parts = [
        f"{label} x{count}"
        for label, count in sorted(counts.items(), key=lambda item: item[1], reverse=True)[:3]
    ]
    return ", ".join(parts)

def _story_primary_finding(
    campaigns: list[dict[str, Any]],
    cases: list[dict[str, Any]],
    top_pattern: str,
    top_surface: str,
    audience: str,
) -> dict[str, Any]:
    if campaigns:
        campaign = campaigns[0]
        campaign_cases = [
            case
            for case in cases
            if case.get("campaign_id") == campaign.get("campaign_id")
            or str(case.get("user_agent") or "") in set(str(value) for value in campaign.get("leads") or [])
        ]
        classification = _story_classification(campaign)
        return {
            "eyebrow": "Primary finding",
            "title": str(campaign.get("campaign_id") or "Linked campaign"),
            "summary": (
                f"{_count_label(len(campaign.get('leads') or []), 'member')} linked by campaign evidence "
                f"with {_fmt_num(campaign.get('total_requests'))} requests."
            ),
            "classification": classification["summary"],
            "rows": [
                {"label": "Members", "value": _count_label(len(campaign.get("leads") or []), "member")},
                {"label": "UA / browser mix", "value": _story_ua_mix(campaign_cases or cases, campaign)},
                {"label": "Timing pattern", "value": campaign.get("temporal_pattern_label") or top_pattern},
                {"label": "Surface", "value": top_surface},
                {"label": "Fan-out lower bound", "value": _story_fanout_lower_bound(campaign_cases or cases)},
                {"label": "Request volume", "value": _fmt_num(campaign.get("total_requests"))},
            ],
            "impact": _print_impact_block(campaign.get("impact_assessment")),
        }
    top = cases[0] if cases else {}
    classification = _story_classification(top)
    return {
        "eyebrow": "Primary finding",
        "title": _parsed_ua_label(top) if top else "No campaign established",
        "summary": (
            f"{_parsed_ua_label(top)} is the highest-volume lead with {_fmt_num(top.get('requests'))} requests."
            if top
            else "No scraper leads were supplied."
        ),
        "classification": classification["summary"],
        "rows": [
            {"label": "Members", "value": "No linked campaign"},
            {"label": "UA / browser mix", "value": _story_ua_mix(cases)},
            {"label": "Timing pattern", "value": top_pattern},
            {"label": "Surface", "value": top_surface},
            {"label": "Fan-out lower bound", "value": _story_fanout_lower_bound(cases)},
            {"label": "Request volume", "value": _fmt_num(top.get("requests")) if top else "unavailable"},
        ],
        "impact": _print_impact_block(top.get("impact_assessment") if top else {}),
    }

def _story_secondary_finding(
    ua_families: list[dict[str, Any]], cases: list[dict[str, Any]], audience: str
) -> dict[str, Any]:
    if ua_families:
        family = sorted(ua_families, key=lambda row: float(row.get("total_requests") or 0), reverse=True)[0]
        classification = _story_classification(family)
        if classification["confidence"] == "confidence unavailable" and family.get("recommended_actions"):
            action = family["recommended_actions"][0]
            category = action.get("threat_category_label") or "Evidence bounded"
            confidence = action.get("threat_confidence_display") or "unavailable"
            classification = {
                "category": category,
                "confidence": f"confidence {confidence}" if confidence != "unavailable" else "confidence unavailable",
                "summary": f"{category}; confidence {confidence}" if confidence != "unavailable" else category,
            }
        version = family.get("version_range_display") or "unavailable"
        if family.get("version_count"):
            version = f"{version}; {family.get('version_count')} versions"
        return {
            "eyebrow": "Secondary finding",
            "title": str(family.get("family_id") or "UA family"),
            "summary": "Version rotation indicates an operator-controlled UA template rather than a single static client.",
            "classification": classification["summary"],
            "rows": [
                {"label": "Top UA family", "value": str(family.get("family_id") or "UA family")},
                {"label": "Version range", "value": version},
                {"label": "Requests", "value": family.get("total_requests_display") or _fmt_num(family.get("total_requests"))},
            ],
            "impact": _print_impact_block(family.get("impact_assessment")),
        }
    top = cases[0] if cases else {}
    classification = _story_classification(top)
    return {
        "eyebrow": "Secondary finding",
        "title": _parsed_ua_label(top) if top else "No UA family",
        "summary": (
            "No parameterized UA-family rotation was established in the supplied artifact."
            if top
            else "No parameterized UA-family rotation was established in the supplied artifact."
        ),
        "classification": classification["summary"],
        "rows": [
            {"label": "Top UA family", "value": "Not established"},
            {"label": "Version range", "value": "Not established"},
            {"label": "Requests", "value": _fmt_num(top.get("requests")) if top else "unavailable"},
        ],
        "impact": _print_impact_block(top.get("impact_assessment") if top else {}),
    }

def _story_independent_leads(cases: list[dict[str, Any]]) -> dict[str, Any]:
    independent = [
        case
        for case in cases
        if not case.get("campaign_id") and not case.get("ua_family_id") and case.get("tone") in {"escalate", "monitor", "observe"}
    ]
    requests = sum(_to_float(case.get("requests")) or 0.0 for case in independent)
    representatives = [
        {
            "label": _parsed_ua_label(case),
            "evidence": ", ".join((case.get("evidence_flag_labels") or [])[:2]) or "Observed",
        }
        for case in independent[:3]
    ]
    return {
        "eyebrow": "Independent leads",
        "count": len(independent),
        "count_display": _count_label(len(independent), "lead"),
        "requests_display": _fmt_num(requests),
        "summary": (
            f"{_count_label(len(independent), 'independent lead')} outside campaign and UA-family groupings "
            f"accounts for {_fmt_num(requests)} requests."
        ),
        "representatives": representatives,
        "impact": _print_impact_block(
            {
                "requests": requests,
                "bytes": sum(_to_float(case.get("bytes")) or 0.0 for case in independent),
                "request_share": sum(
                    _to_float((case.get("impact_assessment") or {}).get("request_share")) or 0.0
                    for case in independent
                ),
                "byte_share": sum(
                    _to_float((case.get("impact_assessment") or {}).get("byte_share")) or 0.0
                    for case in independent
                ),
                "trend_severity": "mixed" if len(independent) > 1 else ((independent[0].get("impact_assessment") or {}).get("trend_severity") if independent else "stable"),
            }
        ),
    }

def _cover_threat_headline(
    campaigns: list[dict[str, Any]],
    ua_families: list[dict[str, Any]],
    cases: list[dict[str, Any]],
    artifact_classification: dict[str, Any] | None,
) -> str:
    source: dict[str, Any] | None = campaigns[0] if campaigns else (ua_families[0] if ua_families else (cases[0] if cases else None))
    classification = _story_classification(source or {"threat_classification": artifact_classification or {}})
    requests = 0.0
    if campaigns:
        requests = sum(_to_float(campaign.get("total_requests")) or 0.0 for campaign in campaigns)
    elif ua_families:
        requests = sum(_to_float(family.get("total_requests")) or 0.0 for family in ua_families)
    else:
        requests = sum(_to_float(case.get("requests")) or 0.0 for case in cases)
    member_count = sum(len(campaign.get("leads") or []) for campaign in campaigns)
    if not member_count:
        member_count = sum(_to_float(family.get("member_count")) or 0.0 for family in ua_families)
    noun = "operation" if campaigns else "lead set"
    return (
        f"Coordinated forged-UA {noun} consistent with {classification['category']}; "
        f"{_count_label(len(campaigns), 'campaign')}, {_count_label(int(member_count), 'member')}, "
        f"{_count_label(len(cases), 'lead')}, {_fmt_num(requests)} requests."
    )

def _print_bot_manager_summary(context: dict[str, Any]) -> dict[str, str] | None:
    if not context.get("available"):
        return None
    aggregate = context.get("aggregate") or {}
    exact_ua = context.get("exact_ua") or {}
    parts = []
    if aggregate.get("available"):
        parts.append(f"{aggregate.get('total_requests_display')} aggregate Bot Manager requests")
    if exact_ua.get("available"):
        parts.append(f"{exact_ua.get('total_requests_display')} exact-UA requests")
    action_mix = aggregate.get("action_class_mix") or []
    if action_mix:
        top = action_mix[0]
        parts.append(
            f"top action {str(top.get('value') or 'unknown').replace('_', ' ')} "
            f"({_fmt_tiny_pct(top.get('share_pct'))})"
        )
    return {
        "label": "Bot Manager context",
        "text": "; ".join(parts) or context.get("summary") or "Bot Manager context supplied",
        "caveat": context.get("caveat")
        or "Operational enrichment only; not independent classification evidence.",
    }

def _print_bot_manager_stack(rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    classes = ["allow", "challenge", "deny", "monitor", "other"]
    stack = []
    legend = []
    for idx, row in enumerate(rows[:5]):
        css_class = classes[idx] if idx < len(classes) else "other"
        share = _to_float(row.get("share_pct")) or 0.0
        label = str(row.get("value") or "unknown").replace("_", " ").title()
        stack.append(
            {
                "class": css_class,
                "flex": max(share, 1.0),
                "label": label,
                "show_label": share >= 8.0,
                "min_width": "16px" if share > 0 else "",
            }
        )
        legend.append(
            {
                "class": css_class,
                "label": label,
                "value": f"{_fmt_num(row.get('requests'))} ({_fmt_tiny_pct(row.get('share_pct'))})",
                "delta": "",
            }
        )
    return stack, legend

def _print_bot_manager_policy_rows(rows: list[dict[str, Any]], limit: int = 6) -> list[dict[str, str]]:
    return [
        {
            "rule": str(row.get("value") or "unknown"),
            "requests": _fmt_num(row.get("requests")),
            "share": _fmt_tiny_pct(row.get("share_pct")),
            "delta": "",
            "delta_class": "ink-3",
        }
        for row in rows[:limit]
    ]

def _print_bot_manager_type_rows(rows: list[dict[str, Any]], limit: int = 5) -> list[dict[str, Any]]:
    out = []
    for row in rows[:limit]:
        share = _to_float(row.get("share_pct")) or 0.0
        out.append(
            {
                "name": str(row.get("value") or "unknown").replace("_", " ").title(),
                "requests": _fmt_num(row.get("requests")),
                "share": _fmt_tiny_pct(row.get("share_pct")),
                "rate_429": "n/a",
                "rate_5xx": "n/a",
                "flagged": False,
                "bar_width": f"{max(min(share, 100.0), 1.0):.1f}%",
                "min_width": "4px",
            }
        )
    return out

def _classification_technique_rows(ctx: dict[str, Any], limit: int = 6) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    sources = [
        *(ctx.get("campaigns") or []),
        *(ctx.get("ua_families") or []),
        *(ctx.get("scraper_cases") or []),
    ]
    for source in sources:
        classification = source.get("threat_classification") or {}
        primary = classification.get("primary") if isinstance(classification, dict) else None
        if not isinstance(primary, dict):
            continue
        mapping = primary.get("attack_mapping") or {}
        category = str(primary.get("category") or "")
        evidence = "; ".join(str(item) for item in (primary.get("trigger_evidence") or [])[:2])
        tactics = ", ".join(mapping.get("mitre_tactics") or []) or "ATT&CK"
        key = (_label(category), tactics)
        row = grouped.setdefault(
            key,
            {
                "tid": "",
                "technique_ids": [],
                "tactic": tactics,
                "name": _label(category),
                "evidence_html": (
                    f"Consistent with observed {category.replace('_', ' ')} signal only; "
                    f"not attribution. {evidence}"
                ),
                "span_full": False,
            },
        )
        for technique in mapping.get("mitre_techniques") or []:
            tid = str(technique)
            if tid in row["technique_ids"]:
                continue
            row["technique_ids"].append(tid)
        for technique in mapping.get("hdx_techniques") or []:
            tid = str(technique)
            if tid in row["technique_ids"]:
                continue
            row["technique_ids"].append(tid)
    rows = list(grouped.values())[:limit]
    for row in rows:
        row["tid"] = ", ".join(row["technique_ids"]) or "Technique unavailable"
    return rows

__all__ = [name for name in globals() if not name.startswith("__")]
