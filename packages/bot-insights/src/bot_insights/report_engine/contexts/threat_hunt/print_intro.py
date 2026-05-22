from __future__ import annotations

from ._shared import *

def _build_primary_concern(
    summary: dict[str, Any], campaigns: list[dict[str, Any]], cases: list[dict[str, Any]]
) -> dict[str, Any] | None:
    if campaigns:
        top = campaigns[0]
        return {
            "title": "Coordinated scraper campaign",
            "summary": (
                f"{top.get('campaign_id')} groups {_count_label(len(top.get('leads') or []), 'lead')} "
                f"and {_fmt_num(top.get('total_requests'))} requests."
            ),
            "boundary": "Coordination means deterministic linkage in this artifact, not a named operator.",
            "evidence": (top.get("link_narratives") or [])[:3],
        }
    if cases:
        top = cases[0]
        return {
            "title": "Independent scraper lead",
            "summary": (
                f"{_parsed_ua_label(top)} accounts for {_fmt_num(top.get('requests'))} requests "
                f"with {', '.join(top.get('evidence_flag_labels') or []) or 'limited evidence flags'}."
            ),
            "boundary": "The case remains a lead unless additional independent evidence is supplied.",
            "evidence": (top.get("case_for") or [])[:3],
        }
    return None

def _print_primary_concern_stats(
    campaigns: list[dict[str, Any]], cases: list[dict[str, Any]]
) -> list[dict[str, str]]:
    if campaigns:
        top = campaigns[0]
        coverage = top.get("drilldown_coverage_summary") or {}
        return [
            {
                "label": "Campaign",
                "value": str(top.get("campaign_id") or "campaign"),
                "detail": _count_label(len(top.get("leads") or []), "lead"),
                "value_size": "13pt",
            },
            {
                "label": "Requests",
                "value": _fmt_num(top.get("total_requests")),
                "detail": top.get("baseline_delta_display") or "",
                "value_size": "15pt",
            },
            {
                "label": "Surface",
                "value": coverage.get("surface_label_display") or "Bounded",
                "detail": f"{coverage.get('weighted_coverage_display') or 'unavailable'} coverage",
                "value_size": "10pt",
            },
        ]
    if cases:
        top = cases[0]
        return [
            {
                "label": "Lead",
                "value": _parsed_ua_label(top),
                "detail": top.get("verdict_label") or "Lead",
                "value_size": "10pt",
            },
            {
                "label": "Requests",
                "value": _fmt_num(top.get("requests")),
                "detail": top.get("baseline_delta_display") or "",
                "value_size": "15pt",
            },
            {
                "label": "Evidence",
                "value": _count_label(len(top.get("evidence_flag_labels") or []), "tag"),
                "detail": ", ".join((top.get("evidence_flag_labels") or [])[:2]),
                "value_size": "11pt",
            },
        ]
    return [
        {"label": "Evidence", "value": "Unavailable", "detail": "No scraper lead rows", "value_size": "11pt"}
    ]

def _risk_value(summary: dict[str, Any], campaigns: list[dict[str, Any]], cases: list[dict[str, Any]]) -> int:
    if summary.get("severity_level") == "critical":
        return 98
    if summary.get("severity_level") == "high":
        return 82 if campaigns else 76
    if summary.get("severity_level") == "medium":
        return 58
    if cases:
        return 34
    return 12

def _band_position(level: str) -> int:
    return {"low": 10, "medium": 35, "elevated": 58, "high": 78, "critical": 94}.get(level, 10)

def _print_window(scope: dict[str, Any]) -> dict[str, str]:
    current = scope.get("current_window") or {}
    start = current.get("start")
    end = current.get("end")
    return {
        "date": _fmt_dt(start, "%b %d, %Y") or "Threat hunt window",
        "start": _fmt_dt(start, "%H:%M") or str(start or ""),
        "end": _fmt_dt(end, "%H:%M") or str(end or ""),
        "tz": "UTC",
        "duration_short": "current window",
    }

def _print_chart(ctx: dict[str, Any]) -> dict[str, Any]:
    # Threat-hunt artifacts do not carry the incident time-series. Keep the
    # incident chart component available with a flat evidence-coverage trace
    # so the fixed-letter cover keeps the same visual hierarchy.
    return {
        "title": "Evidence Coverage",
        "subtitle": "Campaign and scraper-lead evidence",
        "baseline_label": "baseline",
        "baseline_path": "M 44,196 L 744,196",
        "spike_path": "M 44,196 L 210,184 L 360,132 L 520,92 L 744,92",
        "y_ticks": [
            {"y": "196", "label": "0"},
            {"y": "118", "label": "Leads"},
            {"y": "40", "label": "Campaigns"},
        ],
        "x_ticks": [
            {"x": "44", "label": "start", "anchor_end": False},
            {"x": "394", "label": "hunt", "anchor_end": False},
            {"x": "744", "label": "end", "anchor_end": True},
        ],
        "incident_band": {
            "x": "44",
            "y": "36",
            "width": "700",
            "height": "160",
            "label_x": "394",
            "label_y": "30",
            "label": "THREAT HUNT WINDOW",
        },
        "inflection_points": [],
        "peak": {"x": "520", "y": "92", "label_x": "528", "label_y": "82", "time": "evidence", "value": ctx["impact_tiles"][2]["value"]},
        "missing": False,
    }

def _print_actor_rows(cases: list[dict[str, Any]], limit: int = 8) -> list[dict[str, str]]:
    rows = []
    for idx, case in enumerate(cases[:limit], start=1):
        baseline = case.get("baseline_comparison") or _baseline_comparison(case)
        evidence = (case.get("evidence_flag_labels") or [])[:3]
        classification = case.get("threat_classification") or {}
        primary = classification.get("primary") if isinstance(classification, dict) else {}
        verdict = primary.get("category_label") if isinstance(primary, dict) else None
        campaign_id = case.get("campaign_id")
        rows.append(
            {
                "rank": str(idx),
                "ip": _parsed_ua_label(case),
                "asn_meta": str(campaign_id or case.get("ua_family_id") or "independent lead"),
                "requests": case.get("requests_display") or _fmt_num(case.get("requests")),
                "share": baseline.get("display") or "",
                "rate_429": baseline.get("display") or "",
                "rate_429_class": baseline.get("class") or "ink-3",
                "severity": "critical" if case.get("tone") == "escalate" else "high",
                "severity_label": case.get("verdict_label") or "Lead",
                "edge_action_html": ", ".join(evidence) or "Observed",
                "attck": verdict or case.get("verdict_label") or "Lead",
                "is_campaign_member": bool(campaign_id),
                "campaign_id": str(campaign_id or ""),
                "row_class": "campaign-member" if campaign_id else "",
            }
        )
    if rows:
        return rows
    return [
        {
            "n": "01",
            "severity": "observe",
            "chip_text": "No Action",
            "scope_label": "Empty state",
            "target_html": "<code>no recommended target</code>",
            "action_label": "Monitor",
            "classification_label": "Evidence bounded",
            "confidence_label": "confidence unavailable",
            "impact_html": "0 observed requests",
            "endpoint_html": "No endpoint target supplied",
            "evidence_tags": ["No recommended actions"],
            "action_text": "No recommended actions were generated; preserve the fixed six-page report flow and re-run after new evidence arrives.",
        }
    ]

def _print_endpoint_rows(
    campaigns: list[dict[str, Any]], cases: list[dict[str, Any]], limit: int = 6
) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    seen: set[str] = set()
    for source in [*campaigns, *cases]:
        for endpoint in source.get("endpoint_targets") or []:
            if not isinstance(endpoint, dict):
                continue
            path = endpoint.get("endpoint_prefix") or endpoint.get("request_path") or endpoint.get("value")
            if not path or path in seen:
                continue
            seen.add(str(path))
            share = endpoint.get("share_pct")
            if share is None:
                share = endpoint.get("request_share_pct")
            rows.append(
                {
                    "path": str(path),
                    "requests": _fmt_num(endpoint.get("requests")),
                    "share": _fmt_pct(share),
                }
            )
            if len(rows) >= limit:
                return rows
    return rows

def _print_signal_rows(cases: list[dict[str, Any]], limit: int = 6) -> list[dict[str, str]]:
    counts: dict[str, int] = {}
    for case in cases:
        for flag in case.get("evidence_flag_labels") or []:
            counts[str(flag)] = counts.get(str(flag), 0) + 1
    return [
        {
            "name": name,
            "status": "yes" if count > 1 else "partial",
            "status_label": _count_label(count, "lead"),
        }
        for name, count in sorted(counts.items(), key=lambda item: item[1], reverse=True)[:limit]
    ]

def _lead_has_flag(case: dict[str, Any], *needles: str) -> bool:
    haystack = " ".join(
        [
            *(str(flag) for flag in case.get("evidence_flags") or []),
            *(str(flag) for flag in case.get("evidence_flag_labels") or []),
        ]
    ).lower()
    return any(needle.lower() in haystack for needle in needles)

def _print_campaign_descriptor(
    campaigns: list[dict[str, Any]], cases: list[dict[str, Any]], top_pattern: str, top_surface: str
) -> dict[str, str]:
    if campaigns:
        top = campaigns[0]
        member_count = len(top.get("leads") or [])
        return {
            "campaign_id": str(top.get("campaign_id") or "campaign"),
            "member_count": _count_label(member_count, "member"),
            "timing_pattern": top.get("temporal_pattern_label") or top_pattern,
            "surface": top_surface,
            "requests": _fmt_num(top.get("total_requests")),
        }
    return {
        "campaign_id": "No linked campaign",
        "member_count": _count_label(len(cases), "independent lead"),
        "timing_pattern": top_pattern,
        "surface": top_surface,
        "requests": _fmt_num(sum(float(case.get("requests") or 0) for case in cases)),
    }

def _print_evidence_distribution(cases: list[dict[str, Any]]) -> list[dict[str, str]]:
    specs = [
        (
            "Temporal Regularity",
            lambda case: bool(case.get("temporal_regularity")) or _lead_has_flag(case, "temporal"),
        ),
        (
            "Coordinated Activity",
            lambda case: bool(case.get("campaign_id")) or _lead_has_flag(case, "coordinated", "campaign"),
        ),
        (
            "UA Anomaly",
            lambda case: (case.get("ua_plausibility") or {}).get("verdict") in {"confirmed", "elevated"}
            or _lead_has_flag(case, "ua anomaly", "ua plausibility", "automation signature"),
        ),
        (
            "Automation Signature",
            lambda case: _lead_has_flag(case, "automation signature", "automation"),
        ),
        (
            "Rate Limit / Error Pressure",
            lambda case: _lead_has_flag(case, "rate limit", "error pressure", "429", "5xx"),
        ),
    ]
    rows = []
    for label, predicate in specs:
        count = sum(1 for case in cases if isinstance(case, dict) and predicate(case))
        rows.append(
            {
                "label": label,
                "count": count,
                "count_display": _count_label(count, "lead"),
                "status": "yes" if count else "na",
            }
        )
    return rows

def _print_findings_summary(
    campaigns: list[dict[str, Any]], cases: list[dict[str, Any]], top_pattern: str, top_surface: str
) -> dict[str, Any]:
    member_count = sum(len(campaign.get("leads") or []) for campaign in campaigns)
    timing_count = sum(1 for case in cases if isinstance(case, dict) and case.get("temporal_regularity"))
    ua_count = sum(
        1
        for case in cases
        if isinstance(case, dict)
        and (case.get("ua_plausibility") or {}).get("verdict") in {"confirmed", "elevated"}
    )
    automation_count = sum(
        1 for case in cases if isinstance(case, dict) and _lead_has_flag(case, "automation signature", "automation")
    )
    return {
        "rows": [
            {"label": "Campaigns", "value": _count_label(len(campaigns), "campaign")},
            {"label": "Campaign members", "value": _count_label(member_count, "member")},
            {"label": "Scraper leads", "value": _count_label(len(cases), "lead")},
            {"label": "Timing evidence", "value": _count_label(timing_count, "lead")},
            {"label": "UA anomaly evidence", "value": _count_label(ua_count, "lead")},
            {"label": "Automation evidence", "value": _count_label(automation_count, "lead")},
            {"label": "Campaign timing pattern", "value": top_pattern},
            {"label": "Campaign surface", "value": top_surface},
        ],
    }

def _print_boundary_rows(ctx: dict[str, Any], cases: list[dict[str, Any]]) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    boundaries = [
        {
            "label": "Operator identity",
            "status": "Not established",
            "detail": "The artifact links behavior, not a named operator.",
        },
        {
            "label": "Malicious intent",
            "status": "Not established",
            "detail": "The artifact supports scraper and automation leads, not intent.",
        },
        {
            "label": "Cross-customer reuse",
            "status": "Not established",
            "detail": "Reuse outside this customer and window is not established.",
        },
    ]
    partials: list[dict[str, str]] = []
    for item in (ctx.get("evidence_boundaries") or {}).get("not_established", [])[3:]:
        partials.append({"label": "Evidence gap", "status": "Partial", "detail": str(item)})
    for row in ctx.get("limitations") or []:
        if not isinstance(row, dict):
            continue
        detail = row.get("detail") or row.get("summary") or row.get("module")
        if detail:
            partials.append({"label": _label(str(row.get("module") or "limitation")), "status": "Partial", "detail": str(detail)})
    if any((case.get("fanout_enrichment") or {}).get("source") == "unavailable" for case in cases if isinstance(case, dict)):
        partials.append(
            {
                "label": "Fan-out",
                "status": "Partial",
                "detail": "Fan-out enrichment is missing or lower-bound only for at least one visible lead.",
            }
        )
    bot_manager = ctx.get("bot_manager_context") or {}
    if not bot_manager.get("available"):
        partials.append(
            {
                "label": "Bot Manager",
                "status": "Partial",
                "detail": "Bot Manager operational context was not supplied as independent attribution evidence.",
            }
        )
    classification_gap = ctx.get("classification_gap") or {}
    if classification_gap.get("summary"):
        partials.append(
            {
                "label": "SIEM / classification",
                "status": "Partial",
                "detail": str(classification_gap.get("summary")),
            }
        )
    seen: set[tuple[str, str]] = set()
    unique_partials = []
    for row in partials:
        key = (row["label"], row["detail"])
        if key in seen:
            continue
        seen.add(key)
        unique_partials.append(row)
    return boundaries, unique_partials[:5]

__all__ = [name for name in globals() if not name.startswith("__")]
