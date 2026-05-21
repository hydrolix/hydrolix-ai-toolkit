"""Context preparer for ``bot_threat_hunt.v3``."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any


SCHEMA = "bot_threat_hunt.v3"
REPORT_TYPE = "threat_hunt"
TEMPLATE = "reports/threat_hunt.html"
PRINT_TEMPLATE = "reports/incident_report_print.html"
NOTE_ID_TO_SLOT = {
    "llm-interpretation": "executive_summary",
}
SCRAPER_PATTERN_LINKS = {
    "owasp_oat_011": {
        "label": "OWASP OAT-011 Scraping",
        "url": "https://owasp.org/www-project-automated-threats-to-web-applications/assets/oats/EN/OAT-011_Scraping",
    },
    "owasp_bot_management": {
        "label": "OWASP Bot Management Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Bot_Management_and_Anti-Automation_Cheat_Sheet.html",
    },
    "f5_scraper_patterns": {
        "label": "F5 scraper behavior patterns",
        "url": "https://www.f5.com/labs/articles/how-to-identify-and-stop-scrapers",
    },
    "cloudflare_bot_detection": {
        "label": "Cloudflare bot detection concepts",
        "url": "https://developers.cloudflare.com/bots/concepts/bot-detection-engines/",
    },
}


def _artifact(artifacts: list[dict[str, Any]]) -> dict[str, Any]:
    for artifact in artifacts:
        if artifact.get("schema_version") == SCHEMA:
            return artifact
    raise ValueError(f"threat_hunt requires {SCHEMA}")


def assemble(artifacts: list[dict[str, Any]]) -> dict[str, Any]:
    return _artifact(artifacts)


def _label(value: str) -> str:
    return value.replace("_", " ").title()


def _subject_label(scope: dict[str, Any]) -> str:
    value = str(scope.get("customer") or scope.get("tenant") or scope.get("cluster") or "").strip()
    if not value:
        return "Threat Hunt"
    return value.replace("_", " ").replace("-", " ").title()


def _tone(verdict: str) -> str:
    return {
        "confirmed": "escalate",
        "likely": "monitor",
        "possible": "observe",
        "strong_lead": "escalate",
        "lead": "monitor",
        "weak_lead": "observe",
        "not_enough_data": "neutral",
    }.get(verdict, "neutral")


def _fmt_num(value: Any) -> str:
    try:
        n = float(value)
    except (TypeError, ValueError):
        return "unavailable"
    if abs(n) >= 1_000_000:
        return f"{n / 1_000_000:,.1f}M"
    if abs(n) >= 1_000:
        return f"{n / 1_000:,.1f}K"
    return f"{n:.0f}"


def _to_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _fmt_signed_num(value: Any) -> str:
    number = _to_float(value)
    if number is None:
        return "unavailable"
    sign = "+" if number >= 0 else "-"
    return f"{sign}{_fmt_num(abs(number))}"


def _baseline_comparison(row: dict[str, Any]) -> dict[str, Any]:
    current = _to_float(row.get("requests") if row.get("requests") is not None else row.get("total_requests"))
    baseline = _to_float(row.get("baseline_requests"))
    delta = _to_float(row.get("request_delta"))
    if delta is None and current is not None and baseline is not None:
        delta = current - baseline
    if baseline is None:
        return {
            "baseline": baseline,
            "delta": delta,
            "ratio": None,
            "display": "no baseline",
            "delta_display": _fmt_signed_num(delta) if delta is not None else "unavailable",
            "class": "ink-3",
        }
    if baseline == 0:
        if current and current > 0:
            return {
                "baseline": baseline,
                "delta": delta,
                "ratio": None,
                "display": f"new ({_fmt_signed_num(delta if delta is not None else current)})",
                "delta_display": _fmt_signed_num(delta if delta is not None else current),
                "class": "critical",
            }
        return {
            "baseline": baseline,
            "delta": delta,
            "ratio": 0.0,
            "display": "no change",
            "delta_display": _fmt_signed_num(delta or 0),
            "class": "ink-3",
        }
    if current is None:
        return {
            "baseline": baseline,
            "delta": delta,
            "ratio": None,
            "display": "unavailable",
            "delta_display": _fmt_signed_num(delta),
            "class": "ink-3",
        }
    ratio = current / baseline
    css_class = "critical" if ratio >= 2.0 else "high" if ratio >= 1.25 else "ink-3"
    return {
        "baseline": baseline,
        "delta": delta,
        "ratio": ratio,
        "display": f"{ratio:.1f}x ({_fmt_signed_num(delta if delta is not None else current - baseline)})",
        "delta_display": _fmt_signed_num(delta if delta is not None else current - baseline),
        "class": css_class,
    }


def _fmt_pct(value: Any) -> str:
    if value is None:
        return "unavailable"
    try:
        return f"{float(value):.1f}%"
    except (TypeError, ValueError):
        return "unavailable"


def _fmt_tiny_pct(value: Any) -> str:
    number = _to_float(value)
    if number is None:
        return "unavailable"
    if 0 < number < 0.01:
        return "<0.01%"
    if number < 1.0:
        return f"{number:.2f}%"
    return f"{number:.1f}%"


def _fmt_share(value: Any) -> str:
    number = _to_float(value)
    if number is None:
        return "unavailable"
    return _fmt_tiny_pct(number * 100.0)


def _fmt_money(value: Any) -> str:
    number = _to_float(value)
    if number is None:
        return "unavailable"
    if abs(number) >= 1000:
        return f"${number:,.0f}"
    return f"${number:,.2f}"


def _fmt_bytes(value: Any) -> str:
    number = _to_float(value)
    if number is None:
        return "unavailable"
    magnitude = abs(number)
    units = [
        (1_000_000_000_000_000, "P"),
        (1_000_000_000_000, "T"),
        (1_000_000_000, "B"),
        (1_000_000, "M"),
        (1_000, "K"),
    ]
    for divisor, suffix in units:
        if magnitude >= divisor:
            return f"{number / divisor:.1f}{suffix}"
    return f"{number:.0f}"


def _fmt_bytes_long(value: Any) -> str:
    number = _to_float(value)
    if number is None:
        return "unavailable"
    magnitude = abs(number)
    units = [
        (1_000_000_000_000_000, "PB"),
        (1_000_000_000_000, "TB"),
        (1_000_000_000, "GB"),
        (1_000_000, "MB"),
        (1_000, "KB"),
    ]
    for divisor, suffix in units:
        if magnitude >= divisor:
            return f"{number / divisor:.1f} {suffix}"
    return f"{number:.0f} bytes"


def _impact_action_text(impact: dict[str, Any]) -> str:
    response_bytes = impact.get("response_body_bytes")
    response_share = impact.get("response_body_byte_share")
    if response_bytes is None:
        response_bytes = impact.get("bytes")
        response_share = impact.get("byte_share")
    return (
        f"IMPACT: {_fmt_num(impact.get('requests'))} requests"
        f" ({_fmt_share(impact.get('request_share'))} of window total)"
        f" · {_fmt_bytes(response_bytes)} response body"
        f" ({_fmt_share(response_share)} of response bytes)"
    )


def _impact_trend_sentence(subject: str, impact: dict[str, Any] | None, *, audience: str) -> str:
    view = _impact_view(impact)
    current = view.get("request_share_display") or "unavailable"
    baseline = view.get("baseline_request_share_display") or "unavailable"
    direction = str(view.get("share_direction") or "")
    trend = str(view.get("trend_severity") or "")
    if current == "unavailable":
        return f"{subject} has no available total-traffic share for this window."
    if subject == "This UA family" and (
        direction == "new_entrant" or trend in {"new_entrant", "accelerating", "growing"}
    ):
        return "This UA family is newly visible or sharply growing relative to baseline."
    if direction == "new_entrant" or trend == "new_entrant" or baseline == "unavailable":
        return f"{subject} represents {current} of all {audience} traffic in this window and is newly visible relative to baseline."
    if direction == "shrinking_share":
        phrase = f"down from baseline window share of {baseline}"
    elif direction == "growing_share":
        phrase = f"up from baseline window share of {baseline}"
    else:
        phrase = f"stable versus baseline window share of {baseline}"
    return f"{subject} represents {current} of all {audience} traffic in this window, {phrase}."


def _impact_view(impact: dict[str, Any] | None) -> dict[str, Any]:
    impact = impact or {}
    cost = impact.get("cost_estimate") if isinstance(impact.get("cost_estimate"), dict) else {}
    low = _to_float(cost.get("low")) if cost else None
    high = _to_float(cost.get("high")) if cost else None
    cost_range = None
    if low is not None and high is not None:
        cost_range = f"{_fmt_money(low)}-{_fmt_money(high)}"
    return {
        **impact,
        "requests_display": _fmt_num(impact.get("requests")),
        "baseline_requests_display": _fmt_num(impact.get("baseline_requests")),
        "request_share_display": _fmt_share(impact.get("request_share")),
        "baseline_request_share_display": _fmt_share(impact.get("baseline_request_share")),
        "bytes_display": _fmt_bytes(impact.get("bytes")),
        "baseline_bytes_display": _fmt_bytes(impact.get("baseline_bytes")),
        "byte_share_display": _fmt_share(impact.get("byte_share")),
        "hydrolix_log_ingest_bytes_display": _fmt_bytes(impact.get("hydrolix_log_ingest_bytes")),
        "hydrolix_log_ingest_byte_share_display": _fmt_share(
            impact.get("hydrolix_log_ingest_byte_share")
        ),
        "response_body_bytes_display": _fmt_bytes(impact.get("response_body_bytes")),
        "response_body_byte_share_display": _fmt_share(impact.get("response_body_byte_share")),
        "akamai_billed_bytes_display": _fmt_bytes(impact.get("akamai_billed_bytes")),
        "akamai_billed_byte_share_display": _fmt_share(impact.get("akamai_billed_byte_share")),
        "share_severity_label": _label(str(impact.get("share_severity") or "minor")),
        "trend_severity_label": _label(str(impact.get("trend_severity") or "stable")),
        "share_direction_label": _label(str(impact.get("share_direction") or "stable_share")),
        "interpretation": impact.get("interpretation"),
        "cost_estimate": cost,
        "cost_range_display": cost_range,
        "cost_basis_label": cost.get("basis_label") if cost else None,
        "cost_disclaimer": cost.get("disclaimer") if cost else None,
    }


def _short_ua_label(user_agent: Any, max_len: int = 42) -> str:
    ua = str(user_agent or "unknown UA").strip()
    if not ua:
        return "unknown UA"
    if len(ua) <= max_len:
        return ua
    first_token = ua.split(" ", 1)[0]
    if "/" in first_token and len(first_token) <= max_len:
        return first_token
    return ua[: max_len - 3].rstrip() + "..."


def _parsed_ua_label(case: dict[str, Any]) -> str:
    ua = str(case.get("user_agent") or "unknown UA")
    parsed = ((case.get("ua_plausibility") or {}).get("parsed") or {})
    browser = parsed.get("browser_family")
    major = parsed.get("browser_major")
    platform = parsed.get("platform")
    app_match = ua.split(" ", 1)[0]
    if browser and str(browser).lower() not in {"unknown", "other"}:
        label = f"{browser}/{major}" if major is not None else str(browser)
        if platform:
            label = f"{label} - {platform}"
        return label
    if app_match and "/" in app_match:
        return app_match
    return _short_ua_label(ua)


def _coverage_view(coverage: dict[str, Any] | None) -> dict[str, Any]:
    coverage = coverage or {}
    status = str(coverage.get("status") or "unavailable")
    return {
        **coverage,
        "status": status,
        "status_label": _label(status),
        "coverage_display": _fmt_tiny_pct(coverage.get("coverage_pct")),
        "drilldown_requests_display": _fmt_num(coverage.get("drilldown_requests")),
        "total_requests_display": _fmt_num(coverage.get("total_requests")),
    }


def _endpoint_evidence_view(evidence: dict[str, Any] | None) -> dict[str, Any]:
    evidence = evidence or {}
    tier = str(evidence.get("tier") or "not_available")
    source = evidence.get("source")
    return {
        **evidence,
        "tier": tier,
        "tier_label": _label(tier),
        "source": source,
        "source_label": _label(str(source)) if source else "Not Available",
        "counts_for_verdict": bool(evidence.get("counts_for_verdict")),
        "reason": evidence.get("reason") or "not_available",
    }


def _campaign_endpoint_summary_view(summary: dict[str, Any] | None) -> dict[str, Any]:
    summary = summary or {}
    return {
        **summary,
        "confirmed_member_count": int(_to_float(summary.get("confirmed_member_count")) or 0),
        "inferred_member_count": int(_to_float(summary.get("inferred_member_count")) or 0),
        "unconfirmed_member_count": int(_to_float(summary.get("unconfirmed_member_count")) or 0),
        "not_available_member_count": int(_to_float(summary.get("not_available_member_count")) or 0),
        "counts_for_verdict": bool(summary.get("counts_for_verdict")),
        "dominant_categories": summary.get("dominant_categories") or [],
        "confirmed_member_display": _fmt_num(summary.get("confirmed_member_count")),
        "inferred_member_display": _fmt_num(summary.get("inferred_member_count")),
        "unconfirmed_member_display": _fmt_num(summary.get("unconfirmed_member_count")),
        "not_available_member_display": _fmt_num(summary.get("not_available_member_count")),
        "reason_label": _label(str(summary.get("reason") or "not_available")),
    }


def _campaign_coverage_view(summary: dict[str, Any] | None) -> dict[str, Any]:
    summary = summary or {}
    label = str(summary.get("surface_label") or "mixed_surface")
    return {
        **summary,
        "surface_label": label,
        "surface_label_display": _label(label),
        "weighted_coverage_display": _fmt_tiny_pct(summary.get("weighted_coverage_pct")),
        "drilldown_requests_display": _fmt_num(summary.get("drilldown_requests")),
        "total_requests_display": _fmt_num(summary.get("total_requests")),
    }


def _ua_plausibility_view(plausibility: dict[str, Any] | None) -> dict[str, Any]:
    plausibility = plausibility or {}
    verdict = str(plausibility.get("verdict") or "unavailable")
    score = _to_float(plausibility.get("composite_score"))
    if verdict == "confirmed":
        boundary = "UA plausibility anomaly confirmed"
    elif verdict == "elevated":
        boundary = "UA plausibility elevated but not verdict-driving"
    else:
        boundary = "UA plausibility unavailable or inconclusive"
    return {
        **plausibility,
        "verdict": verdict,
        "verdict_label": _label(verdict),
        "score_display": f"{score:.2f}" if score is not None else "unavailable",
        "trigger_reason": plausibility.get("trigger_reason") or boundary,
        "fired_structural_checks": plausibility.get("fired_structural_checks") or [],
        "counts_for_verdict": bool(plausibility.get("counts_for_verdict")),
        "boundary_text": boundary,
    }


def _fanout_view(fanout: dict[str, Any] | None) -> dict[str, Any]:
    fanout = fanout or {}
    source = str(fanout.get("source") or "unavailable")
    unique_ips = _to_float(fanout.get("unique_ips") if fanout.get("unique_ips") is not None else fanout.get("unique_client_ips"))
    effective_ips = _to_float(fanout.get("effective_ips")) or unique_ips
    probe_hours = _to_float(fanout.get("probe_window_hours"))
    caveat = fanout.get("caveat")
    if source == "summary_hour":
        line = f"Fan-out: {_fmt_num(unique_ips)} unique IPs across the full current window from summary_hour."
    elif source == "logs_probe":
        line = (
            f"Fan-out: {_fmt_num(unique_ips)} unique IPs in the peak-hour logs probe"
            f"{' over ' + _fmt_float(probe_hours) + 'h' if probe_hours else ''}; "
            f"conservative effective lower-bound {_fmt_num(effective_ips)} IPs."
        )
    elif source == "cooccurrence_lower_bound":
        if unique_ips is None:
            line = "Fan-out: cooccurrence lower-bound enrichment unavailable for this lead; true full-window fan-out is unknown."
        else:
            line = f"Fan-out: at least {_fmt_num(unique_ips)} cooccurring IPs; true full-window fan-out is unknown."
    else:
        line = "Fan-out enrichment unavailable for this lead."
    shelf_life = (
        "Fan-out counts are hunt-window specific; re-query them in the next hunt window because proxy pools, app releases, and device populations change."
        if source != "unavailable" and unique_ips is not None
        else None
    )
    return {
        **fanout,
        "source": source,
        "source_label": _label(source),
        "unique_ips_display": _fmt_num(unique_ips),
        "effective_ips_display": _fmt_num(effective_ips),
        "probe_window_hours_display": _fmt_float(probe_hours) if probe_hours is not None else "unavailable",
        "threshold_class": str(fanout.get("threshold_class") or "unavailable"),
        "threshold_class_label": _label(str(fanout.get("threshold_class") or "unavailable")),
        "caveat": caveat or line,
        "line": line,
        "shelf_life_guidance": shelf_life,
    }


def _confidence_view(confidence: dict[str, Any] | None) -> dict[str, Any]:
    confidence = confidence or {}
    qualifier = str(confidence.get("qualifier") or "unavailable")
    background_rates = []
    for family, rate in (confidence.get("background_rates") or {}).items():
        if not isinstance(rate, dict):
            continue
        if rate.get("rate_pct") is None:
            continue
        background_rates.append(
            {
                "family": family,
                "family_label": _label(str(family)),
                "rate_display": _fmt_tiny_pct(rate.get("rate_pct")),
                "concern": str(rate.get("concern") or "unavailable"),
            }
        )
    baseline = (
        confidence.get("baseline_significance")
        if isinstance(confidence.get("baseline_significance"), dict)
        else {}
    )
    shelf_life = [
        {
            **item,
            "evidence_label": _label(str(item.get("evidence") or "")),
            "shelf_life_label": _label(str(item.get("shelf_life") or "")),
        }
        for item in (confidence.get("evidence_shelf_life") or [])
        if isinstance(item, dict)
    ]
    return {
        **confidence,
        "qualifier": qualifier,
        "qualifier_label": _label(qualifier),
        "score_display": f"{float(confidence.get('score') or 0):.2f}",
        "reasons": confidence.get("reasons") or [],
        "background_rate_rows": background_rates,
        "baseline_significance": baseline,
        "baseline_z_display": f"{float(baseline.get('z_score')):.2f}"
        if baseline.get("z_score") is not None
        else "unavailable",
        "shelf_life_rows": shelf_life,
    }


def _attack_mapping_view(mapping: dict[str, Any] | None) -> dict[str, Any]:
    mapping = mapping or {}
    return {
        "mitre_techniques": mapping.get("mitre_techniques") or [],
        "mitre_tactics": mapping.get("mitre_tactics") or [],
        "hdx_techniques": mapping.get("hdx_techniques") or [],
        "mapping_note": mapping.get("mapping_note")
        or "Mappings are consistent with observed signal only; they are not attribution.",
    }


def _hypothesis_view(hypothesis: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(hypothesis, dict) or not hypothesis.get("category"):
        return None
    confidence = _to_float(hypothesis.get("confidence"))
    return {
        **hypothesis,
        "category_label": _label(str(hypothesis.get("category") or "")),
        "confidence_display": f"{confidence:.2f}" if confidence is not None else "unavailable",
        "trigger_evidence": hypothesis.get("trigger_evidence") or [],
        "distinguishing_signals": hypothesis.get("distinguishing_signals") or [],
        "recommended_action_modifier": hypothesis.get("recommended_action_modifier"),
        "attack_mapping": _attack_mapping_view(hypothesis.get("attack_mapping")),
    }


def _classification_view(classification: dict[str, Any] | None) -> dict[str, Any]:
    classification = classification or {}
    primary = _hypothesis_view(classification.get("primary"))
    secondary = [
        item
        for item in (_hypothesis_view(row) for row in classification.get("secondary") or [])
        if item
    ]
    return {
        "primary": primary,
        "secondary": secondary,
        "ambiguity_note": classification.get("ambiguity_note"),
        "has_mapping": bool(
            primary
            and (
                primary["attack_mapping"]["mitre_techniques"]
                or primary["attack_mapping"]["hdx_techniques"]
            )
        ),
    }


def _action_view(action: dict[str, Any] | None) -> dict[str, Any]:
    action = action or {}
    impact = (
        action.get("estimated_observed_window_impact")
        if isinstance(action.get("estimated_observed_window_impact"), dict)
        else {}
    )
    target_values = action.get("target_values") if isinstance(action.get("target_values"), dict) else {}
    return {
        **action,
        "target_values": {
            "campaign_id": target_values.get("campaign_id"),
            "ua_family_id": target_values.get("ua_family_id"),
            "ua_family_template": target_values.get("ua_family_template"),
            "user_agents": target_values.get("user_agents") or [],
            "endpoint_prefixes": target_values.get("endpoint_prefixes") or [],
        },
        "supporting_evidence": action.get("supporting_evidence") or [],
        "validation_notes": action.get("validation_notes") or [],
        "rollback_monitoring": action.get("rollback_monitoring") or [],
        "false_positive_caveat": action.get("false_positive_caveat") or "Verify existing Bot Manager coverage before enforcement.",
        "tier_label": _label(str(action.get("tier") or "tier_4")),
        "scope_label": _label(str(action.get("scope") or "lead")),
        "action_type_label": _label(str(action.get("action_type") or "monitor")),
        "impact_requests_display": _fmt_num(impact.get("requests")),
        "impact_request_share_display": _fmt_share(impact.get("request_share")),
        "impact_bytes_display": _fmt_bytes(impact.get("bytes"))
        if impact.get("bytes") is not None
        else "unavailable",
        "impact_byte_share_display": _fmt_share(impact.get("byte_share")),
        "impact_assessment": _impact_view(action.get("impact_assessment")),
        "wording_label": _label(str(action.get("enforcement_wording") or "challenge_first")),
        "threat_category": action.get("threat_category"),
        "threat_category_label": _label(str(action.get("threat_category") or "unclassified")),
        "threat_confidence": action.get("threat_confidence"),
        "threat_confidence_display": f"{float(action.get('threat_confidence')):.2f}"
        if action.get("threat_confidence") is not None
        else "unavailable",
        "threat_action_modifier": action.get("threat_action_modifier"),
        "classification_ambiguity_note": action.get("classification_ambiguity_note"),
    }


def _mix_view(rows: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    return [
        {
            **row,
            "label": str(row.get("value") or "unknown").replace("_", " "),
            "requests_display": _fmt_num(row.get("requests")),
            "share_display": _fmt_tiny_pct(row.get("share_pct")),
        }
        for row in (rows or [])
        if isinstance(row, dict) and row.get("value") not in (None, "")
    ]


def _bot_manager_source_view(source: dict[str, Any] | None) -> dict[str, Any]:
    source = source or {}
    window = source.get("window") if isinstance(source.get("window"), dict) else {}
    score = _to_float(source.get("average_bot_score"))
    return {
        **source,
        "available": source.get("availability") == "evidence_backed",
        "total_requests_display": _fmt_num(source.get("total_requests")),
        "average_bot_score_display": f"{score:.1f}" if score is not None else "unavailable",
        "action_class_mix": _mix_view(source.get("action_class_mix")),
        "bot_type_mix": _mix_view(source.get("bot_type_mix")),
        "policy_mix": _mix_view(source.get("policy_mix")),
        "window_label": (
            f"{window.get('start')} to {window.get('end')}"
            if window.get("start") and window.get("end")
            else None
        ),
    }


def _bot_manager_context_view(context: dict[str, Any] | None) -> dict[str, Any]:
    context = context or {}
    aggregate = _bot_manager_source_view(context.get("aggregate"))
    exact_ua = _bot_manager_source_view(context.get("exact_ua"))
    return {
        **context,
        "available": context.get("availability") == "evidence_backed",
        "summary": context.get("summary") or "Bot Manager operational context was not supplied.",
        "caveat": context.get("caveat")
        or (
            "Bot Manager context is operational enrichment, not threat-hunt attribution "
            "or independent evidence for classification."
        ),
        "aggregate": aggregate,
        "exact_ua": exact_ua,
        "has_aggregate": aggregate["available"],
        "has_exact_ua": exact_ua["available"],
    }


def _known_traffic_view(row: dict[str, Any]) -> dict[str, Any]:
    disposition = str(row.get("disposition") or "known_traffic")
    return {
        **row,
        "user_agent": row.get("user_agent") or "unknown user-agent",
        "disposition": disposition,
        "disposition_label": _label(disposition),
        "reason": row.get("reason") or "Known crawler or infrastructure traffic.",
        "requests_display": _fmt_num(row.get("requests")),
        "baseline_display": _fmt_num(row.get("baseline_requests")),
        "evidence_flag_labels": [_label(str(flag)) for flag in row.get("evidence_flags") or []],
    }


def _ua_family_view(family: dict[str, Any]) -> dict[str, Any]:
    version_range = (
        family.get("version_range")
        if isinstance(family.get("version_range"), dict)
        else {}
    )
    overlaps = []
    for overlap in family.get("campaign_overlaps") or []:
        if not isinstance(overlap, dict):
            continue
        member_count = int(_to_float(overlap.get("member_count")) or 0)
        campaign_id = str(overlap.get("campaign_id") or "campaign")
        overlaps.append(
            {
                **overlap,
                "member_count": member_count,
                "summary": f"{member_count} members also appear in {campaign_id}",
            }
        )
    return {
        **family,
        "family_id": family.get("family_id"),
        "template": family.get("template"),
        "members": family.get("members") or [],
        "member_count": int(_to_float(family.get("member_count")) or 0),
        "version_min": version_range.get("min"),
        "version_max": version_range.get("max"),
        "version_range_display": (
            f"{version_range.get('min')}-{version_range.get('max')}"
            if version_range.get("min") is not None and version_range.get("max") is not None
            else "unavailable"
        ),
        "version_count": int(_to_float(family.get("version_count")) or 0),
        "versions_display": ", ".join(str(value) for value in family.get("versions") or []),
        "total_requests_display": _fmt_num(family.get("total_requests")),
        "total_baseline_display": _fmt_num(family.get("total_baseline")),
        "impact_assessment": _impact_view(family.get("impact_assessment")),
        "request_volume_cv_display": _fmt_float(family.get("request_volume_cv")),
        "common_evidence": family.get("common_evidence") or [],
        "structural_checks": family.get("structural_checks") or [],
        "campaign_overlaps": overlaps,
        "threat_classification": _classification_view(family.get("threat_classification")),
        "recommended_actions": [
            _action_view(action)
            for action in family.get("recommended_actions") or []
            if isinstance(action, dict)
        ],
    }


def _campaign_ua_summary_view(summary: dict[str, Any] | None) -> dict[str, Any]:
    summary = summary or {}
    max_score = _to_float(summary.get("max_score"))
    return {
        **summary,
        "member_count": int(_to_float(summary.get("member_count")) or 0),
        "anomalous_member_count": int(_to_float(summary.get("anomalous_member_count")) or 0),
        "weak_member_count": int(_to_float(summary.get("weak_member_count")) or 0),
        "max_score_display": f"{max_score:.2f}" if max_score is not None else "unavailable",
        "forged_ua_candidate": bool(summary.get("forged_ua_candidate")),
        "top_triggers": summary.get("top_triggers") or [],
        "dominant_anomaly_types": summary.get("dominant_anomaly_types") or [],
    }


def _campaign_fanout_summary_view(summary: dict[str, Any] | None) -> dict[str, Any]:
    summary = summary or {}
    return {
        **summary,
        "member_count": int(_to_float(summary.get("member_count")) or 0),
        "source_label": _label(str(summary.get("source") or "unavailable")),
        "unique_ips_display": _fmt_num(summary.get("unique_ips_lower_bound")),
        "effective_ips_display": _fmt_num(summary.get("effective_ips_composite")),
        "line": summary.get("line")
        or "Campaign fan-out enrichment unavailable; no exact member-union IP count is claimed.",
    }


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
        evidence = campaign.get("endpoint_evidence_summary") or {}
        source_text = "confirmed campaign endpoint evidence" if evidence.get("counts_for_verdict") else "campaign endpoint context"
        for row in campaign.get("endpoint_targets") or []:
            if isinstance(row, dict) and row.get("endpoint_prefix"):
                share = _fmt_pct(row.get("share_pct"))
                return f"{row.get('endpoint_prefix')} ({share} of campaign traffic; {source_text})"
    for case in cases:
        evidence = case.get("endpoint_evidence") or {}
        source_text = (
            "confirmed scoped endpoint targeting"
            if evidence.get("counts_for_verdict")
            else "endpoint context"
        )
        for row in case.get("endpoint_targets") or []:
            if isinstance(row, dict):
                value = row.get("request_path") or row.get("value")
                if value:
                    share = row.get("share_pct")
                    if share is None:
                        share = row.get("request_share_pct")
                    return f"{value} ({_fmt_pct(share)} of lead traffic; {source_text})"
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


def _build_impact_tiles(
    artifact: dict[str, Any], campaigns: list[dict[str, Any]], cases: list[dict[str, Any]]
) -> list[dict[str, str]]:
    request_total = _request_total(campaigns, cases, artifact)
    timing_count = sum(1 for case in cases if isinstance(case, dict) and case.get("temporal_regularity"))
    drilldown_count = sum(
        1
        for case in cases
        if isinstance(case, dict)
        and (case.get("drilldown_coverage") or {}).get("status", "unavailable") != "unavailable"
    )
    return [
        {
            "label": "Request volume",
            "value": _fmt_num(request_total),
            "delta": "campaign requests" if campaigns else "lead requests",
        },
        {
            "label": "Campaigns",
            "value": str(len(campaigns)),
            "delta": "linked lead groups",
        },
        {
            "label": "Scraper leads",
            "value": str(len(cases)),
            "delta": "behavioral cases",
        },
        {
            "label": "Top endpoint",
            "value": _first_endpoint_label(artifact, campaigns, cases).split(" (", 1)[0],
            "delta": _first_endpoint_label(artifact, campaigns, cases).split("(", 1)[1].rstrip(")")
            if "(" in _first_endpoint_label(artifact, campaigns, cases)
            else "not supplied",
        },
        {
            "label": "Evidence coverage",
            "value": f"{timing_count}/{len(cases)}",
            "delta": f"timing; {drilldown_count}/{len(cases)} drilldown",
        },
    ]


def _build_threat_findings(
    artifact: dict[str, Any], campaigns: list[dict[str, Any]], cases: list[dict[str, Any]]
) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    if campaigns:
        top = campaigns[0]
        pattern = _label(str(top.get("temporal_pattern") or "not_established"))
        ua_summary = top.get("ua_plausibility_summary") or {}
        forged_text = (
            " It is a forged-UA residential proxy operation candidate based on repeated UA plausibility anomalies."
            if ua_summary.get("forged_ua_candidate")
            else ""
        )
        findings.append(
            {
                "label": "Finding 1",
                "lead": f"{top.get('campaign_id')} is the strongest coordinated lead.",
                "body": (
                    f"It links {_count_label(len(top.get('leads') or []), 'user-agent fingerprint')} "
                    f"across {_fmt_num(top.get('total_requests'))} requests with {len(top.get('link_narratives') or [])} "
                    f"link evidence row(s); timing pattern is {pattern}.{forged_text}"
                ),
            }
        )
    else:
        findings.append(
            {
                "label": "Finding 1",
                "lead": "No coordinated scraper campaign cleared the linking threshold.",
                "body": "The report preserves singleton scraper leads as independent cases instead of inferring coordination.",
            }
        )
    if cases:
        top_case = next(
            (case for case in cases if not _is_weak_first_party_app_lead(case)),
            cases[0],
        )
        ua_view = top_case.get("ua_plausibility") or {}
        ua_text = (
            f" UA plausibility: {ua_view.get('trigger_reason')}."
            if ua_view.get("verdict") in {"confirmed", "elevated"}
            else ""
        )
        if _is_weak_first_party_app_lead(top_case):
            lead = f"{_parsed_ua_label(top_case)} is the highest-volume evidence-bounded lead."
            body = (
                f"It accounts for {_fmt_num(top_case.get('requests'))} requests, but the first-party "
                "app user-agent shape and current evidence do not support stronger scraper wording."
            )
        else:
            lead = f"{_parsed_ua_label(top_case)} is the strongest non-campaign lead."
            body = (
                f"It accounts for {_fmt_num(top_case.get('requests'))} requests with "
                f"{', '.join(top_case.get('evidence_flag_labels') or []) or 'no named evidence flags'}.{ua_text}"
            )
        findings.append(
            {
                "label": "Finding 2",
                "lead": lead,
                "body": body,
            }
        )
    else:
        findings.append(
            {
                "label": "Finding 2",
                "lead": "No scraper leads could be assembled from the supplied actor evidence.",
                "body": "The report remains an evidence availability review until actor or drilldown inputs are supplied.",
            }
        )
    missing_drilldown = not any(
        isinstance(c, dict) and (c.get("endpoint_targets") or c.get("hourly_bursts"))
        for c in cases
    )
    missing_timing = not any(isinstance(c, dict) and c.get("temporal_regularity") for c in cases)
    gap = "timing and drilldown" if missing_timing and missing_drilldown else "timing" if missing_timing else "drilldown" if missing_drilldown else "operator attribution"
    findings.append(
        {
            "label": "Finding 3",
            "lead": "Evidence boundaries remain explicit.",
            "body": f"The hunt does not establish intent, operator identity, or cross-customer reuse; the main unresolved area is {gap}.",
        }
    )
    return findings[:3]


def _is_weak_first_party_app_lead(case: dict[str, Any]) -> bool:
    ua = str(case.get("user_agent") or "")
    parsed = ((case.get("ua_plausibility") or {}).get("parsed") or {})
    first_party = ua.lower().startswith(("expedia/", "vrbo/", "hotels.com/"))
    app_like = parsed.get("ua_class") in {"native_app", "mobile_app", "first_party_app"}
    weak = str(case.get("verdict") or "").lower() in {"weak_lead", "not_enough_data", "possible"}
    confidence = ((case.get("confidence_assessment") or {}).get("qualifier") or "").lower()
    return first_party and (app_like or weak or confidence in {"weak", "low", "partial"})


def _build_evidence_boundaries(
    campaigns: list[dict[str, Any]], cases: list[dict[str, Any]]
) -> dict[str, list[str]]:
    observed = [
        "Current-window scraper leads were derived from the supplied Bot Insights artifacts.",
    ]
    if campaigns:
        observed.append("At least one multi-lead campaign met conservative linking thresholds.")
    if any(isinstance(c, dict) and c.get("temporal_regularity") for c in cases):
        observed.append("Timing regularity is available for at least one scraper lead.")
    confirmed_ua = [
        c
        for c in cases
        if isinstance(c, dict)
        and isinstance(c.get("ua_plausibility"), dict)
        and c["ua_plausibility"].get("counts_for_verdict")
    ]
    elevated_ua = [
        c
        for c in cases
        if isinstance(c, dict)
        and isinstance(c.get("ua_plausibility"), dict)
        and c["ua_plausibility"].get("verdict") == "elevated"
    ]
    if confirmed_ua:
        observed.append("UA plausibility anomaly confirmed for at least one scraper lead.")
    if elevated_ua:
        observed.append("UA plausibility elevated but not verdict-driving for at least one scraper lead.")
    if any(isinstance(c, dict) and c.get("temporal_pattern") == "parallel_independent" for c in campaigns):
        observed.append("A campaign shows parallel independent worker timing: regular hourly cadence without synchronized timing.")
    characterized_cases = [
        c
        for c in cases
        if isinstance(c, dict)
        and (c.get("drilldown_coverage") or {}).get("status")
        in {"partial", "substantial", "focused"}
    ]
    thin_cases = [
        c
        for c in cases
        if isinstance(c, dict)
        and (c.get("drilldown_coverage") or {}).get("status")
        in {"uncharacterized", "thin_slice"}
    ]
    exact_drilldown_cases = [
        c
        for c in cases
        if isinstance(c, dict)
        and (c.get("drilldown_coverage") or {}).get("status") != "unavailable"
    ]
    confirmed_endpoint_cases = [
        c
        for c in cases
        if isinstance(c, dict)
        and (c.get("endpoint_evidence") or {}).get("counts_for_verdict")
    ]
    inferred_endpoint_cases = [
        c
        for c in cases
        if isinstance(c, dict)
        and (c.get("endpoint_evidence") or {}).get("tier") == "inferred_site_context"
    ]
    unconfirmed_endpoint_cases = [
        c
        for c in cases
        if isinstance(c, dict)
        and (c.get("endpoint_evidence") or {}).get("tier") == "unconfirmed_scoped"
    ]
    if confirmed_endpoint_cases:
        observed.append("Scoped endpoint targeting confirmed for at least one scraper lead.")
    if inferred_endpoint_cases:
        observed.append("Endpoint context inferred from site-level summary rows is visible but not lead-specific evidence.")
    if characterized_cases:
        observed.append("At least one lead has partial-or-better scoped endpoint surface coverage.")
    not_established = [
        "Operator identity is not established.",
        "Malicious intent is not established by this artifact.",
        "Cross-customer reuse is not established.",
    ]
    if not any(isinstance(c, dict) and c.get("temporal_regularity") for c in cases):
        not_established.append("timing regularity is not established for the visible leads.")
    if thin_cases:
        not_established.append("Primary request surface characterized is not established for leads with near-zero or thin drilldown coverage.")
    if unconfirmed_endpoint_cases:
        not_established.append("Primary request surface remains uncharacterized or non-targeted for at least one scoped lead.")
    if not exact_drilldown_cases:
        not_established.append("Scoped drilldown behavior is not established for the visible leads.")
    if not confirmed_ua and not elevated_ua:
        not_established.append("UA plausibility unavailable or inconclusive for the visible leads.")
    return {"observed": observed, "not_established": not_established}


def _build_analyst_assessment(summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "conclusion": summary["summary"],
        "pillars": summary["reasons"],
        "boundary": (
            "This readout is deterministic and scoped to the supplied threat-hunt artifact; "
            "it reports observed scraper evidence, not operator identity, intent, or reuse."
        ),
    }


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


def _print_report(ctx: dict[str, Any]) -> dict[str, Any]:
    scope = ctx.get("scope") or {}
    summary = ctx.get("deterministic_summary") or {}
    campaigns = ctx.get("campaigns") or []
    ua_families = ctx.get("ua_families") or []
    cases = ctx.get("scraper_cases") or []
    risk = _risk_value(summary, campaigns, cases)
    severity = summary.get("severity_level") or "low"
    band = {
        "low": "observe",
        "medium": "monitor",
        "elevated": "elevated",
        "high": "high",
        "critical": "critical",
    }.get(severity, "observe")
    band_label = {
        "observe": "Observe",
        "monitor": "Monitor",
        "elevated": "Elevated",
        "high": "High",
        "critical": "Critical",
    }[band]
    actors = _print_actor_rows(cases)
    findings = ctx.get("threat_findings") or []
    primary = ctx.get("primary_concern") or {}
    bot_manager = ctx.get("bot_manager_context") or {}
    timing_count = sum(1 for case in cases if isinstance(case, dict) and case.get("temporal_regularity"))
    top_pattern = (
        _label(str(campaigns[0].get("temporal_pattern") or "not_established"))
        if campaigns
        else "Not established"
    )
    top_surface = (
        (campaigns[0].get("drilldown_coverage_summary") or {}).get("surface_label_display")
        if campaigns
        else None
    ) or "No campaign surface"
    campaign_descriptor = _print_campaign_descriptor(campaigns, cases, top_pattern, top_surface)
    evidence_boundaries, partial_boundaries = _print_boundary_rows(ctx, cases)
    audience = ctx.get("headline") or _subject_label(scope)
    story_primary = _story_primary_finding(campaigns, cases, top_pattern, top_surface, audience)
    story_secondary = _story_secondary_finding(ua_families, cases, audience)
    story_independent = _story_independent_leads(cases)
    pattern_notes = ctx.get("pattern_notes") or []
    cover_headline = _cover_threat_headline(
        campaigns,
        ua_families,
        cases,
        ctx.get("threat_classification") if isinstance(ctx.get("threat_classification"), dict) else None,
    )
    hunt_impact = (ctx.get("impact_assessment") or {}).get("hunt") if isinstance(ctx.get("impact_assessment"), dict) else {}
    if cover_headline and isinstance(hunt_impact, dict) and hunt_impact.get("request_share") is not None:
        cover_headline = cover_headline.rstrip(".") + f" ({hunt_impact.get('request_share_display')} of window traffic)."
    return {
        "customer": ctx.get("headline") or _subject_label(scope),
        "meta": {"schema": SCHEMA},
        "window": _print_window(scope),
        "verdict": {
            "risk_score": risk,
            "risk_max": 100,
            "confidence": (summary.get("confidence_label") or "Evidence bounded").upper(),
            "confidence_total": 5,
            "confidence_filled": 4 if "Conservative" in summary.get("confidence_label", "") else 3,
            "prose_html": cover_headline or summary.get("summary") or "Threat hunt evidence is bounded by supplied artifacts.",
            "bands": [
                {"label": "Observe", "is_critical": False},
                {"label": "Monitor", "is_critical": False},
                {"label": "Elevated", "is_critical": False},
                {"label": "High", "is_critical": False},
                {"label": "Critical", "is_critical": True},
            ],
            "calibration_html": (
                f"Calibration: {band_label} reflects {len(cases)} scraper leads, "
                f"{len(campaigns)} linked campaigns, and the supplied endpoint, timing, "
                "infrastructure, and classification evidence. This is not operator attribution."
            ),
            "band": band,
            "band_label": band_label,
            "band_position_pct": _band_position(severity),
        },
        "cover_threat_headline": cover_headline,
        "cover_impact": _cover_impact_panel(ctx.get("impact_assessment") or {}, campaigns, ua_families, cases),
        "story_page": {
            "eyebrow": "Threat Hunt Story",
            "screen_label": "Story",
            "headline": "What the hunt found",
            "lede_html": "The print story rolls the strongest campaign, UA-family rotation, and independent leads into one analyst-readable sequence.",
            "footer_label": "Story",
        },
        "story_primary_finding": story_primary,
        "story_secondary_finding": story_secondary,
        "story_independent_leads": story_independent,
        "chart": _print_chart(ctx),
        "analyst_assessment": {
            "headline": "Analyst Assessment",
            "prose_html": (ctx.get("analyst_assessment") or {}).get("conclusion") or summary.get("summary") or "",
            "observed": (ctx.get("evidence_boundaries") or {}).get("observed") or [],
            "inferred": (ctx.get("evidence_boundaries") or {}).get("not_established") or [],
            "why_stood_out": [
                {"stat": tile.get("value"), "caption_html": f"{tile.get('label')}: {tile.get('delta')}"}
                for tile in (ctx.get("impact_tiles") or [])[:3]
            ],
        },
        "primary_concern": {
            "eyebrow": "Primary Concern",
            "chip": "Evidence bounded",
            "chip_severity": band,
            "headline_html": primary.get("title") or "Threat hunt lead",
            "prose_html": primary.get("summary") or primary.get("boundary") or "",
            "stats": _print_primary_concern_stats(campaigns, cases),
        },
        "at_a_glance": {
            "footnote": "Metrics and ranks are deterministic; presentation fields do not change artifact semantics.",
            "shape": {
                "subtitle": "Evidence shape",
                "hero": str(len(campaigns)),
                "subline_html": "linked campaigns",
                "facts": [tile.get("label") for tile in (ctx.get("impact_tiles") or [])[1:4]],
            },
            "who": {
                "chip": "Leads",
                "hero": str(len(cases)),
                "subline_html": "scraper leads",
                "facts": [row["ip"] for row in actors[:3]],
            },
            "do_now": {"subtitle": "Boundaries", "items": []},
        },
        "findings_page": {
            "eyebrow": "Findings",
            "headline": "Evidence-backed findings",
            "lede_html": "Findings are generated from deterministic threat-hunt evidence.",
        },
        "finding_ip_cluster": {
            "n": "01",
            "kicker": "Campaign",
            "severity": band,
            "severity_label": band_label,
            "headline": (findings[0] or {}).get("lead") if findings else "No campaign finding.",
            "prose_html": (findings[0] or {}).get("body") if findings else "",
            "chips": [],
            "ips": [],
            "uas": [],
            "as_callout": None,
            "ua_age_callout": None,
        },
        "finding_ua_share": {
            "n": "02",
            "kicker": "Lead",
            "severity": "high",
            "severity_label": "High",
            "headline": (findings[1] or {}).get("lead") if len(findings) > 1 else "No lead finding.",
            "prose_html": (findings[1] or {}).get("body") if len(findings) > 1 else "",
            "chips": [],
            "ips": [],
            "uas": [],
            "as_callout": None,
            "ua_age_callout": None,
        },
        "finding_human_anomaly": {
            "n": "03",
            "kicker": "Boundary",
            "severity": "monitor",
            "severity_label": "Monitor",
            "headline": (findings[2] or {}).get("lead") if len(findings) > 2 else "Evidence boundary.",
            "prose_html": (findings[2] or {}).get("body") if len(findings) > 2 else "",
            "chips": [],
            "ips": [],
            "uas": [],
            "as_callout": None,
            "ua_age_callout": None,
        },
        "actors_page": {
            "eyebrow": "Scraper Leads",
            "screen_label": "Scraper leads",
            "headline": "Lead summary",
            "lede_html": "Rows are shortened for print; full user-agent evidence remains in the source HTML and Markdown artifacts.",
            "actor_column_label": "UA label",
            "rate_column_label": "Delta vs baseline",
            "evidence_column_label": "Evidence tags",
            "basis_column_label": "Verdict",
            "footer_label": "Scraper leads",
            "total_flagged": len(cases),
            "appendix_note": "Full UA strings and fan-out caveats are retained outside the fixed-page PDF.",
        },
        "actors": actors,
        "actions_page": {
            "eyebrow": "Recommended Actions",
            "headline": "What to do next",
            "lede_html": "Threat hunt output preserves evidence boundaries; use these as validation-ready control candidates.",
            "footer_note": "Validate target membership before enforcement and monitor rollback indicators after changes.",
        },
        "actions": _print_actions(ctx.get("recommended_actions") or []),
        "known_traffic": _print_known_traffic(ctx.get("known_traffic") or []),
        "bot_manager_print_summary": _print_bot_manager_summary(bot_manager),
        "attck_page": {
            "eyebrow": "Methodology",
            "screen_label": "ATT&CK · Methodology",
            "footer_label": "ATT&CK · Methodology",
            "headline": "Threat taxonomy and ATT&CK mapping",
            "lede_html": "Mapped techniques are consistent with observed signal only. They are not attribution, operator identity, intent, or proof of a named ATT&CK procedure.",
            "techniques": _classification_technique_rows(ctx),
        },
        "risk_explanation": {
            "eyebrow": "Score and Availability",
            "headline": "How this threat-hunt score is bounded",
            "lede_html": "The cover score is presentation-only and derived from deterministic verdict severity, campaign count, and lead count.",
            "severity_rows": [
                {
                    "severity": band,
                    "label": band_label,
                    "count": str(len(cases)),
                    "weight": "presentation",
                    "weighted": str(risk),
                }
            ],
            "reason_rows": [
                {"reason": "Scraper leads", "count": str(len(cases))},
                {"reason": "Linked campaigns", "count": str(len(campaigns))},
            ],
        },
        "analysis_availability_print": {
            "eyebrow": "Evidence Availability",
            "headline": "What was and was not established",
            "boundary_html": "Availability rows preserve the artifact's limitations and evidence boundaries.",
            "rows": [
                {
                    "analysis": "Observed",
                    "status": "available",
                    "detail_html": item,
                }
                for item in (ctx.get("evidence_boundaries") or {}).get("observed", [])[:3]
            ]
            + [
                {
                    "analysis": "Not established",
                    "status": "bounded",
                    "detail_html": item,
                }
                for item in (ctx.get("evidence_boundaries") or {}).get("not_established", [])[:3]
            ],
            "bot_manager_summary": _print_bot_manager_summary(bot_manager),
        },
        "actor_correlation_callouts": [],
        "top_hosts": [],
        "top_hosts_meta": "Endpoint evidence",
        "top_hosts_footnote": "Endpoint evidence is shown in the source artifact tables.",
        "geo": [],
        "geo_footnote": "Geo evidence is shown only when infrastructure rollups are present.",
        "attack_shape": {
            "eyebrow": "Threat Hunt Shape",
            "screen_label": "Evidence shape",
            "footer_label": "Evidence shape",
            "headline": "Findings and evidence boundaries",
            "lede_html": "What the hunt found, how much customer traffic it represents, and what the supplied evidence does not establish.",
            "campaign_descriptor": campaign_descriptor,
            "findings_summary": _print_findings_summary(campaigns, cases, top_pattern, top_surface),
            "impact_story": _print_impact_story(ctx.get("impact_assessment") or {}, audience, pattern_notes),
            "impact_rows": _print_impact_rows(ctx.get("impact_assessment") or {}),
            "pattern_notes": _print_pattern_notes(pattern_notes),
            "evidence_distribution": _print_evidence_distribution(cases),
            "boundaries": evidence_boundaries,
            "partial_boundaries": partial_boundaries,
            "timeline": [
                {
                    "time": "Campaigns",
                    "phase": _count_label(len(campaigns), "linked group"),
                    "caption_html": f"Conservative multi-lead groupings; surface {top_surface}",
                    "is_peak": bool(campaigns),
                },
                {
                    "time": "Leads",
                    "phase": _count_label(len(cases), "scraper lead"),
                    "caption_html": "Behavioral UA fingerprints",
                    "is_peak": not campaigns,
                },
                {
                    "time": "Timing",
                    "phase": f"{timing_count}/{len(cases)} with timing",
                    "caption_html": f"Campaign timing pattern: {top_pattern}",
                    "is_peak": timing_count > 0,
                },
                {
                    "time": "Boundaries",
                    "phase": "No attribution",
                    "caption_html": "No operator, intent, or reuse claim",
                    "is_peak": False,
                },
            ],
            "top_paths": _print_endpoint_rows(campaigns, cases),
            "top_path_meta_html": "Top endpoints",
            "paths_footnote": "Endpoint rows may be unavailable when raw drilldown is degraded.",
            "signals_summary_html": "Observed evidence flags",
            "coordination_signals": _print_signal_rows(cases),
            "signals_footnote": "Signals are mechanical evidence, not attribution claims.",
        },
        "classification": {
            "eyebrow": "Classification and Response",
            "screen_label": "07 Classification &amp; edge",
            "headline": "Classification and response",
            "lede_html": "Classification evidence is bounded to supplied threat-hunt artifacts.",
            "cohort_header": "Cohort · Requests · Share · 429% · 5xx%",
            "action_mix_label": "Edge action mix · What the edge decided",
            "policy_label": "Top deny rules · Which rules fired",
            "policy_column_label": "Deny rule",
            "footer_label": "Classification &amp; edge response",
        },
        "cohorts": [],
        "edge_action_meta_html": "No edge-action mix supplied",
        "edge_action_stack": [],
        "edge_action_legend": [],
        "deny_rules": [],
        "browser_age": {
            "eyebrow": "User-Agent Context",
            "headline": "User-agent evidence boundaries",
            "boundary_html": "Threat-hunt UA rows are fingerprints, not identity evidence.",
            "meta": "No browser-age enrichment supplied.",
            "rows": [],
            "comparison_rows": [],
        },
        "print_sections": {
            "actions": True,
            "classification": False,
            "browser_age": False,
            "score_availability": False,
        },
        "page_numbers": {
            "actions": "03",
            "attack_shape": "04",
            "actors": "05",
            "methodology": "06",
            "score_availability": "07",
        },
        "ua_rotation_print": {"available": False},
        "ua_rotation_page_number": None,
        "as_reputation_print": {"available": False},
        "as_reputation_page_number": None,
        "methodology": {
            "prose_html": "Deterministic threat-hunt artifact rendered through the incident fixed-letter print tooling.",
            "window_summary_html": "The report preserves the original bot_threat_hunt.v3 artifact semantics.",
            "analysis_rows": [
                {
                    "analysis": "Traffic and byte-share impact",
                    "helps_identify": "Identifies which findings consume the largest share of total requests and bytes in the window.",
                },
                {
                    "analysis": "Baseline trajectory comparison",
                    "helps_identify": "Identifies new entrants, growing pressure, stable activity, or declining share versus baseline.",
                },
                {
                    "analysis": "Campaign linkage and coordination",
                    "helps_identify": "Identifies UA fingerprints that move together through shared IPs, paths, timing, or surface patterns.",
                },
                {
                    "analysis": "UA plausibility and family rotation",
                    "helps_identify": "Identifies future-dated, structurally unusual, or templated browser versions consistent with automation.",
                },
                {
                    "analysis": "Endpoint, fan-out, and timing evidence",
                    "helps_identify": "Identifies focused route pressure, broad client distribution, and regular request cadence.",
                },
                {
                    "analysis": "Evidence-boundary review",
                    "helps_identify": "Identifies what remains unproven, including operator identity, malicious intent, and cross-customer reuse.",
                },
            ],
            "metadata": [
                {"label": "Schema", "value": SCHEMA},
                {"label": "Cluster", "value": scope.get("cluster") or ""},
                {"label": "Database", "value": scope.get("database") or ""},
            ],
        },
        "page_count": 6,
    }


def _timing_summary(case: dict[str, Any]) -> dict[str, Any] | None:
    timing = case.get("temporal_regularity")
    status = case.get("timing_status") if isinstance(case.get("timing_status"), dict) else {}
    if not isinstance(timing, dict):
        if not status:
            return None
        status_label = _label(str(status.get("status") or "unavailable"))
        metric_parts = []
        if status.get("hourly_request_cv") is not None:
            metric_parts.append(f"hourly CV {_fmt_float(status.get('hourly_request_cv'))}")
        if status.get("active_hour_count") is not None:
            metric_parts.append(f"active hours {status.get('active_hour_count')}/{status.get('window_hour_count')}")
        return {
            "status": str(status.get("status") or "unavailable"),
            "status_label": status_label,
            "resolution": status.get("resolution") or "not_available",
            "archetype": status_label,
            "sample_size": status.get("active_hour_count") or status.get("sample_size"),
            "summary": "Timing unavailable." if status.get("status") == "unavailable" else status_label,
            "metric_line": "; ".join(metric_parts) if metric_parts else "timing unavailable",
            "top_pairs": [],
        }
    metrics = timing.get("metrics") if isinstance(timing.get("metrics"), dict) else {}
    if timing.get("resolution") == "hourly_coarse":
        metric_parts = [
            f"hourly CV {_fmt_float(metrics.get('hourly_request_cv'))}",
            f"active hours {metrics.get('active_hour_count') or timing.get('sample_size')}/{metrics.get('window_hour_count') or timing.get('window_hour_count')}",
        ]
    else:
        metric_parts = [
            f"CV {_fmt_float(metrics.get('cv'))}",
            f"entropy {_fmt_float(metrics.get('log_bucket_entropy'))}",
            f"spectral {_fmt_float(metrics.get('spectral_peak_ratio'))}",
        ]
    return {
        "resolution": timing.get("resolution"),
        "status": "regular",
        "status_label": "Regular",
        "archetype": _label(str(timing.get("archetype", "timing_regular"))),
        "sample_size": timing.get("sample_size"),
        "summary": timing.get("summary"),
        "metric_line": "; ".join(metric_parts),
        "top_pairs": timing.get("top_pairs") or [],
    }


def post_prepare(ctx: dict[str, Any]) -> None:
    if ctx.get("profile") != "print":
        return
    print_report = _print_report(ctx)
    ctx["print_report"] = print_report
    ctx.update(print_report)


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


def _pattern_link(*keys: str) -> list[dict[str, str]]:
    return [SCRAPER_PATTERN_LINKS[key] for key in keys if key in SCRAPER_PATTERN_LINKS]


def _has_endpoint_pattern(ctx: dict[str, Any]) -> tuple[bool, list[str], float | None]:
    basis: list[str] = []
    max_share: float | None = None
    scoped_terms = ("api", "catalog", "search", "listing", "list", "product", "inventory", "graphql")

    def observe_endpoint(row: dict[str, Any], source: str) -> None:
        nonlocal max_share
        haystack = " ".join(
            str(value)
            for value in [
                row.get("endpoint_prefix"),
                row.get("request_path"),
                row.get("value"),
                row.get("endpoint_category"),
                row.get("category"),
                *(row.get("markers") or []),
            ]
            if value
        ).lower()
        share = _to_float(row.get("share_pct"))
        if share is None:
            share = _to_float(row.get("request_share_pct"))
        if share is not None:
            max_share = max(max_share or 0.0, share)
        if any(term in haystack for term in scoped_terms):
            basis.append(source)
        elif share is not None and share >= 50.0:
            basis.append(source)

    for campaign in ctx.get("campaigns") or []:
        summary = campaign.get("endpoint_evidence_summary") or {}
        if summary.get("counts_for_verdict") or summary.get("confirmed_member_count"):
            basis.append("campaign endpoint evidence")
        for row in campaign.get("endpoint_targets") or []:
            if isinstance(row, dict):
                observe_endpoint(row, "campaign endpoint target")
    for case in ctx.get("scraper_cases") or []:
        evidence = case.get("endpoint_evidence") or {}
        if evidence.get("counts_for_verdict"):
            basis.append("lead scoped endpoint evidence")
        for row in case.get("endpoint_targets") or []:
            if isinstance(row, dict):
                observe_endpoint(row, "lead endpoint target")
    for row in ctx.get("endpoints") or []:
        if isinstance(row, dict):
            observe_endpoint(row, "site-level endpoint row")
    return bool(basis), sorted(set(basis)), max_share


def _has_timing_pattern(ctx: dict[str, Any]) -> tuple[bool, list[str]]:
    basis: list[str] = []
    for campaign in ctx.get("campaigns") or []:
        pattern = str(campaign.get("temporal_pattern") or "")
        summary = campaign.get("timing_summary") if isinstance(campaign.get("timing_summary"), dict) else {}
        if pattern and pattern not in {"not_established", "unavailable", "unknown"}:
            basis.append(f"campaign timing pattern {campaign.get('temporal_pattern_label') or _label(pattern)}")
        if summary.get("evidence_text"):
            basis.append("campaign timing summary")
    for case in ctx.get("scraper_cases") or []:
        timing = case.get("timing") if isinstance(case.get("timing"), dict) else {}
        raw = case.get("temporal_regularity") if isinstance(case.get("temporal_regularity"), dict) else {}
        sample_size = _to_float(timing.get("sample_size") if timing else raw.get("sample_size"))
        if (timing and timing.get("status") != "unavailable") or raw:
            if sample_size is None or sample_size >= 20:
                basis.append("lead timing regularity")
    return bool(basis), sorted(set(basis))


def _has_ua_pattern(ctx: dict[str, Any]) -> tuple[bool, list[str]]:
    basis: list[str] = []
    for family in ctx.get("ua_families") or []:
        version_count = _to_float(family.get("version_count")) or 0.0
        member_count = _to_float(family.get("member_count")) or 0.0
        checks = " ".join(str(value) for value in family.get("structural_checks") or []).lower()
        if version_count >= 3 and member_count >= 2:
            basis.append("UA-family version rotation")
        if "rotation" in checks or "imperson" in checks or "version" in checks:
            basis.append("UA-family structural check")
    for campaign in ctx.get("campaigns") or []:
        summary = campaign.get("ua_plausibility_summary") or {}
        if summary.get("forged_ua_candidate") or summary.get("anomalous_member_count"):
            basis.append("campaign UA plausibility summary")
    for case in ctx.get("scraper_cases") or []:
        plausibility = case.get("ua_plausibility") or {}
        if plausibility.get("verdict") in {"confirmed", "elevated"}:
            basis.append("lead UA plausibility anomaly")
    return bool(basis), sorted(set(basis))


def _has_fanout_pattern(ctx: dict[str, Any]) -> tuple[bool, list[str], dict[str, float]]:
    basis: list[str] = []
    maxima = {"ips": 0.0, "asns": 0.0, "countries": 0.0}

    def observe(ip_value: Any = None, asn_value: Any = None, country_value: Any = None, source: str = "") -> None:
        ip_count = _to_float(ip_value) or 0.0
        asn_count = _to_float(asn_value) or 0.0
        country_count = _to_float(country_value) or 0.0
        maxima["ips"] = max(maxima["ips"], ip_count)
        maxima["asns"] = max(maxima["asns"], asn_count)
        maxima["countries"] = max(maxima["countries"], country_count)
        if ip_count >= 50 or asn_count >= 3 or country_count >= 3:
            basis.append(source)

    for campaign in ctx.get("campaigns") or []:
        fanout = campaign.get("fanout_summary") or {}
        observe(
            fanout.get("unique_ips_lower_bound") or fanout.get("effective_ips_composite") or campaign.get("unique_client_ips"),
            campaign.get("unique_asns"),
            campaign.get("unique_countries"),
            "campaign fan-out lower bound",
        )
    for case in ctx.get("scraper_cases") or []:
        fanout = case.get("fanout_enrichment") or {}
        observe(
            fanout.get("unique_ips") or fanout.get("unique_client_ips") or case.get("unique_client_ips"),
            case.get("unique_asns"),
            case.get("unique_countries"),
            "lead fan-out lower bound",
        )
    for row in ctx.get("fingerprints") or []:
        if isinstance(row, dict):
            observe(
                row.get("unique_client_ips"),
                row.get("unique_asns"),
                row.get("unique_countries"),
                "fingerprint fan-out lower bound",
            )
    for row in (ctx.get("infrastructure") or {}).get("asn_rollups") or []:
        if isinstance(row, dict):
            observe(row.get("client_ip_count"), 1, row.get("country_count"), "infrastructure rollup")
    return bool(basis), sorted(set(basis)), maxima


def _pattern_note(
    *,
    title: str,
    text: str,
    evidence_basis: list[str],
    links: list[dict[str, str]],
    surface_priority: int,
) -> dict[str, Any]:
    return {
        "title": title,
        "text": text,
        "evidence_basis": evidence_basis,
        "links": links,
        "confidence_boundary": (
            "Pattern note only. It supports validation dimensions and is not classification evidence; "
            "it does not prove intent, operator identity, or enforcement eligibility by itself."
        ),
        "surface_priority": surface_priority,
    }


def _build_pattern_notes(ctx: dict[str, Any]) -> list[dict[str, Any]]:
    assessment = ctx.get("impact_assessment") if isinstance(ctx.get("impact_assessment"), dict) else {}
    hunt = assessment.get("hunt") if isinstance(assessment.get("hunt"), dict) else {}
    request_share = _to_float(hunt.get("request_share"))
    response_share = _to_float(hunt.get("response_body_byte_share"))
    has_endpoint, endpoint_basis, endpoint_share = _has_endpoint_pattern(ctx)
    has_timing, timing_basis = _has_timing_pattern(ctx)
    has_ua, ua_basis = _has_ua_pattern(ctx)
    has_fanout, fanout_basis, fanout_max = _has_fanout_pattern(ctx)
    has_campaign = bool(ctx.get("campaigns"))
    notes: list[dict[str, Any]] = []

    corroborating = []
    if has_endpoint:
        corroborating.append("endpoint targeting")
    if has_timing:
        corroborating.append("timing regularity")
    if has_ua:
        corroborating.append("UA plausibility or rotation")
    if has_fanout:
        corroborating.append("fan-out")
    if has_campaign:
        corroborating.append("campaign linkage")

    if (
        request_share is not None
        and response_share is not None
        and request_share >= 0.01
        and response_share <= request_share * 0.75
        and request_share - response_share >= 0.01
        and corroborating
    ):
        notes.append(
            _pattern_note(
                title="Light payload / high hits",
                text=(
                    f"The hit share materially exceeds response-byte share "
                    f"({_fmt_share(request_share)} hits vs {_fmt_share(response_share)} response bytes). "
                    f"That is consistent with many lighter-than-average requests when paired with "
                    f"{', '.join(corroborating[:4])}; treat it as supporting context, not a standalone scraper signature."
                ),
                evidence_basis=[
                    "hunt request share and response-byte share",
                    *corroborating[:4],
                ],
                links=_pattern_link("owasp_oat_011", "owasp_bot_management", "f5_scraper_patterns"),
                surface_priority=10,
            )
        )

    if has_endpoint and (endpoint_share is None or endpoint_share >= 25.0 or request_share is None or request_share >= 0.01):
        notes.append(
            _pattern_note(
                title="Direct-to-data/API focus",
                text=(
                    "Endpoint evidence is concentrated on scoped API, catalog, search, listing, or similarly narrow flow points. "
                    "Use this to validate endpoint/session controls and current Bot Manager coverage; do not escalate enforcement from endpoint shape alone."
                ),
                evidence_basis=endpoint_basis,
                links=_pattern_link("owasp_oat_011", "f5_scraper_patterns"),
                surface_priority=20,
            )
        )

    if has_timing:
        notes.append(
            _pattern_note(
                title="Boxy or interval cadence",
                text=(
                    "Timing evidence shows regular, continuous, or interval-shaped behavior that can diverge from typical human diurnal variation. "
                    "Validate with current inter-arrival samples and endpoint context before treating cadence as response evidence."
                ),
                evidence_basis=timing_basis,
                links=_pattern_link("owasp_bot_management", "f5_scraper_patterns", "cloudflare_bot_detection"),
                surface_priority=30,
            )
        )

    if has_ua:
        notes.append(
            _pattern_note(
                title="UA impersonation / rotation",
                text=(
                    "UA plausibility or version-family evidence suggests the declared client identity should not be trusted alone. "
                    "Pair UA strings with behavior, fingerprints, endpoint surface, and session controls before enforcement."
                ),
                evidence_basis=ua_basis,
                links=_pattern_link("owasp_bot_management", "cloudflare_bot_detection", "f5_scraper_patterns"),
                surface_priority=40,
            )
        )

    if has_fanout and (has_endpoint or has_timing or has_ua or has_campaign):
        spread_bits = []
        if fanout_max["ips"]:
            spread_bits.append(f"at least {_fmt_num(fanout_max['ips'])} IPs")
        if fanout_max["asns"]:
            spread_bits.append(f"{_fmt_num(fanout_max['asns'])} ASNs")
        if fanout_max["countries"]:
            spread_bits.append(f"{_fmt_num(fanout_max['countries'])} countries")
        notes.append(
            _pattern_note(
                title="Distributed fan-out",
                text=(
                    f"Fan-out lower bounds show requests spread across {' / '.join(spread_bits) or 'multiple infrastructure pivots'}. "
                    "Evaluate identity, session, endpoint, and behavioral controls; IP-only blocking may be brittle for this evidence shape."
                ),
                evidence_basis=fanout_basis,
                links=_pattern_link("owasp_bot_management", "cloudflare_bot_detection", "f5_scraper_patterns"),
                surface_priority=50,
            )
        )

    return sorted(notes, key=lambda row: int(row.get("surface_priority") or 999))


def _hunt_impact_ui(ctx: dict[str, Any]) -> dict[str, Any] | None:
    assessment = ctx.get("impact_assessment") if isinstance(ctx.get("impact_assessment"), dict) else {}
    hunt = assessment.get("hunt") if isinstance(assessment.get("hunt"), dict) else {}
    if not hunt:
        return None
    view = _impact_view(hunt)
    return {
        "eyebrow": "Hunt impact",
        "scope": ctx.get("headline") or _subject_label(ctx.get("scope") or {}),
        "rows": [
            {
                "label": "Hits",
                "value": view["requests_display"],
                "share": view["request_share_display"],
                "denom": "of window HTTP requests",
            },
            {
                "label": "Hydrolix log ingest",
                "value": _fmt_bytes_long(hunt.get("hydrolix_log_ingest_bytes")),
                "share": view["hydrolix_log_ingest_byte_share_display"],
                "denom": "of customer log volume - Hydrolix bill driver",
            },
            {
                "label": "Response body",
                "value": _fmt_bytes_long(hunt.get("response_body_bytes")),
                "share": view["response_body_byte_share_display"],
                "denom": "response data copied to scrapers",
            },
            {
                "label": "Akamai-billed",
                "value": _fmt_bytes_long(hunt.get("akamai_billed_bytes")),
                "share": view["akamai_billed_byte_share_display"],
                "denom": "of CDN billed bandwidth",
            },
        ],
        "footnote": _hydrolix_ingest_note(assessment),
        "pattern_note": (ctx.get("pattern_notes") or [None])[0],
    }


def _iocs_from_context(ctx: dict[str, Any]) -> dict[str, list[str]]:
    uas: list[str] = []
    endpoints: list[str] = []
    ips: list[str] = []
    asns: list[str] = []

    for action in ctx.get("recommended_actions") or []:
        targets = _target_values(action)
        for ua in targets.get("user_agents") or []:
            _add_unique(uas, ua)
        for endpoint in targets.get("endpoint_prefixes") or []:
            _add_unique(endpoints, endpoint)
    for campaign in ctx.get("campaigns") or []:
        for ua in campaign.get("leads") or []:
            _add_unique(uas, ua)
        for row in campaign.get("endpoint_targets") or []:
            if isinstance(row, dict):
                _add_unique(endpoints, _endpoint_path(row))
        for key in ("client_ips", "ip_samples", "shared_ip_samples"):
            for ip in campaign.get(key) or []:
                _add_unique(ips, ip)
        if campaign.get("asn"):
            _add_unique(asns, campaign.get("asn"))
    for case in ctx.get("scraper_cases") or []:
        _add_unique(uas, case.get("user_agent"))
        for row in case.get("endpoint_targets") or []:
            if isinstance(row, dict):
                _add_unique(endpoints, _endpoint_path(row))
        for key in ("client_ips", "ip_samples", "shared_ip_samples"):
            for ip in case.get(key) or []:
                _add_unique(ips, ip)
        if case.get("asn"):
            _add_unique(asns, case.get("asn"))
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


def _exports_for_ui(data: dict[str, Any]) -> dict[str, str]:
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


def _threat_hunt_ui(ctx: dict[str, Any]) -> dict[str, Any]:
    scope = ctx.get("scope") or {}
    summary = ctx.get("deterministic_summary") or {}
    campaign = _campaign_ui(ctx.get("campaigns") or [])
    iocs = _iocs_from_context(ctx)
    data = {
        "meta": {
            "customer": ctx.get("headline") or _subject_label(scope),
            "cluster": scope.get("cluster") or "",
            "schema": SCHEMA,
            "generated_at": ctx.get("generated_at"),
            "window_current": {"pretty": _window_pretty((ctx.get("windows") or {}).get("current"))},
            "window_baseline": {"pretty": _window_pretty((ctx.get("windows") or {}).get("baseline"))},
        },
        "verdict": {
            "level": summary.get("severity_level") or "low",
            "level_label": summary.get("level_label") or "Evidence bounded",
            "confidence": summary.get("confidence") or "bounded",
            "confidence_label": summary.get("confidence_label") or "Evidence bounded",
            "ladder": [
                {**step, "id": step.get("id") or step.get("key") or "observe"}
                for step in (ctx.get("severity_ladder") or [])
            ],
            "summary": summary.get("summary") or "Threat hunt evidence is bounded by supplied artifacts.",
        },
        "impact_tiles": _impact_tiles_ui(ctx),
        "impact_rows": _impact_rows_ui(ctx),
        "impact_note": _hydrolix_ingest_note(ctx.get("impact_assessment")),
        "pattern_notes": ctx.get("pattern_notes") or [],
        "hunt_impact": _hunt_impact_ui(ctx),
        "actions": [],
        "leads": [_lead_ui(case) for case in (ctx.get("lead_cards") or [])],
        "campaign_count": len(ctx.get("campaigns") or []),
        "campaign": campaign,
        "infra": {
            "available": bool((ctx.get("infrastructure") or {}).get("asn_rollups")),
            "note": (
                "GeoIP / ASN enrichment was not supplied; IP and ASN pivots require enrichment in the source pipeline."
                if not iocs["client_ips"] and not iocs["asns"]
                else "Infrastructure enrichment is included where supplied by the artifact."
            ),
            "stats": [
                {"value": len(iocs["asns"]), "label": "ASNs identified"},
                {"value": campaign.get("countries", 0), "label": "Countries"},
                {"value": len(iocs["client_ips"]) or campaign.get("ips", 0), "label": "Distinct IPs"},
            ],
        },
        "boundaries": {
            "observed": (ctx.get("evidence_boundaries") or {}).get("observed") or [],
            "not_established": (ctx.get("evidence_boundaries") or {}).get("not_established") or [],
        },
        "iocs": iocs,
    }
    for action in ctx.get("recommended_actions") or []:
        target_kind, target_value = _action_primary_target(action)
        impact = action.get("estimated_observed_window_impact") or {}
        confidence_scope = _action_source_confidence(action, ctx)
        data["actions"].append(
            {
                "ordinal": len(data["actions"]) + 1,
                "tier": action.get("tier") or "tier_4",
                "tier_label": action.get("tier_label") or _label(str(action.get("tier") or "tier_4")),
                "scope": action.get("scope") or "lead",
                "scope_label": action.get("scope_label") or _label(str(action.get("scope") or "lead")),
                "action_type": action.get("action_type_label") or _label(str(action.get("action_type") or "monitor")),
                "wording": action.get("wording_label") or _label(str(action.get("enforcement_wording") or "challenge_first")),
                "target_kind": target_kind,
                "target_value": target_value,
                "target_secondary": _action_secondary_targets(action),
                "impact_requests": action.get("impact_requests_display") or _fmt_num(impact.get("requests")),
                "impact_share": action.get("impact_request_share_display") or _fmt_share(impact.get("request_share")),
                "impact_bytes": action.get("impact_bytes_display") or _fmt_bytes(impact.get("bytes")),
                "impact_byte_share": action.get("impact_byte_share_display") or _fmt_share(impact.get("byte_share")),
                "classification": action.get("threat_category_label"),
                "confidence": action.get("threat_confidence_display"),
                "confidence_scope": confidence_scope["label"],
                "confidence_bucket": confidence_scope["bucket"],
                "attack": _attack_labels(action),
                "reasons": [_label(str(flag)) for flag in action.get("supporting_evidence") or []],
                "caveat": action.get("false_positive_caveat") or action.get("threat_action_modifier") or "Validate target membership before enforcement.",
            }
        )
    data["action_groups"] = _action_groups(data["actions"])
    data["topline_lede"] = _topline_lede(data)
    data["exports"] = _exports_for_ui(data)
    return data


def _edge_narrative(edge: dict[str, Any]) -> str:
    left = str(edge.get("left_user_agent") or "one lead")
    right = str(edge.get("right_user_agent") or "another lead")
    parts = []
    if edge.get("shared_ip_count"):
        parts.append(f"{edge.get('shared_ip_count')} shared IPs")
    if edge.get("path_cosine") is not None:
        parts.append(f"path similarity {_fmt_float(edge.get('path_cosine'))}")
    if edge.get("temporal_correlation") is not None:
        parts.append(f"temporal correlation {_fmt_float(edge.get('temporal_correlation'))}")
    if edge.get("asn_cosine") is not None:
        parts.append(f"ASN similarity {_fmt_float(edge.get('asn_cosine'))}")
    if not parts:
        parts.append("linked evidence")
    return f"{left} links to {right} via " + ", ".join(parts) + "."


def prepare(artifact: dict[str, Any]) -> dict[str, Any]:
    scope = artifact.get("scope") or {}
    scorecards = [
        {
            **card,
            "module_label": _label(str(card.get("module", ""))),
            "verdict_label": _label(str(card.get("verdict", "not_enough_data"))),
            "tone": _tone(str(card.get("verdict", "not_enough_data"))),
            "rationale": card.get("rationale") or card.get("summary") or "No rationale supplied.",
        }
        for card in artifact.get("module_scorecards", [])
        if isinstance(card, dict)
    ]
    baseline = artifact.get("baseline_movement") or {}
    scraper_cases = []
    for case in artifact.get("scraper_cases") or []:
        if not isinstance(case, dict):
            continue
        baseline_comparison = _baseline_comparison(case)
        drilldown_coverage = _coverage_view(case.get("drilldown_coverage"))
        endpoint_evidence = _endpoint_evidence_view(case.get("endpoint_evidence"))
        ua_plausibility = _ua_plausibility_view(case.get("ua_plausibility"))
        fanout = _fanout_view(case.get("fanout_enrichment") or (case.get("ua_plausibility") or {}).get("signals", {}).get("fanout"))
        confidence = _confidence_view(case.get("confidence_assessment"))
        threat_classification = _classification_view(case.get("threat_classification"))
        scraper_cases.append(
            {
                **case,
                "campaign_id": case.get("campaign_id"),
                "campaign_verdict": case.get("campaign_verdict"),
                "verdict_label": _label(str(case.get("verdict", "not_enough_data"))),
                "tone": _tone(str(case.get("verdict", "not_enough_data"))),
                "evidence_flag_labels": [
                    _label(str(flag)) for flag in case.get("evidence_flags") or []
                ],
                "missing_evidence_labels": [
                    _label(str(flag)) for flag in case.get("missing_evidence") or []
                ],
                "requests_display": _fmt_num(case.get("requests")),
                "bytes_display": _fmt_num(case.get("bytes")),
                "baseline_display": _fmt_num(case.get("baseline_requests")),
                "impact_assessment": _impact_view(case.get("impact_assessment")),
                "request_delta_display": baseline_comparison["delta_display"],
                "baseline_delta_display": baseline_comparison["display"],
                "baseline_delta_class": baseline_comparison["class"],
                "baseline_ratio": baseline_comparison["ratio"],
                "baseline_comparison": baseline_comparison,
                "timing": _timing_summary(case),
                "drilldown_coverage": drilldown_coverage,
                "endpoint_evidence": endpoint_evidence,
                "ua_plausibility": ua_plausibility,
                "fanout_enrichment": fanout,
                "bot_manager_context": _bot_manager_source_view(case.get("bot_manager_context")),
                "threat_classification": threat_classification,
                "confidence_assessment": confidence,
                "recommended_actions": [
                    _action_view(action)
                    for action in case.get("recommended_actions") or []
                    if isinstance(action, dict)
                ],
            }
        )
    campaigns = []
    for campaign in artifact.get("campaigns") or []:
        if not isinstance(campaign, dict):
            continue
        baseline_comparison = _baseline_comparison(campaign)
        drilldown_coverage_summary = _campaign_coverage_view(
            campaign.get("drilldown_coverage_summary")
        )
        endpoint_evidence_summary = _campaign_endpoint_summary_view(
            campaign.get("endpoint_evidence_summary")
        )
        ua_plausibility_summary = _campaign_ua_summary_view(
            campaign.get("ua_plausibility_summary")
        )
        fanout_summary = _campaign_fanout_summary_view(campaign.get("fanout_summary"))
        confidence_summary = campaign.get("confidence_summary") if isinstance(campaign.get("confidence_summary"), dict) else {}
        threat_classification = _classification_view(campaign.get("threat_classification"))
        campaigns.append(
            {
                **campaign,
                "verdict_label": _label(str(campaign.get("verdict", "not_enough_data"))),
                "tone": _tone(str(campaign.get("verdict", "not_enough_data"))),
                "temporal_pattern_label": _label(str(campaign.get("temporal_pattern", "not_established"))),
                "total_requests_display": _fmt_num(campaign.get("total_requests")),
                "bytes_display": _fmt_num(campaign.get("bytes")),
                "baseline_requests_display": _fmt_num(campaign.get("baseline_requests")),
                "impact_assessment": _impact_view(campaign.get("impact_assessment")),
                "baseline_delta_display": baseline_comparison["display"],
                "baseline_delta_class": baseline_comparison["class"],
                "drilldown_coverage_summary": drilldown_coverage_summary,
                "endpoint_evidence_summary": endpoint_evidence_summary,
                "ua_plausibility_summary": ua_plausibility_summary,
                "fanout_summary": fanout_summary,
                "threat_classification": threat_classification,
                "confidence_summary": {
                    **confidence_summary,
                    "dominant_qualifier_label": _label(str(confidence_summary.get("dominant_qualifier") or "unavailable")),
                    "baseline_significance_available_count": int(_to_float(confidence_summary.get("baseline_significance_available_count")) or 0),
                    "strongest_reinforcing_combinations": confidence_summary.get("strongest_reinforcing_combinations") or [],
                    "max_background_rate_concern": confidence_summary.get("max_background_rate_concern") or {},
                },
                "recommended_actions": [
                    _action_view(action)
                    for action in campaign.get("recommended_actions") or []
                    if isinstance(action, dict)
                ],
                "link_narratives": [
                    _edge_narrative(edge)
                    for edge in campaign.get("linking_evidence") or []
                    if isinstance(edge, dict)
                ],
            }
        )
    campaigns.sort(key=lambda item: float(item.get("total_requests") or 0), reverse=True)
    scraper_cases.sort(key=lambda item: float(item.get("requests") or 0), reverse=True)
    ua_families = [
        _ua_family_view(family)
        for family in artifact.get("ua_families") or []
        if isinstance(family, dict)
    ]
    known_traffic = [
        _known_traffic_view(row)
        for row in artifact.get("known_traffic") or []
        if isinstance(row, dict)
    ]
    metric_rows = []
    for row in baseline.get("metric_deltas") or []:
        if not isinstance(row, dict):
            continue
        metric_rows.append(
            {
                **row,
                "metric_label": _label(str(row.get("metric", ""))),
                "current_display": _fmt_num(row.get("current")),
                "baseline_display": _fmt_num(row.get("baseline")),
                "pct_change_display": _fmt_pct(row.get("pct_change")),
            }
        )
    deterministic_summary = _build_deterministic_summary(
        artifact, campaigns, scraper_cases
    )
    bot_manager_context = _bot_manager_context_view(artifact.get("bot_manager_context"))
    recommended_actions = [
        _action_view(action)
        for action in artifact.get("recommended_actions") or []
        if isinstance(action, dict)
    ]
    impact_assessment = artifact.get("impact_assessment") if isinstance(artifact.get("impact_assessment"), dict) else {}
    impact_view = {
        **impact_assessment,
        "hunt": _impact_view(impact_assessment.get("hunt") if isinstance(impact_assessment.get("hunt"), dict) else {}),
        "tiers": {
            tier: _impact_view(value if isinstance(value, dict) else {})
            for tier, value in (impact_assessment.get("tiers") or {}).items()
            if isinstance(impact_assessment.get("tiers"), dict)
        },
        "cost_config": impact_assessment.get("cost_config") if isinstance(impact_assessment.get("cost_config"), dict) else None,
    }
    ctx = {
        "artifact": artifact,
        "title": "Threat Hunt",
        "report_type": REPORT_TYPE,
        "kicker": "Bot Insights — Threat Hunt",
        "headline": _subject_label(scope),
        "dek": "Threat hunt evidence brief for single-customer/window scraper and automation evidence.",
        "scope": scope,
        "windows": {
            "current": scope.get("current_window"),
            "baseline": scope.get("baseline_window"),
        },
        "purpose": None,
        "profile": "screen",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "scorecards": scorecards,
        "campaigns": campaigns,
        "ua_families": ua_families,
        "scraper_cases": scraper_cases,
        "known_traffic": known_traffic,
        "bot_manager_context": bot_manager_context,
        "threat_classification": _classification_view(artifact.get("threat_classification")),
        "recommended_actions": recommended_actions,
        "impact_assessment": impact_view,
        "impact_note": _hydrolix_ingest_note(impact_view),
        "deterministic_summary": deterministic_summary,
        "severity_ladder": _severity_ladder(
            deterministic_summary["severity_level"]
        ),
        "analyst_assessment": _build_analyst_assessment(
            deterministic_summary
        ),
        "primary_concern": _build_primary_concern(
            deterministic_summary, campaigns, scraper_cases
        ),
        "threat_findings": _build_threat_findings(
            artifact, campaigns, scraper_cases
        ),
        "impact_tiles": _build_impact_tiles(artifact, campaigns, scraper_cases),
        "campaign_readouts": campaigns[:5],
        "ua_family_readouts": ua_families[:5],
        "lead_cards": scraper_cases[:8],
        "evidence_boundaries": _build_evidence_boundaries(
            campaigns, scraper_cases
        ),
        "fingerprints": artifact.get("fingerprints") or [],
        "endpoints": artifact.get("endpoints") or [],
        "infrastructure": artifact.get("infrastructure") or {},
        "classification_gap": artifact.get("classification_gap") or {},
        "limitations": artifact.get("limitations") or [],
        "metric_rows": metric_rows,
        "countries": baseline.get("countries") or [],
        "traffic_cohorts": baseline.get("traffic_cohorts") or [],
        "method": {
            "schema_version": artifact.get("schema_version"),
            "constraints": artifact.get("interpretation_constraints") or [],
        },
        "confidence": {
            "reasons": deterministic_summary["reasons"],
        },
    }
    ctx["pattern_notes"] = _build_pattern_notes(ctx)
    ctx["threat_hunt_ui"] = _threat_hunt_ui(ctx)
    return ctx
