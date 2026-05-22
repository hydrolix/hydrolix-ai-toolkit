from __future__ import annotations

from ._shared import *

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

__all__ = [name for name in globals() if not name.startswith("__")]
