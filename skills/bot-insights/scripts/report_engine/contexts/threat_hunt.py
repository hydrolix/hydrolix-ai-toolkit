"""Context preparer for ``bot_threat_hunt.v3``."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


SCHEMA = "bot_threat_hunt.v3"
REPORT_TYPE = "threat_hunt"
TEMPLATE = "reports/threat_hunt.html"
PRINT_TEMPLATE = "reports/incident_report_print.html"
NOTE_ID_TO_SLOT = {
    "llm-interpretation": "executive_summary",
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
        return f"{n / 1_000_000:.1f}M"
    if abs(n) >= 1_000:
        return f"{n / 1_000:.1f}K"
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
        "impact_bytes_display": _fmt_num(impact.get("bytes"))
        if impact.get("bytes") is not None
        else "unavailable",
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
        top_case = cases[0]
        ua_view = top_case.get("ua_plausibility") or {}
        ua_text = (
            f" UA plausibility: {ua_view.get('trigger_reason')}."
            if ua_view.get("verdict") in {"confirmed", "elevated"}
            else ""
        )
        findings.append(
            {
                "label": "Finding 2",
                "lead": f"{top_case.get('user_agent')} is the lead scraper fingerprint.",
                "body": (
                    f"It accounts for {_fmt_num(top_case.get('requests'))} requests with "
                    f"{', '.join(top_case.get('evidence_flag_labels') or []) or 'no named evidence flags'}.{ua_text}"
                ),
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
                f"{top.get('user_agent')} accounts for {_fmt_num(top.get('requests'))} requests "
                f"with {', '.join(top.get('evidence_flag_labels') or []) or 'limited evidence flags'}."
            ),
            "boundary": "The case remains a lead unless additional independent evidence is supplied.",
            "evidence": (top.get("case_for") or [])[:3],
        }
    return None


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


def _print_actor_rows(cases: list[dict[str, Any]], limit: int = 10) -> list[dict[str, str]]:
    rows = []
    for idx, case in enumerate(cases[:limit], start=1):
        baseline = case.get("baseline_comparison") or _baseline_comparison(case)
        coverage = _coverage_view(case.get("drilldown_coverage"))
        endpoint_evidence = _endpoint_evidence_view(case.get("endpoint_evidence"))
        fanout = _fanout_view(case.get("fanout_enrichment") or (case.get("ua_plausibility") or {}).get("signals", {}).get("fanout"))
        rows.append(
            {
                "rank": str(idx),
                "ip": str(case.get("user_agent") or "Lead"),
                "asn_meta": str(case.get("campaign_id") or "independent lead"),
                "requests": case.get("requests_display") or _fmt_num(case.get("requests")),
                "share": f"{coverage['coverage_display']} {coverage['status_label']}; endpoint {endpoint_evidence['tier_label']}; {fanout['line']}",
                "rate_429": baseline.get("display") or "",
                "rate_429_class": baseline.get("class") or "ink-3",
                "severity": "critical" if case.get("tone") == "escalate" else "high",
                "severity_label": case.get("verdict_label") or "Lead",
                "edge_action_html": ", ".join(case.get("evidence_flag_labels") or []) or "Observed",
                "attck": "scraper lead",
            }
        )
    return rows


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


def _print_actions(actions: list[dict[str, Any]], limit: int = 5) -> list[dict[str, str]]:
    severity_by_tier = {
        "tier_1": "critical",
        "tier_2": "high",
        "tier_3": "monitor",
        "tier_4": "low",
    }
    rows = []
    for idx, action in enumerate(actions[:limit], start=1):
        targets = action.get("target_values") if isinstance(action.get("target_values"), dict) else {}
        uas = targets.get("user_agents") or []
        endpoints = targets.get("endpoint_prefixes") or []
        impact = (
            action.get("estimated_observed_window_impact")
            if isinstance(action.get("estimated_observed_window_impact"), dict)
            else {}
        )
        target_label = targets.get("campaign_id") or (uas[0] if uas else "selected lead")
        evidence = [
            _label(str(flag))
            for flag in (action.get("supporting_evidence") or [])[:4]
            if str(flag)
        ]
        evidence_html = (
            "Evidence: " + ", ".join(evidence)
            if evidence
            else "Evidence basis was not supplied in this action."
        )
        rows.append(
            {
                "n": f"{idx:02d}",
                "severity": severity_by_tier.get(str(action.get("tier")), "monitor"),
                "chip_text": _label(str(action.get("tier") or "tier_4")),
                "meta_html": (
                    f"{_label(str(action.get('scope') or 'lead'))} · "
                    f"{_fmt_num(impact.get('requests'))} observed requests"
                ),
                "title_html": f"{_label(str(action.get('action_type') or 'monitor'))}: <code>{target_label}</code>",
                "why_html": (
                    evidence_html
                    + (f". Endpoint focus: <code>{endpoints[0]}</code>." if endpoints else ".")
                    + (
                        f" {action.get('threat_action_modifier')}"
                        if action.get("threat_action_modifier")
                        else " Validate current Bot Manager/SIEM coverage before enforcement."
                    )
                ),
            }
        )
    return rows


def _print_known_traffic(rows: list[dict[str, Any]], limit: int = 5) -> list[dict[str, str]]:
    return [
        {
            "label": _label(str(row.get("disposition") or "known_traffic")),
            "target_html": f"<code>{row.get('user_agent') or 'unknown user-agent'}</code>",
            "detail_html": (
                f"{_fmt_num(row.get('requests'))} observed requests. "
                f"{row.get('reason') or 'Known crawler or infrastructure traffic.'}"
            ),
        }
        for row in rows[:limit]
    ]


def _classification_technique_rows(ctx: dict[str, Any], limit: int = 8) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
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
        for technique in mapping.get("mitre_techniques") or []:
            key = ("mitre", str(technique))
            if key in seen:
                continue
            seen.add(key)
            rows.append(
                {
                    "tid": str(technique),
                    "tactic": ", ".join(mapping.get("mitre_tactics") or []) or "ATT&CK",
                    "name": _label(category),
                    "evidence_html": (
                        f"Consistent with observed {category.replace('_', ' ')} signal only; "
                        f"not attribution. {evidence}"
                    ),
                    "span_full": False,
                }
            )
        for technique in mapping.get("hdx_techniques") or []:
            key = ("hdx", str(technique))
            if key in seen:
                continue
            seen.add(key)
            rows.append(
                {
                    "tid": str(technique),
                    "tactic": "Hydrolix",
                    "name": _label(category),
                    "evidence_html": (
                        f"Hydrolix technique consistent with observed {category.replace('_', ' ')} signal only; "
                        f"not attribution. {evidence}"
                    ),
                    "span_full": False,
                }
            )
        if len(rows) >= limit:
            return rows[:limit]
    return rows[:limit]


def _print_report(ctx: dict[str, Any]) -> dict[str, Any]:
    scope = ctx.get("scope") or {}
    summary = ctx.get("deterministic_summary") or {}
    campaigns = ctx.get("campaigns") or []
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
            "prose_html": summary.get("summary") or "Threat hunt evidence is bounded by supplied artifacts.",
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
            "stats": [
                {"label": f"Evidence {idx}", "value": str(value), "detail": ""}
                for idx, value in enumerate((primary.get("evidence") or [])[:3], start=1)
            ],
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
            "headline": "Behavioral scraper cases",
            "lede_html": "Rows are the highest-volume scraper leads.",
            "actor_column_label": "UA fingerprint",
            "rate_column_label": "Delta vs baseline",
            "evidence_column_label": "Evidence flags",
            "basis_column_label": "Family",
            "footer_label": "Scraper leads",
            "total_flagged": len(cases),
            "appendix_note": "Rows are truncated for fixed-page print layout.",
        },
        "actors": actors,
        "actions_page": {
            "eyebrow": "Recommended Actions",
            "headline": "What to do next",
            "lede_html": "Threat hunt output preserves evidence boundaries; operational actions require external validation.",
        },
        "actions": _print_actions(ctx.get("recommended_actions") or []),
        "known_traffic": _print_known_traffic(ctx.get("known_traffic") or []),
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
            "headline": "How the scraper evidence presented",
            "lede_html": "Evidence shape is derived from deterministic campaign and lead fields.",
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
            "headline": "Classification and response",
            "lede_html": "Classification evidence is bounded to supplied threat-hunt artifacts.",
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
            "actions": bool(ctx.get("recommended_actions")),
            "classification": False,
            "browser_age": False,
        },
        "page_numbers": {
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
            "metadata": [
                {"label": "Schema", "value": SCHEMA},
                {"label": "Cluster", "value": scope.get("cluster") or ""},
                {"label": "Database", "value": scope.get("database") or ""},
            ],
        },
        "page_count": 7,
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
                "baseline_display": _fmt_num(case.get("baseline_requests")),
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
                "baseline_requests_display": _fmt_num(campaign.get("baseline_requests")),
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
    recommended_actions = [
        _action_view(action)
        for action in artifact.get("recommended_actions") or []
        if isinstance(action, dict)
    ]
    return {
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
        "recommended_actions": recommended_actions,
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
