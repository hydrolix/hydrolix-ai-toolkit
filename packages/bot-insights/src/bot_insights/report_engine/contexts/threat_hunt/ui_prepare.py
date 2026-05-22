from __future__ import annotations

from ._shared import *

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

__all__ = [name for name in globals() if not name.startswith("__")]
