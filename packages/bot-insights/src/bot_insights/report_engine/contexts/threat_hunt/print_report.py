from __future__ import annotations

from ._shared import *

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

__all__ = [name for name in globals() if not name.startswith("__")]
