"""Section builders for incident print reports."""

from __future__ import annotations

from typing import Any

from .chart import _attack_timeline, severity_band
from .shared import _html, _prose, _short_user_agent, _text

def _assessment(ctx: dict[str, Any]) -> dict[str, Any]:
    note = (ctx.get("notes_by_slot") or {}).get("executive_summary") or {}
    fallback = ctx.get("analyst_assessment") or {}
    impact_tiles = (ctx.get("impact") or {}).get("tiles") or []
    top_signal_tiles = sorted(
        (
            tile for tile in impact_tiles
            if float(tile.get("rank_score") or 0) > 0 and tile.get("value") != "—"
        ),
        key=lambda tile: float(tile.get("rank_score") or 0),
        reverse=True,
    )[:3]
    why_stood_out = [
        {
            "stat": tile.get("value"),
            "caption_html": _html(f"{tile.get('label')}: {tile.get('sub')}")
        }
        for tile in impact_tiles[:3]
    ]
    prose = note.get("text") or fallback.get("conclusion") or (ctx.get("deterministic_summary") or {}).get("headline")
    if not note and top_signal_tiles:
        signal_text = "; ".join(
            _text(
                f"{tile.get('label')} {tile.get('value')}"
                + (f" ({tile.get('sub')})" if tile.get("sub") else "")
            )
            for tile in top_signal_tiles
            if tile.get("value") or tile.get("label")
        )
        if signal_text:
            prose = f"{prose} Highest signals: {signal_text}."
    return {
        "headline": "Analyst Assessment",
        "prose_html": _prose(prose),
        "observed": ["Volume shift", "Actor concentration", "Edge response"],
        "inferred": ["Automation hypothesis", "Credential-access lead"],
        "why_stood_out": why_stood_out,
    }

def _verdict_prose(ctx: dict[str, Any], summary: dict[str, Any]) -> str:
    claim_profile = ctx.get("claim_profile") or {}
    prose = claim_profile.get("hero_summary") or summary.get("headline")
    return _html(prose)

def _row_count(value: Any) -> int:
    try:
        return int(float(value or 0))
    except (TypeError, ValueError):
        return 0

def _risk_signal_summary(risk: dict[str, Any]) -> dict[str, int]:
    severity_rows = risk.get("severity_rows") or []
    reason_rows = risk.get("reason_rows") or []
    return {
        "target_count": sum(_row_count(row.get("count")) for row in severity_rows),
        "severity_tier_count": len(severity_rows),
        "signal_type_count": len(reason_rows),
        "signal_hit_count": sum(_row_count(row.get("count")) for row in reason_rows),
    }

def _score_calibration(ctx: dict[str, Any], band_label: str) -> str:
    risk = ctx.get("risk_score") or {}
    raw = risk.get("raw_score_display") or "unavailable"
    signal_summary = _risk_signal_summary(risk)
    basis = risk.get("confidence_basis") or "Evidence is bounded by available artifacts."
    return _html(
        f"Calibration: {band_label} reflects {signal_summary['target_count']} "
        f"suspicious targets across {signal_summary['severity_tier_count']} "
        f"severity tiers, with {signal_summary['signal_type_count']} fired signal "
        f"types and {signal_summary['signal_hit_count']} total signal hits. "
        f"Raw score {raw}; displayed score is bounded to the {band_label} band. "
        f"{basis}"
    )

def _primary(ctx: dict[str, Any]) -> dict[str, Any]:
    source = ctx.get("primary_concern") or {}
    evidence = source.get("evidence") or []
    return {
        "eyebrow": "Primary Concern",
        "chip": "Evidence bounded",
        "chip_severity": "critical",
        "headline_html": _html(source.get("title") or "Primary concern"),
        "prose_html": _html(source.get("summary") or source.get("boundary") or ""),
        "stats": [
            {"label": f"Signal {idx}", "value": _text(value), "detail": ""}
            for idx, value in enumerate(evidence[:3], start=1)
        ],
    }

def _attack_shape(ctx: dict[str, Any]) -> dict[str, Any]:
    paths = ctx.get("top_raw_paths_rows") or ctx.get("path_pattern_rows") or []
    signals = ctx.get("coordination_signals") or []
    return {
        "eyebrow": "Attack Shape",
        "headline": "How the pressure presented",
        "lede_html": "Traffic shape is derived from deterministic window evidence.",
        "timeline": _attack_timeline(ctx),
        "top_path_meta_html": "Top paths by request share",
        "top_paths": [
            {
                "path": _text(row.get("value")),
                "requests": _text(row.get("requests_display") or ""),
                "share": _text(row.get("share_pct_display") or ""),
            }
            for row in paths[:5]
        ],
        "paths_footnote": "Path rows may be unavailable when raw drilldown is degraded.",
        "signals_summary_html": "Observed coordination signals",
        "coordination_signals": [
            {
                "name": _text(sig.get("signal") or sig.get("label") or "Signal"),
                "status": _text(sig.get("status") or "partial").replace("_", "-"),
                "status_label": _text(sig.get("status_label") or sig.get("status") or "Observed"),
            }
            for sig in signals[:5]
        ],
        "signals_footnote": "Signals are mechanical evidence, not attribution claims.",
    }

def _classification(ctx: dict[str, Any]) -> dict[str, Any]:
    cohorts = ctx.get("cohort_mix_rows") or []
    actions = ctx.get("siem_action_rows") or ctx.get("edge_action_mix_rows") or []
    max_cohort = max([float(row.get("share_pct") or 0) for row in cohorts] + [1.0])
    total_actions = sum(float(row.get("requests") or 0) for row in actions) or 1.0
    def action_class(value: Any) -> str:
        lowered = _text(value).lower()
        if "deny" in lowered or "block" in lowered:
            return "a-deny"
        if "monitor" in lowered:
            return "a-monitor"
        if "tarpit" in lowered or "challenge" in lowered or "rate" in lowered:
            return "a-tarpit"
        if "allow" in lowered:
            return "a-allow"
        return "a-noaction"

    return {
        "eyebrow": "Classification / Edge Response",
        "headline": "Classification and response mix",
        "lede_html": "Cohort and action rows preserve source evidence percentages.",
        "cohorts": [
            {
                "name": _text(row.get("value")),
                "bar_width": f"{(float(row.get('share_pct') or 0) / max_cohort) * 100:.1f}%",
                "min_width": "2px",
                "share": _text(row.get("share_pct_display")),
                "requests": _text(row.get("requests_display")),
                "rate_429": _text(row.get("req_429_share_display")),
                "rate_5xx": _text(row.get("req_5xx_share_display")),
                "flagged": idx == 0,
            }
            for idx, row in enumerate(cohorts[:5])
        ],
        "edge_action_stack": [
            {
                "class": action_class(row.get("value")),
                "flex": str(max(float(row.get("requests") or 0), 1.0)),
                "show_label": idx < 3,
                "min_width": "3px",
                "label": _text(row.get("value")),
            }
            for idx, row in enumerate(actions[:5])
        ],
        "edge_action_legend": [
            {
                "class": action_class(row.get("value")),
                "label": _text(row.get("value")),
                "value": f"{(float(row.get('requests') or 0) / total_actions) * 100:.1f}%",
                "delta": _text(row.get("delta_vs_baseline_display") or ""),
            }
            for row in actions[:5]
        ],
        "edge_action_meta_html": "Edge response mix",
        "deny_rules": [
            {
                "rule": _text(row.get("value")),
                "requests": _text(row.get("requests_display")),
                "share": _text(row.get("share_pct_display")),
                "delta": _text(row.get("delta_vs_baseline_display") or ""),
                "delta_class": "critical",
            }
            for row in (ctx.get("deny_rule_mix_rows") or [])[:5]
        ],
    }

def _attck(ctx: dict[str, Any]) -> dict[str, Any]:
    techniques = []
    for item in (ctx.get("attack_aggregation") or [])[:6]:
        techniques.append(
            {
                "tid": _text(item.get("id")),
                "tactic": _text(item.get("tactic")),
                "name": _text(item.get("name")),
                "evidence_html": _html(
                    f"{item.get('mapping_class')}: {item.get('supporting_evidence_text')}"
                ),
                "span_full": False,
            }
        )
    if not techniques:
        techniques.append(
            {
                "tid": "N/A",
                "tactic": "Not mapped",
                "name": "No ATT&CK mapping available",
                "evidence_html": "The available evidence did not include mapped techniques.",
                "span_full": True,
            }
        )
    return {
        "eyebrow": "ATT&CK / Methodology",
        "headline": "Technique mapping and method",
        "lede_html": "Mappings are deterministic labels from observed behavior.",
        "techniques": techniques,
    }

def _risk_explanation(ctx: dict[str, Any]) -> dict[str, Any]:
    risk = ctx.get("risk_score") or {}
    signal_summary = _risk_signal_summary(risk)
    band_label = severity_band(
        (ctx.get("deterministic_summary") or {}).get("level"),
        risk.get("value"),
    )["band_label"]
    return {
        "eyebrow": "Score Explanation",
        "headline": "How the score was calculated",
        "lede_html": _html(
            f"Risk {risk.get('value', 0)}/100 reflects "
            f"{signal_summary['target_count']} suspicious targets across "
            f"{signal_summary['severity_tier_count']} severity tiers, with "
            f"{signal_summary['signal_type_count']} fired signal types and "
            f"{signal_summary['signal_hit_count']} total signal hits. Raw score "
            f"{risk.get('raw_score_display', 'unknown')}; displayed score is "
            f"bounded to the {band_label} band. "
            f"{risk.get('confidence_basis', '')}"
        ),
        "severity_rows": [
            {
                "severity": _text(row.get("severity")),
                "label": _text(row.get("severity_label")),
                "count": _text(row.get("count")),
                "weight": _text(row.get("weight")),
                "weighted": _text(row.get("weighted_count")),
            }
            for row in (risk.get("severity_rows") or [])[:6]
        ],
        "reason_rows": [
            {
                "reason": _text(row.get("reason")).replace("_", " "),
                "count": _text(row.get("count")),
            }
            for row in (risk.get("reason_rows") or [])[:8]
        ],
    }

def _analysis_availability(ctx: dict[str, Any]) -> dict[str, Any]:
    source = ctx.get("analysis_availability") or {}
    return {
        "eyebrow": "Analysis Availability",
        "headline": "What the bundled artifacts can and cannot support",
        "boundary_html": _html(source.get("boundary")),
        "rows": [
            {
                "analysis": _text(row.get("analysis")),
                "status": _text(row.get("status")),
                "detail_html": _html(row.get("detail")),
            }
            for row in (source.get("rows") or [])[:6]
        ],
    }

def _browser_age(ctx: dict[str, Any]) -> dict[str, Any]:
    source = ctx.get("browser_version_context") or {}
    return {
        "eyebrow": "Browser UA Age",
        "headline": "Age context for flagged browser user agents",
        "boundary_html": _html(source.get("boundary")),
        "meta": (
            f"{source.get('snapshot_row_count', 0)} local release rows; "
            f"{source.get('stale_threshold_months', 18)} month stale threshold "
            f"as of {source.get('as_of', 'window end')}."
        ),
        "rows": [
            {
                "browser": _text(
                    f"{row.get('browser_label')} {row.get('version_display')}"
                ),
                "status": _text(row.get("status_label")),
                "age": _text(row.get("age_display")),
                "share": _text(row.get("share_pct_display")),
                "requests": _text(row.get("requests_display")),
                "delta": _text(row.get("baseline_delta_display")),
                "source": _text(row.get("source_name") or "local snapshot"),
                "ua": _text(row.get("user_agent")),
                "stale": bool(row.get("stale")),
            }
            for row in (source.get("rows") or [])[:6]
        ],
        "comparison_rows": [
            {
                "browser": _text(
                    f"{row.get('browser_label')} {row.get('version_display')}"
                ),
                "status": _text(row.get("status_label")),
                "age": _text(row.get("age_display")),
                "share": _text(row.get("share_pct_display")),
                "requests": _text(row.get("requests_display")),
            }
            for row in (source.get("comparison_rows") or [])[:3]
        ],
    }

def _user_agent_rotation(ctx: dict[str, Any]) -> dict[str, Any]:
    source = (ctx.get("assessment_explainers") or {}).get("user_agent_rotation") or {}
    rows = []
    for row in (source.get("rows") or [])[:5]:
        rows.append(
            {
                "client_ip": _text(row.get("client_ip")),
                "requests": _text(row.get("requests_display")),
                "distinct_user_agents": _text(row.get("distinct_user_agents")),
                "top_user_agent_share": _text(row.get("top_user_agent_share_display")),
                "entropy_bits": _text(row.get("entropy_bits")),
                "normalized_entropy": _text(row.get("normalized_entropy")),
                "rotation_label": _text(row.get("rotation_label")),
                "top_user_agent": _short_user_agent(row.get("top_user_agent")),
            }
        )
    return {
        "available": bool(source.get("available") and rows),
        "eyebrow": "User-Agent Rotation",
        "headline": "Rotation patterns among flagged client IPs",
        "summary_html": _html(source.get("summary")),
        "boundary_html": _html(source.get("boundary")),
        "rows": rows,
    }

def _as_reputation(ctx: dict[str, Any]) -> dict[str, Any]:
    source = ctx.get("as_reputation_context") or {}
    rows = [
        {
            "asn": _text(row.get("asn_display")),
            "name": _text(row.get("name")),
            "label": _text(row.get("label_display")),
            "confidence": _text(row.get("confidence")),
            "requests": row.get("requests") or 0,
            "requests_display": _text(row.get("requests_display")),
            "flagged_target_count": row.get("flagged_target_count") or 0,
            "external_html": _html(row.get("external_reputation_point")),
            "local_html": _html(row.get("report_local_behavior_point")),
            "sources": [
                _text(src.get("title"))
                for src in (row.get("sources") or [])[:3]
            ],
        }
        for row in (source.get("rows") or [])[:3]
    ]
    return {
        "available": bool(source.get("available") and rows),
        "eyebrow": "External AS Context",
        "headline": "Corroborating public reputation context",
        "boundary_html": _html(source.get("boundary")),
        "rows": rows,
    }

def _actor_correlation_callouts(
    as_reputation: dict[str, Any],
    ua_rotation: dict[str, Any],
) -> list[dict[str, Any]]:
    callouts: list[dict[str, Any]] = []
    as_rows = list(as_reputation.get("rows") or [])
    if as_reputation.get("available") and as_rows:
        strongest = max(
            as_rows,
            key=lambda row: (
                float(row.get("flagged_target_count") or 0),
                float(row.get("requests") or 0),
                row.get("asn") or "",
            ),
        )
        bits = [
            f"{strongest.get('asn')} / {strongest.get('name')}".strip(" /"),
            f"{strongest.get('requests_display')} requests",
        ]
        flagged = int(float(strongest.get("flagged_target_count") or 0))
        if flagged > 0:
            bits.append(f"{flagged} flagged target{'' if flagged == 1 else 's'}")
        callouts.append(
            {
                "kind": "as-reputation",
                "title": "AS reputation cluster",
                "summary_html": _html(
                    "Corroborating context connects this observed actor pattern "
                    f"to {'; '.join(bits)}."
                ),
                "boundary_html": (
                    "External AS reputation is corroborating context only; it "
                    "does not change scoring, target ordering, or incident claims."
                ),
            }
        )

    ua_rows = list(ua_rotation.get("rows") or [])
    if ua_rotation.get("available") and ua_rows:
        strongest_rows = ua_rows[:2]
        row_bits = [
            (
                f"{row.get('client_ip')} used {row.get('distinct_user_agents')} "
                f"distinct UAs with top-UA share {row.get('top_user_agent_share')} "
                f"({row.get('rotation_label')} rotation)"
            )
            for row in strongest_rows
        ]
        callouts.append(
            {
                "kind": "ua-rotation",
                "title": "User-Agent rotation",
                "summary_html": _html(
                    "Observed actor pattern is consistent with automation: "
                    + "; ".join(row_bits)
                    + "."
                ),
                "boundary_html": (
                    "UA rotation is corroborating context only and does not "
                    "prove operator intent."
                ),
            }
        )

    return callouts[:2]
