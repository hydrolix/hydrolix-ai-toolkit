"""Top-level incident print report builder."""

from __future__ import annotations

from typing import Any

from .actors_actions import _actions, _cover_actions, _first_actor_rows
from .chart import severity_band, volume_chart
from .findings import _findings
from .sections import (
    _analysis_availability,
    _as_reputation,
    _assessment,
    _actor_correlation_callouts,
    _attack_shape,
    _attck,
    _browser_age,
    _classification,
    _primary,
    _risk_explanation,
    _score_calibration,
    _user_agent_rotation,
    _verdict_prose,
)
from .shared import _html, _text, _window

def build_print_report(ctx: dict[str, Any]) -> dict[str, Any]:
    summary = ctx.get("deterministic_summary") or {}
    score = int((ctx.get("risk_score") or {}).get("value") or 0)
    band = severity_band(summary.get("level"), score)
    findings = _findings(ctx)
    actors = _first_actor_rows(ctx)
    classification = _classification(ctx)
    methodology = ctx.get("method") or {}
    tiles = (ctx.get("impact") or {}).get("tiles") or []
    ua_rotation = _user_agent_rotation(ctx)
    as_reputation = _as_reputation(ctx)
    actor_correlation_callouts = _actor_correlation_callouts(
        as_reputation, ua_rotation
    )
    page_count = 10 + int(ua_rotation["available"]) + int(as_reputation["available"])
    ua_rotation_page_number = 11 if ua_rotation["available"] else None
    as_reputation_page_number = (
        10 + int(ua_rotation["available"]) + 1
        if as_reputation["available"]
        else None
    )
    return {
        "customer": ctx.get("headline") or (ctx.get("scope") or {}).get("request_host") or "Incident",
        "meta": {"schema": methodology.get("schema_version") or "bot_incident_scope.v1"},
        "window": _window(ctx),
        "verdict": {
            "risk_score": score,
            "risk_max": 100,
            "confidence": (ctx.get("claim_profile") or {}).get(
                "traffic_anomaly_confidence_label"
            ) or summary.get("confidence_label") or "Evidence bounded",
            "confidence_total": 5,
            "confidence_filled": 4 if summary.get("confidence") == "high" else 3,
            "prose_html": _verdict_prose(ctx, summary),
            "bands": [
                {"label": "Observe", "is_critical": False},
                {"label": "Monitor", "is_critical": False},
                {"label": "Elevated", "is_critical": False},
                {"label": "High", "is_critical": False},
                {"label": "Critical", "is_critical": True},
            ],
            "calibration_html": _score_calibration(ctx, band["band_label"]),
            **band,
        },
        "chart": volume_chart(ctx),
        "at_a_glance": {
            "footnote": "Metrics and ranks are deterministic; analyst prose cannot change them.",
            "shape": {
                "subtitle": "Volume shape",
                "hero": tiles[0].get("value") if tiles else "No volume",
                "subline_html": _html(tiles[0].get("sub") if tiles else "Volume series unavailable"),
                "facts": [_html(tile.get("label")) for tile in tiles[1:4]],
            },
            "who": {
                "chip": "Flagged",
                "hero": str(len(ctx.get("suspicious_targets") or actors)),
                "subline_html": "flagged actors or targets",
                "facts": [row["ip"] for row in actors[:3]],
            },
            "do_now": {"subtitle": "Recommended", "items": _cover_actions(ctx, 3)},
        },
        "analyst_assessment": _assessment(ctx),
        "primary_concern": _primary(ctx),
        "findings_page": {
            "eyebrow": "Findings",
            "headline": "Evidence-backed findings",
            "lede_html": "Findings are generated from deterministic suspicious-target evidence.",
        },
        "finding_ip_cluster": findings[0],
        "finding_ua_share": findings[1],
        "finding_human_anomaly": findings[2],
        "actions_page": {
            "eyebrow": "Recommended Actions",
            "headline": "What to do next",
            "lede_html": "Actions are candidates with scope, duration, validation, and rollback criteria.",
        },
        "actions": _actions(ctx),
        "attack_shape": _attack_shape(ctx),
        "actors_page": {
            "eyebrow": "Actors",
            "headline": "Raw actors and action priority",
            "lede_html": "Rows are the highest-volume raw client IPs; severity is only shown when matched to the action-target heuristic.",
            "total_flagged": len(ctx.get("suspicious_targets") or []),
            "appendix_note": "Rows are truncated for fixed-page print layout.",
        },
        "actor_correlation_callouts": actor_correlation_callouts,
        "actors": actors,
        "top_hosts": [
            {
                "name": _text(row.get("value")),
                "bar_width": _text(row.get("share_pct_display") or "0%"),
                "bar_class": "critical",
                "pct": _text(row.get("share_pct_display") or ""),
            }
            for row in ((ctx.get("impact") or {}).get("top_affected_hosts") or {}).get("hosts", [])[:5]
        ],
        "top_hosts_meta": "Affected hosts",
        "top_hosts_footnote": "Top host evidence from scope artifact.",
        "geo": [
            {
                "cc": _text(row.get("value")),
                "bar_width": _text(row.get("share_pct_display") or "0%"),
                "requests": _text(row.get("requests_display")),
                "delta": _text(row.get("delta_vs_baseline_display") or ""),
            }
            for row in (ctx.get("country_mix_rows") or [])[:5]
        ],
        "geo_footnote": "Country mix reflects observed request geolocation.",
        "classification": classification,
        **classification,
        "attck_page": _attck(ctx),
        "risk_explanation": _risk_explanation(ctx),
        "analysis_availability_print": _analysis_availability(ctx),
        "browser_age": _browser_age(ctx),
        "ua_rotation_print": ua_rotation,
        "ua_rotation_page_number": ua_rotation_page_number,
        "as_reputation_print": as_reputation,
        "as_reputation_page_number": as_reputation_page_number,
        "methodology": {
            "prose_html": (
                "This report is presentation-only. Metrics, ranks, evidence limits, "
                "and scores come from deterministic incident artifacts. Credential "
                "ATT&CK mappings require auth-specific corroboration before being "
                "treated as findings."
            ),
            "window_summary_html": _html(
                f"Current: {(ctx.get('windows') or {}).get('current', {}).get('start')} to {(ctx.get('windows') or {}).get('current', {}).get('end')} "
                f"vs baseline {(ctx.get('windows') or {}).get('baseline', {}).get('start')} to {(ctx.get('windows') or {}).get('baseline', {}).get('end')}"
            ),
            "metadata": [
                {"label": "Schema", "value": methodology.get("schema_version")},
                {"label": "Comparison", "value": methodology.get("comparison_type")},
                {"label": "Rows", "value": methodology.get("result_row_count")},
                {"label": "Baseline", "value": (ctx.get("baseline_context") or {}).get("strategy")},
                {"label": "Constraints", "value": ", ".join(methodology.get("interpretation_constraints") or [])},
            ],
        },
        "page_count": page_count,
    }
