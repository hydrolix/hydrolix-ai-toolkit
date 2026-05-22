"""Mitigation coverage projection for incident narrative context."""

from __future__ import annotations

from ..formatters import _format_pct


def _mitigation_coverage_view(scope_art: dict) -> dict | None:
    mitigation = scope_art.get("mitigation_effectiveness") or {}
    if not mitigation:
        return None
    top_rule = mitigation.get("top_deny_rule") or {}
    return {
        "tone": mitigation.get("tone") or "unknown",
        "interpretation": mitigation.get("interpretation") or "",
        "tiles": [
            {
                "label": "Coverage assessment",
                "value": mitigation.get("coverage_assessment") or "Observed only",
            },
            {
                "label": "No Action share",
                "value": _format_pct(mitigation.get("no_action_share_pct")),
            },
            {
                "label": "Deny share",
                "value": _format_pct(mitigation.get("deny_share_pct")),
            },
            {
                "label": "Monitor/Tarpit share",
                "value": _format_pct(mitigation.get("monitor_tarpit_share_pct")),
            },
        ],
        "top_deny_rule": (
            {
                "value": top_rule.get("value") or "",
                "share": _format_pct(top_rule.get("share_pct")),
            }
            if top_rule
            else None
        ),
        "boundary": (
            "Coverage is derived from observed edge-action evidence only. "
            "It does not claim a control worked, failed, or caused recovery."
        ),
    }
