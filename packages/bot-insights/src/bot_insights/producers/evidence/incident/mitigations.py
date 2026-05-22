"""Incident mitigation-effectiveness evidence shaping."""

from __future__ import annotations

def _incident_mitigation_effectiveness(
    scope_artifact: dict,
    suspicious_targets: list[dict],
) -> dict | None:
    """Summarize observed mitigation coverage from edge-action evidence."""
    edge_rows = list(scope_artifact.get("edge_action_mix") or [])
    if not edge_rows:
        return None

    def _row_share(*names: str) -> float:
        wanted = {name.lower() for name in names}
        total = 0.0
        for row in edge_rows:
            value = str(row.get("value") or "No Action").strip().lower()
            if value in wanted or (not value and "no action" in wanted):
                total += float(row.get("share_pct") or 0)
        return round(total, 2)

    no_action_share = _row_share("no action", "", "allow", "passed")
    deny_share = _row_share("deny", "denied")
    monitor_tarpit_share = _row_share("monitor", "monitored", "tarpit")
    blocked_share = (scope_artifact.get("window_confirmation") or {}).get(
        "blocked_share_pct"
    )
    high_severity_count = sum(
        1
        for target in suspicious_targets
        if target.get("severity") in {"critical", "high"}
    )
    deny_rules = list(scope_artifact.get("deny_rule_mix") or [])
    top_deny_rule = deny_rules[0] if deny_rules else None
    if high_severity_count and no_action_share >= max(deny_share + monitor_tarpit_share, 50):
        interpretation = (
            "Coverage gap: No Action/pass-through dominated while high-severity "
            "indicators were present."
        )
        coverage_assessment = "Low relative to anomaly severity"
        tone = "gap"
    elif deny_share or monitor_tarpit_share or blocked_share:
        interpretation = (
            "Observed edge actions covered part of the window; this does not prove "
            "a control caused recovery."
        )
        coverage_assessment = "Partial observed coverage"
        tone = "partial"
    else:
        interpretation = "Edge-action evidence did not show measurable mitigation coverage."
        coverage_assessment = "Unknown observed coverage"
        tone = "unknown"
    return {
        "no_action_share_pct": no_action_share,
        "deny_share_pct": deny_share,
        "monitor_tarpit_share_pct": monitor_tarpit_share,
        "blocked_share_pct": blocked_share,
        "top_deny_rule": top_deny_rule,
        "high_severity_target_count": high_severity_count,
        "coverage_assessment": coverage_assessment,
        "interpretation": interpretation,
        "tone": tone,
    }
