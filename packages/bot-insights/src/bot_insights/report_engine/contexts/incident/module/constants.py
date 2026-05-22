"""Incident report schema constants and analyst-note routing."""

from __future__ import annotations

SCHEMA = "bot_incident_scope.v1"


REPORT_TYPE = "incident_report"


TEMPLATE = "reports/incident_report.html"

PRINT_TEMPLATE = "reports/incident_report_print.html"


PURPOSE = {
    "kicker": "Bot Insights — incident report",
    "measures": (
        "Window-scoped incident shape. Confirms volume, 429%, 5xx%, "
        "bot-share and SIEM-blocked share against a trailing equal-length "
        "baseline, then ranks actors against the cluster's raw access log."
    ),
    "score_legend": (
        "Risk score scales with attack severity; higher is worse. "
        "Share percentages and deltas are computed mechanically against "
        "the trailing window — severity is qualitative."
    ),
    "cant_say": (
        "This report describes traffic patterns, not intent. It is built "
        "from log rules, so it does not claim any actor is malicious or "
        "attribute a root cause."
    ),
    # Risk-score bands for the orientation legend. Incident risk is
    # higher-is-worse (inverted from scorecard reports), so the legend
    # reads observe → critical across 0–100.
    "bands": [
        {"label": "observe · 0–40",    "tone": "observe"},
        {"label": "monitor · 40–70",   "tone": "monitor"},
        {"label": "escalate · 70–90",  "tone": "escalate"},
        {"label": "critical · 90–100", "tone": "critical"},
    ],
}


NOTE_ID_TO_SLOT = {
    "llm-interpretation": "executive_summary",
    "llm-operational": "operational_interpretation",
    "llm-next-steps": "next_steps",
    "llm-executive-impact": "executive_impact",
    "llm-current-status": "current_status",
    "llm-incident-context": "incident_context",
}
