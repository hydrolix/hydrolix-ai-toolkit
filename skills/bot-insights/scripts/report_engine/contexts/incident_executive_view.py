"""Context preparer for the Incident Executive View.

A 1–2 page exec/director-audience render of the same wrapper artifacts
the analyst ``incident_report`` consumes. Mechanical artifacts are
reused as-is; the editorial slot mapping is intentionally narrower so
analysts can author one note set that lights up both views.

Seven sections, in order:

  1. Incident status — Active / Contained / Monitoring / Closed
     (permissive; unknown values render verbatim with a neutral tone).
  2. What happened — analyst paragraph.
  3. Measured impact — mechanical KPI tiles + top-affected sentence.
  4. Business / customer impact — analyst slot; never inferred from logs.
  5. Response taken / recommended — 3–5 bullets, owner + urgency.
  6. Decision needed — analyst slot.
  7. Confidence and caveat — mechanical default, optional analyst override.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

# Make ``config`` (under scripts/) importable when this module is loaded
# from report_engine.contexts.
_SCRIPTS_DIR = Path(__file__).resolve().parents[3]
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

from config import DEFAULT_THRESHOLDS, active_thresholds  # noqa: E402

from . import incident_report as _ir

SCHEMA = "bot_incident_scope.v1"
REPORT_TYPE = "incident_executive_view"
TEMPLATE = "reports/incident_executive_view.html"

# Status enum is permissive. Known values map to a verdict-pill tone;
# unknown values fall back to ``monitor`` and render verbatim so a
# typo or org-specific synonym still ships.
INCIDENT_STATUS_TONE = {
    "Active":     "critical",
    "Contained":  "monitor",
    "Monitoring": "observe",
    "Closed":     "observe-mute",
}
DEFAULT_STATUS = "Active"
CONFIDENCE_CAVEAT_DEFAULT = (
    "High confidence in traffic anomaly and infrastructure concentration; "
    "no root-cause or intent attribution."
)

# Cap actions surfaced to the exec audience. The analyst report uses
# the same upstream generator; this view truncates so a busy reader
# can scan the list in one breath. The constant surfaces the default
# value for legacy importers; ``prepare()`` reads
# ``active_thresholds().display.exec_actions_cap`` at call time so a
# runtime ``--config`` override applies without re-importing.
EXEC_ACTIONS_CAP = DEFAULT_THRESHOLDS.display.exec_actions_cap

# Cap on KPI tiles surfaced in the Measured-impact section. The
# upstream ``_impact_view`` builds 6 tiles for the analyst view; the
# exec view drops the "Top path share" tile (the top-affected sentence
# under the strip already names the path) so the visual lands at 5.
EXEC_IMPACT_TILES_CAP = DEFAULT_THRESHOLDS.display.exec_impact_tiles_cap

# Wrapper analyst-note routing. ``executive_impact`` and
# ``current_status`` slot keys are intentionally shared with
# ``incident_report.NOTE_ID_TO_SLOT`` so analyst tooling can author
# once and have the notes surface in both views.
NOTE_ID_TO_SLOT = {
    "llm-incident-status-level": "incident_status_level",
    "llm-what-happened":         "what_happened",
    "llm-executive-impact":      "executive_impact",
    "llm-response-taken":        "response_taken",
    "llm-decision-needed":       "decision_needed",
    "llm-current-status":        "current_status",
}


def assemble(artifacts: list[dict]) -> dict:
    """Delegate to ``incident_report.assemble`` — the exec view consumes
    the identical mechanical wrapper bundle."""
    return _ir.assemble(artifacts)


def _decision_needed_default(
    deterministic_summary: dict,
    suspicious_targets: list[dict],
    recommended_actions: list[dict],
    raw_drilldown_available: bool,
) -> str:
    """Mechanical fallback sentence for the Decision needed slot.

    Dispatches on ``deterministic_summary.level`` to surface a single
    plain-text sentence the template can render when no analyst override
    is present. Output never contains markdown — the template inserts it
    inside a plain ``<p>``.
    """
    level = (deterministic_summary or {}).get("level") or "low"
    top_target = suspicious_targets[0] if suspicious_targets else None
    top_action = recommended_actions[0] if recommended_actions else None

    if level == "critical" and raw_drilldown_available and top_target and top_action:
        return (
            f"Approve {top_action.get('urgency') or 'the recommended action'} on "
            f"{top_target.get('target_type_label') or 'top target'}: "
            f"{top_target.get('target_value') or ''}. "
            "Confirm the named indicators before the next change-control window."
        )
    if level == "critical":
        return (
            "Approve raw-log access so the suspicious-actor list resolves to "
            "named indicators before any policy change."
        )
    if level in {"elevated", "high"}:
        top_flag = None
        if top_target:
            labels = top_target.get("reason_flag_labels") or top_target.get("reason_flags") or []
            top_flag = labels[0] if labels else None
        if top_flag:
            return (
                f"Decide whether the observed {top_flag} warrants a policy "
                "change or a longer monitoring window before escalating."
            )
        return (
            "Decide whether the observed signal warrants a policy change "
            "or a longer monitoring window before escalating."
        )
    if level == "medium":
        return "No decision required this window; confirm the next monitoring cadence."
    return "No new decision flagged this window."


def prepare(artifact: dict) -> dict:
    scope_art = artifact["scope"]
    actors_art = artifact["actors"]
    action_targets_art = artifact.get("action_targets") or {}

    scope_meta = scope_art.get("scope") or {}
    cluster = scope_meta.get("cluster") or ""
    host = scope_meta.get("host")
    granularity = scope_meta.get("granularity") or ""

    cluster_label = _ir.cluster_display(cluster) if cluster else ""
    headline = host or cluster_label or "fleet"

    impact = _ir._impact_view(scope_art)
    suspicious_targets = _ir._suspicious_targets_view(
        action_targets_art, actors_artifact=actors_art
    )
    deterministic_summary = _ir._deterministic_summary(
        scope_art, actors_art, action_targets_art, suspicious_targets
    )
    full_actions = _ir._recommended_actions_view(
        suspicious_targets, scope_art.get("dashboard_url") or "", None
    )
    display = active_thresholds().display
    recommended_actions = full_actions[:display.exec_actions_cap]
    impact_tiles = list(impact.get("tiles") or [])[:display.exec_impact_tiles_cap]
    top_affected_hosts = impact.get("top_affected_hosts")
    top_path_pattern = impact.get("top_path_pattern")

    windows = {
        "current": {
            "start": scope_meta.get("start") or "",
            "end": scope_meta.get("end") or "",
        },
        "baseline": {
            "start": scope_meta.get("baseline_start") or "",
            "end": scope_meta.get("baseline_end") or "",
        },
    }

    limitations = (
        list(scope_art.get("limitations") or [])
        + list(actors_art.get("limitations") or [])
        + list(action_targets_art.get("limitations") or [])
    )

    return {
        "title": "Incident Executive View",
        "kicker": "Bot Insights — incident executive view",
        "headline": headline,
        "dek": "Director-audience read of the incident wrapper — decision first, evidence underneath.",
        "purpose": None,
        "scope": {
            "cluster": cluster,
            "database": scope_meta.get("database") or "",
            "table_used": (
                f"{scope_meta.get('database') or 'akamai'}.bi_summary_{granularity}"
                if granularity
                else ""
            ),
            "request_host": host or "",
            "asn": scope_meta.get("asn"),
            "path_pattern": scope_meta.get("path_pattern"),
            "granularity": granularity,
            "siem_available": bool(scope_meta.get("siem_available")),
            "scope_filters": _ir._scope_filters(
                host, scope_meta.get("asn"), scope_meta.get("path_pattern")
            ),
        },
        "windows": windows,
        "impact_tiles": impact_tiles,
        "top_affected_hosts": top_affected_hosts,
        "top_path_pattern": top_path_pattern,
        "recommended_actions": recommended_actions,
        "deterministic_summary": deterministic_summary,
        "incident_status_tone": INCIDENT_STATUS_TONE,
        "incident_status_default": DEFAULT_STATUS,
        "confidence_caveat_default": CONFIDENCE_CAVEAT_DEFAULT,
        "decision_needed_default": _decision_needed_default(
            deterministic_summary,
            suspicious_targets,
            recommended_actions,
            bool(actors_art.get("raw_drilldown_available")),
        ),
        "dashboard_url": scope_art.get("dashboard_url") or "",
        "limitations": limitations,
        "method": {
            "schema_version": SCHEMA,
            "comparison_type": "previous_window",
            "producer_limit": actors_art.get("top_n"),
            # Mirror the analyst view's count so the method footer is
            # consistent across the two renders of the same wrapper.
            "result_row_count": sum(
                len(r.get("rows") or [])
                for r in (actors_art.get("actor_rankings") or [])
            ),
            "result_truncated": False,
            "interpretation_constraints": [
                "mechanical_features_only",
                "no_causal_claim",
                "no_malicious_intent_claim",
            ],
        },
        "confidence": {"reasons": []},
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    }
