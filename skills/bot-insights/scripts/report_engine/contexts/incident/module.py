"""Schema constants, analyst-note routing, ``assemble`` and ``prepare``."""

from __future__ import annotations

from ...humanize import cluster_display
from ...theme import editorial_palette
from datetime import datetime, timezone

from .actions import _recommended_actions_view
from .cohorts import _compute_actor_cohort_overlap
from .concentration import _concentration_chart_view
from .findings import _incident_findings
from .impact import _impact_view
from .iocs import (
    _ioc_json_text,
    _ioc_view,
)
from .risk import (
    _deterministic_summary,
    _risk_score,
    _severity_ladder,
)
from .targets import (
    SUSPICIOUS_TARGETS_DISPLAY_CAP,  # noqa: F401 - re-exported public symbol
    _attack_aggregation,
    _suspicious_targets_view,
)
from .views import (
    _actor_rankings_view,
    _cohort_mix_rows,
    _scope_rows,
    _status_mix_rows,
    _top_raw_paths_rows,
)
from .windows import (
    _scope_filters,
    _window_confirmation_view,
)

__all__ = [
    'SCHEMA',
    'REPORT_TYPE',
    'TEMPLATE',
    'PURPOSE',
    'NOTE_ID_TO_SLOT',
    'assemble',
    'prepare',
]


SCHEMA = "bot_incident_scope.v1"


REPORT_TYPE = "incident_report"


TEMPLATE = "reports/incident_report.html"


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


def assemble(artifacts: list[dict]) -> dict:
    """Reshape a ``bot_report_input.v1`` wrapper's artifacts list into the
    dict ``prepare()`` expects.

    The incident report requires all three artifacts. The actors artifact
    may carry ``raw_drilldown_available: false`` — that surfaces the
    limitation banner in the template instead of the actor tables, but
    is not an error. The action-targets artifact must be present but may
    carry an empty ``targets`` list (renders the explanatory banner).
    """
    scope = next(
        (a for a in artifacts if a.get("schema_version") == "bot_incident_scope.v1"),
        None,
    )
    if scope is None:
        raise ValueError(
            "incident_report wrapper missing bot_incident_scope.v1 artifact"
        )
    actors = next(
        (a for a in artifacts if a.get("schema_version") == "bot_incident_actors.v1"),
        None,
    )
    if actors is None:
        raise ValueError(
            "incident_report wrapper missing bot_incident_actors.v1 artifact"
        )
    action_targets = next(
        (
            a
            for a in artifacts
            if a.get("schema_version") == "bot_incident_action_targets.v1"
        ),
        None,
    )
    if action_targets is None:
        raise ValueError(
            "incident_report wrapper missing bot_incident_action_targets.v1 artifact"
        )
    return {
        "schema_version": SCHEMA,
        "scope": scope,
        "actors": actors,
        "action_targets": action_targets,
    }


def _humanize_edge_action_rows(rows: list[dict]) -> list[dict]:
    """Relabel empty action_applied values to "No Action" for display.

    Akamai writes ``action_applied`` as an empty string for requests
    that hit no WAF or bot-manager rule (the pass-through bulk). The
    column value is meaningful, but the editorial table reads as a
    blank cell unless we humanize it — relabel for display only so
    the underlying artifact stays raw.
    """
    for row in rows:
        if not row["value"]:
            row["value"] = "No Action"
    return rows


def _build_scope_view_rows(scope_art: dict, actors_art: dict) -> dict:
    """Project the scope-artifact dimension lists into table rows.

    The ``top_raw_paths`` projection comes from a phase-2 drilldown
    scoped to the suspicious-actor IP set (cluster-only — the parquet
    summary doesn't carry raw paths). Each row carries ``share_pct``
    as share-of-suspicious-actor-traffic (NOT share-of-window) and a
    ``distinct_actors`` count so the editorial table can highlight
    coordinated-many-actors-on-one-URL vs single-actor-scanning patterns.
    """
    return {
        "targeted_hosts_rows": _scope_rows(
            scope_art.get("top_targeted_hosts") or [], value_label="Host"
        ),
        "path_pattern_rows": _scope_rows(
            scope_art.get("top_targeted_path_patterns") or [],
            value_label="Path pattern",
        ),
        "top_raw_paths_rows": _top_raw_paths_rows(
            scope_art.get("top_raw_paths") or []
        ),
        "status_mix_rows": _status_mix_rows(scope_art.get("status_mix") or []),
        "country_mix_rows": _scope_rows(
            scope_art.get("country_mix") or [], value_label="Country"
        ),
        "cohort_mix_rows": _cohort_mix_rows(actors_art),
        "edge_action_mix_rows": _humanize_edge_action_rows(
            _scope_rows(
                scope_art.get("edge_action_mix") or [], value_label="Action"
            )
        ),
        "deny_rule_mix_rows": _scope_rows(
            scope_art.get("deny_rule_mix") or [], value_label="Deny rule"
        ),
    }


def _build_siem_view_rows(scope_art: dict, siem_available: bool) -> dict:
    """SIEM-side dimension rows; empty lists when no SIEM table is available."""
    if not siem_available:
        return {
            "siem_action_rows": [],
            "siem_policy_rows": [],
            "siem_bot_type_rows": [],
        }
    return {
        "siem_action_rows": _scope_rows(
            scope_art.get("siem_action_mix") or [], value_label="Action class"
        ),
        "siem_policy_rows": _scope_rows(
            scope_art.get("siem_policy_mix") or [], value_label="Policy"
        ),
        "siem_bot_type_rows": _scope_rows(
            scope_art.get("siem_bot_type_mix") or [], value_label="Bot type"
        ),
    }


def _build_editorial_extensions(
    scope_art: dict,
    actors_art: dict,
    action_targets_art: dict,
    scope_meta: dict,
    suspicious_targets: list[dict],
    deterministic_summary: dict,
) -> dict:
    """Editorial extensions (Phase 1 deterministic-only).

    Phase 2 will let analyst notes override `incident_findings` and
    `recommended_actions`; the deterministic generators here are the
    always-on fallback. The IOC export reads ``cohort_overlap`` and
    ``actors_art`` (for the actor_cooccurrence cells) so it can embed
    cohort_topology and project per-indicator seen_at / seen_with
    scope qualifiers.
    """
    spike_flags = list(
        (scope_art.get("window_confirmation") or {}).get("spike_flags") or []
    )
    cohort_overlap = _compute_actor_cohort_overlap(suspicious_targets, actors_art)
    iocs = _ioc_view(
        action_targets_art, scope_meta,
        actors_artifact=actors_art, cohort_overlap=cohort_overlap,
    )
    return {
        "risk_score": _risk_score(deterministic_summary, suspicious_targets),
        "severity_ladder": _severity_ladder(deterministic_summary["level"]),
        "attack_aggregation": _attack_aggregation(suspicious_targets),
        "iocs": iocs,
        "iocs_json_text": _ioc_json_text(iocs),
        "incident_findings": _incident_findings(
            suspicious_targets, deterministic_summary, spike_flags,
            cohort_overlap=cohort_overlap,
        ),
        "recommended_actions": _recommended_actions_view(
            suspicious_targets, scope_art.get("dashboard_url") or "", None
        ),
    }


def _build_scope_block(scope_meta: dict, cluster: str) -> dict:
    """The masthead "scope" sub-dict — cluster, host, asn, path filter, etc."""
    host = scope_meta.get("host")
    asn = scope_meta.get("asn")
    path_pattern = scope_meta.get("path_pattern")
    granularity = scope_meta.get("granularity") or ""
    database = scope_meta.get("database") or ""
    return {
        "cluster": cluster,
        "database": database,
        "table_used": (
            f"{database or 'akamai'}.bi_summary_{granularity}" if granularity else ""
        ),
        "request_host": host or "",
        "asn": asn,
        "path_pattern": path_pattern,
        "granularity": granularity,
        "siem_available": bool(scope_meta.get("siem_available")),
        "scope_filters": _scope_filters(host, asn, path_pattern),
    }


def _build_windows_block(scope_meta: dict) -> dict:
    return {
        "current": {
            "start": scope_meta.get("start") or "",
            "end": scope_meta.get("end") or "",
        },
        "baseline": {
            "start": scope_meta.get("baseline_start") or "",
            "end": scope_meta.get("baseline_end") or "",
        },
    }


def _build_method_block(actors_art: dict, actor_rankings: list[dict]) -> dict:
    return {
        "schema_version": SCHEMA,
        "comparison_type": "previous_window",
        "producer_limit": actors_art.get("top_n"),
        "result_row_count": sum(len(r.get("rows") or []) for r in actor_rankings),
        "result_truncated": False,
        "interpretation_constraints": [
            "mechanical_features_only",
            "no_causal_claim",
            "no_malicious_intent_claim",
        ],
    }


def _collect_limitations(*artifacts: dict) -> list[str]:
    """Concatenate ``limitations`` lists from each artifact, in order."""
    out: list[str] = []
    for art in artifacts:
        out.extend(art.get("limitations") or [])
    return out


def _build_orientation_block() -> dict:
    return {
        "measures": PURPOSE["measures"],
        "score_legend": PURPOSE["score_legend"],
        "cant_say": PURPOSE["cant_say"],
        "bands": PURPOSE["bands"],
    }


def _build_suspicious_targets_visible(suspicious_targets: list[dict]) -> dict:
    """Pre-slice the suspicious-targets list for the masthead's visible/hidden split."""
    from config import active_thresholds

    cap = active_thresholds().display.suspicious_targets_cap
    return {
        "suspicious_targets": suspicious_targets,
        "suspicious_targets_visible": suspicious_targets[:cap],
        "suspicious_targets_hidden_count": max(0, len(suspicious_targets) - cap),
    }


def _build_headline(scope_meta: dict) -> str:
    """H1 is scope-only ("Expedia", "www.example.com", etc.). "Incident
    report" is already in the kicker row above the headline, so
    prefixing the H1 with the same words is dead repetition. The
    window the report covers is rendered prominently in the
    masthead window block on the right (see incident_report.html).
    """
    cluster = scope_meta.get("cluster") or ""
    cluster_label = cluster_display(cluster) if cluster else ""
    host = scope_meta.get("host")
    return host or cluster_label or "fleet"


def prepare(artifact: dict) -> dict:
    scope_art = artifact["scope"]
    actors_art = artifact["actors"]
    action_targets_art = artifact.get("action_targets") or {}
    scope_meta = scope_art.get("scope") or {}
    cluster = scope_meta.get("cluster") or ""

    raw_drilldown_available = bool(actors_art.get("raw_drilldown_available"))
    actor_rankings = (
        _actor_rankings_view(actors_art) if raw_drilldown_available else []
    )

    suspicious_targets = _suspicious_targets_view(
        action_targets_art, actors_artifact=actors_art
    )
    deterministic_summary = _deterministic_summary(
        scope_art, actors_art, action_targets_art, suspicious_targets
    )

    return {
        "title": "Incident Report",
        "kicker": PURPOSE["kicker"],
        "headline": _build_headline(scope_meta),
        "dek": "Window-scoped incident confirmation with actor-level drilldown.",
        "purpose": None,
        "orientation": _build_orientation_block(),
        "scope": _build_scope_block(scope_meta, cluster),
        "windows": _build_windows_block(scope_meta),
        "window_confirmation": _window_confirmation_view(
            scope_art.get("window_confirmation") or {}
        ),
        **_build_scope_view_rows(scope_art, actors_art),
        **_build_siem_view_rows(
            scope_art, bool(scope_meta.get("siem_available"))
        ),
        "actor_rankings": actor_rankings,
        "raw_drilldown_available": raw_drilldown_available,
        "raw_table": actors_art.get("raw_table") or "",
        "impact": _impact_view(scope_art),
        **_build_suspicious_targets_visible(suspicious_targets),
        "concentration_chart": _concentration_chart_view(suspicious_targets),
        "deterministic_summary": deterministic_summary,
        **_build_editorial_extensions(
            scope_art, actors_art, action_targets_art, scope_meta,
            suspicious_targets, deterministic_summary,
        ),
        "editorial": editorial_palette(),
        "limitations": _collect_limitations(
            scope_art, actors_art, action_targets_art
        ),
        "dashboard_url": scope_art.get("dashboard_url") or "",
        "method": _build_method_block(actors_art, actor_rankings),
        "confidence": {"reasons": []},
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    }
