"""Top-level incident report context orchestration."""

from __future__ import annotations

from datetime import datetime, timezone

from ....theme import editorial_palette
from ..as_reputation import build_as_reputation_context
from ..browser_versions import build_browser_version_context
from ..claim_gates import build_claim_profile
from ..concentration import _concentration_chart_view
from ..explainers import assessment_explainers
from ..impact import _impact_view
from ..print_adapter import build_print_report
from ..risk import _deterministic_summary
from ..targets import _suspicious_targets_view
from ..views import _actor_rankings_view
from ..windows import _window_confirmation_view

from .availability import _analysis_availability_context, _collect_limitations
from .baseline import _build_baseline_context
from .constants import PURPOSE
from .editorial import _build_editorial_extensions
from .scope import (
    _build_headline,
    _build_orientation_block,
    _build_scope_block,
    _build_scope_view_rows,
    _build_siem_view_rows,
    _build_suspicious_targets_visible,
    _build_windows_block,
)
from .soc_evidence import _build_method_block, _build_soc_evidence_block


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
    claim_profile = build_claim_profile(
        scope_art, actors_art, action_targets_art, suspicious_targets
    )
    explainers = assessment_explainers(
        actors_art, action_targets_art, suspicious_targets
    )
    as_reputation_context = build_as_reputation_context(
        actors_art, suspicious_targets
    )
    browser_version_context = build_browser_version_context(
        actors_art, suspicious_targets, scope_meta
    )
    scope_rows = _build_scope_view_rows(scope_art, actors_art)
    soc_evidence = _build_soc_evidence_block(
        actors_art, action_targets_art, suspicious_targets
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
        "baseline_context": _build_baseline_context(scope_art, scope_meta),
        **scope_rows,
        **_build_siem_view_rows(
            scope_art, bool(scope_meta.get("siem_available"))
        ),
        "actor_rankings": actor_rankings,
        "soc_evidence": soc_evidence,
        "raw_actor_rows": soc_evidence["raw_actor_rows"],
        "action_target_rows": soc_evidence["action_target_rows"],
        "raw_drilldown_available": raw_drilldown_available,
        "raw_table": actors_art.get("raw_table") or "",
        "impact": _impact_view(scope_art),
        **_build_suspicious_targets_visible(suspicious_targets),
        "concentration_chart": _concentration_chart_view(suspicious_targets),
        "deterministic_summary": deterministic_summary,
        "claim_profile": claim_profile,
        "assessment_explainers": explainers,
        "as_reputation_context": as_reputation_context,
        "browser_version_context": browser_version_context,
        "analysis_availability": _analysis_availability_context(
            scope_art, actors_art, action_targets_art, suspicious_targets, scope_rows
        ),
        **_build_editorial_extensions(
            scope_art, actors_art, action_targets_art, scope_meta,
            suspicious_targets, deterministic_summary, scope_rows,
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


def post_prepare(ctx: dict) -> None:
    if ctx.get("profile") != "print":
        return
    print_report = build_print_report(ctx)
    ctx["print_report"] = print_report
    ctx.update(print_report)
