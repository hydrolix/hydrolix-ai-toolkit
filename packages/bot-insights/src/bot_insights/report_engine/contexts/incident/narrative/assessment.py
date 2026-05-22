"""Assessment helpers for incident narrative context."""

from __future__ import annotations

from ..formatters import _format_pct
from ..labels import REASON_FLAG_LABELS, SPIKE_FLAG_LABELS
from .constants import _HUMAN_COHORT_VALUES, _STRONG_SEVERITIES


def _target_flag_labels(target: dict) -> list[str]:
    labels = list(target.get("reason_flag_labels") or [])
    if labels:
        return labels
    return [
        REASON_FLAG_LABELS.get(flag, str(flag).replace("_", " "))
        for flag in target.get("reason_flags") or []
    ]


def _is_human_cohort(value: str) -> bool:
    return str(value or "").strip().lower() in _HUMAN_COHORT_VALUES


def _is_behavioral_anomaly(target: dict) -> bool:
    flags = {str(f) for f in target.get("reason_flags") or []}
    labels = {str(l).lower() for l in _target_flag_labels(target)}
    return "anomaly" in flags or "behavioral anomaly" in labels


def _strong_human_target(target: dict) -> bool:
    return (
        target.get("target_type") == "cohort"
        and _is_human_cohort(target.get("target_value") or "")
        and target.get("severity") in _STRONG_SEVERITIES
        and _is_behavioral_anomaly(target)
        and float(target.get("share_pct") or 0) >= 20.0
    )


def _strong_human_mix_row(row: dict) -> bool:
    return (
        _is_human_cohort(row.get("value") or "")
        and float(row.get("share_pct") or 0) >= 20.0
        and (
            float(row.get("req_429_share_pct") or 0) >= 10.0
            or float(row.get("req_5xx_share_pct") or 0) >= 5.0
        )
    )


def _primary_concern_view(
    suspicious_targets: list[dict],
    cohort_mix_rows: list[dict],
) -> dict | None:
    """Promote strong Human/Browser-classified anomaly evidence.

    The copy deliberately frames this as classification-evasive behavior
    or a Human-classified anomaly, not proven evasion success.
    """
    target = next((t for t in suspicious_targets if _strong_human_target(t)), None)
    if target:
        labels = ", ".join(_target_flag_labels(target)) or "behavioral anomaly"
        return {
            "title": "Primary concern: anomalous Human-classified traffic",
            "summary": (
                f"{target.get('target_value')} traffic was classified as human-like "
                f"but flagged at {target.get('severity_label', 'High').lower()} "
                "severity by behavioral evidence."
            ),
            "evidence": [
                f"{target.get('share_pct_display') or _format_pct(target.get('share_pct'))} of window requests",
                f"{target.get('req_429_share_display') or _format_pct(target.get('req_429_share_pct'))} 429 rate within target traffic",
                f"Reason flags: {labels}",
            ],
            "boundary": (
                "This supports classification-evasive behavior or a Human-classified "
                "anomaly. It does not prove evasion success or intent."
            ),
        }

    row = next((r for r in cohort_mix_rows if _strong_human_mix_row(r)), None)
    if row:
        return {
            "title": "Human-classified traffic carried anomalous texture",
            "summary": (
                f"{row.get('value')} traffic represented a high-share cohort with "
                "elevated response-error texture in the incident window."
            ),
            "evidence": [
                f"{row.get('share_pct_display') or _format_pct(row.get('share_pct'))} of cohort-classified requests",
                f"{row.get('req_429_share_display') or _format_pct(row.get('req_429_share_pct'))} 429 rate within cohort traffic",
                f"{row.get('req_5xx_share_display') or _format_pct(row.get('req_5xx_share_pct'))} 5xx share",
            ],
            "boundary": (
                "This is a cohort-level anomaly, not attribution and not proof "
                "that every request in the cohort was automated."
            ),
        }
    return None


def _top_path(path_pattern_rows: list[dict]) -> dict | None:
    return next((r for r in path_pattern_rows if r.get("value")), None)


def _edge_pass_row(edge_action_mix_rows: list[dict]) -> dict | None:
    for row in edge_action_mix_rows:
        value = str(row.get("value") or "").strip().lower()
        if value in {"allow", "passed", "no action", ""}:
            return row
    return None


def _analyst_assessment_fallback(
    deterministic_summary: dict,
    incident_findings: list[dict],
    cohort_mix_rows: list[dict],
    path_pattern_rows: list[dict],
    edge_action_mix_rows: list[dict],
    spike_flags: list[str],
) -> dict:
    headline = deterministic_summary.get("headline") or (
        "Observed traffic patterns crossed the incident-report heuristic ladder."
    )
    conclusion = headline[:1].upper() + headline[1:] if headline else headline
    pillars: list[str] = []
    for finding in incident_findings[:2]:
        lead = finding.get("lead")
        if lead:
            pillars.append(lead)

    human_row = next((r for r in cohort_mix_rows if _is_human_cohort(r.get("value"))), None)
    if human_row:
        pillars.append(
            f"{human_row.get('value')} cohort represented "
            f"{human_row.get('share_pct_display')} of classified traffic."
        )
    path = _top_path(path_pattern_rows)
    if path:
        pillars.append(
            f"Top path pattern `{path.get('value')}` carried "
            f"{path.get('share_pct_display')} of scoped requests."
        )
    edge_pass = _edge_pass_row(edge_action_mix_rows)
    if edge_pass and float(edge_pass.get("share_pct") or 0) >= 25:
        pillars.append(
            f"Edge action mix showed {edge_pass.get('share_pct_display')} "
            f"{edge_pass.get('value') or 'No Action'} traffic."
        )
    if not pillars and spike_flags:
        labelled = ", ".join(
            SPIKE_FLAG_LABELS.get(flag, flag.replace("_", " "))
            for flag in spike_flags[:3]
        )
        pillars.append(f"Spike flags observed: {labelled}.")

    return {
        "source": "deterministic",
        "conclusion": conclusion,
        "pillars": pillars[:4],
        "boundary": (
            f"Confidence is {deterministic_summary.get('confidence_label', 'evidence-bound')}. "
            "Assessment is bounded to observed request, response, cohort, and edge-action evidence."
        ),
    }


def _stood_out_bullets(
    suspicious_targets: list[dict],
    cohort_mix_rows: list[dict],
    path_pattern_rows: list[dict],
    edge_action_mix_rows: list[dict],
    top_raw_paths_rows: list[dict],
    spike_flags: list[str],
    cohort_overlap: dict | None,
) -> list[str]:
    bullets: list[str] = []
    concern = _primary_concern_view(suspicious_targets, cohort_mix_rows)
    if concern:
        bullets.append(
            "Observed Human-classified anomaly evidence was strong enough to lead "
            "the concern before IP-heavy details."
        )

    path = _top_path(path_pattern_rows)
    if path and float(path.get("share_pct") or 0) >= 20:
        bullets.append(
            f"Observed path concentration: `{path.get('value')}` carried "
            f"{path.get('share_pct_display')} of scoped requests."
        )

    status_flags = [
        SPIKE_FLAG_LABELS.get(flag, flag.replace("_", " "))
        for flag in spike_flags
        if flag in {"rate_429_up", "rate_5xx_up"}
    ]
    if status_flags:
        bullets.append(
            "5xx and 429 behavior diverged from baseline: "
            f"{', '.join(status_flags)} fired against the comparison window."
        )

    edge_pass = _edge_pass_row(edge_action_mix_rows)
    if edge_pass and float(edge_pass.get("share_pct") or 0) >= 25:
        bullets.append(
            f"Edge coverage looked thin for the window: "
            f"{edge_pass.get('share_pct_display')} was {edge_pass.get('value') or 'No Action'}."
        )

    new_or_high = [
        t for t in suspicious_targets
        if any(
            flag in {"new_in_window", "high_volume_new_actor", "high_volume_share"}
            for flag in t.get("reason_flags") or []
        )
    ]
    if new_or_high:
        top = new_or_high[0]
        bullets.append(
            f"New or high-volume actor evidence appeared on "
            f"{top.get('target_type_label')} `{top.get('target_value')}`."
        )

    raw = next((r for r in top_raw_paths_rows if r.get("distinct_actors")), None)
    if raw and float(raw.get("distinct_actors") or 0) >= 2:
        bullets.append(
            f"Shared raw-path targeting was observed: `{raw.get('value')}` had "
            f"{raw.get('distinct_actors_display')} actors."
        )

    if cohort_overlap and cohort_overlap.get("is_disjoint"):
        bullets.append(
            "Flagged IP and user-agent cohorts were disjoint, suggesting separate "
            "observable populations rather than one actor list seen two ways."
        )

    return bullets[:5]
