"""Deterministic narrative helpers for the incident report."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from .formatters import _format_count, _format_pct
from .labels import REASON_FLAG_LABELS, SPIKE_FLAG_LABELS

__all__ = [
    '_analyst_assessment_fallback',
    '_primary_concern_view',
    '_stood_out_bullets',
    '_observed_inferred_taxonomy',
    '_coordination_signals',
    '_temporal_progression_view',
    '_behavior_clusters_view',
    '_entity_clusters_view',
    '_mitigation_coverage_view',
]


_HUMAN_COHORT_VALUES = {"human", "browser"}
_STRONG_SEVERITIES = {"critical", "high"}


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


def _observed_inferred_taxonomy() -> dict:
    return {
        "observed": [
            "request concentration",
            "path concentration",
            "cohort distribution",
            "5xx/429 rates",
            "edge action mix",
        ],
        "inferred": [
            "coordinated infrastructure",
            "evasive automation",
            "application-layer flooding",
        ],
        "boundary": (
            "Inferred labels are analytic interpretations of observed log patterns; "
            "they are not attribution, root cause, or intent claims."
        ),
    }


def _coordination_signals(
    suspicious_targets: list[dict],
    top_raw_paths_rows: list[dict],
    edge_action_mix_rows: list[dict],
    cohort_overlap: dict | None,
    target_evidence: dict | None = None,
    behavior_clusters: list[dict] | None = None,
) -> list[dict]:
    asn_targets = [
        t for t in suspicious_targets
        if "single_asn_cluster" in (t.get("reason_flags") or [])
        or (t.get("supporting") or {}).get("asn_cluster_id")
    ]
    path_targets = [
        t for t in suspicious_targets
        if "single_path_concentration" in (t.get("reason_flags") or [])
    ]
    raw_shared = [
        r for r in top_raw_paths_rows
        if float(r.get("distinct_actors") or 0) >= 2
    ]
    edge_denied = [
        r for r in edge_action_mix_rows
        if str(r.get("value") or "").lower() in {"deny", "denied"}
        and float(r.get("share_pct") or 0) >= 10
    ]
    has_ip_ua_overlap = cohort_overlap is not None
    disjoint = bool(cohort_overlap and cohort_overlap.get("is_disjoint"))
    target_evidence = target_evidence or {}
    behavior_clusters = behavior_clusters or []
    has_target_evidence = bool(target_evidence)
    overlapping_peak = any(
        c.get("basis") == "overlapping_peak_bucket"
        for c in behavior_clusters
    )
    shared_ua_or_cohort = any(
        c.get("basis") in {"shared_user_agent", "shared_cohort"}
        for c in behavior_clusters
    )
    shared_edge_action = any(
        c.get("basis") == "shared_edge_action"
        for c in behavior_clusters
    )

    return [
        {
            "signal": "ASN concentration",
            "status": "yes" if asn_targets else "not observed",
            "detail": (
                f"{len(asn_targets)} flagged row(s) carried single-ASN evidence."
                if asn_targets else "No single-ASN flag was present in flagged rows."
            ),
        },
        {
            "signal": "Shared path targeting",
            "status": "yes" if raw_shared or path_targets else "not observed",
            "detail": (
                f"{len(raw_shared or path_targets)} row(s) showed shared or concentrated path evidence."
                if raw_shared or path_targets else "No shared-path or single-path signal was present."
            ),
        },
        {
            "signal": "Overlapping active window",
            "status": "yes" if overlapping_peak else ("partial" if has_target_evidence else "not available"),
            "detail": (
                "Two or more targets shared a peak bucket in enriched target evidence."
                if overlapping_peak
                else "Per-target windows were available, but no shared peak bucket was observed."
                if has_target_evidence
                else "Per-target bucket evidence was not present in this artifact."
            ),
        },
        {
            "signal": "Shared UA/cohort",
            "status": "yes" if shared_ua_or_cohort else ("not observed" if has_target_evidence else "not available"),
            "detail": (
                "Behavior clusters included a shared user-agent or cohort facet."
                if shared_ua_or_cohort
                else "No shared user-agent or cohort cluster was observed."
                if has_target_evidence
                else "Per-target dominant UA/cohort evidence was not present."
            ),
        },
        {
            "signal": "Shared edge action profile",
            "status": "yes" if shared_edge_action else ("partial" if edge_action_mix_rows else "not available"),
            "detail": (
                "Behavior clusters included a shared dominant edge action."
                if shared_edge_action
                else f"{edge_denied[0].get('share_pct_display')} denied share was visible in action mix."
                if edge_denied
                else "Action mix was present but did not show a shared per-target profile."
                if edge_action_mix_rows
                else "No edge-action evidence was available."
            ),
        },
        {
            "signal": "IP/UA co-occurrence",
            "status": "yes" if has_ip_ua_overlap and not disjoint else ("partial" if has_ip_ua_overlap else "not available"),
            "detail": (
                "Co-occurrence was available and cohorts overlapped."
                if has_ip_ua_overlap and not disjoint
                else "Co-occurrence was available, but flagged IP and UA cohorts were disjoint."
                if has_ip_ua_overlap
                else "No IP/UA co-occurrence artifact was available."
            ),
        },
        {
            "signal": "Disjoint cohort overlap",
            "status": "yes" if disjoint else ("not observed" if has_ip_ua_overlap else "partial"),
            "detail": (
                "Flagged IP and UA overlap stayed below the configured floor."
                if disjoint
                else "Overlap was computed and did not meet the disjoint threshold."
                if has_ip_ua_overlap
                else "Overlap could not be computed from available fields."
            ),
        },
    ]


def _largest_series_delta(points: list[dict]) -> str | None:
    totals: dict[str, int] = {}
    for point in points:
        value = str(point.get("value") or "")
        if value:
            totals[value] = totals.get(value, 0) + int(float(point.get("requests") or 0))
    if len(totals) < 2:
        return None
    top = sorted(totals.items(), key=lambda kv: -kv[1])[:2]
    return f"{top[0][0]} led the mix ahead of {top[1][0]}."


def _parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def _format_ts(value: datetime) -> str:
    normalized = value.astimezone(timezone.utc)
    return normalized.strftime("%Y-%m-%d %H:%M UTC")


def _granularity_delta(granularity: str | None) -> timedelta | None:
    text = str(granularity or "").lower()
    if text == "minute":
        return timedelta(minutes=1)
    if text == "hour":
        return timedelta(hours=1)
    if text == "day":
        return timedelta(days=1)
    return None


def _duration_phrase(bucket_count: int, step: timedelta | None) -> str | None:
    if bucket_count <= 0 or step is None:
        return None
    seconds = int(bucket_count * step.total_seconds())
    if seconds < 3600:
        minutes = max(1, round(seconds / 60))
        return f"{minutes} minute{'s' if minutes != 1 else ''}"
    if seconds < 86400:
        hours = round(seconds / 3600, 1)
        hours_text = str(int(hours)) if hours.is_integer() else str(hours)
        return f"{hours_text} hour{'s' if hours != 1 else ''}"
    days = round(seconds / 86400, 1)
    days_text = str(int(days)) if days.is_integer() else str(days)
    return f"{days_text} day{'s' if days != 1 else ''}"


def _bucket_time(
    start: datetime | None,
    step: timedelta | None,
    index: int,
) -> datetime | None:
    if start is None or step is None:
        return None
    return start + (step * index)


def _temporal_progression_view(scope_art: dict) -> dict:
    volume = scope_art.get("volume_timeseries") or {}
    series = (volume.get("series") or {}).get("requests_per_minute") or {}
    current = [int(float(v or 0)) for v in (series.get("current") or [])]
    evidence_ts = scope_art.get("evidence_timeseries") or {}
    if not current and not any(evidence_ts.values()):
        return {
            "available": False,
            "summary": "Temporal progression is not available in this artifact.",
            "bullets": [],
        }

    bullets: list[str] = []
    if current:
        bullets.extend(_volume_progression_bullets(current, volume, scope_art))

    for key, label in (
        ("cohorts", "Cohort mix"),
        ("paths", "Path mix"),
        ("edge_actions", "Edge action mix"),
    ):
        block = evidence_ts.get(key) or {}
        delta = _largest_series_delta(block.get("points") or [])
        if delta:
            bullets.append(f"{label}: {delta}")

    return {
        "available": True,
        "summary": "Temporal progression is derived from bucketed producer evidence.",
        "bullets": bullets[:6],
    }


def _volume_progression_bullets(
    current: list[int],
    volume: dict,
    scope_art: dict,
) -> list[str]:
    scope = scope_art.get("scope") or {}
    start = _parse_ts(volume.get("start") or scope.get("start"))
    end = _parse_ts(volume.get("end") or scope.get("end"))
    step = _granularity_delta(volume.get("granularity") or scope.get("granularity"))
    peak_value = max(current)
    peak_index = current.index(peak_value)
    first_nonzero = next((i for i, v in enumerate(current) if v > 0), 0)
    last_nonzero = len(current) - 1 - next(
        (i for i, v in enumerate(reversed(current)) if v > 0),
        0,
    )
    peak_time = _bucket_time(start, step, peak_index)
    bullets = _ramp_and_peak_bullets(
        first_nonzero, peak_index, peak_value, peak_time, start, step, volume
    )
    bullets.extend(_sustain_and_taper_bullets(
        current, last_nonzero, peak_index, peak_value, peak_time, start, step, end
    ))
    return bullets


def _ramp_and_peak_bullets(
    first_nonzero: int,
    peak_index: int,
    peak_value: int,
    peak_time: datetime | None,
    start: datetime | None,
    step: timedelta | None,
    volume: dict,
) -> list[str]:
    bullets: list[str] = []
    first_time = _bucket_time(start, step, first_nonzero)
    if first_nonzero < peak_index:
        duration = _duration_phrase(peak_index - first_nonzero, step)
        if first_time and peak_time and duration:
            bullets.append(
                f"Ramp built for {duration}, from {_format_ts(first_time)} to the peak at {_format_ts(peak_time)}."
            )
        else:
            bullets.append("Ramp was visible before the peak bucket.")
    if peak_time:
        bullets.append(
            f"Peak arrived at {_format_ts(peak_time)} with {_format_count(peak_value)} requests in the {volume.get('granularity') or 'bucket'} bucket."
        )
    else:
        bullets.append(
            f"Peak bucket was bucket {peak_index + 1} with {_format_count(peak_value)} requests."
        )
    return bullets


def _sustain_and_taper_bullets(
    current: list[int],
    last_nonzero: int,
    peak_index: int,
    peak_value: int,
    peak_time: datetime | None,
    start: datetime | None,
    step: timedelta | None,
    end: datetime | None,
) -> list[str]:
    bullets: list[str] = []
    last_time = _bucket_time(start, step, last_nonzero)
    if last_nonzero > peak_index:
        duration = _duration_phrase(last_nonzero - peak_index, step)
        if peak_time and last_time and duration:
            bullets.append(
                f"Sustained pressure continued for {duration} after peak, through {_format_ts(last_time)}."
            )
        else:
            bullets.append("Sustained pressure continued after the peak bucket.")
    if current[-1] < peak_value:
        if end:
            bullets.append(
                f"Taper or recovery was visible by the window close at {_format_ts(end)}."
            )
        else:
            bullets.append("Taper or recovery was visible by the final bucket.")
    return bullets


def _behavior_clusters_view(action_targets_art: dict) -> list[dict]:
    clusters = action_targets_art.get("behavior_clusters") or []
    targets_by_key = {}
    for target in action_targets_art.get("targets") or []:
        key = f"{target.get('target_type')}:{target.get('target_value')}"
        targets_by_key[key] = target
    out: list[dict] = []
    label_by_basis = {
        "shared_asn": "Shared ASN",
        "shared_path": "Shared path targeting",
        "shared_user_agent": "Shared user agent",
        "shared_cohort": "Shared cohort",
        "shared_edge_action": "Shared edge action",
        "overlapping_peak_bucket": "Overlapping peak bucket",
    }
    for cluster in clusters:
        target_keys = list(cluster.get("targets") or [])
        target_count = cluster.get("target_count") or len(target_keys)
        summed_requests = None
        if target_keys and all(key in targets_by_key for key in target_keys):
            target_types = {targets_by_key[key].get("target_type") for key in target_keys}
            if len(target_types) == 1:
                summed_requests = sum(
                    int(float((targets_by_key[key].get("supporting") or {}).get("requests") or 0))
                    for key in target_keys
                )
        top_members = [
            key.split(":", 1)[1] if ":" in key else key
            for key in target_keys[:3]
        ]
        out.append(
            {
                "title": label_by_basis.get(
                    cluster.get("basis"),
                    str(cluster.get("basis") or "Shared evidence").replace("_", " ").title(),
                ),
                "basis_value": cluster.get("basis_value") or "",
                "target_count": target_count,
                "targets": target_keys,
                "top_members": top_members,
                "member_count_text": f"{target_count} member{'s' if target_count != 1 else ''}",
                "confidence_label": "Observed",
                "confidence_basis": "Legacy behavior-cluster fallback.",
                "summed_requests_display": (
                    _format_count(summed_requests)
                    if summed_requests is not None and summed_requests > 0
                    else None
                ),
                "boundary": cluster.get("boundary") or (
                    "Clustered by shared observed behavior only; not proof of common control."
                ),
            }
        )
    return out


def _entity_clusters_view(action_targets_art: dict) -> list[dict]:
    clusters = action_targets_art.get("entity_clusters") or []
    if not clusters:
        return _behavior_clusters_view(action_targets_art)
    out: list[dict] = []
    for cluster in clusters:
        members = list(cluster.get("representative_actors") or [])
        facets = list(cluster.get("shared_facets") or [])
        action = cluster.get("dominant_action_profile") or {}
        member_count = int(cluster.get("member_count") or len(cluster.get("targets") or []))
        out.append(
            {
                "title": cluster.get("title")
                or str(cluster.get("basis") or "Shared evidence").replace("_", " ").title(),
                "basis_value": cluster.get("basis_value") or "",
                "member_count": member_count,
                "member_count_text": f"{member_count} member{'s' if member_count != 1 else ''}",
                "shared_facets": facets,
                "representative_actors": [
                    {
                        "target_type": str(m.get("target_type") or "").replace("_", " ").title(),
                        "target_value": m.get("target_value") or "",
                        "requests_display": _format_count(m.get("requests")),
                    }
                    for m in members[:4]
                ],
                "total_observed_requests_display": (
                    _format_count(cluster.get("total_observed_requests"))
                    if cluster.get("total_observed_requests") not in (None, "")
                    else None
                ),
                "dominant_action_profile": (
                    {
                        "action": action.get("action") or "No Action",
                        "share_display": _format_pct(action.get("share_pct")),
                    }
                    if action
                    else None
                ),
                "confidence_label": cluster.get("confidence_label") or "Observed",
                "confidence_basis": cluster.get("confidence_basis") or "",
                "aggregate_behavior": cluster.get("aggregate_behavior") or "",
                "coverage_summary": cluster.get("coverage_summary") or "",
                "boundary": cluster.get("boundary")
                or "Clustered by shared observed behavior only; not attribution.",
            }
        )
    return out


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
