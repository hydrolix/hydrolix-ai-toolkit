"""Editorial-findings list builder for the incident report."""

from __future__ import annotations

from .labels import REASON_FLAG_LABELS, SPIKE_FLAG_LABELS

__all__ = [
    '_finding_entity',
    '_incident_findings',
]


def _entity_meta(target: dict) -> str:
    """Build the short " · "-joined meta annotation for a finding entity."""
    supporting = target.get("supporting") or {}
    share_display = target.get("share_pct_display")
    meta_parts: list[str] = []
    asn_id = supporting.get("asn_cluster_id")
    asn_org = supporting.get("asn_cluster_org") or ""
    if asn_id:
        meta_parts.append(f"AS{asn_id}{(' · ' + asn_org) if asn_org else ''}")
    if share_display:
        meta_parts.append(f"{share_display} of window")
    return " · ".join(meta_parts)


def _finding_entity(target: dict) -> dict:
    """Project a suspicious-target row into the entity-list shape used
    by ``incident_findings[].entities``.

    Entities render as a bulleted list inside a finding body, so each
    one gets a ``value`` (the identifier itself, monospace) and an
    optional ``meta`` annotation (the share, ASN org, etc. — whatever
    short context the analyst would want next to the identifier).
    Inline comma-joined lists of long values (IPs, full UA strings)
    are unreadable; the bulleted shape fixes that.
    """
    return {
        "value": target.get("target_value") or "",
        "target_type": target.get("target_type") or "",
        "target_type_label": target.get("target_type_label") or "",
        "meta": _entity_meta(target),
        "severity": target.get("severity") or "",
        "severity_tone": target.get("severity_tone", "observe"),
    }


def _finding_crit_ip_group(crit_ips: list[dict]) -> dict:
    share = sum(float(t.get("share_pct") or 0) for t in crit_ips[:3])
    return {
        "label": "Finding 01",
        "lead": "Critical-tier client IPs coordinated against this window.",
        "body": (
            f"These IPs drove ~{share:.0f}% of window traffic and "
            "crossed the multi-signal heuristic ladder (volume + "
            "429 share + single-path concentration):"
        ),
        "entities": [_finding_entity(t) for t in crit_ips[:3]],
    }


def _finding_top_severity(top: dict) -> dict:
    return {
        "label": "Finding 01",
        "lead": (
            f"{top.get('target_type_label') or 'Top target'} flagged at "
            f"{top.get('severity_label') or 'high'} severity."
        ),
        "body": (
            f"`{top.get('target_value')}` accounted for "
            f"{top.get('share_pct_display') or '—'} of window traffic; "
            f"reason flags: {', '.join(top.get('reason_flag_labels') or []) or '—'}."
        ),
    }


def _finding_top_tier_group(
    crit_ips: list[dict], crits: list[dict], highs: list[dict]
) -> dict | None:
    """Finding 01: top-tier target group (critical IPs if any, else top severity)."""
    if crit_ips:
        return _finding_crit_ip_group(crit_ips)
    if crits or highs:
        return _finding_top_severity((crits or highs)[0])
    return None


def _finding_ua_footprint(ua_targets: list[dict]) -> dict | None:
    """Finding 02: UA footprint dispatched on the actual flags that fired.

    The lead used to be a hardcoded "automation tooling" claim — but the
    UAs that surface here are routinely rotating browser strings, and
    only the ``automation_user_agent`` flag genuinely identifies tooling
    UAs (curl, python-requests, ...). Dispatch on the union of
    ``reason_flags`` across the top-2 UA targets, first match wins.
    """
    if not ua_targets:
        return None
    top = ua_targets[:2]
    share = sum(float(t.get("share_pct") or 0) for t in top)
    flags: set[str] = set()
    for t in top:
        for flag in t.get("reason_flags") or []:
            flags.add(str(flag))
    flag_labels = ", ".join(
        REASON_FLAG_LABELS.get(flag, flag) for flag in sorted(flags)
    ) or "—"

    if "automation_user_agent" in flags:
        lead = "Automation tooling declared in the user agent."
        body = (
            f"These user agents account for ~{share:.0f}% of "
            "traffic and match curated automation patterns "
            f"({flag_labels}). The report does not infer intent "
            "from the identifier — the names below are what the "
            "requests presented:"
        )
    elif "single_path_concentration" in flags:
        lead = "User agents concentrated on a single path."
        body = (
            f"These user agents account for ~{share:.0f}% of "
            f"traffic and fired {flag_labels}. The report does "
            "not infer intent — the identifiers below are what "
            "the requests presented:"
        )
    elif "new_in_window" in flags:
        lead = "User agents new in this window."
        body = (
            f"These user agents account for ~{share:.0f}% of "
            "traffic and were absent from the trailing baseline "
            f"({flag_labels}). The report does not infer intent:"
        )
    elif "high_rate_429_share" in flags:
        lead = "User agents drawing high 429 share."
        body = (
            f"These user agents account for ~{share:.0f}% of "
            f"traffic and fired {flag_labels}. The report does "
            "not infer intent — the identifiers below are what "
            "the requests presented:"
        )
    else:
        lead = "User agents drawing outsized request share."
        body = (
            f"These user agents account for ~{share:.0f}% of "
            f"traffic ({flag_labels}). The report does not infer "
            "intent — the identifiers below are what the requests "
            "presented:"
        )
    return {
        "label": "Finding 02",
        "lead": lead,
        "body": body,
        "entities": [_finding_entity(t) for t in top],
    }


def _finding_disjoint_cohorts(cohort_overlap: dict | None) -> dict | None:
    if not (cohort_overlap and cohort_overlap.get("is_disjoint")):
        return None
    return {
        "label": "Finding 03",
        "lead": "Two disjoint attack cohorts on the same window.",
        "body": (
            f"The {cohort_overlap['flagged_ip_count']} flagged IPs and "
            f"{cohort_overlap['flagged_ua_count']} flagged UAs barely "
            f"overlap — only {cohort_overlap['forward_pct']:.1f}% of "
            "flagged-IP traffic uses a flagged UA, and "
            f"{cohort_overlap['reverse_pct']:.1f}% of flagged-UA "
            "traffic comes from a flagged IP. The two heuristic "
            "ladders are catching different attack populations on the "
            "same target — treat them as separate cohorts, not one fleet."
        ),
    }


def _finding_anomaly_cohort(
    anomalies: list[dict], cohort_targets: list[dict]
) -> dict | None:
    if not (anomalies or cohort_targets):
        return None
    anomaly = (anomalies or cohort_targets)[0]
    return {
        "label": "Finding 03",
        "lead": "Behavioral cohort anomaly is the worry.",
        "body": (
            f"`{anomaly.get('target_value')}` shows a behavioral "
            "departure from the trailing baseline — consistent "
            "with sophisticated automation passing bot-classification."
        ),
    }


def _finding_unattributed_spike(
    spike_flags: list[str], suspicious_targets: list[dict]
) -> dict | None:
    if not (spike_flags and not suspicious_targets):
        return None
    labelled = ", ".join(
        SPIKE_FLAG_LABELS.get(f, f.replace("_", " ")) for f in spike_flags
    )
    return {
        "label": "Finding 03",
        "lead": "Spike flags fired without a named actor.",
        "body": (
            f"{labelled} confirmed at the scope-table level, but "
            "the heuristic ladder did not flag any individual "
            "target — likely a distributed surge spread across "
            "many small contributors."
        ),
    }


def _finding_third_slot(
    cohort_overlap: dict | None,
    anomalies: list[dict],
    cohort_targets: list[dict],
    spike_flags: list[str],
    suspicious_targets: list[dict],
) -> dict | None:
    """Finding 03 — slot priority:

      1. Disjoint IP / UA cohorts (when the producer supplies joint
         cell counts and overlap is below the floor) — the most
         surprising secondary signal when it applies: the heuristic
         ladder is catching two distinct attack populations hitting
         the same target, not one cohort viewed from two angles.
      2. Behavioral anomaly cohort.
      3. Spike flags fired without a named actor.
    """
    return (
        _finding_disjoint_cohorts(cohort_overlap)
        or _finding_anomaly_cohort(anomalies, cohort_targets)
        or _finding_unattributed_spike(spike_flags, suspicious_targets)
    )


def _pad_findings(findings: list[dict], deterministic_summary: dict) -> list[dict]:
    """Pad to exactly 3 with a deterministic placeholder + renumber labels."""
    headline = (deterministic_summary or {}).get("headline") or (
        "Findings will populate as the heuristic surfaces flagged targets."
    )
    while len(findings) < 3:
        findings.append(
            {
                "label": f"Finding {len(findings) + 1:02d}",
                "lead": "No additional flagged signals in this window.",
                "body": headline,
            }
        )
    for idx, finding in enumerate(findings, start=1):
        finding["label"] = f"Finding {idx:02d}"
    return findings[:3]


def _by_severity(targets: list[dict], severity: str) -> list[dict]:
    return [t for t in targets if t.get("severity") == severity]


def _by_target_type(targets: list[dict], target_type: str) -> list[dict]:
    return [t for t in targets if t.get("target_type") == target_type]


def _anomaly_targets(targets: list[dict]) -> list[dict]:
    return [
        t for t in targets
        if "behavioral anomaly" in (t.get("reason_flag_labels") or [])
    ]


def _slice_finding_inputs(
    suspicious_targets: list[dict],
) -> tuple[list[dict], list[dict], list[dict], list[dict], list[dict], list[dict]]:
    """Pre-slice ``suspicious_targets`` into the bucket lists each finding-builder consumes."""
    crits = _by_severity(suspicious_targets, "critical")
    highs = _by_severity(suspicious_targets, "high")
    crit_ips = _by_target_type(crits, "client_ip")
    ua_targets = _by_target_type(suspicious_targets, "user_agent")
    cohort_targets = _by_target_type(suspicious_targets, "cohort")
    anomalies = _anomaly_targets(suspicious_targets)
    return crits, highs, crit_ips, ua_targets, cohort_targets, anomalies


def _incident_findings(
    suspicious_targets: list[dict],
    deterministic_summary: dict,
    spike_flags: list[str],
    cohort_overlap: dict | None = None,
) -> list[dict]:
    """Build the 3-finding editorial verdict block (Phase 1 deterministic).

    Each finding is ``{label, lead, body}`` — the label is the numbered
    eyebrow ("Finding 01"), the lead is a short headline sentence, and
    the body is the supporting evidence paragraph. Findings are
    generated mechanically from the top suspicious targets + spike
    flags so this slot always renders even when no LLM analyst note is
    supplied. Phase 2 layers in an ``llm-incident-findings`` slot that
    replaces this entire list when present.

    Selection rules:
      - Finding 01 always describes the top-tier target group
        (critical IPs if any, otherwise top severity group).
      - Finding 02 describes the next distinct dimension — if Finding
        01 was IP-based, this one prefers UA / ASN / cohort signals.
      - Finding 03 surfaces the most surprising secondary signal — see
        :func:`_finding_third_slot` for the slot-priority rule.

    Always returns exactly 3 items, padding with deterministic
    fallbacks ("No additional flagged signals in this window.") when
    the artifact data is too thin to produce three distinct findings.
    """
    crits, highs, crit_ips, ua_targets, cohort_targets, anomalies = (
        _slice_finding_inputs(suspicious_targets)
    )

    candidates = [
        _finding_top_tier_group(crit_ips, crits, highs),
        _finding_ua_footprint(ua_targets),
        _finding_third_slot(
            cohort_overlap, anomalies, cohort_targets, spike_flags, suspicious_targets,
        ),
    ]
    findings: list[dict] = [f for f in candidates if f is not None]
    return _pad_findings(findings, deterministic_summary)
