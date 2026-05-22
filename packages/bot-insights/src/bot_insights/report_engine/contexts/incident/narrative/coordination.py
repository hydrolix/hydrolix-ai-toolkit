"""Coordination signal projection for incident narrative context."""

from __future__ import annotations


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
