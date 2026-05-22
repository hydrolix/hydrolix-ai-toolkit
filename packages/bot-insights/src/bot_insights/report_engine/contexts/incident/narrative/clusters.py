"""Cluster projections for incident narrative context."""

from __future__ import annotations

from ..formatters import _format_count, _format_pct


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
