"""Incident behavior and entity cluster evidence shaping."""

from __future__ import annotations

def _target_key(target: dict) -> str:
    return f"{target.get('target_type')}:{target.get('target_value')}"
def _target_requests(target: dict) -> int:
    import baselines as baselines_mod

    return int(baselines_mod.to_number((target.get("supporting") or {}).get("requests")) or 0)
def _target_shared_facets(
    target: dict,
    target_evidence: dict[str, dict],
) -> list[dict]:
    supporting = target.get("supporting") or {}
    evidence = target_evidence.get(_target_key(target)) or {}
    facets: list[dict] = []
    asn = supporting.get("asn_cluster_id") or supporting.get("asn")
    if asn not in (None, ""):
        org = supporting.get("asn_cluster_org")
        facets.append(
            {
                "kind": "asn",
                "basis": "shared_asn",
                "label": "ASN/org",
                "value": str(asn),
                "display": f"{asn} ({org})" if org else str(asn),
            }
        )
    for source_field, basis, label in (
        ("botnet_cluster_id", "shared_botnet_cluster", "Botnet cluster"),
        ("dominant_path", "shared_path", "Dominant path"),
        ("dominant_user_agent", "shared_user_agent", "Dominant UA"),
        ("dominant_cohort", "shared_cohort", "Dominant cohort"),
        ("peak_bucket", "overlapping_peak_bucket", "Peak bucket"),
        ("dominant_edge_action", "shared_edge_action", "Edge action profile"),
    ):
        if source_field.startswith("dominant_"):
            value = (evidence.get(source_field) or {}).get("value")
        elif source_field == "peak_bucket":
            value = evidence.get(source_field)
        else:
            value = supporting.get(source_field)
        if value not in (None, ""):
            facets.append(
                {
                    "kind": source_field,
                    "basis": basis,
                    "label": label,
                    "value": str(value),
                    "display": str(value),
                }
            )
    return facets
def _incident_behavior_clusters(
    suspicious_targets: list[dict],
    target_evidence: dict[str, dict],
) -> list[dict]:
    """Build deterministic behavior clusters from shared observed facets.

    Cluster labels are evidence descriptors, not actor attribution. A
    row joins a cluster when at least two targets share one or more of
    ASN, dominant path, dominant user-agent/cohort, dominant edge action,
    or peak bucket.
    """
    buckets: dict[tuple[str, str], list[str]] = {}
    for target in suspicious_targets:
        target_type = str(target.get("target_type") or "")
        target_value = str(target.get("target_value") or "")
        if not target_type or not target_value:
            continue
        key = f"{target_type}:{target_value}"
        for facet in _target_shared_facets(target, target_evidence):
            buckets.setdefault((facet["basis"], facet["value"]), []).append(key)

    clusters: list[dict] = []
    for (facet, value), members in sorted(buckets.items()):
        unique_members = sorted(set(members))
        if len(unique_members) < 2:
            continue
        clusters.append(
            {
                "cluster_id": f"{facet}:{value}",
                "basis": facet,
                "basis_value": value,
                "target_count": len(unique_members),
                "targets": unique_members,
                "boundary": (
                    "Clustered by shared observed behavior only; this is "
                    "not actor attribution or proof of common control."
                ),
            }
        )
    return sorted(
        clusters,
        key=lambda c: (-int(c["target_count"]), c["basis"], c["basis_value"]),
    )
def _dominant_action_profile(
    members: list[dict],
    target_evidence: dict[str, dict],
) -> dict | None:
    import baselines as baselines_mod

    counts: dict[str, int] = {}
    for target in members:
        evidence = target_evidence.get(_target_key(target)) or {}
        action = (evidence.get("dominant_edge_action") or {}).get("value")
        if not action:
            continue
        counts[str(action)] = counts.get(str(action), 0) + _target_requests(target)
    total = sum(counts.values())
    if total <= 0:
        return None
    action, requests = max(counts.items(), key=lambda kv: kv[1])
    return {
        "action": action or "No Action",
        "requests": requests,
        "share_pct": baselines_mod.clean_number(round(100.0 * requests / total, 2)),
    }
def _incident_entity_clusters(
    suspicious_targets: list[dict],
    target_evidence: dict[str, dict],
) -> list[dict]:
    """Build first-class entity clusters from shared observed facets.

    Clusters stay evidence-bound: request totals are included only when all
    members are the same target type, avoiding unsafe sums across overlapping
    entity views.
    """
    targets_by_key = {
        _target_key(target): target
        for target in suspicious_targets
        if target.get("target_type") and target.get("target_value")
    }
    buckets: dict[tuple[str, str], list[str]] = {}
    facet_lookup: dict[tuple[str, str], dict] = {}
    facets_by_target: dict[str, list[dict]] = {}
    for target in targets_by_key.values():
        target_key = _target_key(target)
        facets = _target_shared_facets(target, target_evidence)
        facets_by_target[target_key] = facets
        for facet in facets:
            facet_key = (facet["basis"], facet["value"])
            buckets.setdefault(facet_key, []).append(target_key)
            facet_lookup.setdefault(facet_key, facet)

    primary_buckets, assigned_to_primary = _primary_cluster_buckets(
        facets_by_target, buckets
    )
    fallback_buckets = _fallback_cluster_buckets(buckets, assigned_to_primary)
    facet_rank = {
        "shared_botnet_cluster": 0,
        "shared_asn": 1,
        "shared_path": 2,
        "shared_user_agent": 3,
        "shared_cohort": 4,
        "overlapping_peak_bucket": 5,
        "shared_edge_action": 6,
    }
    all_cluster_buckets = {**primary_buckets, **fallback_buckets}
    clusters: list[dict] = []
    for facet_key, target_key_set in sorted(
        all_cluster_buckets.items(),
        key=lambda item: (facet_rank.get(item[0][0], 99), item[0][1]),
    ):
        cluster = _incident_entity_cluster(
            facet_key,
            target_key_set,
            targets_by_key,
            buckets,
            facet_lookup,
            target_evidence,
        )
        if cluster:
            clusters.append(cluster)
    return sorted(
        clusters,
        key=lambda c: (
            -int(c["member_count"]),
            -(int(c["total_observed_requests"]) if c["total_observed_requests"] else 0),
            facet_rank.get(c["basis"], 99),
            c["basis_value"],
        ),
    )
def _primary_cluster_buckets(
    facets_by_target: dict[str, list[dict]],
    buckets: dict[tuple[str, str], list[str]],
) -> tuple[dict[tuple[str, str], set[str]], set[str]]:
    primary_buckets: dict[tuple[str, str], set[str]] = {}
    assigned_to_primary: set[str] = set()
    for target_key, facets in facets_by_target.items():
        primary = _primary_facet_for_target(facets, buckets)
        if primary:
            facet_key = (primary["basis"], primary["value"])
            primary_buckets.setdefault(facet_key, set()).add(target_key)
            assigned_to_primary.add(target_key)
    return primary_buckets, assigned_to_primary
def _primary_facet_for_target(
    facets: list[dict], buckets: dict[tuple[str, str], list[str]]
) -> dict | None:
    return next(
        (
            facet
            for facet in facets
            if facet["basis"] in {"shared_botnet_cluster", "shared_asn"}
            and len(set(buckets.get((facet["basis"], facet["value"]), []))) >= 2
        ),
        None,
    )
def _fallback_cluster_buckets(
    buckets: dict[tuple[str, str], list[str]], assigned_to_primary: set[str]
) -> dict[tuple[str, str], set[str]]:
    fallback_buckets: dict[tuple[str, str], set[str]] = {}
    for facet_key, target_keys in buckets.items():
        if facet_key[0] in {"shared_botnet_cluster", "shared_asn"}:
            continue
        unique_keys = sorted(set(target_keys) - assigned_to_primary)
        if len(unique_keys) >= 2:
            fallback_buckets[facet_key] = set(unique_keys)
    return fallback_buckets
def _shared_facets_for_cluster(
    target_keys: list[str],
    buckets: dict[tuple[str, str], list[str]],
    facet_lookup: dict[tuple[str, str], dict],
) -> list[dict]:
    target_key_set = set(target_keys)
    shared: list[dict] = []
    for facet_key, bucket_members in sorted(buckets.items()):
        overlapping_members = sorted(target_key_set & set(bucket_members))
        if len(overlapping_members) < 2:
            continue
        facet = dict(facet_lookup[facet_key])
        facet["member_count"] = len(overlapping_members)
        shared.append(facet)
    return sorted(
        shared,
        key=lambda f: (
            f["basis"] not in {"shared_asn", "shared_botnet_cluster"},
            -int(f.get("member_count") or 0),
            f["label"],
            f["display"],
        ),
    )
def _cluster_confidence(shared_facets: list[dict], member_count: int) -> tuple[str, str]:
    primary_count = sum(
        1
        for facet in shared_facets
        if facet["basis"] in {"shared_asn", "shared_botnet_cluster"}
    )
    supporting_count = max(0, len(shared_facets) - primary_count)
    if primary_count and supporting_count >= 2 and member_count >= 3:
        return (
            "High",
            "Shared infrastructure metadata plus multiple observed behavior facets.",
        )
    if primary_count or supporting_count >= 2:
        return "Medium", "Multiple targets share observed clustering facets."
    return "Low", "Cluster is based on a single observed shared facet."
def _target_label_for_cluster(target_key: str, targets_by_key: dict[str, dict]) -> str:
    target = targets_by_key.get(target_key) or {}
    return f"{target.get('target_type')}:{target.get('target_value')}"
def _incident_entity_cluster(
    facet_key: tuple[str, str],
    target_key_set: set[str],
    targets_by_key: dict[str, dict],
    buckets: dict[tuple[str, str], list[str]],
    facet_lookup: dict[tuple[str, str], dict],
    target_evidence: dict[str, dict],
) -> dict | None:
    unique_keys = sorted(target_key_set)
    if len(unique_keys) < 2:
        return None
    members = [targets_by_key[key] for key in unique_keys if key in targets_by_key]
    if len(members) < 2:
        return None
    total_requests = _cluster_total_requests(members)
    facet = facet_lookup[facet_key]
    shared_facets = _shared_facets_for_cluster(unique_keys, buckets, facet_lookup)
    confidence_label, confidence_basis = _cluster_confidence(shared_facets, len(members))
    action_profile = _dominant_action_profile(members, target_evidence)
    return {
        "cluster_id": f"{facet['basis']}:{facet['value']}",
        "title": facet["label"],
        "basis": facet["basis"],
        "basis_value": facet["value"],
        "shared_facets": shared_facets,
        "member_count": len(members),
        "targets": [_target_label_for_cluster(key, targets_by_key) for key in unique_keys],
        "representative_actors": _representative_cluster_actors(members),
        "total_observed_requests": total_requests,
        "dominant_action_profile": action_profile,
        "confidence_label": confidence_label,
        "confidence_basis": confidence_basis,
        "aggregate_behavior": _cluster_aggregate_behavior(
            members, shared_facets, total_requests, action_profile
        ),
        "coverage_summary": _cluster_coverage_summary(action_profile),
        "boundary": (
            "Clustered by shared observed behavior only; this is not "
            "attribution or proof of common control."
        ),
    }
def _cluster_total_requests(members: list[dict]) -> int | None:
    member_types = {member.get("target_type") for member in members}
    if len(member_types) != 1:
        return None
    return sum(_target_requests(member) for member in members)
def _representative_cluster_actors(members: list[dict]) -> list[dict]:
    representative = sorted(
        members,
        key=lambda member: (
            -_target_requests(member),
            str(member.get("target_value") or ""),
        ),
    )[:4]
    return [
        {
            "target_type": member.get("target_type"),
            "target_value": member.get("target_value"),
            "requests": _target_requests(member),
        }
        for member in representative
    ]
def _cluster_aggregate_behavior(
    members: list[dict],
    shared_facets: list[dict],
    total_requests: int | None,
    action_profile: dict | None,
) -> str:
    parts = [
        f"{len(members)} flagged entities shared {len(shared_facets)} observed facet"
        f"{'s' if len(shared_facets) != 1 else ''}"
    ]
    if total_requests is not None:
        parts.append(f"{total_requests} non-overlapping observed requests")
    if action_profile:
        parts.append(
            f"{action_profile['share_pct']}% dominant {action_profile['action']} edge-action profile"
        )
    return "; ".join(parts) + "."
def _cluster_coverage_summary(action_profile: dict | None) -> str:
    if action_profile:
        return (
            f"Dominant observed edge action was {action_profile['action']} "
            f"for {action_profile['share_pct']}% of cluster member traffic."
        )
    return "No per-member edge-action profile was available for this cluster."
