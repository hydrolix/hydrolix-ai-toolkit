"""Incident actor rows and action-target artifact shaping."""

from __future__ import annotations

def _incident_actor_rows(
    rows: list[dict],
) -> list[dict]:
    import baselines as baselines_mod

    out: list[dict] = []
    for row in rows:
        requests = baselines_mod.to_number(row.get("requests")) or 0.0
        req_429 = baselines_mod.to_number(row.get("req_429")) or 0.0
        req_5xx = baselines_mod.to_number(row.get("req_5xx")) or 0.0
        share_429 = 100.0 * req_429 / requests if requests > 0 else 0.0
        share_5xx = 100.0 * req_5xx / requests if requests > 0 else 0.0
        projected = {
            "value": str(row.get("value") if row.get("value") is not None else ""),
            "requests": int(requests),
            "bytes": int(baselines_mod.to_number(row.get("bytes")) or 0),
            "distinct_paths": int(
                baselines_mod.to_number(row.get("distinct_paths")) or 0
            ),
            "req_429": int(req_429),
            "req_5xx": int(req_5xx),
            "req_429_share_pct": baselines_mod.clean_number(round(share_429, 2)),
            "req_5xx_share_pct": baselines_mod.clean_number(round(share_5xx, 2)),
        }
        # Per-row ASN attribution (projected by the scoped-metrics query
        # for the ``client_ip`` field — ``any(asn) AS asn``). Feeds the
        # heuristic's verified per-ASN ``single_asn_cluster`` /
        # ``botnet_member`` pivots.
        raw_asn = row.get("asn")
        if raw_asn not in (None, "", 0):
            asn_num = baselines_mod.to_number(raw_asn)
            if asn_num is not None:
                projected["asn"] = int(asn_num)
        out.append(projected)
    return out
def _build_action_targets_artifact(
    scope_meta: dict,
    suspicious_targets: list[dict],
    *,
    heuristic_version: str = "v2",
    limitations: list[str] | None = None,
    target_evidence: dict[str, dict] | None = None,
    behavior_clusters: list[dict] | None = None,
    entity_clusters: list[dict] | None = None,
) -> dict:
    """Wrap a list of suspicious-target rows in the canonical artifact shape."""
    return {
        "artifact_id": "incident-action-targets-1",
        "schema_version": "bot_incident_action_targets.v1",
        "scope": scope_meta,
        "targets": suspicious_targets,
        "heuristic_version": heuristic_version,
        "limitations": list(limitations or []),
        "target_evidence": target_evidence or {},
        "behavior_clusters": behavior_clusters or [],
        "entity_clusters": entity_clusters or [],
    }
