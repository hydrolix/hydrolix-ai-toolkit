"""Cross-row cluster pivots for suspicious-target rows."""

from __future__ import annotations

from config import DEFAULT_THRESHOLDS, Thresholds
from producers.suspicious_targets.rules import disabled


def _resolve(thresholds: Thresholds | None) -> Thresholds:
    return thresholds if thresholds is not None else DEFAULT_THRESHOLDS


def _apply_asn_grouped_pivots(
    flagged_client_ips: list[dict],
    total_current: float,
    *,
    clean_number,
    thresholds: Thresholds | None = None,
) -> None:
    """Per-ASN grouping path. Rows without an ASN are excluded from
    clustering entirely -- they're attribution-unknown and shouldn't
    claim membership in any specific cluster. Mutates rows in place.
    """
    t = _resolve(thresholds)
    st = t.suspicious_targets
    single_asn_off = disabled("single_asn_cluster", t)
    botnet_off = disabled("botnet_member", t)
    if single_asn_off and botnet_off:
        return
    groups = _asn_groups(flagged_client_ips)
    for asn, members in groups.items():
        if len(members) < st.asn_cluster_min_ips:
            continue
        if not single_asn_off:
            _mark_single_asn_cluster(members, asn)
        if total_current <= 0 or botnet_off:
            continue
        cluster_requests = sum(m["requests"] for m in members)
        cluster_share = cluster_requests / total_current
        if cluster_share < st.botnet_cluster_share_min:
            continue
        _mark_botnet_cluster(members, cluster_requests, cluster_share, clean_number)


def _asn_groups(flagged_client_ips: list[dict]) -> dict[object, list[dict]]:
    groups: dict[object, list[dict]] = {}
    for row in flagged_client_ips:
        asn = row.get("asn")
        if asn not in (None, "", 0):
            groups.setdefault(asn, []).append(row)
    return groups


def _mark_single_asn_cluster(members: list[dict], asn: object) -> None:
    asn_org = next((m.get("asn_org") for m in members if m.get("asn_org")), "")
    for row in members:
        if "single_asn_cluster" not in row["flags"]:
            row["flags"].append("single_asn_cluster")
        extras = row.setdefault("supporting_extras", {})
        extras["asn_cluster_id"] = asn
        if asn_org:
            extras["asn_cluster_org"] = asn_org
        extras["asn_cluster_size"] = len(members)


def _mark_botnet_cluster(
    members: list[dict],
    cluster_requests: float,
    cluster_share: float,
    clean_number,
) -> None:
    cluster_share_pct = clean_number(round(100.0 * cluster_share, 2))
    for row in members:
        if "botnet_member" not in row["flags"]:
            row["flags"].append("botnet_member")
        extras = row.setdefault("supporting_extras", {})
        extras["botnet_cluster_requests"] = int(cluster_requests)
        extras["botnet_cluster_share_pct"] = cluster_share_pct
        extras["botnet_cluster_size"] = len(members)


def _apply_unverified_cluster_pivots(
    flagged_client_ips: list[dict],
    total_current: float,
    *,
    clean_number,
    thresholds: Thresholds | None = None,
) -> None:
    """Legacy fallback for producers without per-row ASN attribution.
    Uses the coarse count + total-share rule and marks the
    supporting_extras so downstream consumers can tell this is an
    approximation, not a verified same-ASN cluster. Mutates rows in
    place.
    """
    t = _resolve(thresholds)
    single_asn_off = disabled("single_asn_cluster", t)
    botnet_off = disabled("botnet_member", t)
    if single_asn_off and botnet_off:
        return
    if not single_asn_off:
        for row in flagged_client_ips:
            if "single_asn_cluster" not in row["flags"]:
                row["flags"].append("single_asn_cluster")
            extras = row.setdefault("supporting_extras", {})
            extras["asn_cluster_attribution"] = "unverified"
            extras["asn_cluster_size"] = len(flagged_client_ips)
    if total_current <= 0 or botnet_off:
        return
    cluster_requests = sum(r["requests"] for r in flagged_client_ips)
    cluster_share = cluster_requests / total_current
    if cluster_share < t.suspicious_targets.botnet_cluster_share_min:
        return
    cluster_share_pct = clean_number(round(100.0 * cluster_share, 2))
    for row in flagged_client_ips:
        if "botnet_member" not in row["flags"]:
            row["flags"].append("botnet_member")
        extras = row.setdefault("supporting_extras", {})
        extras["botnet_cluster_requests"] = int(cluster_requests)
        extras["botnet_cluster_share_pct"] = cluster_share_pct
        extras["botnet_cluster_size"] = len(flagged_client_ips)


def _apply_cluster_pivots(
    intermediate: list[dict],
    total_current: float,
    *,
    clean_number,
    thresholds: Thresholds | None = None,
) -> None:
    """Cross-row pivots that add ``single_asn_cluster`` (shape) and
    ``botnet_member`` (magnitude) flags to flagged client_ip rows.
    Routes through per-ASN grouping when the producer carries ASN
    attribution, falling back to the coarse count + total-share rule
    when no row carries an ``asn`` field.
    """
    t = _resolve(thresholds)
    flagged_client_ips = [r for r in intermediate if r["field"] == "client_ip"]
    have_asn_attribution = any(
        r.get("asn") not in (None, "", 0) for r in flagged_client_ips
    )
    if have_asn_attribution:
        _apply_asn_grouped_pivots(
            flagged_client_ips, total_current,
            clean_number=clean_number, thresholds=t,
        )
    elif len(flagged_client_ips) >= t.suspicious_targets.asn_cluster_min_ips:
        _apply_unverified_cluster_pivots(
            flagged_client_ips, total_current,
            clean_number=clean_number, thresholds=t,
        )
