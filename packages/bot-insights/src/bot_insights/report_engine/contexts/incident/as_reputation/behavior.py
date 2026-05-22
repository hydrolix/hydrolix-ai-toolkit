"""Observed incident behavior helpers for AS reputation context."""

from __future__ import annotations

from ..formatters import _format_count, _format_pct, _safe_number
from .corpus import _format_asn, _normalize_asn


def _ranking_rows_by_asn(actors_artifact: dict) -> dict[str, dict]:
    ranking = next(
        (
            row
            for row in actors_artifact.get("actor_rankings") or []
            if row.get("field") == "asn"
        ),
        None,
    )
    out: dict[str, dict] = {}
    for row in (ranking or {}).get("rows") or []:
        asn = _normalize_asn(row.get("value"))
        if asn:
            out[asn] = row
    return out


def _target_asn(target: dict) -> str:
    if target.get("target_type") == "asn":
        return _normalize_asn(target.get("target_value"))
    supporting = target.get("supporting") or {}
    return _normalize_asn(
        supporting.get("asn_cluster_id")
        or supporting.get("asn")
    )


def _observed_asn_behavior(
    asn: str,
    actors_artifact: dict,
    suspicious_targets: list[dict],
) -> dict:
    ranking_by_asn = _ranking_rows_by_asn(actors_artifact)
    ranking_total = sum(
        float(_safe_number(row.get("requests")) or 0)
        for row in ranking_by_asn.values()
    )
    ranking_row = ranking_by_asn.get(asn) or {}
    related_targets = [
        target for target in suspicious_targets if _target_asn(target) == asn
    ]
    direct_target = next(
        (target for target in related_targets if target.get("target_type") == "asn"),
        None,
    )
    supporting = (direct_target or {}).get("supporting") or {}
    requests = (
        _safe_number(supporting.get("requests"))
        or _safe_number(ranking_row.get("requests"))
        or sum(
            float(_safe_number((target.get("supporting") or {}).get("requests")) or 0)
            for target in related_targets
        )
    )
    share_pct = _safe_number(supporting.get("share_pct"))
    share_basis = "observed incident traffic"
    if share_pct is None and ranking_total > 0 and requests is not None:
        share_pct = 100.0 * float(requests) / ranking_total
        share_basis = "observed ASN-ranked traffic"
    client_ip_targets = [
        target for target in related_targets if target.get("target_type") == "client_ip"
    ]
    flags = sorted(
        {
            flag
            for target in related_targets
            for flag in (target.get("reason_flags") or [])
        }
    )
    parts = [
        f"In this report, {_format_asn(asn)} accounted for "
        f"{_format_count(requests)} requests"
    ]
    if share_pct is not None:
        parts.append(f"/ {_format_pct(share_pct)} of {share_basis}")
    if related_targets:
        parts.append(
            f"and appeared in {len(related_targets)} flagged target"
            f"{'' if len(related_targets) == 1 else 's'}"
        )
    if client_ip_targets:
        parts.append(
            f", including {len(client_ip_targets)} client-IP cluster member"
            f"{'' if len(client_ip_targets) == 1 else 's'}"
        )
    sentence = " ".join(parts) + "."
    if flags:
        sentence += f" Observed report flags included {', '.join(flags[:4])}."
    return {
        "requests": requests,
        "requests_display": _format_count(requests),
        "share_pct": share_pct,
        "share_pct_display": _format_pct(share_pct),
        "share_basis": share_basis,
        "flagged_target_count": len(related_targets),
        "client_ip_cluster_count": len(client_ip_targets),
        "anomaly_flags": flags,
        "report_local_behavior_point": sentence,
    }


def observed_asns(
    actors_artifact: dict,
    suspicious_targets: list[dict],
) -> list[str]:
    """Return normalized ASNs observed in rankings or flagged targets."""
    asns = set(_ranking_rows_by_asn(actors_artifact))
    for target in suspicious_targets:
        asn = _target_asn(target)
        if asn:
            asns.add(asn)
    return sorted(asns, key=lambda value: int(value))
