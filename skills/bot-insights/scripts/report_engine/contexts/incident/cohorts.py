"""Joint client_ip × user_agent cohort overlap / topology computations."""

from __future__ import annotations

from .formatters import _safe_number

__all__ = [
    'COHORT_DISJOINT_OVERLAP_FLOOR_PCT',
    '_compute_actor_cohort_overlap',
    '_compute_actor_cohort_topology',
]


COHORT_DISJOINT_OVERLAP_FLOOR_PCT = 5.0


def _flagged_set(suspicious_targets: list[dict], target_type: str) -> set[str]:
    return {
        t.get("target_value")
        for t in suspicious_targets
        if t.get("target_type") == target_type and t.get("target_value")
    }


def _flagged_ranking_total(ranking: dict | None, flagged: set[str]) -> int:
    return sum(
        int(_safe_number(row.get("requests")) or 0)
        for row in (ranking or {}).get("rows") or []
        if str(row.get("value") or "") in flagged
    )


def _joint_flagged_requests(
    cells: list[dict], flagged_ips: set[str], flagged_uas: set[str]
) -> int:
    """Sum joint-IP×UA cell requests where both axes are in the flagged sets."""
    total = 0
    for cell in cells:
        reqs = int(_safe_number(cell.get("requests")) or 0)
        if reqs <= 0:
            continue
        ip = str(cell.get("ip") or cell.get("client_ip") or "")
        ua = str(cell.get("ua") or cell.get("user_agent") or "")
        if ip in flagged_ips and ua in flagged_uas:
            total += reqs
    return total


def _find_ranking(actors_artifact: dict, field: str) -> dict | None:
    rankings = (actors_artifact or {}).get("actor_rankings") or []
    return next((r for r in rankings if r.get("field") == field), None)


def _resolve_flagged_totals(
    suspicious_targets: list[dict], actors_artifact: dict
) -> tuple[set[str], set[str], list[dict], int, int] | None:
    """Resolve the inputs ``_compute_actor_cohort_overlap`` needs, or
    ``None`` when overlap can't be computed (any input missing /
    empty)."""
    flagged_ips = _flagged_set(suspicious_targets, "client_ip")
    flagged_uas = _flagged_set(suspicious_targets, "user_agent")
    if not flagged_ips or not flagged_uas:
        return None
    cells = (actors_artifact or {}).get("actor_cooccurrence", {}).get(
        "client_ip__user_agent"
    ) or []
    if not cells:
        return None
    ip_ranking = _find_ranking(actors_artifact, "client_ip")
    ua_ranking = _find_ranking(actors_artifact, "user_agent")
    if ip_ranking is None or ua_ranking is None:
        return None
    flagged_ip_total = _flagged_ranking_total(ip_ranking, flagged_ips)
    flagged_ua_total = _flagged_ranking_total(ua_ranking, flagged_uas)
    if flagged_ip_total == 0 or flagged_ua_total == 0:
        return None
    return flagged_ips, flagged_uas, cells, flagged_ip_total, flagged_ua_total


def _compute_actor_cohort_overlap(
    suspicious_targets: list[dict],
    actors_artifact: dict,
) -> dict | None:
    """Bidirectional overlap between flagged client_ip and user_agent cohorts.

    Returns ``None`` when overlap can't be computed (one side empty, or
    the actors artifact has no ``actor_cooccurrence.client_ip__user_agent``
    payload). When both cohorts are populated, returns:

    - ``forward_pct``: of flagged-IP traffic, share that used a flagged UA
    - ``reverse_pct``: of flagged-UA traffic, share that came from a flagged IP
    - ``joint_requests``: requests in cells where both axes are flagged
    - ``flagged_ip_requests``: total flagged-IP traffic (from the client_ip
      ranking — across every UA the IP used, not just cells in the
      cooccurrence payload).
    - ``flagged_ua_requests``: total flagged-UA traffic (from the user_agent ranking)
    - ``is_disjoint``: True when forward AND reverse < ``COHORT_DISJOINT_OVERLAP_FLOOR_PCT``

    Denominators come from the marginal rankings rather than the joint
    cells, so the math stays correct even when the producer scopes the
    cooccurrence payload to ``top_K_ips × top_K_uas`` (a small, bounded
    set) instead of shipping every cell. The flagged sets are subsets
    of the top-K rankings by construction, so the numerator computed
    from the joint cells is complete.

    The disjoint case is the analytically interesting one — it signals
    the IP and UA heuristics are catching two separate attack populations
    hitting the same target, not one cohort viewed from two angles.
    """
    resolved = _resolve_flagged_totals(suspicious_targets, actors_artifact)
    if resolved is None:
        return None
    flagged_ips, flagged_uas, cells, flagged_ip_total, flagged_ua_total = resolved

    joint_total = _joint_flagged_requests(cells, flagged_ips, flagged_uas)
    forward_pct = 100.0 * joint_total / flagged_ip_total
    reverse_pct = 100.0 * joint_total / flagged_ua_total
    return {
        "forward_pct": round(forward_pct, 2),
        "reverse_pct": round(reverse_pct, 2),
        "joint_requests": joint_total,
        "flagged_ip_requests": flagged_ip_total,
        "flagged_ua_requests": flagged_ua_total,
        "flagged_ip_count": len(flagged_ips),
        "flagged_ua_count": len(flagged_uas),
        "is_disjoint": (
            forward_pct < COHORT_DISJOINT_OVERLAP_FLOOR_PCT
            and reverse_pct < COHORT_DISJOINT_OVERLAP_FLOOR_PCT
        ),
    }


def _compute_actor_cohort_topology(cohort_overlap: dict | None) -> dict | None:
    """Project the cohort-overlap helper output into the SOAR-facing
    topology block embedded at the IOC export's top level.

    A SOAR consumer reading only ``indicators[]`` can't see Finding 03
    (it's rendered prose, not machine-readable). The topology block
    surfaces the same disjoint-vs-aligned signal so the consumer can
    branch its mitigation policy on a boolean rather than parsing
    the editorial body. Returns ``None`` when overlap can't be
    computed (one cohort empty, or no joint cell payload).
    """
    if not cohort_overlap:
        return None
    disjoint = bool(cohort_overlap.get("is_disjoint"))
    if disjoint:
        interpretation = (
            "Flagged IPs and flagged UAs target the same window from "
            "separate populations — apply mitigations independently."
        )
    else:
        interpretation = (
            "Flagged IPs and flagged UAs overlap meaningfully — "
            "consider composing them into a single mitigation rule."
        )
    return {
        "client_ip_user_agent": {
            "forward_overlap_pct": cohort_overlap.get("forward_pct"),
            "reverse_overlap_pct": cohort_overlap.get("reverse_pct"),
            "joint_requests": cohort_overlap.get("joint_requests"),
            "flagged_ip_requests": cohort_overlap.get("flagged_ip_requests"),
            "flagged_ua_requests": cohort_overlap.get("flagged_ua_requests"),
            "flagged_ip_count": cohort_overlap.get("flagged_ip_count"),
            "flagged_ua_count": cohort_overlap.get("flagged_ua_count"),
            "disjoint": disjoint,
            "interpretation": interpretation,
        }
    }
