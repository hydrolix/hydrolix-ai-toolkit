"""Per-indicator seen-at and seen-with scope views."""

from __future__ import annotations

from .constants import _IOC_SCOPE_VIEW_TOP_N
from .edge_actions import _compute_edge_action_for_indicator
from .provenance import _compute_provenance_for_indicator
from ..formatters import _safe_number


def _ranking_marginal_total(
    ranking_by_field: dict, field: str, value: str
) -> int:
    ranking = ranking_by_field.get(field) or {}
    for row in ranking.get("rows") or []:
        if str(row.get("value") or "") == value:
            return int(_safe_number(row.get("requests")) or 0)
    return 0


def _top_counterparties(
    cells: list[dict],
    key_self: str,
    key_other: str,
    self_value: str,
    denom_total: int,
    other_type_label: str,
    top_n: int,
) -> list[dict]:
    """Aggregate ``cells`` where ``key_self == self_value``, sum by
    ``key_other``, return the top-N entries with shares against
    ``denom_total``."""
    bucket: dict[str, int] = {}
    for cell in cells:
        if str(cell.get(key_self) or "") != self_value:
            continue
        other = str(cell.get(key_other) or "")
        reqs = int(_safe_number(cell.get("requests")) or 0)
        if not other or reqs <= 0:
            continue
        bucket[other] = bucket.get(other, 0) + reqs
    sorted_pairs = sorted(bucket.items(), key=lambda kv: -kv[1])
    return [
        {
            "type": other_type_label,
            "value": other_value,
            "requests": reqs,
            "share": round(reqs / denom_total if denom_total > 0 else 0.0, 4),
        }
        for other_value, reqs in sorted_pairs[:top_n]
    ]


def _ip_scope_views(
    target_value: str,
    ip_path_cells: list[dict],
    ip_ua_cells: list[dict],
    ip_total: int,
    top_n: int,
) -> dict:
    """``seen_at`` (top paths) + ``seen_with`` (top UAs) for a client_ip indicator."""
    result: dict = {}
    seen_at_paths = _top_counterparties(
        ip_path_cells, "ip", "path", target_value, ip_total, "request_path", top_n,
    )
    if seen_at_paths:
        result["seen_at"] = seen_at_paths
    seen_with_uas = _top_counterparties(
        ip_ua_cells, "ip", "ua", target_value, ip_total, "user_agent", top_n,
    )
    if seen_with_uas:
        result["seen_with"] = seen_with_uas
    return result


def _ua_scope_views(
    target_value: str,
    ip_ua_cells: list[dict],
    ranking_by_field: dict,
    top_n: int,
) -> dict:
    """``seen_with`` (top IPs) for a user_agent indicator."""
    ua_total = _ranking_marginal_total(ranking_by_field, "user_agent", target_value)
    seen_with_ips = _top_counterparties(
        ip_ua_cells, "ua", "ip", target_value, ua_total, "client_ip", top_n,
    )
    return {"seen_with": seen_with_ips} if seen_with_ips else {}


def _path_scope_views(
    target_value: str,
    ip_path_cells: list[dict],
    ranking_by_field: dict,
    top_n: int,
) -> dict:
    """``seen_with`` (top IPs) for a request_path indicator."""
    path_total = _ranking_marginal_total(
        ranking_by_field, "request_path", target_value
    )
    seen_with_ips = _top_counterparties(
        ip_path_cells, "path", "ip", target_value, path_total, "client_ip", top_n,
    )
    return {"seen_with": seen_with_ips} if seen_with_ips else {}


def _extract_scope_view_inputs(
    actors_artifact: dict,
) -> tuple[list[dict], list[dict], dict]:
    """Pluck ``(ip_path_cells, ip_ua_cells, ranking_by_field)`` out of the actors artifact."""
    artifact = actors_artifact or {}
    cooccur = artifact.get("actor_cooccurrence") or {}
    ip_path_cells = cooccur.get("client_ip__request_path") or []
    ip_ua_cells = cooccur.get("client_ip__user_agent") or []
    ranking_by_field = {
        r.get("field"): r
        for r in artifact.get("actor_rankings") or []
        if r.get("field")
    }
    return ip_path_cells, ip_ua_cells, ranking_by_field


def _dispatch_scope_views(
    target_type: str,
    target_value: str,
    ip_path_cells: list[dict],
    ip_ua_cells: list[dict],
    ranking_by_field: dict,
    top_n: int,
) -> dict:
    """Switch on indicator type to compute the matching scope-view block."""
    if target_type == "client_ip":
        ip_total = _ranking_marginal_total(
            ranking_by_field, "client_ip", target_value
        )
        return _ip_scope_views(
            target_value, ip_path_cells, ip_ua_cells, ip_total, top_n,
        )
    if target_type == "user_agent":
        return _ua_scope_views(
            target_value, ip_ua_cells, ranking_by_field, top_n,
        )
    if target_type == "request_path":
        return _path_scope_views(
            target_value, ip_path_cells, ranking_by_field, top_n,
        )
    return {}


def _scope_views_for_indicator(
    target: dict,
    actors_artifact: dict,
    top_n: int = _IOC_SCOPE_VIEW_TOP_N,
) -> dict:
    """Project per-indicator ``seen_at`` / ``seen_with`` from the
    actor_cooccurrence cells.

    ``seen_at`` (on actor indicators): the top targets the actor was
    observed hitting, ranked by share of the actor's own request total.
    Lets a SOAR scope a block to a specific path instead of site-wide.

    ``seen_with`` (on indicators of either side): the top counterparty
    entities seen with this one. For an actor: top targets if path
    cooccurrence is available, else top counterparty actors. For a
    target: top actors hitting it. Lets a SOAR pair indicator-level
    actions across the actor / target axis.

    All shares use the marginal rankings as the denominator (per-entity
    total across the full window), not the cooccurrence cells alone —
    so a row's ``share_of_actor_traffic = 0.91`` is honestly
    "91% of this IP's window traffic went to this path" not "91% of
    the IP's traffic-into-the-top-K-paths."
    """
    target_value = str(target.get("target_value") or "")
    if not target_value:
        return {}
    ip_path_cells, ip_ua_cells, ranking_by_field = _extract_scope_view_inputs(
        actors_artifact
    )
    result = _dispatch_scope_views(
        target.get("target_type") or "",
        target_value, ip_path_cells, ip_ua_cells, ranking_by_field, top_n,
    )
    edge_action = _compute_edge_action_for_indicator(target, actors_artifact)
    if edge_action:
        result["edge_action"] = edge_action
    provenance = _compute_provenance_for_indicator(target, actors_artifact)
    if provenance:
        result["provenance"] = provenance
    return result
