"""Edge-action aggregation for client-IP indicators."""

from __future__ import annotations

from ..formatters import _format_pct, _safe_number
from ..labels import _EDGE_ACTION_LABELS


def _sum_edge_action_cells(cells: list[dict], ip_value: str) -> dict[str, int]:
    """Bucket per-action request totals across the joint cells for a
    single IP. Skips cells without an action or with non-positive
    request counts."""
    bucket: dict[str, int] = {}
    for cell in cells:
        if str(cell.get("ip") or "") != ip_value:
            continue
        action = str(cell.get("action") or "").strip()
        reqs = int(_safe_number(cell.get("requests")) or 0)
        if not action or reqs <= 0:
            continue
        bucket[action] = bucket.get(action, 0) + reqs
    return bucket


def _compute_edge_action_for_indicator(
    target: dict, actors_artifact: dict | None
) -> dict | None:
    """Aggregate the per-IP edge-action share for a client_ip indicator.

    Reads the ``client_ip__action_applied`` cooccurrence cells produced
    by the Step 4c joint GROUP BY. Returns ``None`` when the indicator
    is not an IP, or the cooccurrence payload is absent, or no cells
    matched this IP.

    Output shape:
      - ``denied_share`` / ``monitored_share`` / ``passed_share``:
        floats in ``[0, 1]`` measured against the per-IP request total
        observed across the joint cells (denominator is the sum of all
        action cells for this IP, NOT the marginal ranking total —
        the joint query is scoped to top-K candidates so the marginal
        and joint sums match for actors in the top-K set).
      - ``top_action``: the raw Akamai action_applied value with the
        largest share (e.g. ``"Deny"``).
      - ``top_action_label``: human display of ``top_action``
        (``"Denied"``, ``"Monitored"``, ``"Passed"``).
      - ``top_action_share``: share for ``top_action``.
    """
    if (target.get("target_type") or "") != "client_ip":
        return None
    target_value = str(target.get("target_value") or "")
    if not target_value:
        return None
    cells = (actors_artifact or {}).get("actor_cooccurrence", {}).get(
        "client_ip__action_applied"
    ) or []
    bucket = _sum_edge_action_cells(cells, target_value)
    total = sum(bucket.values())
    if total <= 0:
        return None
    top_action, top_count = max(bucket.items(), key=lambda kv: kv[1])
    return {
        "denied_share": round(bucket.get("Deny", 0) / total, 4),
        "monitored_share": round(bucket.get("Monitor", 0) / total, 4),
        "passed_share": round(bucket.get("Allow", 0) / total, 4),
        "top_action": top_action,
        "top_action_label": _EDGE_ACTION_LABELS.get(top_action, top_action),
        "top_action_share": round(top_count / total, 4),
    }


def _edge_action_display_fields(
    edge_action: dict | None,
) -> tuple[str | None, str | None]:
    """Return ``(top_label, top_share_display)`` from a per-IP edge_action dict."""
    if not edge_action:
        return None, None
    return (
        edge_action.get("top_action_label"),
        _format_pct(round(100.0 * edge_action["top_action_share"], 2)),
    )
