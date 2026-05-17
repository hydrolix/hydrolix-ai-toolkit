"""Suspicious-target row builders + per-indicator scope qualifiers."""

from __future__ import annotations

import sys
from pathlib import Path

# Make ``config`` (under scripts/) importable when this module is loaded
# from report_engine.contexts.incident.
_SCRIPTS_DIR = Path(__file__).resolve().parents[4]
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

from config import DEFAULT_THRESHOLDS  # noqa: E402

from .findings import _finding_entity
from .formatters import (
    _format_count,
    _format_int,
    _format_pct,
    _safe_number,
)
from .labels import (
    ACTION_CLASS_LABELS,
    ACTION_CLASS_TONE,
    REASON_FLAG_LABELS,
    SEVERITY_TONE,
    TARGET_TYPE_LABELS,
    _EDGE_ACTION_LABELS,
)
from .risk import _SEVERITY_ORDER

__all__ = [
    'SUSPICIOUS_TARGETS_DISPLAY_CAP',
    '_IOC_SCOPE_VIEW_TOP_N',
    '_compute_edge_action_for_indicator',
    '_scope_views_for_indicator',
    '_attack_aggregation',
    '_suspicious_targets_view',
]


# Default surfaces here for legacy importers; the renderer reads
# ``active_thresholds().display.suspicious_targets_cap`` at call time
# so a ``--config`` override picks up without re-importing the module.
SUSPICIOUS_TARGETS_DISPLAY_CAP = DEFAULT_THRESHOLDS.display.suspicious_targets_cap


_IOC_SCOPE_VIEW_TOP_N = 3  # entries per seen_at / seen_with list


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
    return result


def _update_attack_tally(tally: dict[str, dict], technique: dict) -> None:
    """Merge one technique into the tally. Prefer the first-seen
    name/tactic; later occurrences with blank fields don't overwrite a
    populated name."""
    tid = technique.get("id") or ""
    if not tid:
        return
    entry = tally.setdefault(
        tid,
        {
            "id": tid,
            "name": technique.get("name") or "",
            "tactic": technique.get("tactic") or "",
            "count": 0,
        },
    )
    if not entry["name"] and technique.get("name"):
        entry["name"] = technique.get("name")
    if not entry["tactic"] and technique.get("tactic"):
        entry["tactic"] = technique.get("tactic")
    entry["count"] += 1


def _attack_aggregation(suspicious_targets: list[dict]) -> list[dict]:
    """Aggregate ATT&CK techniques across the suspicious-target list.

    Iterates every target's ``attack_techniques`` list, dedupes by
    technique id, and tallies how many targets reference each id.
    Output is sorted by ``count desc, id asc`` so the editorial
    "Consistent with" panel reads with the most-referenced techniques
    at the top and ties break alphabetically (deterministic).
    """
    tally: dict[str, dict] = {}
    for target in suspicious_targets or []:
        for technique in target.get("attack_techniques") or []:
            _update_attack_tally(tally, technique)
    return sorted(tally.values(), key=lambda r: (-r["count"], r["id"]))


def _target_sort_key(row: dict) -> tuple[int, float]:
    severity = row.get("severity") or "review"
    severity_rank = _SEVERITY_ORDER.get(severity, 99)
    requests = _safe_number((row.get("supporting") or {}).get("requests")) or 0
    return (severity_rank, -float(requests))


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


def _project_supporting_metrics(supporting: dict) -> dict:
    """Flatten the ``supporting`` dict's numeric fields into display-ready keys."""
    return {
        "requests": _safe_number(supporting.get("requests")),
        "requests_display": _format_count(supporting.get("requests")),
        "share_pct": _safe_number(supporting.get("share_pct")),
        "share_pct_display": _format_pct(supporting.get("share_pct")),
        "req_429": _safe_number(supporting.get("req_429")),
        "req_429_display": _format_count(supporting.get("req_429")),
        "req_429_share_pct": _safe_number(supporting.get("req_429_share_pct")),
        "req_429_share_display": _format_pct(supporting.get("req_429_share_pct")),
        "distinct_paths": _safe_number(supporting.get("distinct_paths")),
        "distinct_paths_display": _format_int(supporting.get("distinct_paths")),
        # Pass the raw supporting dict through (including
        # supporting_extras keys like asn_cluster_id /
        # asn_cluster_org / botnet_cluster_share_pct) so downstream
        # helpers like _finding_entity can annotate entities with
        # cluster context without re-flattening the whole shape into
        # top-level keys.
        "supporting": dict(supporting),
    }


def _target_classification_fields(row: dict) -> dict:
    """Project the classification fields (target type / severity / kind /
    action class) into renderer-ready key+label pairs."""
    target_type = row.get("target_type") or ""
    severity = row.get("severity") or "review"
    kind = row.get("kind") or "actor"
    action_class = row.get("action_class") or "watch"
    return {
        "target_type": target_type,
        "target_type_label": TARGET_TYPE_LABELS.get(
            target_type, target_type.replace("_", " ").title()
        ),
        "kind": kind,
        "kind_label": kind.title(),
        "action_class": action_class,
        "action_class_label": ACTION_CLASS_LABELS.get(
            action_class, action_class.replace("-", " ").title()
        ),
        "action_class_tone": ACTION_CLASS_TONE.get(action_class, "watch"),
        "severity": severity,
        "severity_tone": SEVERITY_TONE.get(severity, "observe"),
        "severity_label": severity.title(),
    }


def _target_flag_fields(row: dict) -> dict:
    """Project the reason-flag / attack-technique lists into renderer-ready shape."""
    flags = list(row.get("reason_flags") or [])
    attack_techniques = list(row.get("attack_techniques") or [])
    return {
        "reason_flags": flags,
        "reason_flag_labels": [
            REASON_FLAG_LABELS.get(f, f.replace("_", " ")) for f in flags
        ],
        "attack_techniques": attack_techniques,
        "attack_techniques_summary": (
            ", ".join(t.get("id", "") for t in attack_techniques) or "—"
        ),
    }


def _suspicious_target_row(row: dict, actors_artifact: dict | None) -> dict:
    """Project one raw action-target row into the renderer's display shape."""
    edge_action = _compute_edge_action_for_indicator(row, actors_artifact)
    top_label, top_share_display = _edge_action_display_fields(edge_action)
    confidence = row.get("confidence") or ""
    return {
        **_target_classification_fields(row),
        "target_value": str(row.get("target_value") or ""),
        "edge_action": edge_action,
        "edge_action_top_label": top_label,
        "edge_action_top_share_display": top_share_display,
        **_target_flag_fields(row),
        "confidence": confidence,
        "confidence_label": confidence.title(),
        "suggested_action_hint": row.get("suggested_action_hint") or "review",
        **_project_supporting_metrics(row.get("supporting") or {}),
    }


def _suspicious_targets_view(
    action_targets_art: dict,
    actors_artifact: dict | None = None,
) -> list[dict]:
    """Order action-target rows for rendering: severity desc, then requests desc.

    When ``actors_artifact`` is supplied and carries
    ``actor_cooccurrence["client_ip__action_applied"]`` cells, each
    client_ip row is annotated with an ``edge_action`` payload plus
    display-ready ``edge_action_top_label`` /
    ``edge_action_top_share_display`` fields so the template can stack
    a mute "95% Denied" sub-line under the action chip without redoing
    the share math.
    """
    rows = list(action_targets_art.get("targets") or [])
    return [
        _suspicious_target_row(row, actors_artifact)
        for row in sorted(rows, key=_target_sort_key)
    ]
