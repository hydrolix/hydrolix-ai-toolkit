"""Recommended-actions block + per-target action effect copy."""

from __future__ import annotations

__all__ = [
    '_ACTION_URGENCY_NOW',
    '_recommended_actions_view',
    '_action_effect_block',
    '_action_effect_rate_limit',
]


_ACTION_URGENCY_NOW = {"now", "today"}


_ActionTuple = tuple[str, str, str, str | None]  # (step, role, urgency, effect)


def _block_at_edge_action(crit_or_high: list[dict]) -> _ActionTuple | None:
    """Block-at-edge candidate: prefer the top severity:critical ASN, then
    severity:critical IP; fall back to the top high IP so the
    recommendation is always concrete when targets exist."""
    for target in crit_or_high:
        if target.get("target_type") in ("asn", "client_ip"):
            type_label = target.get("target_type_label") or ""
            value = target.get("target_value") or ""
            return (
                f"Block {type_label} `{value}` at edge for 24h, monitor 429 trajectory",
                "SOC",
                "now",
                _action_effect_block(target),
            )
    return None


def _enrich_criticals_action(crits: list[dict]) -> _ActionTuple | None:
    if not crits:
        return None
    names = ", ".join(f"`{t.get('target_value')}`" for t in crits[:3])
    suffix = "" if len(crits) <= 3 else f" (+{len(crits) - 3} more)"
    return (
        f"Enrich the {len(crits)} critical target(s) in case management — {names}{suffix}",
        "Threat Intel",
        "today",
        None,
    )


def _rate_limit_action(
    crit_or_high: list[dict], suspicious_targets: list[dict]
) -> _ActionTuple | None:
    """Tighten rate-limit on the top path pattern flagged as
    severity:critical/high if one exists; otherwise on the most-
    concentrated path target overall."""
    path_target = next(
        (t for t in crit_or_high if t.get("target_type") == "request_path"),
        next(
            (t for t in suspicious_targets if t.get("target_type") == "request_path"),
            None,
        ),
    )
    if path_target is None:
        return None
    path_value = path_target.get("target_value") or ""
    return (
        f"Tighten rate-limit on `{path_value}` to a conservative threshold",
        "Platform",
        "today",
        _action_effect_rate_limit(path_target),
    )


def _investigate_anomalies_action(anomalies: list[dict]) -> _ActionTuple | None:
    if not anomalies:
        return None
    names = ", ".join(
        f"{t.get('target_type_label')} `{t.get('target_value')}`"
        for t in anomalies[:2]
    )
    return (
        f"Investigate behavioral-anomaly cohort — {names}",
        "AppSec",
        "this week",
        None,
    )


def _dashboard_link_action(dashboard_url: str) -> _ActionTuple | None:
    if not dashboard_url:
        return None
    return (
        "Continue investigating in the linked Grafana dashboard (pre-scoped to the incident window)",
        "IR Lead",
        "now",
        None,
    )


_RETROSPECTIVE_ACTION: _ActionTuple = (
    "Schedule retrospective — review SIEM coverage on affected endpoints",
    "IR Lead",
    "this week",
    None,
)


def _severity_buckets(suspicious_targets: list[dict]) -> tuple[list[dict], list[dict], list[dict]]:
    """Return ``(crits, crit_or_high, anomalies)`` sliced from suspicious_targets."""
    crits = [t for t in suspicious_targets if t.get("severity") == "critical"]
    highs = [t for t in suspicious_targets if t.get("severity") == "high"]
    anomalies = [
        t for t in suspicious_targets
        if "behavioral anomaly" in (t.get("reason_flag_labels") or [])
    ]
    return crits, crits + highs, anomalies


def _format_action_row(idx: int, action: _ActionTuple) -> dict:
    step, role, urgency, effect = action
    return {
        "num": f"{idx:02d}",
        "step": step,
        "role": role,
        "urgency": urgency,
        "urgency_tone": "critical" if urgency in _ACTION_URGENCY_NOW else "neutral",
        "effect": effect,
    }


def _recommended_actions_view(
    suspicious_targets: list[dict],
    dashboard_url: str,
    notes_by_slot: dict | None = None,  # noqa: ARG001  (Phase 2 hook)
) -> list[dict]:
    """Deterministic recommended-actions list (Phase 1).

    Builds a 3–5 item ordered list seeded from the top suspicious
    targets, the dashboard link, and a retro reminder. Each item
    carries ``{num, step, role, urgency}``. Phase 2 wires in
    ``notes_by_slot["next_steps"]`` for LLM-authored steps; the
    ``notes_by_slot`` parameter is accepted now so the signature is
    stable across the two phases.

    Item generation rules (in fixed order):
      - First action targets the top severity:critical or severity:high
        IP / ASN if one exists ("Block at edge").
      - Second action enriches the next 1–3 critical / high targets
        ("Enrich in case management") — collapses to a count phrase
        when the list grows.
      - Third action tightens rate-limit on the top path pattern.
      - Fourth action surfaces any behavioral-anomaly targets for
        AppSec.
      - Fifth action is the dashboard link (if available).
      - Sixth action is the post-incident retro reminder (always).

    Result is capped at 5 items. Empty-target inputs collapse to the
    dashboard link + retro pair so the list never collapses below two
    items.
    """
    crits, crit_or_high, anomalies = _severity_buckets(suspicious_targets)
    candidates: list[_ActionTuple | None] = [
        _block_at_edge_action(crit_or_high),
        _enrich_criticals_action(crits),
        _rate_limit_action(crit_or_high, suspicious_targets),
        _investigate_anomalies_action(anomalies),
        _dashboard_link_action(dashboard_url),
        _RETROSPECTIVE_ACTION,
    ]
    actions: list[_ActionTuple] = [a for a in candidates if a is not None]
    return [
        _format_action_row(idx, action)
        for idx, action in enumerate(actions[:5], start=1)
    ]


def _action_effect_block(target: dict) -> str | None:
    """Compose an observed-volume sentence for a block-at-edge action.

    Reads the supporting-metrics fields the suspicious_targets view
    already projects (``requests_display``, ``share_pct_display``,
    ``edge_action_top_label``, ``edge_action_top_share_display``) and
    returns a short sentence the template renders as a mute sub-line
    under the action step. The phrasing is observed-window framing
    ("Observed volume: X"), not predicted reduction — the report does
    not assert what a block will remove, only what the target carried.
    Returns None when no usable supporting metric is present so the
    template can omit the line entirely.
    """
    reqs = target.get("requests_display")
    share = target.get("share_pct_display")
    edge_label = target.get("edge_action_top_label")
    edge_share = target.get("edge_action_top_share_display")
    if not reqs:
        return None
    parts = [f"Observed volume: {reqs}"]
    if share:
        parts[0] = f"Observed volume: {reqs} ({share} of window)"
    parts[0] += "."
    if edge_label and edge_share:
        parts.append(f"Edge currently {edge_share} {edge_label.lower()}.")
    return " ".join(parts)


def _action_effect_rate_limit(target: dict) -> str | None:
    """Compose an observed-volume sentence for a rate-limit action.

    Same observed-window framing as :func:`_action_effect_block` — the
    sentence describes what the target carried during the window, not
    a predicted post-rate-limit reduction.
    """
    reqs = target.get("requests_display")
    share = target.get("share_pct_display")
    distinct_paths = target.get("distinct_paths_display")
    path_value = target.get("target_value") or ""
    if not reqs:
        return None
    label = f"`{path_value}`" if path_value else "flagged path"
    head = f"Observed {label} volume: {reqs}"
    if share:
        head += f" ({share} of window)"
    if distinct_paths and distinct_paths != "—":
        return f"{head}; across {distinct_paths} request paths."
    return f"{head}."
