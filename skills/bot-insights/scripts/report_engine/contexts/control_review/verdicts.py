"""Classification thresholds + side-effect verdict logic."""

from __future__ import annotations

from .formatters import _maybe_float

__all__ = [
    '_OVERSHOOT_PCT',
    '_UNDER_DELIVERED_PCT',
    '_classify_verdict',
    '_any_side_effect_moved',
    '_has_missing_side_effect_deltas',
    '_side_effect_note',
]


_OVERSHOOT_PCT = 50.0


_UNDER_DELIVERED_PCT = 25.0


def _classify_verdict(
    dominant: dict,
    collateral_checks: list[dict],
    displacement_checks: list[dict],
) -> tuple[str, str, str]:
    """Return ``(verdict_id, headline_phrase, recommendation)``.

    Five outcomes:
    - ``inconclusive`` — dominant effect has no delta vs expected.
    - ``side_effects_flagged`` — dominant tracks expected (within
      ``_UNDER_DELIVERED_PCT``) but collateral or displacement moved.
    - ``on_target`` — dominant tracks expected and no side effects moved.
    - ``overshoot`` — dominant pct vs expected exceeds ``_OVERSHOOT_PCT``.
    - ``under_delivered`` — dominant pct vs expected is below
      ``-_UNDER_DELIVERED_PCT``.
    """
    pct = _maybe_float(dominant.get("pct_change_vs_expected"))
    if pct is None:
        return (
            "inconclusive",
            "Inconclusive",
            "Regenerate evidence with comparable windows and a populated "
            "expected basis before deciding next steps.",
        )

    side_effects_moved = _any_side_effect_moved(
        collateral_checks, displacement_checks
    )

    if pct > _OVERSHOOT_PCT:
        return (
            "overshoot",
            "Overshoot vs expected",
            "Investigate the magnitude before letting the control ride; "
            "consider rolling back or tightening if side effects are "
            "material.",
        )
    if pct < -_UNDER_DELIVERED_PCT:
        return (
            "under_delivered",
            "Under-delivered vs expected",
            "Verify the control reached the intended traffic; tune or "
            "extend the policy if the gap is operationally meaningful.",
        )
    if side_effects_moved:
        return (
            "side_effects_flagged",
            "On expected magnitude with side effects",
            "Monitor — confirm collateral / displacement movement is within "
            "tolerance before extending or widening the control.",
        )
    return (
        "on_target",
        "On target",
        "Continue monitoring; no immediate action required if side-effect "
        "checks remain clean.",
    )


def _any_side_effect_moved(
    collateral_checks: list[dict],
    displacement_checks: list[dict],
) -> bool:
    """True when any collateral or displacement row reports a non-flat
    ``status`` (e.g. ``increased`` / ``decreased``).

    Used by the verdict classifier to flag side effects regardless of
    whether the producer emitted numeric deltas.
    """
    for row in (*collateral_checks, *displacement_checks):
        status = (row.get("status") or "").lower()
        if status and status not in {"unchanged", "stable", "flat", ""}:
            return True
    return False


def _has_missing_side_effect_deltas(
    collateral_checks: list[dict],
    displacement_checks: list[dict],
) -> bool:
    """True when any collateral / displacement row has a movement status
    but the numeric delta is unavailable. Used to qualify the caveat.
    """
    for row in (*collateral_checks, *displacement_checks):
        status = (row.get("status") or "").lower()
        if status and status not in {"unchanged", "stable", "flat", ""}:
            if row.get("delta") is None and row.get("pct_change") is None:
                return True
    return False


_UNCHANGED_STATUSES = frozenset({"unchanged", "stable", "flat", ""})


def _moved_checks(checks: list[dict]) -> list[dict]:
    return [
        r for r in checks
        if (r.get("status") or "").lower() not in _UNCHANGED_STATUSES
    ]


def _moved_clause(checks: list[dict], label: str) -> str | None:
    if not checks:
        return None
    plural = "s" if len(checks) != 1 else ""
    return f"{len(checks)} {label} check{plural} moved"


def _side_effect_note(
    collateral_checks: list[dict],
    displacement_checks: list[dict],
) -> str:
    """One-line summary of side-effect movement for the body paragraph."""
    candidates = [
        _moved_clause(_moved_checks(collateral_checks), "collateral"),
        _moved_clause(_moved_checks(displacement_checks), "displacement"),
    ]
    parts = [c for c in candidates if c]
    if not parts:
        return ""
    return "Side-effect checks: " + " and ".join(parts) + "."
