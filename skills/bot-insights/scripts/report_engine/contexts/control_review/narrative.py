"""Headline / dek / findings narrative builders."""

from __future__ import annotations

from ...findings import Finding

from .formatters import (
    _maybe_float,
    _short_window,
)
from .labels import _expected_basis_label
from .verdicts import (
    _classify_verdict,
    _has_missing_side_effect_deltas,
    _side_effect_note,
)

__all__ = [
    '_headline',
    '_dek',
    '_findings',
]


def _headline(target_descriptor: str, cluster_label: str, after: dict) -> str:
    after_short = _short_window(after)
    pieces = ["Control Review"]
    if target_descriptor:
        pieces.append(f"— {target_descriptor}")
    if cluster_label:
        pieces.append(f"· {cluster_label}")
    if after_short and after_short != "n/a":
        pieces.append(f"· window ending {after_short}")
    return " ".join(pieces)


def _dek(effects: list[dict], target_descriptor: str) -> str:
    """One-sentence elevator pitch for the report. Always grounded in
    what's measurable from the artifact alone — no causal claim."""
    if not effects:
        return (
            "No target effects recorded for this control. "
            "Inspect the artifact metadata below for the windows compared."
        )
    n = len(effects)
    metric_word = "metric" if n == 1 else "metrics"
    target_clause = f" for {target_descriptor}" if target_descriptor else ""
    return (
        f"Effectiveness review across {n} {metric_word}{target_clause}, "
        "comparing the after-window against the expected baseline."
    )


def _no_effects_finding() -> Finding:
    return Finding(
        finding_id="control_review_no_effects",
        title="No effects to report",
        headline="No target effects were emitted for this control",
        body=(
            "The artifact carries no target_effects. Inspect the "
            "windows compared and the expected basis below."
        ),
        recommendation=(
            "Regenerate evidence with non-empty effects, or document "
            "why effects could not be computed."
        ),
        caveat=(
            "Cannot claim the control caused or failed to cause "
            "movement without measurable effects."
        ),
    )


def _delta_clause(dominant: dict) -> str:
    parts: list[str] = []
    delta = dominant.get("absolute_delta_vs_expected")
    pct = dominant.get("pct_change_vs_expected")
    if delta is not None:
        parts.append(f"absolute delta {delta:+.2f} vs expected")
    if pct is not None:
        parts.append(f"{pct:+.2f}% vs expected")
    return "; ".join(parts)


def _build_headline(
    dominant: dict, target_descriptor: str, verdict_phrase: str
) -> str:
    metric_label = dominant.get("metric_label") or dominant.get("metric") or "metric"
    target_clause = f" for {target_descriptor}" if target_descriptor else ""
    head = f"{verdict_phrase} on {metric_label}{target_clause}"
    delta_clause = _delta_clause(dominant)
    if delta_clause:
        return head + f" ({delta_clause})"
    return head


def _build_body(
    expected_basis: str | None,
    collateral_checks: list[dict],
    displacement_checks: list[dict],
) -> str:
    parts = [
        "Movement compared against the expected baseline. Per-metric "
        "direction and magnitude appear in the effects table below."
    ]
    if expected_basis:
        parts.append(
            f"Expected basis: {_expected_basis_label(expected_basis).lower()}."
        )
    side_effect_note = _side_effect_note(collateral_checks, displacement_checks)
    if side_effect_note:
        parts.append(side_effect_note)
    return " ".join(parts)


def _build_caveat(
    collateral_checks: list[dict], displacement_checks: list[dict]
) -> str:
    parts = [
        "Movement is descriptive, not causal — concurrent changes can "
        "confound the read."
    ]
    if _has_missing_side_effect_deltas(collateral_checks, displacement_checks):
        parts.append(
            "Collateral or displacement deltas are unavailable; side-effect "
            "magnitude cannot be quantified from this evidence alone."
        )
    return " ".join(parts)


def _findings(
    effects: list[dict],
    target_descriptor: str,
    expected_basis: str | None,
    collateral_checks: list[dict] | None = None,
    displacement_checks: list[dict] | None = None,
) -> list[Finding]:
    """Build the executive-summary findings list.

    Headline names the deterministic verdict — *on target*, *overshoot*,
    *under-delivered*, *side effects flagged*, or *inconclusive* — derived
    from |pct vs expected| on the dominant effect plus any movement in
    collateral / displacement checks. Recommendation routes to a concrete
    outcome (continue / monitor / investigate or roll back / regenerate
    evidence).
    """
    if not effects:
        return [_no_effects_finding()]

    coll = collateral_checks or []
    disp = displacement_checks or []
    dominant = max(
        effects,
        key=lambda e: abs(_maybe_float(e.get("absolute_delta_vs_expected")) or 0.0),
    )
    verdict, verdict_phrase, recommendation = _classify_verdict(dominant, coll, disp)
    return [
        Finding(
            finding_id=f"control_review_{verdict}",
            title="Verdict",
            headline=_build_headline(dominant, target_descriptor, verdict_phrase),
            body=_build_body(expected_basis, coll, disp),
            recommendation=recommendation,
            caveat=_build_caveat(coll, disp),
        )
    ]
