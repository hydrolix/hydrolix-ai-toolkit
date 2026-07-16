"""SCHEMA / REPORT_TYPE / TEMPLATE / NOTE_ID_TO_SLOT / PURPOSE + assemble + prepare."""

from __future__ import annotations

from datetime import datetime, timezone
from .._shared import select_control_companions

from .effects import (
    _bar_row,
    _check_rows,
    _effect_row,
)
from .formatters import (
    _cluster_label,
    _target_descriptor,
)
from .labels import _expected_basis_label
from .narrative import (
    _dek,
    _findings,
    _headline,
)

__all__ = [
    'SCHEMA',
    'REPORT_TYPE',
    'TEMPLATE',
    'NOTE_ID_TO_SLOT',
    'PURPOSE',
    'assemble',
    'prepare',
]


SCHEMA = "bot_control_review.v1"


REPORT_TYPE = "control_review"


TEMPLATE = "reports/control_review.html"


NOTE_ID_TO_SLOT = {
    "llm-interpretation": "executive_summary",
    "llm-operational": "operational_interpretation",
    "llm-finding-overrides": "finding_overrides",
}


PURPOSE = {
    "report_class_fleet": "Control Review — before/after for an applied control",
    "report_class_single": "Control Review — before/after for an applied control",
    "measures": (
        "Compares the after-control window against an explicit before window "
        "(or external baseline) for the entities targeted by the control."
    ),
    "score_legend": (
        "Per-metric direction and effect size, plus collateral and "
        "displacement checks for adjacent populations."
    ),
    "cant_say": (
        "Cannot claim the control caused the movement without external "
        "change evidence. Concurrent changes can confound the result."
    ),
}


def assemble(artifacts: list[dict]) -> dict:
    """Reshape a ``bot_report_input.v1`` wrapper's artifact list into the
    dict shape :func:`prepare` consumes.

    A wrapper carries one ``bot_control_review.v1`` plus optional
    posture / mover / timeseries companions. Companion compatibility is
    enforced by :func:`select_control_companions`; rejected companions
    surface as warnings on the supplied ``warn`` callable (none here —
    the engine routes warnings via the report renderer's ``ctx``).
    """
    selection = select_control_companions(artifacts)
    return {
        "schema_version": SCHEMA,
        "control": selection["control"],
        "posture": selection["posture"],
        "mover": selection["mover"],
        "timeseries": selection["timeseries"],
    }


def _build_effects(control: dict) -> list[dict]:
    return [
        _effect_row(effect)
        for effect in (control.get("target_effects") or [])
        if isinstance(effect, dict)
    ]


def _build_confidence_reasons(control: dict) -> list[str]:
    return sorted(
        {
            reason
            for effect in (control.get("target_effects") or [])
            if isinstance(effect, dict)
            for reason in (effect.get("confidence_reasons") or [])
        }
    )


def _build_orientation_block() -> dict:
    return {
        "measures": PURPOSE["measures"],
        "score_legend": PURPOSE["score_legend"],
        "cant_say": PURPOSE["cant_say"],
    }


def _build_method_block(control: dict, n_effects: int) -> dict:
    return {
        "schema_version": control.get("schema_version"),
        "comparison_type": control.get("comparison_type"),
        "producer_limit": None,
        "result_row_count": n_effects,
        "result_truncated": False,
        "interpretation_constraints": control.get("interpretation_constraints") or [],
    }


def _build_scope_block(scope: dict, control: dict, cluster_label: str) -> dict:
    return {
        "cluster": scope.get("cluster") or cluster_label,
        "database": scope.get("database") or "",
        "table_used": control.get("table_used") or "",
    }


def _build_check_rows(control: dict) -> tuple[list[dict], list[dict]]:
    return (
        _check_rows(control.get("collateral_checks") or []),
        _check_rows(control.get("displacement_checks") or []),
    )


def prepare(artifact: dict) -> dict:
    """Build the template context for ``reports/control_review.html``.

    The context model mirrors the other report types: ``title``, ``kicker``,
    ``headline``, ``dek`` for the header; ``purpose``/``orientation`` for
    the disclosure strip; ``scope``/``windows``/``method``/``confidence``
    for provenance; and report-specific keys (``target``, ``effects``,
    ``collateral_checks``, ``displacement_checks``, ``expected_basis``)
    for the body.
    """
    control = artifact["control"]
    scope = control.get("scope") or {}
    target = control.get("target") or {}
    target_descriptor = _target_descriptor(target)
    effects = _build_effects(control)
    bar_rows = [row for row in (_bar_row(r) for r in effects) if row is not None]
    collateral_checks, displacement_checks = _build_check_rows(control)
    cluster_label = _cluster_label(scope)
    expected_basis = control.get("expected_basis")
    after = control.get("after_window") or {}

    return {
        "title": "Control Review",
        "kicker": PURPOSE["report_class_single"],
        "headline": _headline(target_descriptor, cluster_label, after),
        "dek": _dek(effects, target_descriptor),
        "purpose": None,
        "orientation": _build_orientation_block(),
        "scope": _build_scope_block(scope, control, cluster_label),
        "windows": {
            "current": after,
            "baseline": control.get("before_window") or {},
            "expected": control.get("expected_window") or {},
        },
        "target": {"descriptor": target_descriptor, "raw": target},
        "effects": effects,
        "control_bars": bar_rows,
        "collateral_checks": collateral_checks,
        "displacement_checks": displacement_checks,
        "expected_basis": expected_basis,
        "expected_basis_label": _expected_basis_label(expected_basis),
        "findings": _findings(
            effects, target_descriptor, expected_basis,
            collateral_checks, displacement_checks,
        ),
        "method": _build_method_block(control, len(effects)),
        "confidence": {"reasons": _build_confidence_reasons(control)},
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    }
