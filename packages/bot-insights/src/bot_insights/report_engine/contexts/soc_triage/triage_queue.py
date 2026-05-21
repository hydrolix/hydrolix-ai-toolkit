"""Coverage table + domain-score matrix + per-entity actions."""

from __future__ import annotations

from ...theme import DOMAIN_LABELS
from ...theme import DOMAIN_ORDER
from .._shared import _matrix_cell_tone
from ..scorecard_brief import _aggregate_actions

from .entity_view import _entity_display

__all__ = [
    '_coverage_rows',
    '_domain_score_matrix',
    '_entity_actions',
]


def _coverage_rows(coverage: dict[str, dict[str, int]]) -> list[dict]:
    rows: list[dict] = []
    for domain in DOMAIN_ORDER:
        counts = coverage.get(domain) or {}
        triggered = counts.get("triggered", 0)
        evaluated_zero = counts.get("evaluated_zero", 0)
        missing = counts.get("missing_input", 0)
        if triggered + evaluated_zero + missing == 0:
            continue
        rows.append(
            {
                "domain": domain,
                "domain_label": DOMAIN_LABELS.get(domain, domain),
                "triggered": triggered,
                "evaluated_zero": evaluated_zero,
                "missing": missing,
            }
        )
    return rows


def _matrix_cell(domain: str, value: object) -> dict:
    int_value = int(value) if isinstance(value, (int, float)) else 0
    return {
        "domain": domain,
        "domain_label": DOMAIN_LABELS.get(domain, domain),
        "value": int_value,
        "tone": _matrix_cell_tone(value),
    }


def _matrix_row(
    sc: dict,
    domains: list[str],
    rank_lookup: dict[str, int],
    entity_type: str,
) -> dict:
    domain_scores = sc.get("domain_scores") or {}
    cells = [_matrix_cell(d, domain_scores.get(d) or 0) for d in domains]
    return {
        "entity": sc.get("entity"),
        "entity_display": _entity_display(sc.get("entity") or "", entity_type),
        "rank": rank_lookup.get(sc.get("entity") or ""),
        "score": sc.get("score"),
        "cells": cells,
    }


def _domain_score_matrix(
    scorecards: list[dict],
    rank_lookup: dict[str, int],
    entity_type: str,
) -> dict:
    """Entities × domains grid of per-cell point totals.

    The grid lets the analyst see the shape of triggered evidence at a
    glance — does the report concentrate on security_evidence, or did
    movement carry weight too? Cells with no points render as a muted
    dash; non-zero cells render as a tinted pill.
    """
    domains = list(DOMAIN_ORDER)
    rows = [_matrix_row(sc, domains, rank_lookup, entity_type) for sc in scorecards]
    rows.sort(key=lambda r: (-(r.get("score") or 0), r.get("rank") or 999))
    return {
        "domains": [
            {"domain": d, "domain_label": DOMAIN_LABELS.get(d, d)} for d in domains
        ],
        "rows": rows,
    }


def _entity_actions(scorecards: list[dict], entity_type: str) -> list[dict]:
    """Per-entity action rows for the inlined "Recommended next steps"
    section.

    Same shape the executive_posture report consumes: each entry carries
    ``summary`` / ``detail`` plus a preview that names the affected
    entity. Aggregation across entities collapses identical recommendations,
    same rule the brief uses.
    """
    aggregated = _aggregate_actions(scorecards)
    out: list[dict] = []
    for action in aggregated:
        # ``preview`` from _aggregate_actions is a comma-joined entity list.
        # For SOC, prepend the entity-type noun so the preview reads
        # "ASN 64500, ASN 64600" rather than the bare numbers.
        host_count = action.get("host_count") or 0
        preview_entities = (action.get("preview") or "").split(",")
        formatted_preview = ", ".join(
            _entity_display(e.strip(), entity_type)
            for e in preview_entities
            if e.strip()
        )
        out.append(
            {
                "summary": action.get("summary"),
                "detail": action.get("detail") or action.get("step"),
                "step": action.get("step") or action.get("detail"),
                "host_count": host_count,
                "preview": formatted_preview,
                "extra": action.get("extra") or 0,
            }
        )
    return out
