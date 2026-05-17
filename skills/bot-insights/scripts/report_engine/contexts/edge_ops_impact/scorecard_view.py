"""Coverage, domain-score matrix, and entity-actions builders."""

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
    """Coverage rows for edge_ops_impact. Always lead with ``cache_busting``
    and ``origin_impact``, then any domain that contributed evaluations.
    """
    rows: list[dict] = []
    lead_domains = ["cache_busting", "origin_impact"]
    ordered_domains = lead_domains + [d for d in DOMAIN_ORDER if d not in lead_domains]
    for domain in ordered_domains:
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


def _scored_domains(scorecards: list[dict]) -> set[str]:
    """Domains with at least one positive ``domain_scores`` entry across scorecards."""
    out: set[str] = set()
    for sc in scorecards:
        for domain, value in (sc.get("domain_scores") or {}).items():
            try:
                if float(value) > 0:
                    out.add(domain)
            except (TypeError, ValueError):
                continue
    return out


def _active_domains(
    scorecards: list[dict], coverage: dict[str, dict[str, int]]
) -> list[str]:
    """Pick the matrix's column set: always the edge domains, plus any
    other domain that scored or had a triggered rule."""
    active = {"cache_busting", "origin_impact"} | _scored_domains(scorecards)
    for domain, entry in coverage.items():
        if entry.get("triggered", 0):
            active.add(domain)
    domains = [d for d in DOMAIN_ORDER if d in active]
    return domains or ["cache_busting", "origin_impact"]


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
    coverage: dict[str, dict[str, int]],
) -> dict:
    """Entities × domains grid of per-cell point totals.

    Always includes the edge domains; also includes any other domain that
    actually scored.
    """
    domains = _active_domains(scorecards, coverage)
    rows = [_matrix_row(sc, domains, rank_lookup, entity_type) for sc in scorecards]
    rows.sort(key=lambda r: (-(r.get("score") or 0), r.get("rank") or 999))
    return {
        "domains": [
            {"domain": d, "domain_label": DOMAIN_LABELS.get(d, d)} for d in domains
        ],
        "rows": rows,
    }


def _entity_actions(scorecards: list[dict], entity_type: str) -> list[dict]:
    aggregated = _aggregate_actions(scorecards)
    out: list[dict] = []
    for action in aggregated:
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
