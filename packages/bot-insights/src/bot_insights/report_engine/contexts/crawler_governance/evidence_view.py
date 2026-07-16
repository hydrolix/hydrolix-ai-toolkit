"""Coverage, evidence cards, rule ordering, domain-score matrix, actions."""

from __future__ import annotations

from ... import scorecards as scorecards_mod
from ... import verdicts as verdicts_mod
from ...theme import DOMAIN_LABELS
from ...theme import DOMAIN_ORDER
from .._shared import _feature_row
from .._shared import _matrix_cell_tone
from ..scorecard_brief import _aggregate_actions

from .entity_view import _entity_display

__all__ = [
    '_CRAWLER_RULE_ORDER',
    '_coverage_rows',
    '_crawler_evidence_cards',
    '_sort_crawler_rules',
    '_domain_score_matrix',
    '_entity_actions',
]


_CRAWLER_RULE_ORDER = (
    "policy_surface_failure_present",
    "good_bot_429_present",
    "good_bot_error_rate_high",
    "ai_crawler_growth_high",
    "rate_429_delta_high",
    "rate_5xx_delta_high",
)


def _coverage_rows(coverage: dict[str, dict[str, int]]) -> list[dict]:
    """Coverage rows for crawler. Always lead with crawler_governance,
    then any domain that contributed evaluations (triggered, evaluated_zero,
    or missing inputs). Keeps the spotlight on crawler while still
    surfacing secondary-domain context (movement, cache_busting) when the
    producer ranked on ``request_host``.
    """
    rows: list[dict] = []
    ordered_domains = ["crawler_governance"] + [
        d for d in DOMAIN_ORDER if d != "crawler_governance"
    ]
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


_ACTIONABLE_STATES = frozenset({"assign", "watch"})
_STATE_RANK = {"assign": 0, "watch": 1}


def _split_triggered_rules(triggered: list[dict]) -> tuple[list[dict], list[dict]]:
    crawler = [r for r in triggered if r.get("domain") == "crawler_governance"]
    other = [r for r in triggered if r.get("domain") != "crawler_governance"]
    return crawler, other


def _build_crawler_card(
    sc: dict,
    verdict: dict,
    rank_lookup: dict[str, int],
    entity_type: str,
) -> dict | None:
    triggered = [
        r for r in scorecards_mod.normalize_rule_results(sc)
        if r.get("status") == "triggered"
    ]
    if not triggered:
        return None
    crawler_rules, other_rules = _split_triggered_rules(triggered)
    crawler_features = [_feature_row(r) for r in _sort_crawler_rules(crawler_rules)]
    other_features = [
        _feature_row(r) for r in sorted(
            other_rules,
            key=lambda r: (-(r.get("points") or 0), r.get("name") or ""),
        )
    ]
    confidence_chip = verdicts_mod.confidence_chip(scorecards_mod.rule_counts(sc))
    primary_domain = sc.get("primary_domain") or ""
    return {
        "entity": sc["entity"],
        "entity_display": _entity_display(sc["entity"], entity_type),
        "rank": rank_lookup.get(sc["entity"]),
        "score": sc.get("score"),
        "band": sc.get("band"),
        "primary_domain": primary_domain,
        "primary_domain_label": DOMAIN_LABELS.get(primary_domain, primary_domain),
        "verdict_state": verdict["state"],
        "verdict_label": verdict["label"],
        "verdict_tone": verdict["tone"],
        "crawler_features": crawler_features,
        "other_features": other_features,
        "confidence_chip": confidence_chip,
        "evidence_summary": sc.get("evidence_summary") or [],
    }


def _crawler_evidence_cards(
    scorecards: list[dict],
    verdicts_by_entity: dict[str, dict],
    rank_lookup: dict[str, int],
    entity_type: str,
) -> list[dict]:
    """Per-entity card for each Assign or Watch entity.

    Each card foregrounds the crawler_governance domain — the rules
    whose triggers tell the analyst what to investigate first — then
    lists adjacent triggered features (movement, cache_busting, etc.)
    below as supporting context. Closed-as-expected and Insufficient
    entities are omitted; the queue table covers them.
    """
    cards: list[dict] = []
    for sc in scorecards:
        verdict = verdicts_by_entity.get(sc["entity"])
        if not verdict or verdict["state"] not in _ACTIONABLE_STATES:
            continue
        card = _build_crawler_card(sc, verdict, rank_lookup, entity_type)
        if card is not None:
            cards.append(card)
    cards.sort(
        key=lambda c: (
            _STATE_RANK.get(c["verdict_state"], 9),
            -(c.get("score") or 0),
            c.get("rank") or 999,
        )
    )
    return cards


def _sort_crawler_rules(rules: list[dict]) -> list[dict]:
    priority = {name: i for i, name in enumerate(_CRAWLER_RULE_ORDER)}
    return sorted(
        rules,
        key=lambda r: (
            priority.get(r.get("name") or "", len(_CRAWLER_RULE_ORDER)),
            -(r.get("points") or 0),
            r.get("name") or "",
        ),
    )


def _scored_domains(scorecards: list[dict]) -> set[str]:
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
    active = {"crawler_governance"} | _scored_domains(scorecards)
    for domain, entry in coverage.items():
        if entry.get("triggered", 0):
            active.add(domain)
    domains = [d for d in DOMAIN_ORDER if d in active]
    return domains or ["crawler_governance"]


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

    Filters the column set to domains that any entity actually scored
    on, plus crawler_governance regardless. Keeps the matrix dense for
    crawler reports where most domains are zero.
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
