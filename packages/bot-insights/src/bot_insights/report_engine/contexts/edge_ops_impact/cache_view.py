"""Edge-rule evidence cards + cache/origin rule ordering."""

from __future__ import annotations

from ... import scorecards as scorecards_mod
from ... import verdicts as verdicts_mod
from ...theme import DOMAIN_LABELS
from .._shared import _feature_row

from .entity_view import _entity_display

__all__ = [
    '_EDGE_RULE_ORDER',
    '_edge_evidence_cards',
    '_sort_edge_rules',
]


_EDGE_RULE_ORDER = (
    "origin_cost_contribution_high",
    "origin_p95_delta_high",
    "cache_miss_rate_high",
    "cache_miss_delta_high",
    "querystring_diversity_with_high_miss_rate",
    "querystring_diversity_high",
)


_EDGE_DOMAINS = frozenset({"cache_busting", "origin_impact"})
_ACTIONABLE_STATES = frozenset({"assign", "watch"})
_STATE_RANK = {"assign": 0, "watch": 1}


def _split_triggered_rules(triggered: list[dict]) -> tuple[list[dict], list[dict]]:
    """Partition triggered rules into (edge_domain_rules, other_rules)."""
    edge = [r for r in triggered if r.get("domain") in _EDGE_DOMAINS]
    other = [r for r in triggered if r.get("domain") not in _EDGE_DOMAINS]
    return edge, other


def _build_evidence_card(
    sc: dict,
    verdict: dict,
    rank_lookup: dict[str, int],
    entity_type: str,
) -> dict | None:
    """Project one scorecard into an evidence card, or ``None`` when
    the entity has no triggered rules."""
    triggered = [
        r for r in scorecards_mod.normalize_rule_results(sc)
        if r.get("status") == "triggered"
    ]
    if not triggered:
        return None
    edge_rules, other_rules = _split_triggered_rules(triggered)
    edge_features = [_feature_row(r) for r in _sort_edge_rules(edge_rules)]
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
        "edge_features": edge_features,
        "other_features": other_features,
        "confidence_chip": confidence_chip,
        "evidence_summary": sc.get("evidence_summary") or [],
    }


def _edge_evidence_cards(
    scorecards: list[dict],
    verdicts_by_entity: dict[str, dict],
    rank_lookup: dict[str, int],
    entity_type: str,
) -> list[dict]:
    """Per-entity card for each Assign or Watch entity.

    Each card foregrounds the cache_busting and origin_impact domains —
    the rules whose triggers tell the analyst what to investigate — then
    lists adjacent triggered features below as supporting context.
    Closed-as-expected and Insufficient entities are omitted; the queue
    table covers them.
    """
    cards: list[dict] = []
    for sc in scorecards:
        verdict = verdicts_by_entity.get(sc["entity"])
        if not verdict or verdict["state"] not in _ACTIONABLE_STATES:
            continue
        card = _build_evidence_card(sc, verdict, rank_lookup, entity_type)
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


def _sort_edge_rules(rules: list[dict]) -> list[dict]:
    priority = {name: i for i, name in enumerate(_EDGE_RULE_ORDER)}
    return sorted(
        rules,
        key=lambda r: (
            priority.get(r.get("name") or "", len(_EDGE_RULE_ORDER)),
            -(r.get("points") or 0),
            r.get("name") or "",
        ),
    )
