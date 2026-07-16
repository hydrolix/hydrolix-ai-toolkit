"""Security-rule evidence cards + ordered ranking."""

from __future__ import annotations

from ... import scorecards as scorecards_mod
from ... import verdicts as verdicts_mod
from ...theme import DOMAIN_LABELS
from .._shared import _feature_row

from .entity_view import _entity_display

__all__ = [
    '_SECURITY_RULE_ORDER',
    '_security_evidence_cards',
    '_sort_security_rules',
]


_SECURITY_RULE_ORDER = (
    "bad_bot_share_high",
    "siem_auth_fail_present",
    "siem_blocked_present",
    "siem_authfail_blocked_concentration",
)


_ACTIONABLE_STATES = frozenset({"assign", "watch"})
_STATE_RANK = {"assign": 0, "watch": 1}


def _split_triggered_rules(triggered: list[dict]) -> tuple[list[dict], list[dict]]:
    """Partition triggered rules into (security_evidence_rules, other_rules)."""
    sec = [r for r in triggered if r.get("domain") == "security_evidence"]
    other = [r for r in triggered if r.get("domain") != "security_evidence"]
    return sec, other


def _build_security_card(
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
    sec_rules, other_rules = _split_triggered_rules(triggered)
    sec_features = [_feature_row(r) for r in _sort_security_rules(sec_rules)]
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
        "security_features": sec_features,
        "other_features": other_features,
        "confidence_chip": confidence_chip,
        "evidence_summary": sc.get("evidence_summary") or [],
    }


def _security_evidence_cards(
    scorecards: list[dict],
    verdicts_by_entity: dict[str, dict],
    rank_lookup: dict[str, int],
    entity_type: str,
) -> list[dict]:
    """Per-entity card for each Assign or Watch entity.

    Each card foregrounds the security_evidence domain — the rules whose
    triggers tell the analyst what to investigate first — then lists
    adjacent triggered features (movement, etc.) below as supporting
    context. Closed-as-expected and Insufficient entities are omitted;
    the queue table covers them.
    """
    cards: list[dict] = []
    for sc in scorecards:
        verdict = verdicts_by_entity.get(sc["entity"])
        if not verdict or verdict["state"] not in _ACTIONABLE_STATES:
            continue
        card = _build_security_card(sc, verdict, rank_lookup, entity_type)
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


def _sort_security_rules(rules: list[dict]) -> list[dict]:
    """Stable order for the security_evidence rule list inside a card.

    Rules listed in ``_SECURITY_RULE_ORDER`` come first in that order;
    anything else falls in by points descending so a high-points novel
    rule still surfaces near the top.
    """
    priority = {name: i for i, name in enumerate(_SECURITY_RULE_ORDER)}
    return sorted(
        rules,
        key=lambda r: (
            priority.get(r.get("name") or "", len(_SECURITY_RULE_ORDER)),
            -(r.get("points") or 0),
            r.get("name") or "",
        ),
    )
