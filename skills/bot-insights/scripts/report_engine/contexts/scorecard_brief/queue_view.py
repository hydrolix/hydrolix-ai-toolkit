"""Queue ordering + per-entity row builder + lowest-host callout."""

from __future__ import annotations

from ... import scorecards as scorecards_mod
from ... import verdicts as verdicts_mod
from ...theme import DOMAIN_LABELS

__all__ = [
    '_QUEUE_ORDER',
    '_queue_rows',
    '_entity_row',
    '_lowest_host_callout',
    '_lowest_delta_pct',
]


_QUEUE_ORDER = {state: i for i, state in enumerate(verdicts_mod.STATE_ORDER)}


def _queue_rows(entities: list[dict]) -> list[dict]:
    """Sort entities by triage state first, then by score (lowest first),
    then by producer rank as a tiebreaker. Returns the same shape as
    individual entity rows but ordered for action.
    """
    return sorted(
        entities,
        key=lambda e: (
            _QUEUE_ORDER.get(e.get("verdict_state", "watch"), 99),
            e.get("score", 100),
            e.get("rank", 999) if isinstance(e.get("rank"), int) else 999,
        ),
    )


def _entity_row(sc: dict, rank_lookup: dict[str, int]) -> dict:
    triggered_rules = [
        r.get("name") or ""
        for r in scorecards_mod.normalize_rule_results(sc)
        if r.get("status") == "triggered"
    ]
    evidence = sc.get("evidence_summary") or []
    domain_label = DOMAIN_LABELS.get(sc["primary_domain"], sc["primary_domain"])
    delta = sc.get("score_delta_points", 0)
    return {
        "rank": rank_lookup.get(sc["entity"], "—"),
        "entity": sc["entity"],
        # Reader-facing rendering of the entity. The brief reuses the bare
        # identifier (request hosts read fine as-is); SOC overrides with a
        # noun-prefixed form ("ASN 64500") downstream.
        "entity_display": sc["entity"],
        "score": sc["score"],
        "delta": delta,
        "primary_domain": sc["primary_domain"],
        "primary_domain_label": domain_label,
        "band": sc["band"],
        "confidence": sc["confidence"],
        "evidence_top": evidence[0] if evidence else "",
        "triggered_rules": triggered_rules,
    }


def _lowest_host_callout(queue_rows: list[dict]) -> dict | None:
    """Pick the lowest-scoring host from already-sorted queue_rows.

    Returns the entity name, score, and verdict pill data so the brief
    landscape section can render a "Lowest scoring host: X · Score Y ·
    <pill>" callout without forcing the reader through a gauge.
    """
    if not queue_rows:
        return None
    target = min(queue_rows, key=lambda r: r.get("score", 100))
    return {
        "entity": target.get("entity"),
        "score": target.get("score"),
        "verdict_label": target.get("verdict_label"),
        "verdict_tone": target.get("verdict_tone"),
        "verdict_state": target.get("verdict_state"),
    }


def _lowest_delta_pct(scorecards: list[dict]) -> float:
    """Percent change of the lowest-current-score host vs its baseline.

    Uses the per-scorecard `baseline_score` field. Anchors the gauge: the
    big number is the lowest current score; the delta is that same host's
    change vs its prior equivalent window.
    """
    lowest = min(scorecards, key=lambda s: s["score"])
    baseline = lowest.get("baseline_score")
    current = lowest["score"]
    if baseline is None or baseline == 0:
        return 0.0
    return (current - baseline) / baseline * 100
