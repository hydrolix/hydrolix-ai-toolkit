"""Origin-cost share helpers + actionable-summary lead clause."""

from __future__ import annotations

from ... import scorecards as scorecards_mod
from ...findings import Finding
from ...humanize import humanize_identifier
from .._shared import _top_assign_card
from .._shared import _traffic_share_clause

from .cache_view import _sort_edge_rules

__all__ = [
    '_cost_share_from_scorecard',
    '_edge_lead_clause',
    '_rule_based_lead_clause',
    '_actionable_summary',
]


def _cost_share_from_scorecard(sc: dict) -> float | None:
    """Extract origin_cost_contribution_pct from the triggered rule.

    Looks on the ``origin_cost_contribution_high`` rule's ``current``
    field, and falls back to ``supporting_metrics.cost_share_pct``.
    Returns None when the rule is absent or the value is not numeric.
    """
    for rule in scorecards_mod.normalize_rule_results(sc):
        if rule.get("name") != "origin_cost_contribution_high":
            continue
        current = rule.get("current")
        if isinstance(current, (int, float)):
            return float(current)
        supporting = rule.get("supporting_metrics") or {}
        val = supporting.get("cost_share_pct")
        if isinstance(val, (int, float)):
            return float(val)
    return None


def _edge_lead_clause(
    sc: dict,
    actionable_scorecards: list[dict],
    path_candidates: list[dict],
) -> str:
    """Lead clause for the executive-summary headline.

    Prefers cost-share when every actionable scorecard carries
    ``origin_cost_contribution_pct``. Falls back to the highest-priority
    triggered edge rule otherwise.

    When path candidates exist, appends a top-path clause when miss_share
    is available.
    """
    # Attempt cost-share lens.
    cost_shares: list[float] = []
    for asc in actionable_scorecards:
        val = _cost_share_from_scorecard(asc)
        if val is None:
            cost_shares = []
            break
        cost_shares.append(val)

    n_assign = len(actionable_scorecards)
    if cost_shares:
        total_pct = sum(cost_shares)
        lead = (
            f"top {n_assign} {'entity' if n_assign == 1 else 'entities'} "
            f"concentrate {total_pct:.0f}% of origin pressure"
        )
    else:
        lead = _rule_based_lead_clause(sc)

    # Append path clause when top path has a miss_share.
    if path_candidates:
        top = path_candidates[0]
        miss_share = top.get("miss_share_pct")
        primary_label = top.get("primary_label") or ""
        if miss_share is not None and primary_label:
            lead += (
                f"; top path {primary_label} carries {miss_share:.0f}% of cache misses"
            )

    return lead


def _select_lead_rule(sc: dict) -> dict | None:
    """Pick the highest-priority triggered edge rule (cache/origin
    domains), falling back to any triggered rule."""
    all_rules = scorecards_mod.normalize_rule_results(sc)
    triggered = [
        r for r in all_rules
        if r.get("status") == "triggered"
        and r.get("domain") in {"cache_busting", "origin_impact"}
    ]
    if not triggered:
        triggered = [r for r in all_rules if r.get("status") == "triggered"]
    if not triggered:
        return None
    return _sort_edge_rules(triggered)[0]


def _rule_clause_for_origin_p95_delta(supporting: dict) -> str:
    pct = supporting.get("pct_change")
    if isinstance(pct, (int, float)):
        return f"origin p95 latency +{int(pct)}%"
    return "origin p95 latency spike"


def _rule_clause_for_cache_miss_delta(supporting: dict) -> str:
    pct = supporting.get("pct_change")
    if isinstance(pct, (int, float)):
        return f"cache-miss rate +{int(pct)}%"
    return "cache-miss rate spike"


def _clause_origin_cost(current: object, _supporting: dict) -> str | None:
    if isinstance(current, (int, float)):
        return f"origin cost contribution {current:g}%"
    return None


def _clause_cache_miss_rate(current: object, _supporting: dict) -> str | None:
    if isinstance(current, (int, float)):
        return f"cache-miss rate {current:g}%"
    return None


def _clause_qs_diversity_high_miss(current: object, _supporting: dict) -> str | None:
    if isinstance(current, (int, float)):
        return f"query-string diversity {int(current)} unique QS with high miss rate"
    return None


def _clause_qs_diversity(current: object, _supporting: dict) -> str | None:
    if isinstance(current, (int, float)):
        return f"query-string diversity {int(current)} unique QS"
    return None


_LEAD_RULE_FORMATTERS = {
    "origin_cost_contribution_high": _clause_origin_cost,
    "origin_p95_delta_high":
        lambda _c, supporting: _rule_clause_for_origin_p95_delta(supporting),
    "cache_miss_rate_high": _clause_cache_miss_rate,
    "cache_miss_delta_high":
        lambda _c, supporting: _rule_clause_for_cache_miss_delta(supporting),
    "querystring_diversity_with_high_miss_rate": _clause_qs_diversity_high_miss,
    "querystring_diversity_high": _clause_qs_diversity,
}


def _format_lead_rule(rule: dict) -> str:
    name = rule.get("name") or ""
    formatter = _LEAD_RULE_FORMATTERS.get(name)
    if formatter is not None:
        current = rule.get("current")
        supporting = rule.get("supporting_metrics") or {}
        clause = formatter(current, supporting)
        if clause is not None:
            return clause
    return humanize_identifier(name).lower()


def _rule_based_lead_clause(sc: dict) -> str:
    """Lead clause based on the highest-priority triggered edge rule."""
    rule = _select_lead_rule(sc)
    if rule is None:
        return ""
    return _format_lead_rule(rule)


def _noun_pair(noun: str, plural: str | None) -> tuple[str, str]:
    """Resolve ``(singular, plural)`` for an entity-type noun."""
    n = noun or "entity"
    p = plural or (n if n.endswith("s") else f"{n}s")
    return n, p


def _assign_qualifier_suffix(share_clause: str, lead_clause: str) -> str:
    if share_clause and lead_clause:
        return f" ({share_clause}; {lead_clause})"
    if share_clause:
        return f" ({share_clause})"
    if lead_clause:
        return f" ({lead_clause})"
    return ""


def _assign_headline(
    *,
    n_assign: int,
    n_total: int,
    top_entity_card: dict,
    queue_rows: list[dict],
    scorecards: list[dict],
    path_candidates: list[dict],
    noun: str,
    plural: str,
) -> str:
    sc = top_entity_card["scorecard"]
    entity_display = top_entity_card["entity_display"]
    assign_entities = {
        r.get("entity") for r in queue_rows if r.get("verdict_state") == "assign"
    }
    actionable_scs = [s for s in scorecards if s.get("entity") in assign_entities]
    lead_clause = _edge_lead_clause(sc, actionable_scs, path_candidates)
    share_clause = _traffic_share_clause(sc, scorecards, n_total)
    verb = "needs" if n_assign == 1 else "need"
    noun_form = noun if n_assign == 1 else plural
    head = (
        f"{n_assign} of {n_total} {noun_form} {verb} analyst "
        f"attention — start with {entity_display}"
    )
    return head + _assign_qualifier_suffix(share_clause, lead_clause)


def _noun_for(count: int, noun: str, plural: str) -> str:
    return noun if count == 1 else plural


def _watch_headline(n_watch: int, n_total: int, noun: str, plural: str) -> str:
    return (
        f"{n_watch} of {n_total} {_noun_for(n_watch, noun, plural)} to watch"
    )


def _insufficient_headline(
    n_insufficient: int, n_total: int, noun: str, plural: str
) -> str:
    return (
        f"{n_insufficient} of {n_total} "
        f"{_noun_for(n_insufficient, noun, plural)} "
        "cannot be judged from this report alone"
    )


def _summary_headline(
    *,
    n_assign: int, n_watch: int, n_insufficient: int, n_close: int, n_total: int,
    top_entity_card: dict | None,
    queue_rows: list[dict],
    scorecards: list[dict],
    path_candidates: list[dict],
    noun: str,
    plural: str,
) -> str:
    if n_assign and top_entity_card:
        return _assign_headline(
            n_assign=n_assign, n_total=n_total,
            top_entity_card=top_entity_card, queue_rows=queue_rows,
            scorecards=scorecards, path_candidates=path_candidates,
            noun=noun, plural=plural,
        )
    if n_watch:
        return _watch_headline(n_watch, n_total, noun, plural)
    if n_insufficient and not n_close:
        return _insufficient_headline(n_insufficient, n_total, noun, plural)
    if n_close == n_total and n_total > 0:
        return f"All {n_total} {_noun_for(n_total, noun, plural)} read clean"
    return f"{n_total} {_noun_for(n_total, noun, plural)} reviewed"


def _summary_body(n_assign: int, n_watch: int, n_insufficient: int) -> str:
    parts: list[str] = []
    if n_assign and n_watch:
        parts.append(f"{n_watch} to watch")
    if n_insufficient:
        parts.append(f"{n_insufficient} cannot be judged from this report alone")
    return "; ".join(parts) + "." if parts else ""


def _summary_recommendation(
    actions: list[dict], n_total: int, noun: str, plural: str
) -> str | None:
    if not actions:
        return None
    top = actions[0]
    short = (
        top.get("summary") or top.get("detail") or top.get("step") or ""
    ).rstrip(".")
    if not short:
        return None
    host_count = top.get("host_count") or 0
    if host_count and host_count < n_total:
        host_noun = noun if host_count == 1 else plural
        return f"{short} (affects {host_count} {host_noun})."
    return f"{short}."


def _coverage_caveat(coverage: dict[str, dict[str, int]]) -> str | None:
    total_missing = sum(c.get("missing_input", 0) for c in coverage.values())
    total_rules = sum(sum(c.values()) for c in coverage.values())
    if not total_rules or total_missing / total_rules < 0.5:
        return None
    pct = 100 * total_missing / total_rules
    return (
        f"Coverage is thin — {pct:.0f}% of rule evaluations had "
        "missing inputs. Real risk may be higher than the score implies."
    )


def _actionable_summary(
    scorecards: list[dict],
    queue_rows: list[dict],
    triage_strip: dict,
    actions: list[dict],
    coverage: dict[str, dict[str, int]],
    n_total: int,
    entity_type_label: str,
    path_candidates: list[dict],
    entity_type_label_plural: str | None = None,
) -> Finding:
    """Synthesize the executive-summary lead Finding for an edge reader.

    Headline branches on what the queue actually says:
    - Top entity is Assign → lead with the cost-share clause when every
      actionable entity carries origin_cost_contribution_pct, otherwise
      fall back to the highest-priority triggered edge rule.
    - Only Watch → "N to watch."
    - All Insufficient / All Close — analogous boilerplate.
    """
    counts = triage_strip.get("counts", {})
    n_assign = counts.get("assign", 0)
    n_watch = counts.get("watch", 0)
    n_insufficient = counts.get("insufficient_data", 0)
    n_close = counts.get("close_as_expected", 0)

    noun, plural = _noun_pair(entity_type_label, entity_type_label_plural)
    headline = _summary_headline(
        n_assign=n_assign, n_watch=n_watch,
        n_insufficient=n_insufficient, n_close=n_close, n_total=n_total,
        top_entity_card=_top_assign_card(queue_rows, scorecards),
        queue_rows=queue_rows, scorecards=scorecards,
        path_candidates=path_candidates, noun=noun, plural=plural,
    )

    return Finding(
        finding_id="actionable_summary",
        title=headline,
        headline=headline,
        body=_summary_body(n_assign, n_watch, n_insufficient),
        recommendation=_summary_recommendation(actions, n_total, noun, plural),
        caveat=_coverage_caveat(coverage),
        priority=100,
    )
