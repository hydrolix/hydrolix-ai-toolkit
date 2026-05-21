"""Actionable-summary + crawler / fallback lead clauses."""

from __future__ import annotations

from ... import scorecards as scorecards_mod
from ...findings import Finding
from ...humanize import humanize_identifier
from .._shared import _top_assign_card
from .._shared import _traffic_share_clause

from .evidence_view import _sort_crawler_rules

__all__ = [
    '_actionable_summary',
    '_crawler_lead_clause',
    '_fallback_lead_clause',
]


def _noun_pair(noun_label: str, plural_label: str | None) -> tuple[str, str]:
    n = noun_label or "entity"
    p = plural_label or (n if n.endswith("s") else f"{n}s")
    return n, p


def _noun_for(count: int, noun: str, plural: str) -> str:
    return noun if count == 1 else plural


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
    scorecards: list[dict],
    noun: str,
    plural: str,
) -> str:
    sc = top_entity_card["scorecard"]
    entity_display = top_entity_card["entity_display"]
    primary = sc.get("primary_domain") or ""
    lead_clause = (
        _crawler_lead_clause(sc) if primary == "crawler_governance"
        else _fallback_lead_clause(sc)
    )
    share_clause = _traffic_share_clause(sc, scorecards, n_total)
    verb = "needs" if n_assign == 1 else "need"
    head = (
        f"{n_assign} of {n_total} {_noun_for(n_assign, noun, plural)} {verb} "
        f"analyst attention — start with {entity_display}"
    )
    return head + _assign_qualifier_suffix(share_clause, lead_clause)


def _summary_headline(
    *,
    n_assign: int, n_watch: int, n_insufficient: int, n_close: int, n_total: int,
    top_entity_card: dict | None,
    scorecards: list[dict],
    noun: str,
    plural: str,
) -> str:
    if n_assign and top_entity_card:
        return _assign_headline(
            n_assign=n_assign, n_total=n_total,
            top_entity_card=top_entity_card,
            scorecards=scorecards, noun=noun, plural=plural,
        )
    if n_watch:
        return f"{n_watch} of {n_total} {_noun_for(n_watch, noun, plural)} to watch"
    if n_insufficient and not n_close:
        return (
            f"{n_insufficient} of {n_total} "
            f"{_noun_for(n_insufficient, noun, plural)} "
            "cannot be judged from this report alone"
        )
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
    entity_type_label_plural: str | None = None,
) -> Finding:
    """Synthesize the executive-summary lead Finding for a crawler reader.

    Headline branches on what the queue actually says:
    - Top entity is Assign with ``crawler_governance`` primary domain →
      lead with the dominant crawler-governance signal and any second-line
      crawler corroboration.
    - Top Assign with another primary (movement, etc.) → lead with the
      SOC-style highest-points triggered rule pattern.
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
        scorecards=scorecards, noun=noun, plural=plural,
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


def _crawler_clause_with_pct(supporting: dict, prefix: str, fallback: str) -> str:
    pct = supporting.get("pct_change")
    if isinstance(pct, (int, float)):
        return f"{prefix}{int(pct)}%"
    return fallback


def _format_crawler_rule(name: str, current: object, supporting: dict) -> str:
    if name == "policy_surface_failure_present" and isinstance(current, (int, float)):
        return f"{int(current)} governance-surface failures"
    if name == "good_bot_429_present" and isinstance(current, (int, float)):
        return f"{int(current)} good-bot 429 responses"
    if name == "good_bot_error_rate_high" and isinstance(current, (int, float)):
        return f"good-bot error rate {current:g}%"
    if name == "ai_crawler_growth_high":
        return _crawler_clause_with_pct(supporting, "AI crawler volume +", "AI crawler growth")
    if name == "rate_429_delta_high":
        return _crawler_clause_with_pct(supporting, "429 rate +", "429 rate spike")
    if name == "rate_5xx_delta_high":
        return _crawler_clause_with_pct(supporting, "5xx rate +", "5xx rate spike")
    return humanize_identifier(name).lower()


def _crawler_lead_clause(sc: dict) -> str:
    """Tight clause naming the dominant crawler-governance signal.

    Picks the highest-priority triggered crawler_governance rule and
    formats its evidence into a compact phrase.
    """
    triggered = [
        r for r in scorecards_mod.normalize_rule_results(sc)
        if r.get("status") == "triggered" and r.get("domain") == "crawler_governance"
    ]
    if not triggered:
        return ""
    lead_rule = _sort_crawler_rules(triggered)[0]
    return _format_crawler_rule(
        lead_rule.get("name") or "",
        lead_rule.get("current"),
        lead_rule.get("supporting_metrics") or {},
    )


def _fallback_lead_clause(sc: dict) -> str:
    """Lead clause when the top entity's primary domain is not crawler.

    Picks the highest-points triggered rule across all domains and
    humanizes its name. Mirrors the SOC ``_movement_lead_clause`` shape
    without locking onto specific feature names.
    """
    triggered = [
        r
        for r in scorecards_mod.normalize_rule_results(sc)
        if r.get("status") == "triggered"
    ]
    if not triggered:
        return ""
    top = max(triggered, key=lambda r: r.get("points") or 0)
    return humanize_identifier(top.get("name") or "").lower()
