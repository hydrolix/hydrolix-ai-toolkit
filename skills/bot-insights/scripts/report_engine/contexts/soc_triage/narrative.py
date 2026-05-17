"""Actionable-summary clause builders."""

from __future__ import annotations

from ... import scorecards as scorecards_mod
from ...findings import Finding
from ...humanize import humanize_identifier
from .._shared import _top_assign_card
from .._shared import _traffic_share_clause

from .evidence_view import _sort_security_rules

__all__ = [
    '_actionable_summary',
    '_routing_clause',
    '_security_lead_clause',
    '_movement_lead_clause',
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
        _security_lead_clause(sc) if primary == "security_evidence"
        else _movement_lead_clause(sc)
    )
    share_clause = _traffic_share_clause(sc, scorecards, n_total)
    verb = "needs" if n_assign == 1 else "need"
    head = (
        f"{n_assign} of {n_total} {_noun_for(n_assign, noun, plural)} {verb} analyst "
        f"attention — start with {entity_display}"
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


def _summary_body(
    queue_rows: list[dict], n_insufficient: int, noun: str, plural: str
) -> str:
    parts: list[str] = []
    routing = _routing_clause(queue_rows, noun, plural)
    if routing:
        parts.append(routing)
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
    """Synthesize the executive-summary lead Finding for a SOC reader.

    Headline branches on what the queue actually says:
    - Top entity is Assign with ``security_evidence`` primary domain →
      lead with the dominant SIEM/bad-bot signal and any second-line
      SIEM corroboration.
    - Top Assign with a movement primary → lead with volume + bot-share
      delta so the analyst sees the operative concentration.
    - Only Watch → "N to watch."
    - All Insufficient / All Close — analogous boilerplate.

    Body italicizes the queue-state clarification. Recommendation pulls
    from the top aggregated action's ``summary`` form (single source of
    truth — the inlined actions section uses the analyst-grade
    ``detail``). Caveat fires when ≥ 50% of fleet rule evaluations had
    missing inputs.
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
        body=_summary_body(queue_rows, n_insufficient, noun, plural),
        recommendation=_summary_recommendation(actions, n_total, noun, plural),
        caveat=_coverage_caveat(coverage),
        priority=100,
    )


def _routing_names(rows: list[dict], limit: int = 2) -> str:
    labels = [(r.get("entity_display") or r.get("entity") or "") for r in rows]
    labels = [lbl for lbl in labels if lbl]
    if not labels:
        return ""
    if len(labels) <= limit:
        return ", ".join(labels)
    return ", ".join(labels[:limit]) + f", +{len(labels) - limit} more"


def _assign_routing_part(
    assigns: list[dict], noun: str, plural: str
) -> str | None:
    if not assigns:
        return None
    names = _routing_names(assigns)
    if names:
        return f"SOC investigate {names} now"
    verb_noun = noun if len(assigns) == 1 else plural
    return f"investigate {len(assigns)} {verb_noun} now"


def _watch_routing_part(watches: list[dict]) -> str | None:
    if not watches:
        return None
    names = _routing_names(watches)
    return f"monitor / enrich {names}" if names else f"monitor / enrich {len(watches)}"


def _routing_clause(
    queue_rows: list[dict],
    noun: str,
    plural: str,
) -> str:
    """Build a deterministic SOC routing clause from queue verdicts.

    Returns something like ``"SOC investigate ASN 64500 now; monitor / enrich
    ASN 64600"`` — names the Assign entities (up to two) explicitly so the
    reader knows who to act on first, and groups Watch entities with the
    softer verb. Empty when the queue has no Assign or Watch entities.
    """
    assigns = [r for r in queue_rows if (r.get("verdict_state") or "") == "assign"]
    watches = [r for r in queue_rows if (r.get("verdict_state") or "") == "watch"]
    candidates = [
        _assign_routing_part(assigns, noun, plural),
        _watch_routing_part(watches),
    ]
    return "; ".join(p for p in candidates if p)


def _security_rule_lead(name: str, current: object) -> str:
    """Render the security_evidence rule's lead phrase."""
    if name == "bad_bot_share_high" and isinstance(current, (int, float)):
        return f"bad-bot share {current:g}%"
    if name == "siem_auth_fail_present" and isinstance(current, (int, float)):
        return f"{int(current)} SIEM auth failures"
    if name == "siem_blocked_present" and isinstance(current, (int, float)):
        return f"{int(current)} SIEM blocked requests"
    return humanize_identifier(name).lower()


def _has_siem_corroboration(triggered: list[dict], lead_name: str) -> bool:
    return any(
        (r.get("name") or "").startswith("siem_")
        and r.get("name") != lead_name
        for r in triggered
    )


def _security_lead_clause(sc: dict) -> str:
    """Tight clause naming the dominant security-evidence signal.

    Picks the highest-priority triggered security_evidence rule and
    appends a SIEM corroboration tag when a SIEM-named rule also fired.
    """
    triggered = [
        r for r in scorecards_mod.normalize_rule_results(sc)
        if r.get("status") == "triggered" and r.get("domain") == "security_evidence"
    ]
    if not triggered:
        return ""
    lead_rule = _sort_security_rules(triggered)[0]
    name = lead_rule.get("name") or ""
    lead = _security_rule_lead(name, lead_rule.get("current"))
    if not name.startswith("siem_") and _has_siem_corroboration(triggered, name):
        return f"{lead}, SIEM evidence present"
    return lead


def _volume_movement_part(rule: dict | None) -> str | None:
    if not rule:
        return None
    supporting = rule.get("supporting_metrics") or {}
    pct = supporting.get("pct_change")
    if isinstance(pct, (int, float)):
        return f"volume +{int(pct)}%"
    absolute = supporting.get("absolute_delta")
    if isinstance(absolute, (int, float)):
        return f"volume +{int(absolute)}"
    return None


def _share_movement_part(rule: dict | None) -> str | None:
    if not rule:
        return None
    supporting = rule.get("supporting_metrics") or {}
    pp = supporting.get("absolute_delta_points")
    if isinstance(pp, (int, float)):
        return f"bot share +{pp:.1f}pp"
    return None


def _movement_lead_clause(sc: dict) -> str:
    """Lead clause for an Assign entity whose primary domain is movement.

    Pulls the volume_delta_high and bot_share_delta_high triggered rules
    when present and renders them as a "volume +X, bot share +Ypp" pair
    so the analyst sees the operative concentration without scanning
    rule rows.
    """
    rules = {
        r.get("name"): r
        for r in scorecards_mod.normalize_rule_results(sc)
        if r.get("status") == "triggered"
    }
    candidates = [
        _volume_movement_part(rules.get("volume_delta_high")),
        _share_movement_part(rules.get("bot_share_delta_high")),
    ]
    parts = [p for p in candidates if p]
    if not parts and rules:
        # Fall back to humanizing the highest-points triggered rule.
        top = max(rules.values(), key=lambda r: r.get("points") or 0)
        parts.append(humanize_identifier(top.get("name") or "").lower())
    return ", ".join(parts)
