"""Triage verdict strip + actionable-summary headline + dek."""

from __future__ import annotations

from ... import verdicts as verdicts_mod
from ...findings import Finding
from ...formatters import format_share_pct

__all__ = [
    '_triage_strip',
    '_actionable_summary',
    '_compute_dek',
]


def _triage_rationale_parts(state_counts: dict[str, int]) -> list[str]:
    n_assign = state_counts.get("assign", 0)
    n_watch = state_counts.get("watch", 0)
    n_close = state_counts.get("close_as_expected", 0)
    n_insufficient = state_counts.get("insufficient_data", 0)
    parts: list[str] = []
    if n_assign:
        verb = "needs" if n_assign == 1 else "need"
        parts.append(
            f"{n_assign} host{'s' if n_assign != 1 else ''} {verb} attention"
        )
    if n_watch:
        parts.append(f"{n_watch} to watch")
    if n_insufficient:
        parts.append(f"{n_insufficient} cannot be judged from this report alone")
    if not parts and n_close:
        parts.append(f"all {n_close} host{'s' if n_close != 1 else ''} read clean")
    return parts


def _triage_strip(verdicts_by_entity: dict[str, dict], n_total: int) -> dict:
    """Aggregate per-host verdicts into the triage strip.

    Returns counts for each state in canonical order, plus a one-line
    rationale of the fleet split. The strip is the new hero: it answers
    "how many hosts need work" before the reader sees any score chrome.
    """
    state_counts = {state: 0 for state in verdicts_mod.STATE_ORDER}
    for v in verdicts_by_entity.values():
        state_counts[v["state"]] = state_counts.get(v["state"], 0) + 1
    pills = [
        {
            "state": state,
            "label": verdicts_mod.STATE_LABELS[state],
            "tone": verdicts_mod.STATE_TONE[state],
            "count": state_counts.get(state, 0),
        }
        for state in verdicts_mod.STATE_ORDER
    ]
    parts = _triage_rationale_parts(state_counts)
    rationale = "; ".join(parts) + f" (out of {n_total})." if parts else ""
    return {"pills": pills, "rationale": rationale, "counts": state_counts}


def _assign_headline(n_assign: int, n_total: int) -> str:
    verb = "needs" if n_assign == 1 else "need"
    plural_s = "s" if n_assign != 1 else ""
    return f"{n_assign} of {n_total} host{plural_s} {verb} attention now"


def _shared_signal_headline(shared_signal: dict, n_total: int) -> str:
    head = (
        f"{shared_signal['host_count']} of {n_total} hosts share "
        f"{shared_signal['rule_label']}"
    )
    if shared_signal.get("traffic_share_pct") is not None:
        head += (
            f" (covering {format_share_pct(shared_signal['traffic_share_pct'])}"
            " of fleet requests)"
        )
    return head + f" — investigate as one issue, not {shared_signal['host_count']}"


def _host_plural(n: int) -> str:
    return "s" if n != 1 else ""


def _summary_headline_brief(
    *,
    n_assign: int, n_watch: int, n_insufficient: int, n_close: int, n_total: int,
    shared_signal: dict | None,
) -> str:
    if n_assign:
        return _assign_headline(n_assign, n_total)
    if shared_signal:
        return _shared_signal_headline(shared_signal, n_total)
    if n_watch:
        return f"{n_watch} of {n_total} host{_host_plural(n_watch)} to watch"
    if n_insufficient and not n_close:
        return (
            f"{n_insufficient} of {n_total} host{_host_plural(n_insufficient)} "
            "cannot be judged from this report alone"
        )
    if n_close == n_total and n_total > 0:
        return f"All {n_total} hosts read clean"
    return f"{n_total} host{_host_plural(n_total)} reviewed"


def _summary_body(
    *,
    n_assign: int, n_watch: int, n_insufficient: int, n_total: int,
    shared_signal: dict | None, headline: str,
) -> str:
    bits: list[str] = []
    if n_assign and shared_signal:
        bits.append(
            f"{shared_signal['host_count']} of {n_total} share "
            f"{shared_signal['rule_label']}"
        )
    if n_watch and not headline.startswith(f"{n_watch} of"):
        bits.append(f"{n_watch} to watch")
    if n_insufficient and not headline.startswith(f"{n_insufficient} of"):
        bits.append(f"{n_insufficient} cannot be judged from this report alone")
    return "; ".join(bits) + "." if bits else ""


def _short_action_text(action: dict) -> str:
    return (
        action.get("summary") or action.get("detail") or action.get("step") or ""
    ).rstrip(".")


def _summary_recommendation(
    actions: list[dict], shared_signal: dict | None, n_total: int
) -> str | None:
    if not actions:
        return None
    top = actions[0]
    short = _short_action_text(top)
    if not short:
        return None
    host_count = top.get("host_count") or 0
    if shared_signal and host_count == shared_signal["host_count"]:
        return f"{short} — investigate as one cause, not {host_count}."
    if host_count and host_count < n_total:
        plural_s = "s" if host_count != 1 else ""
        return f"{short} (affects {host_count} host{plural_s})."
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
    triage_strip: dict,
    shared_signal: dict | None,
    actions: list[dict],
    n_total: int,
    coverage: dict[str, dict[str, int]],
) -> Finding:
    """Synthesize the top-of-summary actionable take.

    Reads from already-computed deterministic projections — triage strip,
    shared signal, aggregated actions, fleet coverage. Returns a Finding
    that the executive_summary macro renders as the lead paragraph.

    Three slots in the body, each only emitted when meaningful:
    1. State of the queue (X need attention now / Y to watch / Z insufficient).
    2. Recommended action — top aggregated action with host count, framed
       as one-issue-not-N when a shared signal is present.
    3. Coverage caveat when ≥ 50% of fleet rule evaluations were unscored.
    """
    counts = triage_strip.get("counts", {})
    n_assign = counts.get("assign", 0)
    n_watch = counts.get("watch", 0)
    n_insufficient = counts.get("insufficient_data", 0)
    n_close = counts.get("close_as_expected", 0)

    headline = _summary_headline_brief(
        n_assign=n_assign, n_watch=n_watch, n_insufficient=n_insufficient,
        n_close=n_close, n_total=n_total, shared_signal=shared_signal,
    )
    body = _summary_body(
        n_assign=n_assign, n_watch=n_watch, n_insufficient=n_insufficient,
        n_total=n_total, shared_signal=shared_signal, headline=headline,
    )

    return Finding(
        finding_id="actionable_summary",
        title=headline,
        headline=headline,
        body=body,
        recommendation=_summary_recommendation(actions, shared_signal, n_total),
        caveat=_coverage_caveat(coverage),
        priority=100,  # always lead
    )


def _compute_dek(
    n_total: int,
    n_with_triggers: int,
    n_moved: int,
    is_single: bool,
    lowest: int,
    fleet_total: int | None = None,
) -> str:
    """One-sentence outcome summary, deterministic from KPIs."""
    if is_single:
        # Single-entity view: focus on this host's score and movement.
        movement = (
            "no movement vs baseline" if n_moved == 0 else "score moved vs baseline"
        )
        if fleet_total:
            return (
                f"Selected entity from {fleet_total}-host fleet review. "
                f"Score {lowest}; {movement}."
            )
        return f"Score {lowest}; {movement}."

    # Fleet view: focus on triggered/clean split + movement count.
    if n_with_triggers == 0:
        triggers_clause = f"All {n_total} hosts produced no triggered rules"
    elif n_with_triggers == n_total:
        triggers_clause = f"All {n_total} hosts triggered at least one rule"
    else:
        triggers_clause = (
            f"{n_with_triggers} of {n_total} hosts triggered at least one rule"
        )

    movement_clause = (
        "no host scores moved versus baseline"
        if n_moved == 0
        else f"{n_moved} score{'s' if n_moved != 1 else ''} moved versus baseline"
    )
    return f"{triggers_clause}; {movement_clause}."
