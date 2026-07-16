"""Per-domain coverage rollup tables + action aggregation."""

from __future__ import annotations

from collections import Counter
from collections import defaultdict
from ... import scorecards as scorecards_mod
from ...theme import DOMAIN_LABELS
from ...theme import DOMAIN_ORDER

__all__ = [
    '_aggregate_coverage',
    '_coverage_rows',
    '_normalize_step',
    '_aggregate_actions',
    '_rule_counts',
]


def _aggregate_coverage(scorecards: list[dict]) -> dict[str, dict[str, int]]:
    coverage: dict[str, Counter] = defaultdict(Counter)
    for sc in scorecards:
        for rule in scorecards_mod.normalize_rule_results(sc):
            domain = rule.get("domain") or "other"
            status = rule.get("status") or "missing_input"
            coverage[domain][status] += 1
    return {d: dict(c) for d, c in coverage.items()}


def _coverage_rows(coverage: dict[str, dict[str, int]]) -> list[dict]:
    rows = []
    for domain in DOMAIN_ORDER:
        counts = coverage.get(domain, {})
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


def _normalize_step(step: object) -> dict[str, str]:
    """Adapt a recommended-next-step entry to ``{summary, detail}``.

    Current scorecard producers emit dicts with both fields. Older
    artifacts emit plain strings; promote the string into the structured
    shape (summary = first sentence) so the rest of the pipeline only
    deals with one shape.
    """
    if isinstance(step, dict):
        summary = (step.get("summary") or step.get("detail") or "").strip()
        detail = (step.get("detail") or step.get("summary") or "").strip()
        return {"summary": summary, "detail": detail}
    text = str(step).strip()
    head = text.split(".")[0]
    summary = head + ("." if head and head != text else "")
    return {"summary": summary or text, "detail": text}


def _aggregate_actions(scorecards: list[dict]) -> list[dict]:
    """Group recommended next steps across the fleet by their detail text.

    The detail string is the stable identity — different summaries that
    share a detail collapse to one entry. Each entry carries both grades
    so downstream views can pick the lens they need (executive summary
    pulls the short summary; the actions section renders the detail).
    """
    by_detail: dict[str, dict] = {}
    order: list[str] = []
    for sc in scorecards:
        for raw in sc.get("recommended_next_steps") or []:
            normalized = _normalize_step(raw)
            detail = normalized["detail"]
            if not detail:
                continue
            entry = by_detail.get(detail)
            if entry is None:
                entry = {
                    "summary": normalized["summary"],
                    "detail": detail,
                    "hosts": [],
                }
                by_detail[detail] = entry
                order.append(detail)
            entry["hosts"].append(sc["entity"])
    ordered = sorted(
        (by_detail[d] for d in order),
        key=lambda e: -len(e["hosts"]),
    )
    return [
        {
            "summary": e["summary"],
            "detail": e["detail"],
            # Keep ``step`` as an alias of detail for backwards compat with
            # any consumer that still reads the old field name.
            "step": e["detail"],
            "host_count": len(e["hosts"]),
            "preview": ", ".join(e["hosts"][:3]),
            "extra": max(0, len(e["hosts"]) - 3),
        }
        for e in ordered
    ]


def _rule_counts(sc: dict) -> dict:
    return scorecards_mod.rule_counts(sc)
