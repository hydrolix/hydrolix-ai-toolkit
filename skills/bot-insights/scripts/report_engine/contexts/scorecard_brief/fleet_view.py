"""Fleet-coverage detail block + shared-signal aggregator."""

from __future__ import annotations

from collections import Counter
from collections import defaultdict
from ... import scorecards as scorecards_mod
from ...humanize import humanize_identifier
from ...theme import DOMAIN_LABELS

__all__ = [
    '_shared_signal',
    '_fleet_coverage_detail',
]


def _collect_triggered_rule_stats(
    scorecards: list[dict],
) -> tuple[Counter, dict[str, set[str]]]:
    """Aggregate triggered-rule counts + which hosts triggered each rule."""
    counts: Counter = Counter()
    hosts_by_rule: dict[str, set[str]] = defaultdict(set)
    for sc in scorecards:
        for r in scorecards_mod.normalize_rule_results(sc):
            if r.get("status") == "triggered":
                name = r.get("name") or ""
                counts[name] += 1
                hosts_by_rule[name].add(sc.get("entity") or "")
    return counts, hosts_by_rule


def _compute_traffic_share(
    scorecards: list[dict], affected: set[str]
) -> float | None:
    """Share of fleet requests carried by the affected-host subset, or
    ``None`` when any host is missing the request-volume metric."""
    fleet_requests = 0.0
    affected_requests = 0.0
    have_any_volume = False
    for sc in scorecards:
        cur = (sc.get("entity_metrics") or {}).get("current_requests")
        if cur is None:
            return None
        have_any_volume = True
        fleet_requests += float(cur)
        if (sc.get("entity") or "") in affected:
            affected_requests += float(cur)
    if not have_any_volume or fleet_requests <= 0:
        return None
    return affected_requests / fleet_requests * 100.0


def _shared_signal(scorecards: list[dict], n_total: int) -> dict | None:
    """Surface the dominant triggered rule when ≥ 50% of the fleet shares it.

    A shared signal more often points to a single fleet-wide cause than
    to N independent occurrences. Promoting it to the hero strip saves
    the reader from having to derive that pattern from the findings list.

    When request-volume data is available, also computes
    ``traffic_share_pct`` — the share of fleet requests carried by the
    affected hosts — so the headline can lead with traffic weight rather
    than a raw host count. ``None`` when any input is missing so the
    template can fall back to count-only framing.
    """
    if n_total < 2:
        return None
    counts, hosts_by_rule = _collect_triggered_rule_stats(scorecards)
    if not counts:
        return None
    name, count = counts.most_common(1)[0]
    if count / n_total < 0.5:
        return None
    traffic_share_pct = _compute_traffic_share(scorecards, hosts_by_rule[name])
    return {
        "rule_name": name,
        "rule_label": humanize_identifier(name),
        "host_count": count,
        "fleet_total": n_total,
        "traffic_share_pct": traffic_share_pct,
        "headline": (
            f"{count} of {n_total} hosts share {humanize_identifier(name)} — "
            f"investigate as one issue, not {count}."
        ),
    }


def _fleet_coverage_detail(scorecards: list[dict], n_total: int) -> dict | None:
    """Group rules that are missing inputs across the fleet by domain.

    A rule that is unscored on most or all hosts surfaces as a coverage
    gap that needs to be fixed at the producer / data source, not at
    the host. Director sees "rule X has missing inputs on 18 of 20 hosts"
    not just per-host counts.
    """
    by_rule: dict[str, dict] = {}
    for sc in scorecards:
        for r in scorecards_mod.normalize_rule_results(sc):
            if r.get("status") != "missing_input":
                continue
            name = r.get("name") or ""
            entry = by_rule.setdefault(
                name,
                {
                    "name": name,
                    "domain": r.get("domain") or "other",
                    "missing_inputs": tuple(r.get("missing_inputs") or []),
                    "host_count": 0,
                },
            )
            entry["host_count"] += 1
    if not by_rule:
        return None
    grouped: dict[str, list[dict]] = {}
    for entry in by_rule.values():
        grouped.setdefault(entry["domain"], []).append(entry)

    return {
        "n_total_hosts": n_total,
        "groups": [
            {
                "domain": d,
                "domain_label": DOMAIN_LABELS.get(d, d),
                "rules": sorted(rules, key=lambda r: (-r["host_count"], r["name"])),
            }
            for d, rules in sorted(grouped.items())
        ],
    }
