"""Grouping rule for entity signatures (collapse duplicates)."""

from __future__ import annotations

__all__ = [
    '_GROUP_THRESHOLD',
    '_entity_signature',
    '_group_entities',
]


_GROUP_THRESHOLD = 5


def _entity_signature(e: dict) -> tuple:
    """Identity tuple for collapsing visually identical rows.

    Excludes ``evidence_top`` since that string typically embeds a
    per-host numeric (e.g. cache-miss percentage), which would defeat
    grouping. The group row surfaces variance in the evidence cell.
    """
    return (
        e["score"],
        e["delta"],
        e["primary_domain"],
        e["band"],
        e["confidence"],
    )


def _group_entities(entities: list[dict]) -> list[dict]:
    """Collapse contiguous runs of identical entity rows into group rows.

    Runs of >= _GROUP_THRESHOLD identical rows render as a single summary
    row with the host list available behind a disclosure. Shorter runs
    render as individual rows (current behavior).
    """
    rows: list[dict] = []
    i = 0
    while i < len(entities):
        sig = _entity_signature(entities[i])
        j = i
        while j < len(entities) and _entity_signature(entities[j]) == sig:
            j += 1
        run = entities[i:j]
        if len(run) >= _GROUP_THRESHOLD:
            evidence_values = {e["evidence_top"] for e in run}
            rows.append(
                {
                    "kind": "group",
                    "count": len(run),
                    "first_rank": run[0]["rank"],
                    "last_rank": run[-1]["rank"],
                    "hosts": [e["entity"] for e in run],
                    "representative": run[0],
                    "evidence_varies": len(evidence_values) > 1,
                }
            )
        else:
            for e in run:
                rows.append({"kind": "single", "entity": e})
        i = j
    return rows
