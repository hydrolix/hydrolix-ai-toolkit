"""Per-section view builders consumed by ``prepare()``."""

from __future__ import annotations

from .formatters import (
    _format_count,
    _format_int,
    _format_pct,
    _format_signed_pct,
    _safe_number,
)
from .labels import _default_field_label

__all__ = [
    '_cohort_mix_rows',
    '_scope_rows',
    '_top_raw_paths_rows',
    '_status_mix_rows',
    '_actor_rankings_view',
]


def _cohort_mix_row(row: dict, total: float) -> dict:
    requests = _safe_number(row.get("requests")) or 0
    share = (100.0 * requests / total) if total > 0 else 0.0
    return {
        "value": str(row.get("value") or ""),
        "requests": requests,
        "requests_display": _format_count(requests),
        "share_pct": round(share, 2),
        "share_pct_display": _format_pct(share),
        "req_429_share_pct": _safe_number(row.get("req_429_share_pct")),
        "req_429_share_display": _format_pct(row.get("req_429_share_pct")),
        "req_5xx_share_pct": _safe_number(row.get("req_5xx_share_pct")),
        "req_5xx_share_display": _format_pct(row.get("req_5xx_share_pct")),
        "value_label": "Cohort",
    }


def _cohort_mix_rows(actors_artifact: dict) -> list[dict]:
    """Project the ``trafficCohort`` actor-ranking into a mini-table
    view for the editorial geo+cohort row.

    Pairs with Top Countries in the same 2-col section: geographic
    origin on the left, classification on the right. Together they
    describe the shape of attack traffic — where it came from and
    how the upstream classifier bucketed it. The 429% / 5xx% columns
    surface per-cohort response-rate texture (a Bot cohort with 4%
    5xx vs Browser at 0.5% is a real signal even when bot volume is
    small in absolute terms).

    Share is computed against the cohort total across this ranking,
    not against the window-wide request total — the cohorts ARE the
    window's traffic, so summing them and dividing back is the
    honest 100% share split (a fixed-cardinality field with no
    "other" bucket to worry about).
    """
    rankings = (actors_artifact or {}).get("actor_rankings") or []
    cohort = next((r for r in rankings if r.get("field") == "trafficCohort"), None)
    if cohort is None:
        return []
    rows = cohort.get("rows") or []
    total = sum(_safe_number(r.get("requests")) or 0 for r in rows)
    return [_cohort_mix_row(row, total) for row in rows]


def _scope_rows(rows: list[dict], *, value_label: str) -> list[dict]:
    out: list[dict] = []
    for row in rows:
        out.append(
            {
                "value": str(row.get("value") if row.get("value") is not None else ""),
                "requests": _safe_number(row.get("requests")),
                "requests_display": _format_count(row.get("requests")),
                "share_pct": _safe_number(row.get("share_pct")),
                "share_pct_display": _format_pct(row.get("share_pct")),
                "delta_vs_baseline_pct": _safe_number(row.get("delta_vs_baseline_pct")),
                "delta_vs_baseline_display": _format_signed_pct(
                    row.get("delta_vs_baseline_pct")
                ),
                "value_label": value_label,
            }
        )
    return out


def _top_raw_paths_rows(rows: list[dict]) -> list[dict]:
    """Project the raw-reqPath drilldown rows for the editorial Top
    Paths panel's "specific URLs" mini-table.

    The producer (a phase-2 raw scan, scoped to the suspicious-actor
    IP set) supplies absolute counts plus a share_pct that's
    share-of-suspicious-actor-traffic (not share-of-window). Each row
    also carries a ``distinct_actors`` count so the renderer can
    surface coordinated-many-actors-on-one-URL signal vs
    single-actor-scanning noise.
    """
    out: list[dict] = []
    for row in rows:
        out.append(
            {
                "value": str(row.get("value") if row.get("value") is not None else ""),
                "requests": _safe_number(row.get("requests")),
                "requests_display": _format_count(row.get("requests")),
                "share_pct": _safe_number(row.get("share_pct")),
                "share_pct_display": _format_pct(row.get("share_pct")),
                "distinct_actors": _safe_number(row.get("distinct_actors")),
                "distinct_actors_display": _format_int(row.get("distinct_actors")),
                "req_429": _safe_number(row.get("req_429")),
                "req_429_display": _format_count(row.get("req_429")),
                "req_5xx": _safe_number(row.get("req_5xx")),
                "req_5xx_display": _format_count(row.get("req_5xx")),
                "req_5xx_share_pct": _safe_number(row.get("req_5xx_share_pct")),
                "req_5xx_share_display": _format_pct(row.get("req_5xx_share_pct")),
            }
        )
    return out


def _status_mix_rows(rows: list[dict]) -> list[dict]:
    out: list[dict] = []
    for row in rows:
        status_code = row.get("status_code")
        if status_code is None:
            display = ""
        else:
            display = str(status_code)
        out.append(
            {
                "value": display,
                "status_code": status_code,
                "requests": _safe_number(row.get("requests")),
                "requests_display": _format_count(row.get("requests")),
                "share_pct": _safe_number(row.get("share_pct")),
                "share_pct_display": _format_pct(row.get("share_pct")),
            }
        )
    return out


def _actor_rankings_view(actors_art: dict) -> list[dict]:
    rankings = actors_art.get("actor_rankings") or []
    out: list[dict] = []
    for ranking in rankings:
        field = ranking.get("field") or ""
        label = ranking.get("field_label") or _default_field_label(field)
        rows = []
        for row in ranking.get("rows") or []:
            rows.append(
                {
                    "value": str(
                        row.get("value") if row.get("value") is not None else ""
                    ),
                    "requests": _safe_number(row.get("requests")),
                    "requests_display": _format_count(row.get("requests")),
                    "bytes": _safe_number(row.get("bytes")),
                    "bytes_display": _format_count(row.get("bytes")),
                    "distinct_paths": _safe_number(row.get("distinct_paths")),
                    "distinct_paths_display": _format_int(row.get("distinct_paths")),
                    "req_429": _safe_number(row.get("req_429")),
                    "req_429_display": _format_count(row.get("req_429")),
                    "req_429_share_pct": _safe_number(row.get("req_429_share_pct")),
                    "req_429_share_display": _format_pct(row.get("req_429_share_pct")),
                    "req_5xx": _safe_number(row.get("req_5xx")),
                    "req_5xx_display": _format_count(row.get("req_5xx")),
                    "req_5xx_share_pct": _safe_number(row.get("req_5xx_share_pct")),
                    "req_5xx_share_display": _format_pct(row.get("req_5xx_share_pct")),
                }
            )
        out.append(
            {
                "field": field,
                "field_label": label,
                "rows": rows,
            }
        )
    return out
