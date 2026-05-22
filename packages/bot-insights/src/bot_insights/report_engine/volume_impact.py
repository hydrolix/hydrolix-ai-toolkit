"""Volume/impact projection for scorecard reports.

Both the entity-review (one host) and the fleet brief surface a
"Volume & impact" KPI strip so the reader sees what the host(s)
actually did — request count, cache misses, origin p95 — alongside
the verdict. Projection logic is shared; the fleet adds aggregation
on top.
"""

from __future__ import annotations

from typing import Iterable


def format_count(value: float | int | None) -> str:
    if value is None:
        return "—"
    n = float(value)
    if n >= 1_000_000:
        return f"{n / 1_000_000:.2f}M"
    if n >= 10_000:
        return f"{n / 1_000:.1f}k"
    if n >= 1_000:
        return f"{n / 1_000:.2f}k"
    return f"{int(n) if n.is_integer() else round(n, 2)}"


def format_pct(value: float | int | None) -> str:
    if value is None:
        return "—"
    n = float(value)
    if n < 1:
        return f"{n:.3f}%"
    if n < 10:
        return f"{n:.2f}%"
    # Preserve fractional precision when values approach 100% — rounding
    # 99.99 to 100.0 reads as a clean state and hides the actual signal.
    if n >= 99 and n < 100:
        return f"{n:.2f}%"
    return f"{n:.1f}%"


def format_pct_delta(delta_pct: float) -> str:
    sign = "+" if delta_pct >= 0 else ""
    return f"{sign}{delta_pct:.1f}% vs baseline"


def format_pp_delta(delta_pp: float | None) -> str | None:
    if delta_pp is None:
        return None
    sign = "+" if delta_pp >= 0 else ""
    if abs(delta_pp) < 0.05:
        return "no change vs baseline"
    return f"{sign}{delta_pp:.2f} pp vs baseline"


def format_ms_delta(delta_ms: float | None) -> str | None:
    if delta_ms is None:
        return None
    sign = "+" if delta_ms >= 0 else ""
    return f"{sign}{delta_ms:.0f} ms vs baseline"


def project_entity(metrics: dict | None) -> dict | None:
    """Project a single host's ``entity_metrics`` into KPI rows.

    Returns ``None`` when no metric is available so the template can
    suppress the section without fabricating zeros.
    """
    if not metrics:
        return None

    rows = [
        row
        for row in (
            _project_request_row(metrics),
            _project_cache_miss_row(metrics),
            _project_origin_p95_row(metrics),
            _project_5xx_row(metrics),
        )
        if row is not None
    ]

    if not rows:
        return None
    return {"rows": rows}


def _project_request_row(metrics: dict) -> dict | None:
    cur_req = metrics.get("current_requests")
    base_req = metrics.get("baseline_requests")
    if cur_req is None:
        return None
    delta_pct = (cur_req - base_req) / base_req * 100.0 if base_req else None
    return {
        "label": "Requests",
        "value": format_count(cur_req),
        "delta": format_pct_delta(delta_pct) if delta_pct is not None else "no baseline",
    }


def _project_cache_miss_row(metrics: dict) -> dict | None:
    cur_misses = metrics.get("current_cache_misses")
    cur_miss_pct = metrics.get("current_cache_miss_pct")
    base_miss_pct = metrics.get("baseline_cache_miss_pct")
    if cur_miss_pct is None and cur_misses is None:
        return None
    if cur_miss_pct is not None:
        value = (
            f"{format_count(cur_misses)} ({format_pct(cur_miss_pct)})"
            if cur_misses is not None
            else format_pct(cur_miss_pct)
        )
    else:
        value = format_count(cur_misses)
    delta_pp = (
        cur_miss_pct - base_miss_pct
        if cur_miss_pct is not None and base_miss_pct is not None
        else None
    )
    return {
        "label": "Cache misses",
        "value": value,
        "delta": format_pp_delta(delta_pp) if delta_pp is not None else None,
    }


def _project_origin_p95_row(metrics: dict) -> dict | None:
    cur_p95 = metrics.get("current_origin_p95_ms")
    base_p95 = metrics.get("baseline_origin_p95_ms")
    if cur_p95 is None:
        return None
    delta_ms = cur_p95 - base_p95 if base_p95 is not None else None
    return {
        "label": "Origin p95",
        "value": f"{format_count(cur_p95)} ms",
        "delta": format_ms_delta(delta_ms) if delta_ms is not None else None,
    }


def _project_5xx_row(metrics: dict) -> dict | None:
    cur_5xx = metrics.get("current_5xx_pct")
    base_5xx = metrics.get("baseline_5xx_pct")
    if cur_5xx is None:
        return None
    delta_pp = cur_5xx - base_5xx if base_5xx is not None else None
    return {
        "label": "5xx rate",
        "value": format_pct(cur_5xx),
        "delta": format_pp_delta(delta_pp) if delta_pp is not None else None,
    }


def project_fleet(scorecards: Iterable[dict]) -> dict | None:
    """Project entity_metrics across a fleet into aggregated KPI rows.

    Sums request and cache-miss counts when available; takes a
    request-weighted average for cache-miss percentage. Skips rows
    without underlying data — never fabricates aggregates from partial
    coverage.
    """
    cards = [sc for sc in scorecards if sc.get("entity_metrics")]
    if not cards:
        return None

    stats = _fleet_stats(cards)

    rows: list[dict] = []
    n = len(cards)

    if stats["n_with_requests"]:
        delta_pct = None
        if stats["n_with_baseline_requests"] and stats["total_base_req"]:
            delta_pct = (
                (stats["total_cur_req"] - stats["total_base_req"])
                / stats["total_base_req"]
                * 100.0
            )
        sub = (
            f"across {stats['n_with_requests']} of {n} hosts"
            if stats["n_with_requests"] < n
            else f"across {n} hosts"
        )
        rows.append(
            {
                "label": "Fleet requests",
                "value": format_count(stats["total_cur_req"]),
                "delta": format_pct_delta(delta_pct)
                if delta_pct is not None
                else "no baseline",
                "sub": sub,
            }
        )

    cache_row = _fleet_cache_miss_row(stats, n)
    if cache_row:
        rows.append(cache_row)

    if stats["n_with_origin"] and stats["weight_for_origin"] > 0:
        rows.append(
            {
                "label": "Origin p95",
                "value": f"{format_count(stats['weighted_origin_p95'] / stats['weight_for_origin'])} ms",
                "delta": None,
                "sub": f"weighted across {stats['n_with_origin']} of {n} hosts",
            }
        )

    if stats["n_with_5xx"] and stats["weight_for_5xx"] > 0:
        rows.append(
            {
                "label": "5xx rate",
                "value": format_pct(stats["weighted_5xx"] / stats["weight_for_5xx"]),
                "delta": None,
                "sub": f"weighted across {stats['n_with_5xx']} of {n} hosts",
            }
        )

    if not rows:
        return None
    return {"rows": rows}


def _fleet_stats(cards: list[dict]) -> dict[str, float | int]:
    stats: dict[str, float | int] = {
        "total_cur_req": 0.0,
        "total_base_req": 0.0,
        "total_cur_misses": 0.0,
        "weighted_miss_pct": 0.0,
        "weighted_origin_p95": 0.0,
        "weight_for_origin": 0.0,
        "weighted_5xx": 0.0,
        "weight_for_5xx": 0.0,
        "n_with_requests": 0,
        "n_with_baseline_requests": 0,
        "n_with_misses": 0,
        "n_with_miss_pct": 0,
        "n_with_origin": 0,
        "n_with_5xx": 0,
    }
    for sc in cards:
        _accumulate_fleet_metrics(stats, sc["entity_metrics"])
    return stats


def _accumulate_fleet_metrics(stats: dict[str, float | int], m: dict) -> None:
    cur = m.get("current_requests") or 0.0
    if m.get("current_requests") is not None:
        stats["total_cur_req"] += cur
        stats["n_with_requests"] += 1
    if m.get("baseline_requests") is not None:
        stats["total_base_req"] += m["baseline_requests"] or 0.0
        stats["n_with_baseline_requests"] += 1
    if m.get("current_cache_misses") is not None:
        stats["total_cur_misses"] += m["current_cache_misses"] or 0.0
        stats["n_with_misses"] += 1
    _accumulate_weighted_metric(stats, m, cur, "current_cache_miss_pct", "weighted_miss_pct", "n_with_miss_pct")
    _accumulate_weighted_metric(stats, m, cur, "current_origin_p95_ms", "weighted_origin_p95", "n_with_origin", "weight_for_origin")
    _accumulate_weighted_metric(stats, m, cur, "current_5xx_pct", "weighted_5xx", "n_with_5xx", "weight_for_5xx")


def _accumulate_weighted_metric(
    stats: dict[str, float | int],
    m: dict,
    cur: float,
    metric_key: str,
    weighted_key: str,
    count_key: str,
    weight_key: str | None = None,
) -> None:
    if m.get(metric_key) is None or cur <= 0:
        return
    stats[weighted_key] += (m[metric_key] or 0.0) * cur
    stats[count_key] += 1
    if weight_key is not None:
        stats[weight_key] += cur


def _fleet_cache_miss_row(stats: dict[str, float | int], n: int) -> dict | None:
    if not stats["n_with_misses"] and not stats["n_with_miss_pct"]:
        return None
    weighted_pct = (
        stats["weighted_miss_pct"] / stats["total_cur_req"]
        if stats["n_with_miss_pct"] and stats["total_cur_req"]
        else None
    )
    if stats["n_with_misses"] and weighted_pct is not None:
        value = f"{format_count(stats['total_cur_misses'])} ({format_pct(weighted_pct)} weighted)"
    elif stats["n_with_misses"]:
        value = format_count(stats["total_cur_misses"])
    else:
        value = format_pct(weighted_pct) if weighted_pct is not None else "—"
    return {
        "label": "Cache misses",
        "value": value,
        "delta": None,
        "sub": f"across {max(stats['n_with_misses'], stats['n_with_miss_pct'])} of {n} hosts",
    }
