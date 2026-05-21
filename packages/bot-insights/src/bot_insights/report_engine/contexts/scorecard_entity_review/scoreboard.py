"""Score summary, windows projection, dek copy."""

from __future__ import annotations

from ... import volume_impact as vi

__all__ = [
    '_score_summary',
    '_windows',
    '_compute_dek',
]


def _score_summary(sc: dict) -> dict:
    """Minimal score_summary for the gauge — no histogram, no fleet stats."""
    score = sc["score"]
    baseline = sc.get("baseline_score")
    delta_pct = 0.0
    if baseline:
        delta_pct = (score - baseline) / baseline * 100
    return {
        "lowest": score,
        "median": score,
        "highest": score,
        "distribution": [(score, 1)],
        "bands": {sc["band"]: 1},
        "lowest_delta_pct": delta_pct,
        "scores": [score],
    }


def _windows(sc: dict, index: dict | None) -> dict | None:
    if index and index.get("current_window") and index.get("baseline_windows"):
        return {
            "current": index["current_window"],
            "baseline": index["baseline_windows"][0],
        }
    if sc.get("current_window") and sc.get("baseline_windows"):
        return {
            "current": sc["current_window"],
            "baseline": sc["baseline_windows"][0],
        }
    return None


def _cache_miss_dek_clause(metrics: dict) -> str | None:
    miss_pct = (metrics or {}).get("current_cache_miss_pct")
    if miss_pct is None or miss_pct < 50:
        return None
    base_miss_pct = (metrics or {}).get("baseline_cache_miss_pct")
    if base_miss_pct is not None and abs(miss_pct - base_miss_pct) < 2:
        return f"Cache miss rate {vi.format_pct(miss_pct)}, persistent vs prior window."
    return f"Cache miss rate {vi.format_pct(miss_pct)}."


def _triggered_dek_clause(triggered: list[dict]) -> str | None:
    if not triggered:
        return None
    n = len(triggered)
    rule_word = "rule" if n == 1 else "rules"
    domains = sorted({r["domain_label"] for r in triggered})
    domain_clause = (
        f" in {domains[0]}" if len(domains) == 1
        else f" across {len(domains)} domains"
    )
    return f"{n} {rule_word} triggered{domain_clause}."


def _missing_dek_clause(missing: list[dict], verdict: dict) -> str | None:
    if not missing:
        return None
    plural = "s" if len(missing) != 1 else ""
    if verdict.get("state") == "insufficient_data":
        return (
            f"{len(missing)} rule input{plural} missing — "
            "impact cannot be judged from this report alone."
        )
    return f"{len(missing)} rule{plural} could not be scored."


def _compute_dek(
    verdict: dict,
    score: int,
    triggered: list[dict],
    missing: list[dict],
    metrics: dict,
    is_selected_from_fleet: bool,
    fleet_total: int,
) -> str:
    parts = [f"{verdict['label']}."]
    # Lead with the dominant signal where available rather than the score.
    lead_clause = _cache_miss_dek_clause(metrics) or _triggered_dek_clause(triggered)
    if lead_clause:
        parts.append(lead_clause)
    missing_clause = _missing_dek_clause(missing, verdict)
    if missing_clause:
        parts.append(missing_clause)
    if is_selected_from_fleet:
        parts.append(f"Selected from {fleet_total}-host fleet review.")
    parts.append(f"Score {score}.")
    return " ".join(parts)
