"""Path-grain candidate row builders (cache_origin_impact_report.v1)."""

from __future__ import annotations

__all__ = [
    '_path_primary_label',
    '_miss_share',
    '_origin_share',
    '_path_evidence_line',
    '_build_path_candidates',
]


def _path_primary_label(dimensions: dict) -> str:
    """Join dimension values with ' · ', leading with request_path_norm."""
    if not dimensions:
        return ""
    parts: list[str] = []
    path = dimensions.get("request_path_norm")
    if path is not None:
        parts.append(str(path))
    for key, value in sorted(dimensions.items()):
        if key != "request_path_norm" and value is not None:
            parts.append(str(value))
    return " · ".join(parts) if parts else ""


def _miss_share(cand: dict) -> float | None:
    """Extract cache_miss_pct from the candidate's current metrics."""
    try:
        val = cand.get("current", {}).get("cache_miss_pct")
        if val is None:
            return None
        return float(val)
    except (TypeError, ValueError):
        return None


def _origin_share(cand: dict) -> float | None:
    """Extract origin pressure contribution share from current metrics."""
    current = cand.get("current") or {}
    for key in ("origin_pressure_contribution_pct", "origin_cost_contribution_pct"):
        val = current.get(key)
        if val is not None:
            try:
                return float(val)
            except (TypeError, ValueError):
                pass
    return None


def _path_evidence_line(cand: dict) -> str:
    """One short string summarizing the deltas for the path row footer."""
    deltas = cand.get("deltas") or {}
    parts: list[str] = []
    for key, value in sorted(deltas.items()):
        if value is None:
            continue
        try:
            f = float(value)
        except (TypeError, ValueError):
            continue
        # Render percentage-point-like fields as pp, ratio/pct fields as %
        if "pct" in key or "rate" in key or "share" in key:
            sign = "+" if f >= 0 else ""
            parts.append(f"{key} {sign}{f:.0f}pp")
        else:
            sign = "+" if f >= 0 else ""
            parts.append(f"{key} {sign}{f:.0f}%")
    return ", ".join(parts[:4])  # cap at 4 clauses to keep it readable


def _build_path_candidates(path_report: dict | None) -> list[dict]:
    """Build the path_candidates list from a cache_origin_impact_report.v1."""
    if path_report is None:
        return []
    raw_candidates = path_report.get("candidates") or []
    result: list[dict] = []
    for cand in raw_candidates:
        result.append(
            {
                "rank": cand.get("rank"),
                "dimensions": cand.get("entity") or {},
                "primary_label": _path_primary_label(cand.get("entity") or {}),
                "score": cand.get("candidate_score"),
                "band": cand.get("candidate_band"),
                "confidence": cand.get("confidence"),
                "current": cand.get("current") or {},
                "baseline": cand.get("baseline") or {},
                "deltas": cand.get("deltas") or {},
                "finding_types": cand.get("finding_types") or [],
                "miss_share_pct": _miss_share(cand),
                "origin_share_pct": _origin_share(cand),
                "evidence": _path_evidence_line(cand),
            }
        )
    return result
