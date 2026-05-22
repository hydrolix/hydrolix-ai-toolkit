"""Dimension, status, mix, and per-target evidence shaping."""

from __future__ import annotations

def _incident_dimension_rows(
    rows: list[dict], *, total_current: float, include_delta: bool = True
) -> list[dict]:
    import baselines as baselines_mod

    out: list[dict] = []
    for row in rows:
        current = baselines_mod.to_number(row.get("current_requests")) or 0.0
        baseline = baselines_mod.to_number(row.get("baseline_requests")) or 0.0
        share = 100.0 * current / total_current if total_current > 0 else 0.0
        entry: dict = {
            "value": str(row.get("value") if row.get("value") is not None else ""),
            "requests": int(current),
            "share_pct": baselines_mod.clean_number(round(share, 2)),
        }
        if include_delta:
            entry["delta_vs_baseline_pct"] = baselines_mod.clean_number(
                round(baselines_mod.pct_delta(current, baseline), 2)
            )
        out.append(entry)
    return out
def _incident_status_rows(
    rows: list[dict], *, total_current: float
) -> list[dict]:
    import baselines as baselines_mod

    out: list[dict] = []
    for row in rows:
        requests = baselines_mod.to_number(row.get("requests")) or 0.0
        share = 100.0 * requests / total_current if total_current > 0 else 0.0
        status_code_val = baselines_mod.to_number(row.get("status_code"))
        out.append(
            {
                "status_code": int(status_code_val) if status_code_val is not None else None,
                "requests": int(requests),
                "share_pct": baselines_mod.clean_number(round(share, 2)),
            }
        )
    return out
def _incident_bucketed_mix_timeseries(
    rows: list[dict],
    *,
    series_type: str,
    value_label: str,
) -> dict | None:
    """Project bucketed top-dimension rows into an optional evidence block."""
    import baselines as baselines_mod

    if not rows:
        return None
    out: list[dict] = []
    for row in rows:
        value = row.get("value")
        bucket = row.get("bucket")
        requests = baselines_mod.to_number(row.get("requests")) or 0
        if value in (None, "") or bucket in (None, "") or requests <= 0:
            continue
        out.append(
            {
                "bucket": str(bucket),
                "value": str(value),
                "requests": int(requests),
            }
        )
    if not out:
        return None
    return {
        "series_type": series_type,
        "value_label": value_label,
        "points": out,
    }
def _incident_target_evidence_rows(rows: list[dict]) -> dict[str, dict]:
    """Compute optional per-target evidence from target/bucket rows.

    Input rows are intentionally simple so old artifacts remain valid:
    ``target_type``, ``target_value``, ``bucket``, ``requests`` plus
    optional dominant dimension columns. Missing dominant dimensions are
    ignored instead of guessed.
    """
    import baselines as baselines_mod

    grouped: dict[str, list[dict]] = {}
    for row in rows:
        target_type = str(row.get("target_type") or "")
        target_value = str(row.get("target_value") or "")
        bucket = str(row.get("bucket") or "")
        requests = baselines_mod.to_number(row.get("requests")) or 0
        if not target_type or not target_value or not bucket or requests <= 0:
            continue
        key = f"{target_type}:{target_value}"
        grouped.setdefault(key, []).append({**row, "requests": int(requests)})

    evidence: dict[str, dict] = {}
    for key, target_rows in grouped.items():
        target_rows.sort(key=lambda r: str(r.get("bucket") or ""))
        evidence[key] = _incident_target_evidence_entry(key, target_rows)
    return evidence
def _incident_target_evidence_entry(key: str, target_rows: list[dict]) -> dict:
    peak = max(target_rows, key=lambda r: int(r.get("requests") or 0))
    target_type, target_value = key.split(":", 1)
    entry: dict = {
        "target_type": target_type,
        "target_value": target_value,
        "first_seen": str(target_rows[0].get("bucket") or ""),
        "last_seen": str(target_rows[-1].get("bucket") or ""),
        "peak_bucket": str(peak.get("bucket") or ""),
        "peak_requests": int(peak.get("requests") or 0),
        "bucketed_requests": [
            {
                "bucket": str(row.get("bucket") or ""),
                "requests": int(row.get("requests") or 0),
            }
            for row in target_rows
        ],
    }
    for field, output_name, share_name in (
        ("dominant_path", "dominant_path", None),
        ("dominant_user_agent", "dominant_user_agent", None),
        ("dominant_cohort", "dominant_cohort", None),
        ("dominant_edge_action", "dominant_edge_action", "action_share_pct"),
    ):
        dominant = _incident_dominant_target_value(target_rows, field, share_name)
        if dominant:
            entry[output_name] = dominant
    return entry
def _incident_dominant_target_value(
    target_rows: list[dict], field: str, share_field: str | None = None
) -> dict | None:
    import baselines as baselines_mod

    total = sum(int(row.get("requests") or 0) for row in target_rows)
    counts: dict[str, int] = {}
    for row in target_rows:
        value = str(row.get(field) or "")
        if field == "dominant_edge_action" and not value.strip():
            value = "No Action"
        if value:
            counts[value] = counts.get(value, 0) + int(row.get("requests") or 0)
    if not counts:
        return None
    value, requests = max(counts.items(), key=lambda kv: kv[1])
    out = {
        "value": value,
        "requests": requests,
        "share_pct": baselines_mod.clean_number(round(100.0 * requests / total, 2))
        if total > 0
        else 0,
    }
    if share_field:
        out[share_field] = out["share_pct"]
    return out
