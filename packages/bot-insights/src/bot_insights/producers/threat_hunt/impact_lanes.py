from __future__ import annotations

from ._shared import *

def merge_impact_lanes_into_artifact(
    artifact: dict[str, Any],
    *,
    total_rows: list[dict[str, Any]] | None = None,
    scoped_hunt_rows: list[dict[str, Any]] | None = None,
    required: bool = False,
) -> dict[str, Any]:
    """Merge raw-log byte lane totals into a generated threat-hunt artifact."""
    impact = artifact.get("impact_assessment")
    if not isinstance(impact, dict):
        raise SystemExit("threat-hunt artifact is missing impact_assessment")
    totals = impact.get("totals")
    hunt = impact.get("hunt")
    if not isinstance(totals, dict) or not isinstance(hunt, dict):
        raise SystemExit("threat-hunt artifact has malformed impact_assessment")
    total_by_scope = _impact_lane_rows_by_scope(total_rows or [])
    hunt_by_scope = _impact_lane_rows_by_scope(scoped_hunt_rows or [])
    if required:
        missing_total = [scope for scope in IMPACT_LANE_TOTAL_SCOPES if scope not in total_by_scope]
        missing_hunt = [
            scope for scope in IMPACT_LANE_SCOPED_HUNT_SCOPES if scope not in hunt_by_scope
        ]
        if missing_total or missing_hunt:
            missing = [*missing_total, *missing_hunt]
            raise SystemExit(
                "impact lane rows missing required scope(s): " + ", ".join(missing)
            )

    current_totals = totals.get("current")
    baseline_totals = totals.get("baseline")
    if not isinstance(current_totals, dict) or not isinstance(baseline_totals, dict):
        raise SystemExit("threat-hunt artifact has malformed impact_assessment totals")

    current_total_lane = total_by_scope.get("current_total")
    baseline_total_lane = total_by_scope.get("baseline_total")
    current_hunt_lane = hunt_by_scope.get("current_high_partial")
    baseline_hunt_lane = hunt_by_scope.get("baseline_high_partial")

    _apply_impact_lane_totals(current_totals, current_total_lane)
    _apply_impact_lane_totals(baseline_totals, baseline_total_lane)
    _apply_impact_lane_hunt(hunt, current_hunt_lane, baseline_hunt_lane)
    _apply_impact_lane_hunt_request_shares(
        hunt,
        current_total_lane=current_total_lane,
        baseline_total_lane=baseline_total_lane,
        current_hunt_lane=current_hunt_lane,
        baseline_hunt_lane=baseline_hunt_lane,
    )
    _apply_impact_lane_hydrolix_estimate(
        impact,
        current_total_lane=current_total_lane,
        baseline_total_lane=baseline_total_lane,
        current_hunt_lane=current_hunt_lane,
        baseline_hunt_lane=baseline_hunt_lane,
    )
    _recompute_artifact_impact_lane_shares(artifact)
    return artifact

def _apply_impact_lane_totals(
    totals: dict[str, Any],
    row: dict[str, Any] | None,
) -> None:
    if not row:
        return
    totals["response_body_bytes"] = _num(row.get("response_body_bytes"))
    totals["akamai_billed_bytes"] = _num(row.get("akamai_billed_bytes"))

def _apply_impact_lane_hunt(
    hunt: dict[str, Any],
    current_row: dict[str, Any] | None,
    baseline_row: dict[str, Any] | None,
) -> None:
    if current_row:
        hunt["response_body_bytes"] = _num(current_row.get("response_body_bytes"))
        hunt["akamai_billed_bytes"] = _num(current_row.get("akamai_billed_bytes"))
    if baseline_row:
        hunt["baseline_response_body_bytes"] = _num(baseline_row.get("response_body_bytes"))
        hunt["baseline_akamai_billed_bytes"] = _num(baseline_row.get("akamai_billed_bytes"))

def _apply_impact_lane_hunt_request_shares(
    hunt: dict[str, Any],
    *,
    current_total_lane: dict[str, Any] | None,
    baseline_total_lane: dict[str, Any] | None,
    current_hunt_lane: dict[str, Any] | None,
    baseline_hunt_lane: dict[str, Any] | None,
) -> None:
    if not (current_total_lane and baseline_total_lane and current_hunt_lane and baseline_hunt_lane):
        return
    requests = _num(current_hunt_lane.get("requests"))
    baseline_requests = _num(baseline_hunt_lane.get("requests"))
    current_total_requests = _num(current_total_lane.get("requests"))
    baseline_total_requests = _num(baseline_total_lane.get("requests"))
    request_share = _share_fraction(requests, current_total_requests)
    baseline_request_share = _share_fraction(baseline_requests, baseline_total_requests)
    hunt["requests"] = requests
    hunt["baseline_requests"] = baseline_requests
    hunt["request_delta"] = requests - baseline_requests
    hunt["request_share"] = request_share
    hunt["baseline_request_share"] = baseline_request_share
    hunt["request_share_delta"] = (
        request_share - baseline_request_share
        if request_share is not None and baseline_request_share is not None
        else None
    )
    hunt["request_share_ratio"] = (
        request_share / baseline_request_share
        if request_share is not None and baseline_request_share not in (None, 0)
        else None
    )
    hunt["share_severity"] = _share_severity(request_share)
    hunt["trend_severity"] = _trend_severity(request_share, baseline_request_share)
    hunt["share_direction"] = _share_direction(request_share, baseline_request_share)

def _impact_lane_hydrolix_bytes(
    metadata: dict[str, Any],
    row: dict[str, Any] | None,
) -> float | None:
    if not row or metadata.get("availability") != "available":
        return None
    bytes_per_row = _num(metadata.get("billing_bytes_per_row"))
    if bytes_per_row <= 0:
        return None
    return _num(row.get("requests")) * bytes_per_row

def _apply_impact_lane_hydrolix_estimate(
    impact: dict[str, Any],
    *,
    current_total_lane: dict[str, Any] | None,
    baseline_total_lane: dict[str, Any] | None,
    current_hunt_lane: dict[str, Any] | None,
    baseline_hunt_lane: dict[str, Any] | None,
) -> None:
    metadata = impact.get("hydrolix_log_ingest_metadata")
    if not isinstance(metadata, dict):
        return
    totals = impact["totals"]
    hunt = impact["hunt"]
    current_total = _impact_lane_hydrolix_bytes(metadata, current_total_lane)
    baseline_total = _impact_lane_hydrolix_bytes(metadata, baseline_total_lane)
    current_hunt = _impact_lane_hydrolix_bytes(metadata, current_hunt_lane)
    baseline_hunt = _impact_lane_hydrolix_bytes(metadata, baseline_hunt_lane)
    if current_total is not None:
        totals["current"]["hydrolix_log_ingest_bytes"] = current_total
    if baseline_total is not None:
        totals["baseline"]["hydrolix_log_ingest_bytes"] = baseline_total
    if current_hunt is not None:
        hunt["hydrolix_log_ingest_bytes"] = current_hunt
    if baseline_hunt is not None:
        hunt["baseline_hydrolix_log_ingest_bytes"] = baseline_hunt

def _recompute_artifact_impact_lane_shares(artifact: dict[str, Any]) -> None:
    impact = artifact["impact_assessment"]
    totals = impact["totals"]
    current_totals = totals["current"]
    baseline_totals = totals["baseline"]
    for row in _walk_dicts(artifact):
        if "baseline_request_share" in row and (
            "response_body_byte_share" in row or "akamai_billed_byte_share" in row
        ):
            _recompute_impact_lane_shares(row, current_totals, baseline_totals)
        row_impact = row.get("impact_assessment")
        estimated = row.get("estimated_observed_window_impact")
        if isinstance(estimated, dict) and isinstance(row_impact, dict):
            for field in BYTE_LANE_FIELDS:
                share_field = field.replace("_bytes", "_byte_share")
                estimated[field] = row_impact.get(field)
                estimated[share_field] = row_impact.get(share_field)

def _walk_dicts(value: Any) -> Iterable[dict[str, Any]]:
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _walk_dicts(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_dicts(child)

def _recompute_impact_lane_shares(
    impact: dict[str, Any],
    current_totals: dict[str, Any],
    baseline_totals: dict[str, Any],
) -> None:
    lanes = (
        ("response_body_bytes", "response_body_byte_share"),
        ("akamai_billed_bytes", "akamai_billed_byte_share"),
        ("hydrolix_log_ingest_bytes", "hydrolix_log_ingest_byte_share"),
    )
    for field, share_field in lanes:
        baseline_field = f"baseline_{field}"
        baseline_share_field = f"baseline_{share_field}"
        current_total = (
            _num(current_totals.get(field))
            if current_totals.get(field) not in (None, "")
            else None
        )
        baseline_total = (
            _num(baseline_totals.get(field))
            if baseline_totals.get(field) not in (None, "")
            else None
        )
        current_value = (
            _num(impact.get(field))
            if impact.get(field) not in (None, "")
            else None
        )
        baseline_value = (
            _num(impact.get(baseline_field))
            if impact.get(baseline_field) not in (None, "")
            else None
        )
        impact[share_field] = _lane_share(current_value, current_total)
        impact[baseline_share_field] = _lane_share(baseline_value, baseline_total)

__all__ = [name for name in globals() if not name.startswith("__")]
