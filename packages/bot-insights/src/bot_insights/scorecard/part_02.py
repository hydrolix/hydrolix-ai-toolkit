from __future__ import annotations

from ._shared import *
from .part_01 import *

def combine_period_rows(
    rows: list[dict[str, Any]], entity_type: str
) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    saw_period = False
    saw_non_period = False

    for row in rows:
        period = str(row.get("period", "")).lower()
        if period not in {"current", "baseline", "after", "before"}:
            saw_non_period = True
            continue
        saw_period = True
        normalized_period = (
            "current"
            if period == "after"
            else "baseline"
            if period == "before"
            else period
        )
        row_entity_type = infer_entity_type(
            row, entity_type if entity_type != "value" else None
        )
        entity = entity_value(row, row_entity_type)
        key = (row_entity_type, entity)
        combined = grouped.setdefault(key, {row_entity_type: entity})
        for field, value in row.items():
            if field in METADATA_KEYS or field in SUPPORTED_ENTITY_TYPES:
                continue
            if field in PROVENANCE_KEYS:
                merge_period_metadata(
                    combined,
                    field,
                    value,
                    entity_type=row_entity_type,
                    entity=entity,
                )
                continue
            combined[f"{normalized_period}_{field}"] = value

    if not saw_period:
        return rows
    if saw_non_period:
        raise ValueError(
            "Input rows must not mix period-split rows with already-combined "
            "entity rows. Normalize or join rows before running scorecard.py."
        )
    return list(grouped.values())

def metadata_from(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    metadata = dict(
        value.get("confidence_context", {})
        if isinstance(value.get("confidence_context"), dict)
        else {}
    )
    for key in (
        "scope",
        "comparison_type",
        "granularity",
        "table_used",
        "current_window",
        "baseline_windows",
        "summary_table_used",
        "source_coverage_caveat",
        "source_caveats",
        "rowset_complete",
        "contribution_basis",
        "rowset_scope",
        "feature_provenance",
        "analysis_domains",
    ):
        if key in value:
            metadata[key] = value[key]
    return json_safe(metadata)

def normalize_analysis_domains(value: Any) -> tuple[str, ...]:
    if value is None or value == "":
        return tuple(DOMAINS)
    if isinstance(value, str):
        candidates = [item.strip() for item in value.split(",")]
    elif isinstance(value, list):
        candidates = [str(item).strip() for item in value]
    elif isinstance(value, tuple):
        candidates = [str(item).strip() for item in value]
    else:
        raise ValueError("analysis_domains must be a list or comma-separated string.")

    domains = tuple(dict.fromkeys(item for item in candidates if item))
    invalid = [domain for domain in domains if domain not in DOMAINS]
    if invalid:
        raise ValueError(
            "analysis_domains contains unsupported domains: "
            + ", ".join(invalid)
            + ". Supported domains: "
            + ", ".join(DOMAINS)
        )
    return domains or tuple(DOMAINS)

def prepared_rows(
    value: Any, entity_type: str | None = None
) -> tuple[list[dict[str, Any]], str]:
    rows = result_rows(value)
    if not rows and isinstance(value, dict):
        rows = [value]

    requested = entity_type
    if requested is None and isinstance(value, dict):
        candidate = value.get("entity_type") or value.get("dimension")
        if str(candidate) in SUPPORTED_ENTITY_TYPES:
            requested = str(candidate)

    inferred = requested or (infer_entity_type(rows[0]) if rows else "value")
    rows = combine_period_rows(rows, inferred)
    if rows and inferred == "value":
        inferred = infer_entity_type(rows[0])
    return rows, inferred

def metric_values(
    row: dict[str, Any], metric: tuple[str, ...]
) -> tuple[float | None, float | None]:
    return current_number(row, *metric), baseline_number(row, *metric)

def make_feature(
    name: str,
    domain: str,
    points: int,
    evidence: str,
    *,
    current: float | None = None,
    baseline: float | None = None,
    threshold: float | None = None,
    supporting_metrics: dict[str, Any] | None = None,
) -> dict[str, Any]:
    feature: dict[str, Any] = {
        "name": name,
        "domain": domain,
        "points": points,
        "evidence": evidence,
    }
    if current is not None:
        feature["current"] = clean_number(current)
    if baseline is not None:
        feature["baseline"] = clean_number(baseline)
    if threshold is not None:
        feature["threshold"] = clean_number(threshold)
    if supporting_metrics:
        feature["supporting_metrics"] = supporting_metrics
    return feature

def evaluated_zero_feature(
    name: str,
    domain: str,
    *,
    current: float | None = None,
    baseline: float | None = None,
    threshold: float | None = None,
    supporting_metrics: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return make_feature(
        name,
        domain,
        0,
        "Rule evaluated below threshold.",
        current=current,
        baseline=baseline,
        threshold=threshold,
        supporting_metrics=supporting_metrics,
    )

def missing_feature(
    name: str, domain: str, missing_inputs: list[str]
) -> dict[str, Any]:
    return {
        "name": name,
        "domain": domain,
        "missing_inputs": sorted(set(missing_inputs)),
        "reason": "feature_input_missing",
    }

def eval_new_entity(
    row: dict[str, Any],
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    current, baseline = count_values(row)
    if current is None or baseline is None:
        return None, missing_feature(
            "new_entity", "movement", ["current_requests", "baseline_requests"]
        )
    if baseline < 1 and current > 0:
        return make_feature(
            "new_entity",
            "movement",
            12,
            f"Entity has {clean_number(current)} current requests and no baseline support.",
            current=current,
            baseline=baseline,
            threshold=1,
        ), None
    return evaluated_zero_feature(
        "new_entity",
        "movement",
        current=current,
        baseline=baseline,
        threshold=1,
    ), None

def eval_volume_delta_high(
    row: dict[str, Any],
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    current, baseline = count_values(row)
    if current is None or baseline is None:
        return None, missing_feature(
            "volume_delta_high", "movement", ["current_requests", "baseline_requests"]
        )
    delta = current - baseline
    change = pct_delta(current, baseline)
    if delta >= 100 and change >= 100:
        return make_feature(
            "volume_delta_high",
            "movement",
            12,
            f"Request volume increased by {clean_number(delta)} ({clean_number(change)}%).",
            current=current,
            baseline=baseline,
            threshold=100,
            supporting_metrics={
                "absolute_delta": clean_number(delta),
                "pct_change": clean_number(change),
            },
        ), None
    return evaluated_zero_feature(
        "volume_delta_high",
        "movement",
        current=current,
        baseline=baseline,
        threshold=100,
        supporting_metrics={
            "absolute_delta": clean_number(delta),
            "pct_change": clean_number(change),
        },
    ), None

def eval_contribution_to_total_delta_high(
    row: dict[str, Any],
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    contribution = first_number(
        row, ("contribution_pct", "contribution_to_total_delta_pct")
    )
    if contribution is None:
        return None, missing_feature(
            "contribution_to_total_delta_high",
            "movement",
            ["contribution_pct"],
        )
    if contribution >= 20:
        return make_feature(
            "contribution_to_total_delta_high",
            "movement",
            10,
            f"Entity contributes {clean_number(contribution)}% of the total absolute delta.",
            current=contribution,
            threshold=20,
        ), None
    return evaluated_zero_feature(
        "contribution_to_total_delta_high",
        "movement",
        current=contribution,
        threshold=20,
    ), None

def eval_bot_share_delta_high(
    row: dict[str, Any],
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    current, baseline = metric_values(row, ("bot_share_pct", "bot_pct"))
    if current is None or baseline is None:
        return None, missing_feature(
            "bot_share_delta_high",
            "movement",
            ["current_bot_share_pct", "baseline_bot_share_pct"],
        )
    delta = current - baseline
    if delta >= 10:
        return make_feature(
            "bot_share_delta_high",
            "movement",
            8,
            f"Bot share increased by {clean_number(delta)} percentage points.",
            current=current,
            baseline=baseline,
            threshold=10,
            supporting_metrics={"absolute_delta_points": clean_number(delta)},
        ), None
    return evaluated_zero_feature(
        "bot_share_delta_high",
        "movement",
        current=current,
        baseline=baseline,
        threshold=10,
        supporting_metrics={"absolute_delta_points": clean_number(delta)},
    ), None

def eval_cache_miss_rate_high(
    row: dict[str, Any],
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    current = current_number(row, "cache_miss_pct", "miss_rate_pct")
    baseline = baseline_number(row, "cache_miss_pct", "miss_rate_pct")
    if current is None:
        misses = current_number(row, "cache_misses", "cnt_cache_miss")
        requests, _ = count_values(row)
        if misses is not None and requests and requests > 0:
            current = misses / requests * 100.0
    if current is None:
        return None, missing_feature(
            "cache_miss_rate_high", "cache_busting", ["cache_miss_pct"]
        )
    if current >= 50:
        return make_feature(
            "cache_miss_rate_high",
            "cache_busting",
            10,
            f"Cache miss rate is {clean_number(current)}%.",
            current=current,
            baseline=baseline,
            threshold=50,
            supporting_metrics={
                "absolute_delta_points": clean_number(current - baseline)
            }
            if baseline is not None
            else None,
        ), None
    return evaluated_zero_feature(
        "cache_miss_rate_high",
        "cache_busting",
        current=current,
        baseline=baseline,
        threshold=50,
        supporting_metrics={"absolute_delta_points": clean_number(current - baseline)}
        if baseline is not None
        else None,
    ), None

def eval_cache_miss_delta_high(
    row: dict[str, Any],
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    current, baseline = metric_values(row, ("cache_miss_pct", "miss_rate_pct"))
    if current is None or baseline is None:
        return None, missing_feature(
            "cache_miss_delta_high",
            "cache_busting",
            ["current_cache_miss_pct", "baseline_cache_miss_pct"],
        )
    delta = current - baseline
    if delta >= 15:
        return make_feature(
            "cache_miss_delta_high",
            "cache_busting",
            8,
            f"Cache miss rate increased by {clean_number(delta)} percentage points.",
            current=current,
            baseline=baseline,
            threshold=15,
            supporting_metrics={"absolute_delta_points": clean_number(delta)},
        ), None
    return evaluated_zero_feature(
        "cache_miss_delta_high",
        "cache_busting",
        current=current,
        baseline=baseline,
        threshold=15,
        supporting_metrics={"absolute_delta_points": clean_number(delta)},
    ), None

__all__ = [name for name in globals() if not name.startswith("__")]
