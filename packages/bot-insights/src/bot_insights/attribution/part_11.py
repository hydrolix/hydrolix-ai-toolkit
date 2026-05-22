from __future__ import annotations

from ._shared import *
from .part_01 import *
from .part_02 import *
from .part_03 import *
from .part_04 import *
from .part_05 import *
from .part_06 import *
from .part_07 import *
from .part_08 import *
from .part_09 import *
from .part_10 import *

def normalize_attribution(input_doc: Any, trusted_context: Any = None, *, options: Any = None) -> dict[str, Any]:
    normalized = normalize_input_rows(input_doc, options=options)
    opts = normalize_options(options)
    analysis_type = normalized["analysis_type"]

    min_count_value = opts.get("min_count")
    if min_count_value is None:
        min_count_value = 100.0
    min_count = float(min_count_value)

    limit_value = opts.get("limit")
    limit = int(limit_value) if limit_value is not None else 0

    digest_payload = digest_payload_v1_from_normalized(normalized, options=opts)
    recomputed_digest = sha256_payload_digest(digest_payload)
    trust_validation = validate_trusted_context(
        trusted_context,
        normalized,
        digest_payload,
        recomputed_digest,
    )

    report_reasons = {"standalone_confidence_cap"}
    if analysis_type == "policy_displacement":
        report_reasons.add("policy_displacement_review")
    report_reasons.update(trust_validation["reasons"])
    if trusted_context is not None:
        report_reasons.add("trusted_context_reserved_for_future_tasks")

    report_reasons.update(normalized["limitations"])
    limitation_codes = {"aggregate_rows_only", "no_causal_claim", "contribution_withheld"}
    limitation_codes.update(
        reason for reason in trust_validation["reasons"] if reason in LIMITATION_MESSAGES
    )
    if normalized["metric_kind"] != "additive_count":
        report_reasons.add("non_additive_metric_contribution_withheld")
    if normalized.get("input_assertions"):
        report_reasons.add("caller_assertion_not_trusted")
        limitation_codes.add("caller_assertion_not_trusted")

    summary_table_used = normalized["report_metadata"].get("summary_table_used")
    if summary_table_used is True:
        report_reasons.add("summary_table_used")
    elif summary_table_used is False:
        report_reasons.add("request_level_query")
    summary_validation = normalized.get("summary_validation")
    if summary_validation and summary_validation["supported"]:
        report_reasons.add("summary_dimension_set_supported")

    skipped_period_absence: list[dict[str, Any]] = []
    lifecycle_support_missing_values: list[dict[str, Any]] = []
    movers: list[dict[str, Any]] = []
    saw_sparse = False

    for canonical_row in normalized["canonical_rows"]:
        classification = classify_row(canonical_row, min_count=min_count)
        if not classification["emit"]:
            if classification["skip_reason"] == "period_absence_not_trusted":
                skipped_period_absence.append(dict(canonical_row["dimensions"]))
            continue

        current = float(canonical_row["current"])
        baseline = float(canonical_row["baseline"])
        delta = current - baseline
        pct = pct_change(current, baseline)
        pct_guarded = baseline < 1.0
        row_reasons = set(classification["confidence_reasons"])
        candidate_flags = list(classification["candidate_flags"])

        if pct_guarded:
            row_reasons.add("pct_change_guarded")
            if baseline == 0:
                row_reasons.add("zero_baseline_guard")
            else:
                row_reasons.add("subunit_baseline_guard")
        if candidate_flags or "sparse_counts" in row_reasons:
            saw_sparse = True
            report_reasons.add("sparse_counts")
        if "lifecycle_support_missing" in row_reasons:
            lifecycle_support_missing_values.append(dict(canonical_row["dimensions"]))
            limitation_codes.add("lifecycle_support_missing")
            report_reasons.add("lifecycle_support_missing")

        mover = {
            "values": dict(canonical_row["dimensions"]),
            "current": clean_number(current),
            "baseline": clean_number(baseline),
            "absolute_delta": clean_number(delta),
            "pct_change": clean_number(pct),
            "pct_change_guarded": pct_guarded,
            "direction": direction(delta),
            "presence_lifecycle": classification["presence_lifecycle"],
            "support_change_label": classification["support_change_label"],
            "candidate_flags": candidate_flags,
            "confidence": "low" if row_reasons & {"sparse_counts", "lifecycle_support_missing"} else "medium",
            "confidence_reasons": sorted(row_reasons),
        }
        if canonical_row.get("current_support_raw") is not None:
            mover["current_support_raw"] = clean_number(canonical_row["current_support_raw"])
        if canonical_row.get("baseline_support_raw") is not None:
            mover["baseline_support_raw"] = clean_number(canonical_row["baseline_support_raw"])
        if canonical_row.get("baseline_support_normalized") is not None:
            mover["baseline_support_normalized"] = clean_number(canonical_row["baseline_support_normalized"])
        movers.append(mover)

    if skipped_period_absence:
        report_reasons.add("period_absence_not_trusted")
        limitation_codes.add("period_absence_not_trusted")

    if not movers:
        raise_invalid(
            "no_usable_metric_values",
            f"Rows do not contain comparable current/baseline values for metric '{normalized['metric']}'.",
            details={"metric": normalized["metric"]},
        )

    ranked_movers = sorted(
        movers,
        key=lambda mover: (
            -abs(float(mover["absolute_delta"])),
            dimension_sort_key(mover["values"], normalized["dimensions"]),
        ),
    )
    for rank, mover in enumerate(ranked_movers, start=1):
        mover["rank"] = rank

    output_limit_applied = limit > 0 and len(ranked_movers) > limit
    returned_movers = ranked_movers[:limit] if limit > 0 else ranked_movers
    total_current = sum(float(mover["current"]) for mover in returned_movers)
    total_baseline = sum(float(mover["baseline"]) for mover in returned_movers)
    total_delta = total_current - total_baseline
    total_abs_delta = sum(abs(float(mover["absolute_delta"])) for mover in returned_movers)

    if (
        saw_sparse
        or "metadata_poor_input" in report_reasons
        or "request_level_query" in report_reasons
        or "lifecycle_support_missing" in report_reasons
        or "unsupported_summary_dimension_set" in report_reasons
        or "unsupported_summary_filter" in report_reasons
    ):
        confidence = "low"
    else:
        confidence = "medium"

    not_evaluated_components: list[dict[str, Any]] = [
        {
            "name": "contribution_pct",
            "reason": "complete_scope_not_proven",
            "required_metadata": CONTRIBUTION_REQUIRED_METADATA,
        }
    ]
    if skipped_period_absence:
        not_evaluated_components.append(
            {
                "name": "presence_lifecycle",
                "reason": "period_absence_not_trusted",
                "skipped_count": len(skipped_period_absence),
                "sample_entity_values": skipped_period_absence[:SAMPLE_ENTITY_VALUES_LIMIT],
                "required_metadata": ZERO_FILL_REQUIRED_METADATA,
            }
        )
    if lifecycle_support_missing_values:
        not_evaluated_components.append(
            {
                "name": "presence_lifecycle",
                "reason": "lifecycle_support_missing",
                "affected_count": len(lifecycle_support_missing_values),
                "sample_entity_values": lifecycle_support_missing_values[:SAMPLE_ENTITY_VALUES_LIMIT],
            }
        )
    if summary_validation:
        if summary_validation["unsupported_grouped_dimensions"]:
            not_evaluated_components.append(
                {
                    "name": "summary_grouped_dimensions",
                    "reason": "unsupported_summary_dimension_set",
                    "selected_table": summary_validation["selected_table"],
                    "unsupported_columns": summary_validation["unsupported_grouped_dimensions"],
                    "retained_dimensions": summary_validation["retained_dimensions"],
                }
            )
        if summary_validation["unsupported_filter_columns"]:
            not_evaluated_components.append(
                {
                    "name": "summary_scope_filters",
                    "reason": "unsupported_summary_filter",
                    "selected_table": summary_validation["selected_table"],
                    "unsupported_columns": summary_validation["unsupported_filter_columns"],
                    "retained_dimensions": summary_validation["retained_dimensions"],
                }
            )

    method = (
        "policy_displacement_attribution"
        if analysis_type == "policy_displacement"
        else "aggregate_delta_attribution"
    )
    interpretation_constraints = list(INTERPRETATION_CONSTRAINTS)
    if analysis_type == "policy_displacement":
        interpretation_constraints.extend(
            [
                "policy_displacement_review",
                "requires_external_policy_change_evidence",
            ]
        )

    result = {
        "schema_version": ATTRIBUTION_SCHEMA,
        "method": method,
        "analysis_type": analysis_type,
        "metric": normalized["metric"],
        "metric_kind": normalized["metric_kind"],
        "dimensions": normalized["dimensions"],
        "row_shape": normalized["row_shape"],
        "rowset_complete": False,
        "source_limit_applied": normalized["report_metadata"].get("source_limit_applied", False),
        "output_limit_applied": output_limit_applied,
        "contribution_basis": "none",
        "totals_basis": "returned_rows",
        "total_current": clean_number(total_current),
        "total_baseline": clean_number(total_baseline),
        "total_delta": clean_number(total_delta),
        "total_abs_delta": clean_number(total_abs_delta),
        "movers": returned_movers,
        "returned_rows": len(returned_movers),
        "buckets": build_buckets(returned_movers),
        "not_evaluated_components": not_evaluated_components,
        "limitations": [limitation_doc(code) for code in sorted(limitation_codes | set(normalized["limitations"]))],
        "confidence": confidence,
        "confidence_reasons": sorted(report_reasons),
        "interpretation_constraints": interpretation_constraints,
    }
    if analysis_type == "policy_displacement":
        result["displacement_summary"] = displacement_summary(returned_movers)

    if limit > 0:
        result["output_limit"] = limit
    for key in (
        "analysis_type",
        "comparison_type",
        "granularity",
        "scope",
        "filters",
        "applied_scope_filters",
        "current_window",
        "policy_change",
        "policy_change_window",
        "reviewed_policy",
        "target_effect",
        "table_used",
        "summary_table_used",
    ):
        if key in normalized["report_metadata"]:
            result[key] = normalized["report_metadata"][key]
    if summary_validation is not None:
        result["summary_validation"] = summary_validation
    if "baseline_method" in normalized:
        result["baseline_method"] = normalized["baseline_method"]
    if "baseline_value_semantic" in normalized:
        result["baseline_value_semantic"] = normalized["baseline_value_semantic"]
    if "baseline_windows" in normalized:
        result["baseline_windows"] = normalized["baseline_windows"]
    if normalized.get("input_assertions"):
        result["input_assertions"] = normalized["input_assertions"]
    if trusted_context is not None:
        result["trusted_context_validation"] = {
            "trusted": trust_validation["trusted"],
            "valid": trust_validation["valid"],
            "result_digest": trust_validation["result_digest"],
            "evidence_types": trust_validation["evidence_types"],
            "reasons": sorted(trust_validation["reasons"]),
        }
    return result

def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        input_doc = json.loads(read_input(args))
    except json.JSONDecodeError as exc:
        print(
            json.dumps(
                invalid_input_doc("malformed_json", f"Input is not valid JSON: {exc.msg}.")
            ),
            indent=2,
            sort_keys=True,
        )
        return 2
    except OSError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    try:
        result = normalize_attribution(
            input_doc,
            trusted_context=None,
            options={
                "metric": args.metric,
                "dimensions": args.dimensions,
                "analysis": args.analysis,
                "min_count": args.min_count,
                "limit": args.limit,
                "output": args.output,
            },
        )
    except InvalidInputError as exc:
        print(json.dumps(exc.document, indent=2, sort_keys=True))
        return 2

    print(json.dumps(result, indent=2, sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

__all__ = [name for name in globals() if not name.startswith("__")]
