from __future__ import annotations

from ._shared import *
from .part_01 import *
from .part_02 import *
from .part_03 import *

def trust_report_selector_matches(
    applies_to: Any,
    normalized: dict[str, Any],
) -> bool:
    if applies_to == {"scope": "report"}:
        return True
    if not isinstance(applies_to, dict):
        return False
    row_key = applies_to.get("row_key")
    if not isinstance(row_key, dict):
        return False
    dimensions = normalized["dimensions"]
    if sorted(row_key) != sorted(dimensions):
        return False
    normalized_row_key = {dimension: normalize_dimension_value(row_key.get(dimension)) for dimension in dimensions}
    return any(row["dimensions"] == normalized_row_key for row in normalized["canonical_rows"])

def values_match(left: Any, right: Any) -> bool:
    try:
        return normalize_digest_value(left, path="$.left") == normalize_digest_value(right, path="$.right")
    except InvalidInputError:
        return False

def append_once(values: list[str], value: str) -> None:
    if value not in values:
        values.append(value)

def validate_common_evidence_fields(
    evidence: dict[str, Any],
    *,
    context: dict[str, Any],
    normalized: dict[str, Any],
    contract: dict[str, Any],
    reasons: list[str],
) -> bool:
    valid = True
    if evidence.get("evidence_source") != TRUSTED_EVIDENCE_SOURCE:
        append_once(reasons, "trusted_evidence_mismatch")
        valid = False
    if evidence.get("generator_name") != SQL_GENERATOR_NAME:
        append_once(reasons, "trusted_evidence_mismatch")
        valid = False
    if evidence.get("generator_version") != SQL_GENERATOR_VERSION:
        append_once(reasons, "trusted_evidence_mismatch")
        valid = False
    if evidence.get("template_id") != contract.get("template_id"):
        append_once(reasons, "trusted_evidence_mismatch")
        valid = False

    if not is_sha256_digest(evidence.get("query_fingerprint")) or evidence.get("query_fingerprint") != context.get("query_fingerprint"):
        append_once(reasons, "trusted_evidence_mismatch")
        if evidence.get("query_fingerprint") in (None, ""):
            append_once(reasons, "query_fingerprint_missing")
        valid = False
    if not is_sha256_digest(evidence.get("result_digest")) or evidence.get("result_digest") != context.get("result_digest"):
        append_once(reasons, "trusted_evidence_mismatch")
        if evidence.get("result_digest") in (None, ""):
            append_once(reasons, "result_digest_missing")
        valid = False
    if not trust_report_selector_matches(evidence.get("applies_to"), normalized):
        append_once(reasons, "trusted_evidence_mismatch")
        valid = False
    for key in REQUIRED_TRUST_CONTRACT_FIELDS:
        if key not in contract or key not in evidence or not values_match(evidence[key], contract[key]):
            append_once(reasons, "trusted_evidence_mismatch")
            valid = False
    for key in (
        "scope_matches_report",
        "windows_match_report",
        "baseline_method_matches_report",
    ):
        if evidence.get(key) is not True:
            append_once(reasons, "trusted_evidence_mismatch")
            valid = False
    return valid

def trusted_decimal(value: Any, *, path: str) -> Decimal | None:
    try:
        return decimal_value(value, path=path)
    except InvalidInputError:
        return None

def digest_decimal_matches(left: Decimal, right: Decimal, *, places: int = 6) -> bool:
    try:
        return digest_decimal(left, path="$.left", places=places) == digest_decimal(right, path="$.right", places=places)
    except InvalidInputError:
        return False

def validate_provided_contribution_values(
    evidence: dict[str, Any],
    normalized: dict[str, Any],
    reasons: list[str],
) -> bool:
    valid = True
    tolerance = PROVIDED_CONTRIBUTION_TOLERANCE_PP
    if "contribution_pct_tolerance_pp" in evidence:
        evidence_tolerance = trusted_decimal(
            evidence.get("contribution_pct_tolerance_pp"),
            path="$.trusted_evidence.contribution_pct_tolerance_pp",
        )
        if evidence_tolerance is None or evidence_tolerance < 0:
            append_once(reasons, "provided_contribution_inconsistent")
            valid = False
        elif evidence_tolerance > PROVIDED_CONTRIBUTION_TOLERANCE_PP:
            append_once(reasons, "provided_contribution_inconsistent")
            valid = False
        else:
            tolerance = evidence_tolerance

    if evidence.get("contribution_pct_field") != "contribution_pct":
        append_once(reasons, "provided_contribution_inconsistent")
        valid = False
    if evidence.get("denominator_field") != "complete_scope_total_abs_delta":
        append_once(reasons, "provided_contribution_inconsistent")
        valid = False
    if not isinstance(evidence.get("denominator_expression"), str) or not evidence.get("denominator_expression").strip():
        append_once(reasons, "provided_contribution_inconsistent")
        valid = False
    if evidence.get("pre_denominator_filter_applied") is not False:
        append_once(reasons, "provided_contribution_inconsistent")
        valid = False
    if evidence.get("metric_semantics_reviewed") is not True:
        append_once(reasons, "provided_contribution_inconsistent")
        valid = False
    if evidence.get("reviewed_metric_kind") != normalized.get("metric_kind"):
        append_once(reasons, "provided_contribution_inconsistent")
        valid = False
    if normalized.get("metric_kind") != "additive_count":
        append_once(reasons, "provided_contribution_inconsistent")
        valid = False

    denominators: list[Decimal] = []
    for index, row in enumerate(normalized["canonical_rows"]):
        denominator = trusted_decimal(
            row.get("complete_scope_total_abs_delta"),
            path=f"$.canonical_rows[{index}].complete_scope_total_abs_delta",
        )
        if denominator is None or denominator < 0:
            append_once(reasons, "provided_contribution_inconsistent")
            valid = False
            continue
        denominators.append(denominator)

        contribution_present = "contribution_pct" in row
        contribution = trusted_decimal(
            row.get("contribution_pct"),
            path=f"$.canonical_rows[{index}].contribution_pct",
        ) if contribution_present and row.get("contribution_pct") is not None else None
        if denominator == 0:
            if contribution_present and row.get("contribution_pct") is not None:
                append_once(reasons, "provided_contribution_inconsistent")
                valid = False
            continue
        if contribution is None:
            append_once(reasons, "provided_contribution_inconsistent")
            valid = False
            continue
        rounded_contribution = trusted_decimal(
            digest_percentage(contribution, path=f"$.canonical_rows[{index}].contribution_pct"),
            path=f"$.canonical_rows[{index}].contribution_pct",
        )
        if rounded_contribution is None or rounded_contribution < 0 or rounded_contribution > 100:
            append_once(reasons, "provided_contribution_inconsistent")
            valid = False
            continue

        current = trusted_decimal(row.get("current"), path=f"$.canonical_rows[{index}].current")
        baseline = trusted_decimal(row.get("baseline"), path=f"$.canonical_rows[{index}].baseline")
        if current is None or baseline is None:
            append_once(reasons, "provided_contribution_inconsistent")
            valid = False
            continue
        absolute_delta = current - baseline
        if "absolute_delta" in row and row["absolute_delta"] is not None:
            supplied_absolute_delta = trusted_decimal(
                row["absolute_delta"],
                path=f"$.canonical_rows[{index}].absolute_delta",
            )
            if supplied_absolute_delta is None or not digest_decimal_matches(supplied_absolute_delta, absolute_delta):
                append_once(reasons, "provided_contribution_inconsistent")
                valid = False
        if "abs_delta" in row and row["abs_delta"] is not None:
            supplied_abs_delta = trusted_decimal(row["abs_delta"], path=f"$.canonical_rows[{index}].abs_delta")
            if supplied_abs_delta is None or not digest_decimal_matches(supplied_abs_delta, abs(absolute_delta)):
                append_once(reasons, "provided_contribution_inconsistent")
                valid = False

        expected = abs(absolute_delta) / denominator * Decimal("100")
        if abs(rounded_contribution - expected) > tolerance:
            append_once(reasons, "provided_contribution_inconsistent")
            valid = False

    if not denominators:
        append_once(reasons, "provided_contribution_inconsistent")
        valid = False
    elif any(not digest_decimal_matches(denominator, denominators[0]) for denominator in denominators[1:]):
        append_once(reasons, "provided_contribution_inconsistent")
        valid = False

    top_level_denominator = normalized.get("input_assertions", {}).get("complete_scope_total_abs_delta")
    if top_level_denominator is not None and denominators:
        top_level = trusted_decimal(top_level_denominator, path="$.complete_scope_total_abs_delta")
        if top_level is None or not digest_decimal_matches(top_level, denominators[0]):
            append_once(reasons, "provided_contribution_inconsistent")
            valid = False

    return valid

def validate_specific_evidence_fields(
    evidence: dict[str, Any],
    *,
    normalized: dict[str, Any],
    reasons: list[str],
) -> bool:
    evidence_type = evidence.get("evidence_type")
    valid = True
    if evidence_type == "complete_scope_pre_limit_evidence":
        required_true = (
            "computed_over_complete_grouped_scope",
            "computed_before_output_limit",
            "denominator_scope_matches_report",
        )
        if any(evidence.get(key) is not True for key in required_true):
            append_once(reasons, "trusted_evidence_mismatch")
            valid = False
        if evidence.get("denominator_basis") != "sum_abs_delta":
            append_once(reasons, "trusted_evidence_mismatch")
            valid = False
        if not isinstance(evidence.get("denominator_expression"), str) or not evidence.get("denominator_expression").strip():
            append_once(reasons, "trusted_evidence_mismatch")
            valid = False
        if evidence.get("source_limit_applied_before_denominator") is True:
            append_once(reasons, "trusted_evidence_mismatch")
            valid = False
    elif evidence_type == "zero_fill_evidence":
        period_value_trust = evidence.get("period_value_trust")
        if not isinstance(period_value_trust, dict) or not {
            "current",
            "baseline",
        }.issubset(period_value_trust):
            append_once(reasons, "trusted_evidence_mismatch")
            valid = False
        elif any(
            period_value_trust[side] not in {"complete_grouped_scope", "trusted_full_scope_join"}
            for side in ("current", "baseline")
        ):
            append_once(reasons, "trusted_evidence_mismatch")
            valid = False
        if not (evidence.get("grouped_scope_complete") is True or evidence.get("full_scope_joined_grouped_rowset") is True):
            append_once(reasons, "trusted_evidence_mismatch")
            valid = False
        if evidence.get("computed_before_output_limit") is not True:
            append_once(reasons, "trusted_evidence_mismatch")
            valid = False
    elif evidence_type == "provided_contribution_evidence":
        required_true = (
            "denominator_scope_matches_report",
            "computed_over_complete_grouped_scope",
            "computed_before_output_limit",
            "per_row_contribution",
        )
        if any(evidence.get(key) is not True for key in required_true):
            append_once(reasons, "provided_contribution_inconsistent")
            valid = False
        if evidence.get("source_limit_applied_before_denominator") is True:
            append_once(reasons, "provided_contribution_inconsistent")
            valid = False
        if evidence.get("denominator_basis") != "sum_abs_delta":
            append_once(reasons, "provided_contribution_inconsistent")
            valid = False
        if not isinstance(evidence.get("contribution_pct_field"), str) or not evidence.get("contribution_pct_field").strip():
            append_once(reasons, "provided_contribution_inconsistent")
            valid = False
        if not isinstance(evidence.get("denominator_field"), str) or not evidence.get("denominator_field").strip():
            append_once(reasons, "provided_contribution_inconsistent")
            valid = False
        if not validate_provided_contribution_values(evidence, normalized, reasons):
            valid = False
    elif evidence_type == "complete_rowset_evidence":
        if evidence.get("grouped_scope_complete") is not True or evidence.get("all_grouped_rows_returned") is not True:
            append_once(reasons, "trusted_evidence_mismatch")
            valid = False
    elif evidence_type == "request_level_coverage_evidence":
        if evidence.get("coverage_reviewed") is not True and evidence.get("request_level_coverage_reviewed") is not True:
            append_once(reasons, "trusted_evidence_mismatch")
            valid = False
    elif evidence_type == "duplicate_aggregation_evidence":
        if evidence.get("aggregation_allowed") is not True:
            append_once(reasons, "duplicate_aggregation_not_trusted")
            valid = False
        if evidence.get("partition_semantics") != "disjoint_source_partitions":
            append_once(reasons, "duplicate_aggregation_not_trusted")
            valid = False
        if not isinstance(evidence.get("partition_fields"), list) or not evidence.get("partition_fields"):
            append_once(reasons, "duplicate_aggregation_not_trusted")
            valid = False
    return valid

__all__ = [name for name in globals() if not name.startswith("__")]
