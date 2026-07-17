from __future__ import annotations

from typing import Any

from .constants import (
    ADVANCED_ATTRIBUTION_SCHEMA,
    ADVANCED_SCORECARD_INPUT_SCHEMA,
    ARTIFACT_SCHEMA,
    DOMAINS,
    INDEX_SCHEMA,
    INTERPRETATION_CONSTRAINTS,
    SCORECARD_SCHEMA,
    SUPPORTED_ENTITY_TYPES,
)
from .errors import InvalidScorecardInputError
from .features import metadata_from, normalize_analysis_domains, prepared_rows
from .numeric import json_safe
from .rows import (
    count_values,
    entity_value,
    first_number,
    validate_feature_provenance,
    validate_rowset_scope,
)
from .rules import BASELINE_SCORE_DELTA_BASIS
from .scoring import (
    _domain_scores,
    _entity_metrics,
    _evaluate_scorecard_rules,
    _primary_domain,
    baseline_score,
    confidence,
    evidence_summary,
    recommended_next_steps,
    score_band,
)


def score_entity(
    row: dict[str, Any],
    entity_type: str,
    metadata: dict[str, Any],
    min_count: float = 100.0,
    analysis_domains: tuple[str, ...] | None = None,
) -> dict[str, Any]:
    active_domains = analysis_domains or tuple(DOMAINS)
    features, not_evaluated, rule_results = _evaluate_scorecard_rules(
        row, active_domains
    )
    domain_scores = _domain_scores(features, rule_results)
    risk_points = min(100, sum(int(feature["points"]) for feature in features))
    score = 100 - risk_points
    prior_score = baseline_score(row, active_domains)
    primary_domain = _primary_domain(domain_scores)
    label, reasons = confidence(row, metadata, not_evaluated, min_count, active_domains)
    entity_metrics = _entity_metrics(row)
    scorecard = _base_scorecard(
        row=row,
        entity_type=entity_type,
        metadata=metadata,
        active_domains=active_domains,
        features=features,
        not_evaluated=not_evaluated,
        rule_results=rule_results,
        domain_scores=domain_scores,
        score=score,
        prior_score=prior_score,
        primary_domain=primary_domain,
        label=label,
        reasons=reasons,
        entity_metrics=entity_metrics,
    )
    _attach_scorecard_metadata(scorecard, row, metadata, active_domains)
    return scorecard


def _base_scorecard(
    *,
    row: dict[str, Any],
    entity_type: str,
    metadata: dict[str, Any],
    active_domains: tuple[str, ...],
    features: list[dict[str, Any]],
    not_evaluated: list[dict[str, Any]],
    rule_results: list[dict[str, Any]],
    domain_scores: dict[str, int],
    score: int,
    prior_score: int,
    primary_domain: str,
    label: str,
    reasons: list[str],
    entity_metrics: dict[str, Any],
) -> dict[str, Any]:
    return {
        "schema_version": SCORECARD_SCHEMA,
        "entity_type": entity_type,
        "entity": entity_value(row, entity_type),
        "scope": json_safe(metadata.get("scope", {})),
        "comparison_type": metadata.get("comparison_type", "previous_window"),
        "granularity": metadata.get("granularity", ""),
        "table_used": metadata.get("table_used", ""),
        "score": score,
        "baseline_score": prior_score,
        "score_delta_points": score - prior_score,
        "score_delta_basis": BASELINE_SCORE_DELTA_BASIS,
        "band": score_band(score),
        "primary_domain": primary_domain,
        "domain_scores": domain_scores,
        "features": sorted(
            features, key=lambda item: (str(item["domain"]), str(item["name"]))
        ),
        "not_evaluated_features": sorted(
            not_evaluated, key=lambda item: (str(item["domain"]), str(item["name"]))
        ),
        "rule_results": sorted(
            rule_results, key=lambda item: (str(item["domain"]), str(item["name"]))
        ),
        "evidence_summary": evidence_summary(features, not_evaluated),
        "recommended_next_steps": recommended_next_steps(features, not_evaluated),
        "confidence": label,
        "confidence_reasons": reasons,
        "entity_metrics": entity_metrics,
        "interpretation_constraints": INTERPRETATION_CONSTRAINTS,
    }


def _attach_scorecard_metadata(
    scorecard: dict[str, Any],
    row: dict[str, Any],
    metadata: dict[str, Any],
    active_domains: tuple[str, ...],
) -> None:
    if active_domains != tuple(DOMAINS):
        scorecard["analysis_domains"] = list(active_domains)
    if "current_window" in metadata:
        scorecard["current_window"] = json_safe(metadata["current_window"])
    if "baseline_windows" in metadata:
        scorecard["baseline_windows"] = json_safe(metadata["baseline_windows"])

    row_rowset_scope = row.get("rowset_scope")
    if row_rowset_scope is not None:
        scorecard["rowset_scope"] = validate_rowset_scope(
            row_rowset_scope, "row.rowset_scope"
        )
    elif "rowset_scope" in metadata:
        scorecard["rowset_scope"] = json_safe(metadata["rowset_scope"])

    row_feature_provenance = row.get("feature_provenance")
    if row_feature_provenance is not None:
        scorecard["feature_provenance"] = validate_feature_provenance(
            row_feature_provenance, "row.feature_provenance"
        )
    elif "feature_provenance" in metadata:
        scorecard["feature_provenance"] = json_safe(metadata["feature_provenance"])


def complete_contribution_scope(metadata: dict[str, Any]) -> bool:
    return (
        metadata.get("rowset_complete") is True
        or metadata.get("contribution_basis") == "complete_scope"
    )


def add_contribution_percentages(
    rows: list[dict[str, Any]], metadata: dict[str, Any]
) -> None:
    if not complete_contribution_scope(metadata):
        return

    row_deltas: list[tuple[dict[str, Any], float, bool]] = []
    for row in rows:
        current, baseline = count_values(row)
        if current is None or baseline is None:
            continue
        has_contribution = (
            first_number(row, ("contribution_pct", "contribution_to_total_delta_pct"))
            is not None
        )
        row_deltas.append((row, current - baseline, has_contribution))

    basis = sum(abs(delta) for _, delta, _ in row_deltas)
    if basis <= 0:
        return
    for row, delta, has_contribution in row_deltas:
        if has_contribution:
            continue
        row["contribution_pct"] = abs(delta) / basis * 100.0


def limit_metadata(total_count: int, emitted_count: int, limit: int) -> dict[str, Any]:
    if limit <= 0:
        return {}
    return {
        "producer_limit": limit,
        "result_row_count": emitted_count,
        "result_truncated": total_count > emitted_count,
        "total_ranked_entities": total_count,
    }


def build_index(
    scorecards: list[dict[str, Any]],
    metadata: dict[str, Any],
    limit: int = 0,
    total_count: int | None = None,
) -> dict[str, Any]:
    ranked = sorted(
        scorecards,
        key=lambda card: (
            int(card["score"]),
            str(card["entity_type"]),
            str(card["entity"]),
        ),
    )
    if limit > 0:
        ranked = ranked[:limit]
    total = len(scorecards) if total_count is None else total_count
    index = {
        "schema_version": INDEX_SCHEMA,
        "scope": json_safe(metadata.get("scope", {})),
        "comparison_type": metadata.get("comparison_type", "previous_window"),
        "table_used": metadata.get("table_used", ""),
        "ranked_entities": [
            {
                "rank": index + 1,
                "entity_type": card["entity_type"],
                "entity": card["entity"],
                "score": card["score"],
                "band": card["band"],
                "primary_domain": card["primary_domain"],
                "confidence": card["confidence"],
            }
            for index, card in enumerate(ranked)
        ],
        "interpretation_constraints": INTERPRETATION_CONSTRAINTS,
    }
    if "analysis_domains" in metadata:
        index["analysis_domains"] = json_safe(metadata["analysis_domains"])
    index.update(limit_metadata(total, len(ranked), limit))
    if "current_window" in metadata:
        index["current_window"] = json_safe(metadata["current_window"])
    if "baseline_windows" in metadata:
        index["baseline_windows"] = json_safe(metadata["baseline_windows"])
    return index


def validate_advanced_scorecard_input_boundary(
    value: Any,
    *,
    scorecard_trusted_context: Any = None,
) -> None:
    if not isinstance(value, dict):
        return

    schema_version = value.get("schema_version")
    if schema_version == ADVANCED_ATTRIBUTION_SCHEMA:
        raise InvalidScorecardInputError(
            "advanced_attribution_report_not_scorecard_input",
            "Direct bot_attribution_report.v1 input is not accepted by scorecard.py.",
            details={"schema_version": schema_version},
        )

    if schema_version != ADVANCED_SCORECARD_INPUT_SCHEMA:
        return

    if scorecard_trusted_context is None:
        raise InvalidScorecardInputError(
            "scorecard_trusted_context_missing",
            "bot_scorecard_input.v1 requires an in-process trusted scorecard context.",
            details=json_safe(
                {
                    "schema_version": schema_version,
                    "scorecard_export_safe": value.get("scorecard_export_safe"),
                }
            ),
        )

    raise InvalidScorecardInputError(
        "scorecard_trusted_context_invalid",
        "bot_scorecard_input.v1 trusted handoff validation is not implemented in this package.",
        details={"schema_version": schema_version},
    )


def build_artifacts(
    value: Any,
    *,
    entity_type: str | None = None,
    min_count: float = 100.0,
    limit: int = 0,
    analysis_domains: tuple[str, ...] | list[str] | str | None = None,
    scorecard_trusted_context: Any = None,
) -> dict[str, Any]:
    validate_advanced_scorecard_input_boundary(
        value,
        scorecard_trusted_context=scorecard_trusted_context,
    )
    metadata = metadata_from(value)
    if "rowset_scope" in metadata:
        validate_rowset_scope(metadata["rowset_scope"], "rowset_scope")
    if "feature_provenance" in metadata:
        validate_feature_provenance(
            metadata["feature_provenance"], "feature_provenance"
        )
    active_domains = normalize_analysis_domains(
        analysis_domains
        if analysis_domains is not None
        else metadata.get("analysis_domains")
    )
    if active_domains != tuple(DOMAINS):
        metadata["analysis_domains"] = list(active_domains)
    rows, inferred_entity_type = prepared_rows(value, entity_type)
    if inferred_entity_type not in SUPPORTED_ENTITY_TYPES:
        raise ValueError(
            "Input must include one of these entity columns: "
            + ", ".join(SUPPORTED_ENTITY_TYPES)
        )
    rows = [dict(row) for row in rows]
    add_contribution_percentages(rows, metadata)
    scorecards = [
        score_entity(row, inferred_entity_type, metadata, min_count, active_domains)
        for row in rows
        if entity_value(row, inferred_entity_type) != ""
    ]
    scorecards = sorted(
        scorecards,
        key=lambda card: (int(card["score"]), str(card["entity"])),
    )
    total_scorecards = len(scorecards)
    if limit > 0:
        scorecards = scorecards[:limit]
    index = build_index(scorecards, metadata, limit=limit, total_count=total_scorecards)
    artifacts = {
        "schema_version": ARTIFACT_SCHEMA,
        "scorecards": scorecards,
        "index": index,
    }
    artifacts.update(limit_metadata(total_scorecards, len(scorecards), limit))
    return artifacts
