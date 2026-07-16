"""Scorecard-fleet analysis helpers used by legacy MD + HTML builders."""

from __future__ import annotations

from typing import Any
from report_engine.humanize import rule_label_parts
from report_engine.humanize import stringify

from .constants import (
    CONFIDENCE_ORDER,
    CRAWLER_FEATURES,
    EDGE_OPS_DOMAINS,
    EDGE_OPS_FEATURES,
    GENERIC_CRAWLER_RATE_FEATURES,
    SCORECARD_SCHEMA,
    TIMESERIES_SCHEMA,
)
from .formatters import to_float
from .validators import schema_of

__all__ = [
    'domain_score_order',
    'ordered_scorecards',
    'crawler_specific_provenance',
    'crawler_provenance_gaps',
    'crawler_features_for_card',
    'edge_ops_features_for_card',
    'scorecard_triggered_rules',
    'scorecard_has_trigger',
    'lowest_confidence',
    'scorecard_rank_lookup',
    'fleet_ordered_scorecards',
    'scorecard_primary_evidence',
    'fleet_rule_coverage',
    'fleet_common_triggered_feature',
    'fleet_health_score',
    'scorecard_rule_results',
    'timeseries_artifacts',
    'spark_points',
    '_format_scope_value',
    '_format_list_value',
    '_producer_limit_bullet',
    '_source_population_caveat',
]


def domain_score_order(scorecards: list[dict[str, Any]]) -> list[str]:
    domains: list[str] = []
    seen: set[str] = set()
    for card in scorecards:
        domain_scores = card.get("domain_scores")
        if not isinstance(domain_scores, dict):
            continue
        for domain in domain_scores:
            domain_text = str(domain)
            if domain_text in seen:
                continue
            seen.add(domain_text)
            domains.append(domain_text)
    return domains


def ordered_scorecards(
    scorecards: list[dict[str, Any]], index: dict[str, Any] | None
) -> list[dict[str, Any]]:
    if not index:
        return scorecards
    by_key = {
        (str(card.get("entity_type")), str(card.get("entity"))): card
        for card in scorecards
    }
    ordered = []
    for row in index.get("ranked_entities", []):
        key = (str(row.get("entity_type")), str(row.get("entity")))
        if key in by_key:
            ordered.append(by_key.pop(key))
    ordered.extend(by_key.values())
    return ordered


def crawler_specific_provenance(card: dict[str, Any], feature: dict[str, Any]) -> bool:
    allowed = {"crawler", "good_bot", "ai_crawler"}
    provenance = card.get("feature_provenance")
    name = str(feature.get("name"))
    if isinstance(provenance, dict):
        feature_provenance = provenance.get(name)
        if isinstance(feature_provenance, dict):
            rowset = feature_provenance.get("rowset_scope")
            if isinstance(rowset, dict) and rowset.get("population") in allowed:
                return True
    rowset = card.get("rowset_scope")
    return isinstance(rowset, dict) and rowset.get("population") in allowed


def crawler_provenance_gaps(card: dict[str, Any]) -> list[dict[str, Any]]:
    gaps: list[dict[str, Any]] = []
    if schema_of(card) != SCORECARD_SCHEMA:
        return gaps
    for feature in card.get("features", []):
        if not isinstance(feature, dict):
            continue
        if feature.get("domain") != "crawler_governance":
            continue
        name = str(feature.get("name"))
        if name not in GENERIC_CRAWLER_RATE_FEATURES:
            continue
        if crawler_specific_provenance(card, feature):
            continue
        gaps.append(feature)
    return gaps


def crawler_features_for_card(
    card: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    features: list[dict[str, Any]] = []
    for feature in card.get("features", []):
        if feature.get("domain") != "crawler_governance":
            continue
        name = str(feature.get("name"))
        if name not in CRAWLER_FEATURES:
            continue
        if name in GENERIC_CRAWLER_RATE_FEATURES and not crawler_specific_provenance(
            card, feature
        ):
            continue
        features.append(feature)
    missing = [
        item
        for item in card.get("not_evaluated_features", [])
        if item.get("domain") == "crawler_governance"
        and item.get("name") in CRAWLER_FEATURES
    ]
    return features, missing


def edge_ops_features_for_card(
    card: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    features = [
        feature
        for feature in card.get("features", [])
        if feature.get("domain") in EDGE_OPS_DOMAINS
        and feature.get("name") in EDGE_OPS_FEATURES
    ]
    missing = [
        item
        for item in card.get("not_evaluated_features", [])
        if item.get("domain") in EDGE_OPS_DOMAINS
        and item.get("name") in EDGE_OPS_FEATURES
    ]
    return features, missing


def scorecard_triggered_rules(card: dict[str, Any]) -> list[dict[str, Any]]:
    rules = [
        rule
        for rule in card.get("rule_results", [])
        if isinstance(rule, dict) and rule.get("status") == "triggered"
    ]
    if rules:
        return rules
    return [
        feature
        for feature in card.get("features", [])
        if isinstance(feature, dict) and (to_float(feature.get("points")) or 0) > 0
    ]


def scorecard_has_trigger(card: dict[str, Any]) -> bool:
    return bool(scorecard_triggered_rules(card))


def lowest_confidence(cards: list[dict[str, Any]]) -> str:
    values = [stringify(card.get("confidence")).lower() for card in cards]
    known_values = [value for value in values if value in CONFIDENCE_ORDER]
    if not known_values:
        return "unavailable"
    return min(known_values, key=lambda value: CONFIDENCE_ORDER[value])


def scorecard_rank_lookup(
    index: dict[str, Any] | None,
) -> dict[tuple[str, str], dict[str, Any]]:
    if not isinstance(index, dict):
        return {}
    lookup: dict[tuple[str, str], dict[str, Any]] = {}
    for row in index.get("ranked_entities", []):
        if isinstance(row, dict):
            lookup[
                (stringify(row.get("entity_type")), stringify(row.get("entity")))
            ] = row
    return lookup


def fleet_ordered_scorecards(
    cards: list[dict[str, Any]], index: dict[str, Any] | None
) -> list[tuple[int | None, dict[str, Any], dict[str, Any] | None]]:
    ranks = scorecard_rank_lookup(index)
    rows: list[tuple[int | None, int, dict[str, Any], dict[str, Any] | None]] = []
    for position, card in enumerate(cards):
        row = ranks.get(
            (stringify(card.get("entity_type")), stringify(card.get("entity")))
        )
        rank_number = to_float(row.get("rank")) if row else None
        rank = int(rank_number) if rank_number is not None else None
        rows.append((rank, position, card, row))
    rows.sort(key=lambda item: (item[0] is None, item[0] or item[1] + 1, item[1]))
    return [(rank, card, row) for rank, _position, card, row in rows]


def scorecard_primary_evidence(card: dict[str, Any]) -> str:
    summary = card.get("evidence_summary")
    if isinstance(summary, list):
        for item in summary:
            if item not in (None, ""):
                return stringify(item)
    for rule in scorecard_triggered_rules(card):
        evidence = rule.get("evidence")
        if evidence not in (None, ""):
            return stringify(evidence)
    return "No concise evidence emitted."


def fleet_rule_coverage(cards: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    coverage: dict[str, dict[str, int]] = {}
    for card in cards:
        for rule in card.get("rule_results", []):
            if not isinstance(rule, dict):
                continue
            status = rule.get("status")
            if status not in {"triggered", "evaluated_zero", "missing_input"}:
                continue
            domain = stringify(rule.get("domain"))
            bucket = coverage.setdefault(
                domain,
                {"triggered": 0, "evaluated_zero": 0, "missing_input": 0},
            )
            bucket[status] += 1
    return coverage


def fleet_common_triggered_feature(cards: list[dict[str, Any]]) -> tuple[str, int]:
    counts: dict[str, int] = {}
    for card in cards:
        seen_for_card: set[str] = set()
        for rule in scorecard_triggered_rules(card):
            name = stringify(rule.get("name"))
            if name in seen_for_card:
                continue
            seen_for_card.add(name)
            counts[name] = counts.get(name, 0) + 1
    if not counts:
        return "No triggered feature emitted", 0
    name, count = sorted(counts.items(), key=lambda item: (-item[1], item[0]))[0]
    return " ".join(part for part in rule_label_parts(name) if part), count


def fleet_health_score(cards: list[dict[str, Any]]) -> float | None:
    scores = [
        score for card in cards if (score := to_float(card.get("score"))) is not None
    ]
    if not scores:
        return None
    return sum(scores) / len(scores)


def scorecard_rule_results(card: dict[str, Any]) -> list[dict[str, Any]]:
    rule_results = [
        rule
        for rule in card.get("rule_results", [])
        if isinstance(rule, dict)
        and rule.get("status") in {"triggered", "evaluated_zero"}
    ]
    if rule_results:
        return rule_results
    fallback: list[dict[str, Any]] = []
    for feature in card.get("features", []):
        if isinstance(feature, dict):
            result = dict(feature)
            result["status"] = "triggered"
            fallback.append(result)
    return fallback


def timeseries_artifacts(artifacts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        artifact
        for artifact in artifacts
        if artifact.get("schema_version") == TIMESERIES_SCHEMA
        and isinstance(artifact.get("metrics"), list)
    ]


def spark_points(
    values: list[float], *, x: int, y: int, width: int, height: int
) -> str:
    if not values:
        return ""
    if len(values) == 1:
        return f"{x},{y + height / 2:.1f}"
    min_value = min(values)
    max_value = max(values)
    span = max(max_value - min_value, 1.0)
    points: list[str] = []
    for index, value in enumerate(values):
        px = x + (index / (len(values) - 1)) * width
        py = y + height - ((value - min_value) / span) * height
        points.append(f"{px:.1f},{py:.1f}")
    return " ".join(points)


def _format_scope_value(scope: Any) -> str:
    if isinstance(scope, dict) and scope:
        return ", ".join(f"{key}={value}" for key, value in sorted(scope.items()))
    if scope in (None, "", {}, []):
        return "unavailable"
    return stringify(scope)


def _format_list_value(value: Any) -> str:
    if isinstance(value, list):
        return ", ".join(stringify(item) for item in value) if value else "unavailable"
    if value in (None, "", [], {}):
        return "unavailable"
    return stringify(value)


def _producer_limit_bullet(artifact: dict[str, Any]) -> str | None:
    fields = (
        "result_row_count",
        "producer_limit",
        "result_truncated",
        "source_row_count",
        "total_ranked_entities",
    )
    parts = [
        f"{field}={stringify(artifact[field])}" for field in fields if field in artifact
    ]
    if not parts:
        return None
    return "Producer limits: " + ", ".join(parts)


def _source_population_caveat(artifact: dict[str, Any]) -> str | None:
    has_truncation_context = any(
        field in artifact
        for field in ("producer_limit", "result_row_count", "result_truncated")
    )
    if not has_truncation_context:
        return None
    if any(
        field in artifact for field in ("source_row_count", "total_ranked_entities")
    ):
        return None
    return (
        "Source population caveat: producer did not provide full source-population metadata;"
        " counts reflect emitted artifacts only, not the upstream population."
    )
