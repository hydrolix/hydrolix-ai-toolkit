"""Reusable legacy Markdown section and table builders."""

from __future__ import annotations

from typing import Any

from report_engine.humanize import display_label
from report_engine.humanize import rule_label_parts

from .errors import ReportContext
from .formatters import (
    clean_display,
    md_escape,
    to_float,
)
from .scorecard_helpers import (
    domain_score_order,
    ordered_scorecards,
)
from .tables import (
    limited_rows,
    md_table,
)

__all__ = [
    'md_domain_report',
    'md_ranking',
    'md_movers',
    'md_domain_matrix',
    'md_executive_scorecard_rollup',
    'md_feature_list',
    'md_feature_rows',
    'md_missing_rows',
]


def md_domain_report(
    heading: str,
    selected: dict[str, Any],
    limit: int,
    ctx: ReportContext,
    feature_selector: Any,
) -> str:
    scorecards = selected.get("scorecards") or []
    index = selected.get("index")
    relevant: list[tuple[dict[str, Any], list[dict[str, Any]]]] = []
    missing_count = 0
    for card in ordered_scorecards(scorecards, index):
        features, missing = feature_selector(card)
        missing_count += len(missing)
        if features:
            relevant.append((card, features))
    if not relevant:
        ctx.warn(
            f"{heading} report has scorecards but no eligible evaluated relevant evidence."
        )
        if missing_count:
            ctx.warn(
                f"{heading} report found {missing_count} relevant missing feature inputs."
            )
        return f"## {heading} Summary\n\nNo relevant {heading.lower()} evidence available. This is not evidence that posture is safe."
    limited = limited_rows(relevant, limit, f"{heading.lower()} entities", ctx)
    order_label = (
        "Rows follow scorecard index order."
        if index and selected.get("index_order_usable")
        else "Rows follow normalized scorecard input order; this is not a ranking."
    )
    rows = [
        [
            card.get("entity_type"),
            card.get("entity"),
            card.get("score"),
            ", ".join(str(feature.get("name")) for feature in features),
            card.get("confidence"),
        ]
        for card, features in limited
    ]
    parts = [
        f"## {heading} Summary",
        order_label,
        md_table(
            ["Entity type", "Entity", "Score", "Relevant features", "Confidence"], rows
        ),
        f"## {heading} Evidence",
    ]
    for card, features in limited:
        parts.append(
            f"### {md_escape(card.get('entity'))}\n\n" + md_feature_rows(features)
        )
    if missing_count:
        ctx.warn(
            f"{heading} report found {missing_count} relevant missing feature inputs."
        )
    return "\n\n".join(parts)


def md_ranking(index: dict[str, Any], limit: int, ctx: ReportContext) -> str:
    ranked = limited_rows(
        index.get("ranked_entities", []), limit, "ranked entities", ctx
    )
    rows = [
        [
            row.get("rank"),
            row.get("entity_type"),
            row.get("entity"),
            row.get("score"),
            row.get("band"),
            row.get("primary_domain"),
            row.get("confidence"),
        ]
        for row in ranked
    ]
    return (
        md_table(
            [
                "Rank",
                "Entity type",
                "Entity",
                "Score",
                "Band",
                "Primary domain",
                "Confidence",
            ],
            rows,
        )
        if rows
        else "No ranked entities available."
    )


def md_movers(mover: dict[str, Any], limit: int, ctx: ReportContext) -> str:
    movers = limited_rows(mover.get("movers", []), limit, "movers", ctx)
    rows = [
        [
            row.get("value"),
            row.get("metric"),
            row.get("current"),
            row.get("baseline"),
            row.get("absolute_delta"),
            row.get("contribution_pct"),
            row.get("confidence"),
        ]
        for row in movers
    ]
    return (
        md_table(
            [
                "Value",
                "Metric",
                "Current",
                "Baseline",
                "Delta",
                "Contribution pct",
                "Confidence",
            ],
            rows,
        )
        if rows
        else "No mover attribution available."
    )


def md_domain_matrix(
    scorecards: list[dict[str, Any]], limit: int, ctx: ReportContext
) -> str:
    domains = domain_score_order(scorecards)
    rows = []
    for card in limited_rows(scorecards, limit, "scorecards", ctx):
        domain_scores = card.get("domain_scores") or {}
        rows.append(
            [card.get("entity"), card.get("score")]
            + [domain_scores.get(domain, "unavailable") for domain in domains]
        )
    return (
        md_table(["Entity", "Total score"] + domains, rows)
        if rows
        else "No scorecard domain scores available."
    )


def md_executive_scorecard_rollup(
    scorecards: list[dict[str, Any]], limit: int, ctx: ReportContext
) -> str:
    domain_totals: dict[str, float] = {}
    primary_counts: dict[str, int] = {}
    caveats: dict[str, int] = {}
    for card in scorecards:
        primary = str(card.get("primary_domain") or "none")
        primary_counts[primary] = primary_counts.get(primary, 0) + 1
        domain_scores = card.get("domain_scores") or {}
        if isinstance(domain_scores, dict):
            for domain, score in domain_scores.items():
                numeric = to_float(score)
                if numeric is not None:
                    domain_text = str(domain)
                    domain_totals[domain_text] = (
                        domain_totals.get(domain_text, 0.0) + numeric
                    )
        for reason in card.get("confidence_reasons") or []:
            reason_text = str(reason)
            if reason_text in {
                "feature_input_missing",
                "siem_unavailable",
                "source_coverage_caveat",
                "sparse_counts",
            }:
                caveats[reason_text] = caveats.get(reason_text, 0) + 1

    domain_rows = [
        [domain, clean_display(score)]
        for domain, score in sorted(
            domain_totals.items(), key=lambda item: (-item[1], item[0])
        )
    ]
    primary_rows = [
        [domain, count]
        for domain, count in sorted(
            primary_counts.items(), key=lambda item: (-item[1], item[0])
        )
    ]
    caveat_rows = [
        [reason, count]
        for reason, count in sorted(
            caveats.items(), key=lambda item: (-item[1], item[0])
        )
    ]
    parts = [
        "Scorecard rollup uses emitted scorecard fields only; it does not create executive-only features.",
        "### Domain Totals",
        md_table(
            ["Domain", "Total score"],
            limited_rows(domain_rows, limit, "domain rollup rows", ctx),
        )
        if domain_rows
        else "No numeric domain scores available.",
        "### Primary Lens Counts",
        md_table(
            ["Primary domain", "Entities"],
            limited_rows(primary_rows, limit, "primary lens rows", ctx),
        )
        if primary_rows
        else "No primary domain values available.",
        "### Caveats",
        md_table(
            ["Caveat", "Entities"], limited_rows(caveat_rows, limit, "caveat rows", ctx)
        )
        if caveat_rows
        else "No scorecard caveats reported.",
    ]
    return "\n\n".join(parts)


def md_feature_list(
    scorecards: list[dict[str, Any]],
    domains: set[str],
    names: set[str] | None,
    limit: int,
    ctx: ReportContext,
) -> str:
    selected = []
    for card in scorecards:
        features = [
            feature
            for feature in card.get("features", [])
            if feature.get("domain") in domains
            and (names is None or feature.get("name") in names)
        ]
        if features:
            selected.append((card, features))
    if not selected:
        return "No matching feature evidence available."
    lines = []
    for card, features in limited_rows(selected, limit, "feature evidence groups", ctx):
        lines.append(
            f"### {md_escape(card.get('entity'))}\n\n{md_feature_rows(features)}"
        )
    return "\n\n".join(lines)


def md_feature_rows(features: list[dict[str, Any]]) -> str:
    rows = []
    for feature in features:
        feature_label, condition = rule_label_parts(feature.get("name"))
        rows.append(
            [
                display_label(feature.get("domain")),
                feature_label,
                condition,
                feature.get("points"),
                feature.get("evidence"),
            ]
        )
    return md_table(["Domain", "Feature", "Condition", "Points", "Evidence"], rows)


def md_missing_rows(missing: list[dict[str, Any]]) -> str:
    rows = []
    for feature in missing:
        feature_label, condition = rule_label_parts(feature.get("name"))
        rows.append(
            [
                display_label(feature.get("domain")),
                feature_label,
                condition,
                ", ".join(str(item) for item in feature.get("missing_inputs", [])),
                display_label(feature.get("reason")),
            ]
        )
    return md_table(
        ["Domain", "Feature", "Condition", "Missing inputs", "Reason"], rows
    )
