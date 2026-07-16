"""Legacy markdown body builders (test infrastructure only)."""

from __future__ import annotations

from typing import Any
from report_engine.humanize import display_label
from report_engine.humanize import human_metric_name
from report_engine.humanize import rule_label_parts
from report_engine.humanize import stringify

from .citations import resolve_citation
from .constants import (
    POSTURE_SCHEMA,
    SCORECARD_SCHEMA,
    TIMESERIES_SCHEMA,
)
from .errors import (
    ReportContext,
    ReportError,
)
from .formatters import (
    clean_display,
    human_delta,
    human_number,
    md_escape,
    to_float,
)
from .metrics import executive_summary_lines
from .scorecard_helpers import (
    _format_list_value,
    _format_scope_value,
    _producer_limit_bullet,
    _source_population_caveat,
    crawler_features_for_card,
    crawler_provenance_gaps,
    domain_score_order,
    edge_ops_features_for_card,
    ordered_scorecards,
)
from .tables import (
    artifact_display_name,
    limited_rows,
    md_table,
    resolve_scope_display,
    window_text,
)

__all__ = [
    'render_markdown',
    'md_executive',
    'md_soc',
    'md_scorecard_analysis',
    'md_missing_feature_evidence',
    'md_confidence_notes',
    'md_control',
    'md_control_check_table',
    'md_scorecard_brief',
    'md_domain_report',
    'md_ranking',
    'md_movers',
    'md_domain_matrix',
    'md_executive_scorecard_rollup',
    'md_feature_list',
    'md_feature_rows',
    'md_missing_rows',
    'md_evidence_limits',
    'md_analyst_notes',
    'validate_analyst_notes',
]


def render_markdown(
    title: str,
    report_type: str,
    selected: dict[str, Any],
    all_artifacts: list[dict[str, Any]],
    notes: list[dict[str, Any]],
    limit: int,
    ctx: ReportContext,
    *,
    scope_label: str | None = None,
    include_metadata: bool = True,
) -> str:
    scope_text = resolve_scope_display(scope_label, selected, ctx)
    parts = [
        f"# {md_escape(title)}",
    ]
    if include_metadata:
        parts.extend(
            [
                f"Report type: `{report_type}`",
                f"Scope: {md_escape(scope_text)}",
                "",
            ]
        )
    parts.append(md_analyst_notes(notes, all_artifacts, ctx))
    if report_type == "executive_posture":
        parts.append(md_executive(selected, limit, ctx))
    elif report_type == "soc_triage":
        parts.append(md_soc(selected, limit, ctx))
    elif report_type == "control_review":
        parts.append(md_control(selected, limit, ctx))
    elif report_type == "scorecard_brief":
        parts.append(md_scorecard_brief(selected, ctx))
    elif report_type == "crawler_governance":
        parts.append(
            md_domain_report(
                "Crawler Governance", selected, limit, ctx, crawler_features_for_card
            )
        )
    elif report_type == "edge_ops_impact":
        parts.append(
            md_domain_report(
                "Edge/Ops Impact", selected, limit, ctx, edge_ops_features_for_card
            )
        )
    parts.append(md_evidence_limits(all_artifacts, ctx))
    if ctx.warnings:
        parts.append(
            "## Warnings\n\n"
            + "\n".join(f"- {md_escape(warning)}" for warning in ctx.warnings)
        )
    return "\n\n".join(part for part in parts if part.strip()) + "\n"


def md_executive(selected: dict[str, Any], limit: int, ctx: ReportContext) -> str:
    posture = selected["posture"]
    metrics = limited_rows(posture.get("metrics", []), limit, "posture metrics", ctx)
    scorecards = selected.get("scorecards") or []
    rows = [
        [
            human_metric_name(metric.get("name")),
            human_number(metric.get("current")),
            human_number(metric.get("baseline")),
            human_delta(metric.get("absolute_delta")),
            human_number(metric.get("pct_change"), percent=True),
            metric.get("direction"),
            metric.get("confidence"),
        ]
        for metric in metrics
    ]
    parts = [
        "## Executive Summary",
        "\n".join(f"- {md_escape(line)}" for line in executive_summary_lines(metrics)),
        "## Metric Deltas",
        md_table(
            [
                "Metric",
                "Current",
                "Baseline",
                "Delta",
                "Pct change",
                "Direction",
                "Confidence",
            ],
            rows,
        )
        if rows
        else "No metric deltas available.",
    ]
    index = selected.get("index")
    if index:
        parts.extend(["## Top Scorecard Ranking", md_ranking(index, limit, ctx)])
        if scorecards:
            parts.extend(
                [
                    "## Lens Rollup",
                    md_executive_scorecard_rollup(scorecards, limit, ctx),
                    "## Domain Score Matrix",
                    md_domain_matrix(scorecards, limit, ctx),
                ]
            )
        else:
            parts.extend(
                [
                    "## Lens Rollup",
                    "Scorecard index is available, but compatible scorecard details were not provided; lens/domain rollups are unavailable.",
                ]
            )
    mover = selected.get("mover")
    if mover:
        parts.extend(["## Movers", md_movers(mover, limit, ctx)])
    return "\n\n".join(parts)


def md_soc(selected: dict[str, Any], limit: int, ctx: ReportContext) -> str:
    parts = ["## Top Risky Entities", md_ranking(selected["index"], limit, ctx)]
    scorecards = selected.get("scorecards") or []
    if scorecards:
        parts.extend(
            ["## Scorecard Analysis", md_scorecard_analysis(scorecards, limit, ctx)]
        )
        parts.extend(
            ["## Domain Score Matrix", md_domain_matrix(scorecards, limit, ctx)]
        )
        parts.extend(
            [
                "## Security Evidence Notes",
                md_feature_list(scorecards, {"security_evidence"}, None, limit, ctx),
            ]
        )
        missing_section = md_missing_feature_evidence(scorecards, limit, ctx)
        if missing_section:
            parts.extend(["## Missing Feature Evidence", missing_section])
        confidence_section = md_confidence_notes(scorecards, limit, ctx)
        if confidence_section:
            parts.extend(["## Confidence Notes", confidence_section])
    return "\n\n".join(parts)


def md_scorecard_analysis(
    scorecards: list[dict[str, Any]], limit: int, ctx: ReportContext
) -> str:
    sections: list[str] = []
    for card in limited_rows(scorecards, limit, "scorecard analysis entities", ctx):
        lines = [
            f"### {md_escape(card.get('entity'))}",
            "",
            md_table(
                ["Score", "Band", "Primary domain", "Confidence"],
                [
                    [
                        card.get("score"),
                        card.get("band"),
                        card.get("primary_domain"),
                        card.get("confidence"),
                    ]
                ],
            ),
        ]
        evidence = [
            item
            for item in card.get("evidence_summary", [])
            if item is not None and str(item) != ""
        ]
        if evidence:
            lines.extend(
                [
                    "",
                    "**Evidence Summary**",
                    "",
                    "\n".join(f"- {md_escape(item)}" for item in evidence),
                ]
            )
        features = card.get("features") or []
        if features:
            lines.extend(["", "**Evaluated Features**", "", md_feature_rows(features)])
        steps = [
            step["detail"] if isinstance(step, dict) else step
            for step in card.get("recommended_next_steps", [])
            if step is not None and str(step) != ""
        ]
        steps = [step for step in steps if step]
        if steps:
            lines.extend(
                [
                    "",
                    "**Recommended Next Steps**",
                    "",
                    "\n".join(f"- {md_escape(step)}" for step in steps),
                ]
            )
        if not evidence and not features and not steps:
            lines.extend(
                [
                    "",
                    "No scorecard narrative fields were emitted for this entity.",
                ]
            )
        sections.append("\n".join(lines))
    return "\n\n".join(sections) if sections else "No scorecard analysis available."


def md_missing_feature_evidence(
    scorecards: list[dict[str, Any]], limit: int, ctx: ReportContext
) -> str:
    groups = []
    for card in scorecards:
        missing = card.get("not_evaluated_features") or []
        if isinstance(missing, list) and missing:
            groups.append((card, missing))
    if not groups:
        return ""
    lines = []
    for card, missing in limited_rows(groups, limit, "missing-feature groups", ctx):
        lines.append(
            f"### {md_escape(card.get('entity'))}\n\n{md_missing_rows(missing)}"
        )
    return "\n\n".join(lines)


def md_confidence_notes(
    scorecards: list[dict[str, Any]], limit: int, ctx: ReportContext
) -> str:
    rows: list[list[Any]] = []
    for card in scorecards:
        reasons = card.get("confidence_reasons") or []
        confidence = card.get("confidence")
        if not confidence and not reasons:
            continue
        rows.append(
            [
                card.get("entity_type"),
                card.get("entity"),
                confidence or "unavailable",
                ", ".join(str(reason) for reason in reasons)
                if reasons
                else "unavailable",
            ]
        )
    if not rows:
        return ""
    rows = limited_rows(rows, limit, "confidence rows", ctx)
    return md_table(["Entity type", "Entity", "Confidence", "Confidence reasons"], rows)


def md_control(selected: dict[str, Any], limit: int, ctx: ReportContext) -> str:
    control = selected["control"]
    rows = []
    for effect in limited_rows(
        control.get("target_effects", []), limit, "control effects", ctx
    ):
        rows.append(
            [
                human_metric_name(effect.get("metric")),
                human_number(effect.get("before")),
                human_number(effect.get("after")),
                human_number(effect.get("expected")),
                human_delta(effect.get("absolute_delta_vs_expected")),
                human_number(effect.get("pct_change_vs_expected"), percent=True),
                effect.get("status"),
                effect.get("confidence"),
            ]
        )
    parts = [
        "## Control Review Summary",
        "Effectiveness review based on emitted artifact fields. The artifact alone is not causal proof.",
        f"Target: {md_escape(control.get('target', {}))}",
        f"Windows: {md_escape(window_text(control))}",
        "## Before/After/Expected",
        md_table(
            [
                "Metric",
                "Before",
                "After",
                "Expected",
                "Delta vs expected",
                "Pct change",
                "Status",
                "Confidence",
            ],
            rows,
        )
        if rows
        else "No target effects available.",
        "## Collateral Checks",
        md_control_check_table(
            control.get("collateral_checks") or [], limit, ctx, "collateral checks"
        ),
        "## Displacement Checks",
        md_control_check_table(
            control.get("displacement_checks") or [], limit, ctx, "displacement checks"
        ),
    ]
    basis = control.get("expected_basis")
    if basis:
        basis_label = stringify(basis).replace("_", " ")
        parts.extend(
            [
                "## Confidence",
                f"Expected basis: {md_escape(basis_label)}. This is an effectiveness review, not proof of cause.",
            ]
        )
    return "\n\n".join(parts)


def md_control_check_table(
    checks: list[Any], limit: int, ctx: ReportContext, label: str
) -> str:
    filtered = [check for check in checks if isinstance(check, dict)]
    if not filtered:
        return f"No {label} reported."
    limited = limited_rows(filtered, limit, label, ctx)
    rows = [
        [
            check.get("metric") or check.get("name"),
            check.get("before"),
            check.get("after"),
            check.get("absolute_delta") or check.get("delta"),
            check.get("pct_change"),
            check.get("status"),
            check.get("confidence"),
        ]
        for check in limited
    ]
    return md_table(
        ["Metric", "Before", "After", "Delta", "Pct change", "Status", "Confidence"],
        rows,
    )


def md_scorecard_brief(selected: dict[str, Any], ctx: ReportContext) -> str:
    card = selected["scorecard"]
    index = selected.get("index") or {}
    rank = None
    total_ranked = index.get("total_ranked_entities") or index.get("result_row_count")
    entity_type_label = display_label(card.get("entity_type"))
    for row in index.get("ranked_entities", []):
        if (
            isinstance(row, dict)
            and row.get("entity_type") == card.get("entity_type")
            and row.get("entity") == card.get("entity")
        ):
            rank = row.get("rank")
            break
    if rank is not None and total_ranked:
        rank_display = (
            f"{human_number(rank)} of {human_number(total_ranked)} scored "
            f"{entity_type_label} entities"
        )
    elif rank is not None:
        rank_display = f"{human_number(rank)} in scored entity set"
    else:
        rank_display = "unavailable"
    summary_rows = [
        ["Scored dimension", entity_type_label],
        ["Selected entity", card.get("entity")],
        ["Rank in scored set", rank_display],
        ["Current health score", human_number(card.get("score"))],
        ["Primary risk domain", display_label(card.get("primary_domain"))],
        ["Evidence confidence", card.get("confidence")],
    ]
    parts = [
        "## Selected Entity Context",
        (
            f"This brief explains one selected `{md_escape(entity_type_label)}` "
            "from the larger scored entity set."
        ),
        md_table(["Field", "Value"], summary_rows),
        "## Domain Scores",
        md_table(
            ["Domain", "Score"],
            [
                [display_label(domain), human_number(score)]
                for domain, score in (card.get("domain_scores") or {}).items()
            ],
        ),
        "## Evaluated Feature Evidence",
        md_feature_rows(card.get("features", []))
        if card.get("features")
        else "No evaluated features crossed thresholds.",
        "## Missing Scorecard Inputs",
        md_missing_rows(card.get("not_evaluated_features", []))
        if card.get("not_evaluated_features")
        else "No missing feature inputs reported.",
    ]
    steps = card.get("recommended_next_steps")
    if isinstance(steps, list) and steps:
        normalized = [
            step["detail"] if isinstance(step, dict) else step for step in steps
        ]
        parts.extend(
            [
                "## Recommended Next Steps",
                "\n".join(f"- {md_escape(step)}" for step in normalized),
            ]
        )
    producer = _producer_limit_bullet(card) or _producer_limit_bullet(index)
    if producer:
        parts.extend(["## Rowset Limits", md_escape(producer)])
    return "\n\n".join(parts)


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


def md_evidence_limits(artifacts: list[dict[str, Any]], ctx: ReportContext) -> str:
    sections: list[str] = ["## Evidence Limits"]
    for artifact in artifacts:
        aid = artifact.get("artifact_id") or "unavailable"
        schema = artifact.get("schema_version") or "unavailable"
        if schema == POSTURE_SCHEMA:
            bullets = [
                "- This is a movement report. It does not identify root cause by itself.",
            ]
            sections.append(
                f"### {md_escape(artifact_display_name(artifact))}\n\n"
                + "\n".join(bullets)
            )
            continue
        if schema == TIMESERIES_SCHEMA:
            metrics = artifact.get("metrics")
            metric_count = len(metrics) if isinstance(metrics, list) else 0
            is_control_trend = (
                artifact.get("title") == "Control Review Trends"
                or artifact.get("report_type") == "control_review"
            )
            comparison_label = (
                "after and expected windows"
                if is_control_trend
                else "current and prior windows"
            )
            exact_label = (
                "control effects table" if is_control_trend else "metric deltas table"
            )
            bullets = [
                f"- Trend cards: {metric_count} hourly metric series comparing {comparison_label}.",
                f"- Trend cards show shape and direction; exact aggregate values are in the {exact_label}.",
            ]
            sections.append(
                f"### {md_escape(artifact_display_name(artifact))}\n\n"
                + "\n".join(bullets)
            )
            continue
        bullets: list[str] = [f"- Schema: {md_escape(schema)}"]
        parent_id = artifact.get("parent_artifact_id")
        if parent_id:
            pointer = artifact.get("parent_json_pointer")
            parent_line = f"- Parent: {md_escape(parent_id)}"
            if pointer:
                parent_line += f" at {md_escape(pointer)}"
            bullets.append(parent_line)
        bullets.append(
            f"- Table: {md_escape(artifact.get('table_used') or 'unavailable')}"
        )
        bullets.append(
            f"- Scope: {md_escape(_format_scope_value(artifact.get('scope')))}"
        )
        bullets.append(
            f"- Confidence: {md_escape(artifact.get('confidence') or 'unavailable')}"
        )
        bullets.append(
            f"- Confidence reasons: {md_escape(_format_list_value(artifact.get('confidence_reasons')))}"
        )
        bullets.append(
            f"- Interpretation constraints: {md_escape(_format_list_value(artifact.get('interpretation_constraints')))}"
        )
        windows_text = window_text(artifact)
        if windows_text != "unavailable":
            bullets.append(f"- Windows: {md_escape(windows_text)}")
        not_evaluated = artifact.get("not_evaluated_features")
        if isinstance(not_evaluated, list) and not_evaluated:
            bullets.append("- Not-evaluated features:")
            for item in not_evaluated:
                if not isinstance(item, dict):
                    continue
                domain = item.get("domain") or "unavailable"
                name = item.get("name") or "unavailable"
                missing = ", ".join(
                    str(missing_input)
                    for missing_input in item.get("missing_inputs", [])
                )
                reason = item.get("reason") or "unavailable"
                missing_text = missing or "unavailable"
                bullets.append(
                    f"  - {md_escape(domain)} / {md_escape(name)}"
                    f" (missing inputs: {md_escape(missing_text)}; reason: {md_escape(reason)})"
                )
            if schema == SCORECARD_SCHEMA and isinstance(
                artifact.get("domain_scores"), dict
            ):
                domains = sorted(
                    {
                        str(item.get("domain"))
                        for item in not_evaluated
                        if isinstance(item, dict) and item.get("domain")
                    }
                )
                if domains:
                    bullets.append(
                        "- Domain score ambiguity: emitted numeric domain scores are rendered as-is; "
                        "missing inputs remain unresolved for "
                        + md_escape(", ".join(domains))
                        + "."
                    )
        provenance_gaps = crawler_provenance_gaps(artifact)
        if provenance_gaps:
            bullets.append("- Crawler provenance gaps:")
            for feature in provenance_gaps:
                name = feature.get("name") or "unavailable"
                bullets.append(
                    f"  - {md_escape(name)}: structured `rowset_scope`/`feature_provenance` "
                    "population is missing or non-crawler; generic 429/5xx feature was not rendered as a crawler finding."
                )
        producer_line = _producer_limit_bullet(artifact)
        if producer_line:
            bullets.append(f"- {md_escape(producer_line)}")
        caveat = _source_population_caveat(artifact)
        if caveat:
            bullets.append(f"- {md_escape(caveat)}")
        sections.append(f"### Artifact {md_escape(aid)}\n\n" + "\n".join(bullets))
    sections.append(
        "Reports use emitted artifact fields only. Missing evidence is unavailable, not zero or safe."
    )
    return "\n\n".join(sections)


def md_analyst_notes(
    notes: list[dict[str, Any]], artifacts: list[dict[str, Any]], ctx: ReportContext
) -> str:
    if not notes:
        return ""
    parts = [
        "## Analyst Notes",
        "These notes are interpretive narrative, not facts strictly proven by artifact data alone.",
    ]
    for index, note in enumerate(notes, start=1):
        author = note.get("author_type")
        if author not in {"llm", "analyst"}:
            ctx.warn(
                f"Analyst note {note.get('note_id', index)} has unsupported author_type {author}."
            )
            author = "analyst"
        label = "LLM interpretation" if author == "llm" else "Analyst interpretation"
        title = note.get("title") or f"Note {index}"
        parts.append(
            f"### {md_escape(title)}\n\n_{label}._ {md_escape(note.get('text', ''))}"
        )
        if note.get("show_data_sources") is False:
            continue
        sources = note.get("data_sources")
        if not isinstance(sources, list) or not sources:
            ctx.warn(
                f"Analyst note {note.get('note_id', index)} has no cited data sources."
            )
            continue
        citations = []
        for source in sources:
            _artifact, normalized_pointer, resolved = resolve_citation(
                source, artifacts
            )
            label = source.get("label") or "Supporting value"
            percent = normalized_pointer.endswith("/pct_change")
            citations.append(
                f"- {md_escape(label)}: {md_escape(human_number(resolved, percent=percent))}"
            )
        if citations:
            parts.append("Supporting evidence:\n\n" + "\n".join(citations))
    return "\n\n".join(parts)


def validate_analyst_notes(
    notes: list[dict[str, Any]], artifacts: list[dict[str, Any]]
) -> None:
    for index, note in enumerate(notes, start=1):
        note_id = note.get("note_id", index)
        text = note.get("text")
        if not isinstance(text, str) or not text.strip():
            raise ReportError(f"Analyst note {note_id} must include non-empty text.")
        author = note.get("author_type")
        if author not in {"llm", "analyst"}:
            raise ReportError(f"Analyst note {note_id} has unsupported author_type.")
        sources = note.get("data_sources", [])
        if sources is None:
            sources = []
        if not isinstance(sources, list):
            raise ReportError(f"Analyst note {note_id} data_sources must be an array.")
        for source in sources:
            if not isinstance(source, dict):
                raise ReportError(
                    f"Analyst note {note_id} data_sources entries must be objects."
                )
            resolve_citation(source, artifacts)
