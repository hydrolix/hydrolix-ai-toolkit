"""Legacy markdown body builders (test infrastructure only)."""

from __future__ import annotations

from typing import Any
from report_engine.humanize import display_label
from report_engine.humanize import human_metric_name
from report_engine.humanize import stringify

from .errors import ReportContext
from .formatters import (
    human_delta,
    human_number,
    md_escape,
)
from .legacy_markdown_evidence import (
    md_analyst_notes,
    md_evidence_limits,
    validate_analyst_notes,
)
from .legacy_markdown_sections import (
    md_domain_matrix,
    md_domain_report,
    md_executive_scorecard_rollup,
    md_feature_list,
    md_feature_rows,
    md_missing_rows,
    md_movers,
    md_ranking,
)
from .metrics import executive_summary_lines
from .scorecard_helpers import (
    _producer_limit_bullet,
    crawler_features_for_card,
    edge_ops_features_for_card,
)
from .tables import (
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
