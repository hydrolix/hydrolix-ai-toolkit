"""Legacy HTML scorecard fleet report builders."""

from __future__ import annotations

from typing import Any

from report_engine.humanize import display_label
from report_engine.humanize import stringify

from .errors import ReportContext
from .formatters import (
    compact_window_range,
    h_escape,
    human_delta,
    human_number,
    to_float,
)
from .legacy_html_markdown import markdown_to_simple_html
from .legacy_markdown import md_analyst_notes
from .scorecard_helpers import (
    _producer_limit_bullet,
    fleet_common_triggered_feature,
    fleet_health_score,
    fleet_ordered_scorecards,
    fleet_rule_coverage,
    lowest_confidence,
    scorecard_has_trigger,
    scorecard_primary_evidence,
)
from .tables import resolve_scope_display

__all__ = [
    'html_fleet_kpis',
    'html_fleet_findings',
    'html_fleet_coverage',
    'html_fleet_ranked_entities',
    'html_fleet_next_steps',
    'html_fleet_method',
    'html_scorecard_fleet_report',
]


def html_fleet_kpis(cards: list[dict[str, Any]], index: dict[str, Any] | None) -> str:
    entity_count = (
        index.get("total_ranked_entities")
        if isinstance(index, dict) and index.get("total_ranked_entities") is not None
        else len(cards)
    )
    triggered_count = sum(1 for card in cards if scorecard_has_trigger(card))
    movement_count = sum(
        1 for card in cards if (to_float(card.get("score_delta_points")) or 0) != 0
    )
    confidence = lowest_confidence(cards)
    health_score = fleet_health_score(cards)
    kpis = [
        (
            "Fleet Health Score",
            human_number(health_score) if health_score is not None else "unavailable",
        ),
        ("Entities Evaluated", human_number(entity_count)),
        ("Entities With Triggered Rules", human_number(triggered_count)),
        ("Score Movement Count", human_number(movement_count)),
        ("Confidence Ceiling", confidence),
    ]
    return (
        '<section class="fleet-kpis" aria-label="Fleet KPI Strip">'
        + "".join(
            '<div class="fleet-kpi">'
            f'<div class="fleet-kpi-label">{h_escape(label)}</div>'
            f'<div class="fleet-kpi-value">{h_escape(value)}</div>'
            "</div>"
            for label, value in kpis
        )
        + "</section>"
    )


def html_fleet_findings(cards: list[dict[str, Any]]) -> str:
    triggered_count = sum(1 for card in cards if scorecard_has_trigger(card))
    feature_label, feature_count = fleet_common_triggered_feature(cards)
    coverage = fleet_rule_coverage(cards)
    missing_total = sum(bucket["missing_input"] for bucket in coverage.values())
    movement_count = sum(
        1 for card in cards if (to_float(card.get("score_delta_points")) or 0) != 0
    )
    findings = [
        f"{human_number(triggered_count)} of {human_number(len(cards))} entities have triggered scorecard rules or positive scored features.",
        (
            f"Most common triggered feature: {feature_label} "
            f"across {human_number(feature_count)} entities."
            if feature_count
            else "No triggered feature was emitted by the scorecards."
        ),
        f"Missing-input coverage: {human_number(missing_total)} rule evaluations were unavailable across {human_number(len(coverage))} domains.",
        f"Score movement count: {human_number(movement_count)} entities have nonzero score_delta_points.",
    ]
    return (
        '<section class="fleet-findings" aria-label="What this report says">'
        "<h2>What This Report Says</h2><ul>"
        + "".join(f"<li>{h_escape(finding)}</li>" for finding in findings)
        + "</ul></section>"
    )


def html_fleet_coverage(cards: list[dict[str, Any]]) -> str:
    coverage = fleet_rule_coverage(cards)
    if not coverage:
        return "<section><h2>Rule Coverage By Domain</h2><p>No rule_results coverage emitted.</p></section>"
    rows = []
    for domain, counts in sorted(coverage.items()):
        total = sum(counts.values()) or 1
        bars = "".join(
            f'<span class="coverage-segment coverage-{h_escape(status.replace("_", "-"))}" '
            f'style="width:{counts[status] / total * 100:.1f}%"></span>'
            for status in ("triggered", "evaluated_zero", "missing_input")
            if counts[status]
        )
        rows.append(
            "<tr>"
            f"<td>{h_escape(display_label(domain))}</td>"
            f"<td>{h_escape(human_number(counts['triggered']))}</td>"
            f"<td>{h_escape(human_number(counts['evaluated_zero']))}</td>"
            f"<td>{h_escape(human_number(counts['missing_input']))}</td>"
            f'<td><div class="coverage-bar">{bars}</div></td>'
            "</tr>"
        )
    return (
        '<section class="fleet-coverage"><h2>Rule Coverage By Domain</h2>'
        "<table><thead><tr><th>Domain</th><th>Triggered</th><th>Evaluated Zero</th>"
        "<th>Missing Input</th><th>Coverage</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table></section>"
    )


def html_fleet_ranked_entities(
    cards: list[dict[str, Any]], index: dict[str, Any] | None, limit: int
) -> str:
    ordered = fleet_ordered_scorecards(cards, index)
    if limit > 0:
        ordered = ordered[:limit]
    rows = []
    for fallback_position, (rank, card, row) in enumerate(ordered, start=1):
        effective_rank = rank if rank is not None else fallback_position
        score = (
            row.get("score")
            if row and row.get("score") is not None
            else card.get("score")
        )
        primary = (
            row.get("primary_domain")
            if row and row.get("primary_domain") is not None
            else card.get("primary_domain")
        )
        confidence = (
            row.get("confidence")
            if row and row.get("confidence") is not None
            else card.get("confidence")
        )
        rows.append(
            "<tr>"
            f"<td>{h_escape(human_number(effective_rank))}</td>"
            f"<td>{h_escape(stringify(card.get('entity')))}</td>"
            f"<td>{h_escape(human_number(score))}</td>"
            f"<td>{h_escape(human_delta(card.get('score_delta_points')))}</td>"
            f"<td>{h_escape(display_label(primary))}</td>"
            f"<td>{h_escape(confidence)}</td>"
            f"<td>{h_escape(scorecard_primary_evidence(card))}</td>"
            "</tr>"
        )
    return (
        '<section class="fleet-ranking"><h2>Ranked Entities</h2>'
        "<table><thead><tr><th>Rank</th><th>Entity</th><th>Score</th>"
        "<th>Score Delta</th><th>Primary Domain</th><th>Confidence</th>"
        "<th>Concise Evidence</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table></section>"
    )


def html_fleet_next_steps(cards: list[dict[str, Any]]) -> str:
    groups: dict[str, list[str]] = {}
    for card in cards:
        for step in card.get("recommended_next_steps") or []:
            if step in (None, ""):
                continue
            text = step["detail"] if isinstance(step, dict) else step
            if not text:
                continue
            groups.setdefault(stringify(text), []).append(stringify(card.get("entity")))
    if not groups:
        return "<section><h2>Recommended Next Steps</h2><p>No recommended next steps emitted.</p></section>"
    rows = [
        "<tr>"
        f"<td>{h_escape(step)}</td>"
        f"<td>{h_escape(human_number(len(entities)))}</td>"
        f"<td>{h_escape(', '.join(entities[:8]))}</td>"
        "</tr>"
        for step, entities in sorted(
            groups.items(), key=lambda item: (-len(item[1]), item[0])
        )
    ]
    return (
        '<section class="fleet-next-steps"><h2>Recommended Next Steps</h2>'
        "<table><thead><tr><th>Action</th><th>Affected Entities</th><th>Entities</th>"
        "</tr></thead><tbody>" + "".join(rows) + "</tbody></table></section>"
    )


def html_fleet_method(
    cards: list[dict[str, Any]], index: dict[str, Any] | None, scope_text: str
) -> str:
    reference = index or cards[0]
    confidence_reasons = sorted(
        {
            stringify(reason)
            for card in cards
            for reason in (card.get("confidence_reasons") or [])
            if reason not in (None, "")
        }
    )
    constraints = sorted(
        {
            stringify(item)
            for artifact in ([index] if index else []) + cards
            if isinstance(artifact, dict)
            for item in (artifact.get("interpretation_constraints") or [])
            if item not in (None, "")
        }
    )
    producer = (
        _producer_limit_bullet(index or {})
        or _producer_limit_bullet(cards[0])
        or "unavailable"
    )
    rows = [
        ["Scope", scope_text],
        ["Current Window", compact_window_range(reference.get("current_window"))],
        [
            "Baseline Window",
            compact_window_range((reference.get("baseline_windows") or [{}])[0])
            if isinstance(reference.get("baseline_windows"), list)
            else "unavailable",
        ],
        ["Table", reference.get("table_used")],
        [
            "Confidence Reasons",
            ", ".join(confidence_reasons) if confidence_reasons else "unavailable",
        ],
        ["Producer Limits", producer],
        [
            "Interpretation Constraints",
            ", ".join(constraints) if constraints else "unavailable",
        ],
    ]
    return (
        '<section class="fleet-method"><h2>Method And Caveats</h2>'
        "<table><thead><tr><th>Field</th><th>Value</th></tr></thead><tbody>"
        + "".join(
            f"<tr><td>{h_escape(label)}</td><td>{h_escape(value)}</td></tr>"
            for label, value in rows
        )
        + "</tbody></table></section>"
    )


def html_scorecard_fleet_report(
    title: str,
    selected: dict[str, Any],
    all_artifacts: list[dict[str, Any]],
    notes: list[dict[str, Any]],
    limit: int,
    ctx: ReportContext,
    scope_label: str | None,
) -> str:
    cards = selected.get("scorecards") or [selected["scorecard"]]
    index = selected.get("index")
    reference = index or cards[0]
    scope_text = resolve_scope_display(scope_label, selected, ctx)
    entity_type = (
        (reference.get("scope") or {}).get("entity_type")
        or cards[0].get("entity_type")
        or "entity"
    )
    header_items = [
        ("Scope", scope_text),
        ("Entity Type", display_label(entity_type)),
        ("Current Window", compact_window_range(reference.get("current_window"))),
        (
            "Baseline Window",
            compact_window_range((reference.get("baseline_windows") or [{}])[0])
            if isinstance(reference.get("baseline_windows"), list)
            else "unavailable",
        ),
    ]
    header = (
        f"<h1>{h_escape(title)}</h1>"
        '<section class="fleet-header" aria-label="Report Header">'
        + "".join(
            '<span class="entity-metadata-item">'
            f'<span class="entity-metadata-label">{h_escape(label)}</span>'
            f'<span class="entity-metadata-value">{h_escape(value)}</span>'
            "</span>"
            for label, value in header_items
        )
        + "</section>"
    )
    notes_html = (
        markdown_to_simple_html(md_analyst_notes(notes, all_artifacts, ctx))
        if notes
        else ""
    )
    return (
        header
        + html_fleet_kpis(cards, index)
        + html_fleet_findings(cards)
        + notes_html
        + html_fleet_coverage(cards)
        + html_fleet_ranked_entities(cards, index, limit)
        + html_fleet_next_steps(cards)
        + html_fleet_method(cards, index, scope_text)
    )


