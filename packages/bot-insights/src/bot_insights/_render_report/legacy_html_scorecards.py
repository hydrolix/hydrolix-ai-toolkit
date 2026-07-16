"""Legacy HTML scorecard widget builders."""

from __future__ import annotations

from typing import Any

from report_engine.humanize import display_label
from report_engine.humanize import rule_label_parts
from report_engine.humanize import stringify

from .charts import (
    _chart_numeric,
    _chart_skip,
    _gauge_arc_path,
)
from .errors import ReportContext
from .formatters import (
    h_escape,
    human_number,
)
from .scorecard_helpers import scorecard_rule_results

__all__ = [
    'html_scorecard_overall_gauge',
    'html_scorecard_context_panel',
    'html_scorecard_feature_cards',
]


def html_scorecard_overall_gauge(card: dict[str, Any], ctx: ReportContext) -> str:
    score = _chart_numeric(card.get("score"))
    if score is None:
        return ""
    baseline = _chart_numeric(card.get("baseline_score"))
    delta = _chart_numeric(card.get("score_delta_points"))
    if delta is None and baseline is not None:
        delta = score - baseline
    fill_pct = min(100.0, max(0.0, score))
    start_degrees = 150.0
    sweep_degrees = 240.0
    end_degrees = start_degrees + sweep_degrees
    fill_degrees = start_degrees + sweep_degrees * (fill_pct / 100.0)
    track = _gauge_arc_path(100, 96, 78, start_degrees, end_degrees)
    fill = (
        _gauge_arc_path(100, 96, 78, start_degrees, fill_degrees)
        if fill_pct > 0
        else ""
    )
    fill_path = (
        f'<path class="overall-gauge-fill" d="{h_escape(fill)}"></path>' if fill else ""
    )
    if delta is None:
        delta_text = "Delta unavailable vs baseline"
        delta_class = "score-delta-neutral"
    else:
        delta_class = (
            "score-delta-up"
            if delta > 0
            else "score-delta-down"
            if delta < 0
            else "score-delta-neutral"
        )
        if delta == 0:
            delta_text = "No Change"
        else:
            sign = "+" if delta > 0 else "-"
            delta_text = f"{sign}{human_number(abs(delta))} pts vs baseline"
    score_text = human_number(card.get("score"))
    return (
        '<section class="score-hero" aria-label="Overall Score">'
        '<div class="score-hero-label">Overall Score</div>'
        '<svg class="overall-gauge" viewBox="0 0 200 150" role="img" aria-label="Overall Score Gauge">'
        f'<path class="overall-gauge-track" d="{h_escape(track)}"></path>'
        f"{fill_path}"
        f'<text class="overall-gauge-metric" x="100" y="96" text-anchor="middle">{h_escape(score_text)}</text>'
        "</svg>"
        f'<div class="{delta_class}">{h_escape(delta_text)}</div>'
        "</section>"
    )


def html_scorecard_context_panel(selected: dict[str, Any]) -> str:
    card = selected["scorecard"]
    index = selected.get("index") or {}
    rank = None
    total_ranked = index.get("total_ranked_entities") or index.get("result_row_count")
    for row in index.get("ranked_entities", []):
        if (
            isinstance(row, dict)
            and row.get("entity_type") == card.get("entity_type")
            and row.get("entity") == card.get("entity")
        ):
            rank = row.get("rank")
            break
    if rank is not None and total_ranked:
        rank_display = f"{human_number(rank)} of {human_number(total_ranked)}"
    elif rank is not None:
        rank_display = human_number(rank)
    else:
        rank_display = "Unavailable"
    entity_type = display_label(card.get("entity_type"))
    metadata_items = [
        ("Rank", rank_display),
        ("Current Score", human_number(card.get("score"))),
        ("Baseline Score", human_number(card.get("baseline_score"))),
        ("Primary Domain", display_label(card.get("primary_domain"))),
        ("Confidence", stringify(card.get("confidence"))),
    ]
    metadata_html = "".join(
        '<span class="entity-metadata-item">'
        f'<span class="entity-metadata-label">{h_escape(label)}</span>'
        f'<span class="entity-metadata-value">{h_escape(value)}</span>'
        "</span>"
        for label, value in metadata_items
    )
    return (
        "<h2>Selected Entity Context</h2>"
        '<section class="entity-identity" aria-label="Selected Entity Context">'
        f'<div class="entity-dimension">{h_escape(entity_type)}</div>'
        f'<div class="entity-name">{h_escape(stringify(card.get("entity")))}</div>'
        "<p>This brief explains the selected entity from the larger scored entity set.</p>"
        f'<div class="entity-metadata-row">{metadata_html}</div>'
        "</section>"
    )


def html_scorecard_feature_cards(
    card: dict[str, Any], limit: int, ctx: ReportContext
) -> str:
    heading = "Rule Score Matrix"
    rules = scorecard_rule_results(card)
    if not rules:
        return _chart_skip(heading, "no evaluated scorecard rules available", ctx)
    rules = sorted(
        rules,
        key=lambda rule: (str(rule.get("domain")), str(rule.get("name"))),
    )

    cards: list[str] = []
    for rule in rules:
        domain = display_label(rule.get("domain"))
        name, condition = rule_label_parts(rule.get("name"))
        status = stringify(rule.get("status")).replace("_", " ")
        current = _chart_numeric(rule.get("current"))
        gauge_current = _rule_gauge_value(rule, current)
        value = _rule_metric_text(rule, gauge_current)
        delta, delta_class = _rule_delta_text(rule)
        points = _rule_points_badge_text(rule.get("points") or 0)
        gauge = _rule_gauge_html(rule, gauge_current, value)
        status_class = (
            "rule-status rule-status-triggered"
            if rule.get("status") == "triggered"
            else "rule-status"
        )
        cards.append(
            '<div class="rule-card">'
            f'<div class="rule-card-top"><span class="rule-domain">{h_escape(domain)}</span>'
            f'<span class="rule-points">{h_escape(points)} pts</span></div>'
            f'<div class="rule-name">{h_escape(name)}</div>'
            f'<div class="rule-condition">{h_escape(condition)}</div>'
            f"{gauge}"
            f'<div class="{delta_class}">{h_escape(delta)}</div>'
            f'<div class="{status_class}">{h_escape(status)}</div>'
            "</div>"
        )
    return (
        f'<section class="rule-matrix" aria-label="{h_escape(heading)}">'
        f"<h2>{h_escape(heading)}</h2>"
        '<div class="rule-grid">' + "".join(cards) + "</div></section>"
    )


def _is_percent_rule(rule: dict[str, Any]) -> bool:
    text = str(rule.get("name", ""))
    return any(token in text for token in ("pct", "rate", "share", "miss"))


def _rule_metric_text(rule: dict[str, Any], value: float | None) -> str:
    if value is None:
        return "N/A"
    if _is_percent_rule(rule):
        return f"{value:.2f}%"
    return human_number(value)


def _rule_delta_value(rule: dict[str, Any]) -> float | None:
    supporting = rule.get("supporting_metrics")
    if isinstance(supporting, dict):
        for key in (
            "absolute_delta_points",
            "pct_change",
            "absolute_delta",
            "absolute_delta_ms",
        ):
            value = _chart_numeric(supporting.get(key))
            if value is not None:
                return value
    current = _chart_numeric(rule.get("current"))
    baseline = _chart_numeric(rule.get("baseline"))
    if current is not None and baseline is not None:
        return current - baseline
    return None


def _rule_gauge_value(
    rule: dict[str, Any], current: float | None
) -> float | None:
    if "delta" in stringify(rule.get("name")):
        delta = _rule_delta_value(rule)
        if delta is not None:
            return abs(delta)
    return current


def _rule_points_badge_text(value: Any) -> str:
    points = _chart_numeric(value)
    if points is None:
        return stringify(value)
    if points > 0:
        return f"-{human_number(points)}"
    return human_number(points)


def _rule_delta_text(rule: dict[str, Any]) -> tuple[str, str]:
    if rule.get("status") == "missing_input":
        return "Missing inputs", "rule-delta-neutral"
    delta = _rule_delta_value(rule)
    if delta is None:
        return "delta unavailable", "rule-delta-neutral"
    css_class = _rule_delta_class(delta)
    display = f"{abs(delta):.2f}%" if _is_percent_rule(rule) else human_number(abs(delta))
    return f"{_rule_delta_symbol(delta)} {display}", css_class


def _rule_delta_symbol(delta: float) -> str:
    if delta > 0:
        return "^"
    if delta < 0:
        return "v"
    return "-"


def _rule_delta_class(delta: float) -> str:
    if delta > 0:
        return "rule-delta-up"
    if delta < 0:
        return "rule-delta-down"
    return "rule-delta-neutral"


def _rule_gauge_html(rule: dict[str, Any], current: float | None, value: str) -> str:
    if current is None:
        return ""
    max_value = _rule_gauge_max_value(rule, current)
    fill_pct = min(100.0, max(0.0, abs(current) / max_value * 100.0))
    start_degrees = 150.0
    sweep_degrees = 240.0
    end_degrees = start_degrees + sweep_degrees
    fill_degrees = start_degrees + sweep_degrees * (fill_pct / 100.0)
    track = _gauge_arc_path(60, 58, 44, start_degrees, end_degrees)
    fill = (
        _gauge_arc_path(60, 58, 44, start_degrees, fill_degrees)
        if fill_pct > 0
        else ""
    )
    fill_path = f'<path class="gauge-fill" d="{h_escape(fill)}"></path>' if fill else ""
    return (
        '<svg class="rule-gauge" viewBox="0 0 120 90" aria-hidden="true" focusable="false">'
        f'<path class="gauge-track" d="{h_escape(track)}"></path>'
        f"{fill_path}"
        f'<text class="gauge-metric" x="60" y="57" text-anchor="middle">{h_escape(value)}</text>'
        "</svg>"
    )


def _rule_gauge_max_value(rule: dict[str, Any], current: float) -> float:
    threshold = _chart_numeric(rule.get("threshold"))
    baseline = _chart_numeric(rule.get("baseline"))
    if _is_percent_rule(rule):
        return 100.0
    if threshold is not None and threshold > 0:
        return threshold * 1.25
    if baseline is not None and abs(baseline) > 0:
        return max(abs(current), abs(baseline))
    return abs(current) if abs(current) > 0 else 1.0


