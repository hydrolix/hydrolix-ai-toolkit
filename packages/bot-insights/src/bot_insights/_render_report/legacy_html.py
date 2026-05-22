"""Legacy HTML body builders + post-processing (test infrastructure only)."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any
from report_engine.humanize import display_label
from report_engine.humanize import human_metric_name
from report_engine.humanize import rule_label_parts
from report_engine.humanize import stringify

from .charts import (
    _chart_numeric,
    _chart_open,
    _chart_skip,
    _gauge_arc_path,
    _horizontal_bars_svg,
)
from .constants import (
    CONTROL_SCHEMA,
    POSTURE_SCHEMA,
    SCORECARD_SCHEMA,
    TIMESERIES_SCHEMA,
)
from .errors import ReportContext
from .formatters import (
    _demd,
    _find_unescaped,
    compact_window_range,
    h_escape,
    human_delta,
    human_number,
    human_timestamp,
    parse_utc_timestamp,
    to_float,
)
from .legacy_markdown import (
    md_analyst_notes,
    render_markdown,
)
from .scorecard_helpers import (
    _producer_limit_bullet,
    fleet_common_triggered_feature,
    fleet_health_score,
    fleet_ordered_scorecards,
    fleet_rule_coverage,
    lowest_confidence,
    scorecard_has_trigger,
    scorecard_primary_evidence,
    scorecard_rule_results,
    timeseries_artifacts,
)
from .tables import (
    artifact_display_name,
    resolve_scope_display,
)

__all__ = [
    'render_html',
    'html_metric_delta_cards',
    'html_current_baseline_bars',
    'html_ranking_bars',
    'html_scorecard_score_bars',
    'html_scorecard_overall_gauge',
    'html_scorecard_context_panel',
    'html_fleet_kpis',
    'html_fleet_findings',
    'html_fleet_coverage',
    'html_fleet_ranked_entities',
    'html_fleet_next_steps',
    'html_fleet_method',
    'html_scorecard_fleet_report',
    'html_mover_bars',
    'html_scorecard_domain_bars',
    'html_scorecard_feature_cards',
    'html_domain_matrix',
    'html_control_bars',
    'html_timeseries_cards',
    'html_window_timeline',
    'html_chart_sections',
    'markdown_to_simple_html',
    'inline_html',
    '_split_table_row',
    'table_to_html',
]


def render_html(
    title: str,
    report_type: str,
    selected: dict[str, Any],
    all_artifacts: list[dict[str, Any]],
    notes: list[dict[str, Any]],
    limit: int,
    ctx: ReportContext,
    *,
    scope_label: str | None = None,
) -> str:
    fleet_scorecard_brief = report_type == "scorecard_brief" and selected.get(
        "is_fleet"
    )
    if fleet_scorecard_brief:
        body = html_scorecard_fleet_report(
            title,
            selected,
            all_artifacts,
            notes,
            limit,
            ctx,
            scope_label,
        )
        chart_html = ""
    else:
        chart_html = html_chart_sections(report_type, selected, limit, ctx)
        markdown = render_markdown(
            title,
            report_type,
            selected,
            all_artifacts,
            notes,
            limit,
            ctx,
            scope_label=scope_label,
            include_metadata=False,
        )
        body = markdown_to_simple_html(markdown)
        timeline_html = html_window_timeline(all_artifacts, report_type)
        trend_html = html_timeseries_cards(all_artifacts, limit, ctx, report_type)
        trend_anchor = None
        if "<h2>Executive Summary</h2>" in body:
            trend_anchor = "<h2>Executive Summary</h2>"
        elif "<h2>Control Review Summary</h2>" in body:
            trend_anchor = "<h2>Control Review Summary</h2>"
        elif (
            report_type == "scorecard_brief"
            and "<h2>Selected Entity Context</h2>" in body
        ):
            trend_anchor = "<h2>Selected Entity Context</h2>"
        if (timeline_html or trend_html) and trend_anchor:
            body = body.replace(
                trend_anchor,
                timeline_html + trend_html + trend_anchor,
                1,
            )
        if report_type == "scorecard_brief":
            hero_html = html_scorecard_overall_gauge(selected["scorecard"], ctx)
            context_panel = html_scorecard_context_panel(selected)
            body = re.sub(
                r"<h2>Selected Entity Context</h2>.*?(?=<h2>Domain Scores</h2>)",
                "",
                body,
                count=1,
                flags=re.S,
            )
            if "</h1>" in body:
                body = body.replace("</h1>", "</h1>" + hero_html + context_panel, 1)
            if chart_html and "<h2>Domain Scores</h2>" in body:
                body = body.replace(
                    "<h2>Domain Scores</h2>", chart_html + "<h2>Domain Scores</h2>", 1
                )
                chart_html = ""
        if report_type == "scorecard_brief" and chart_html and trend_anchor:
            body = body.replace(trend_anchor, chart_html + trend_anchor, 1)
            chart_html = ""
    css = """
body{font-family:Arial,sans-serif;margin:0;color:#17202a;background:#f7f8fa}
main{max-width:1120px;margin:0 auto;padding:32px}
h1{font-size:34px;margin:0 0 8px}h2{margin-top:32px;border-top:1px solid #d9dee7;padding-top:20px}
table{border-collapse:collapse;width:100%;margin:12px 0;background:#fff}
th,td{border:1px solid #d8dee8;padding:8px;text-align:left;vertical-align:top}
th{background:#eef2f7}code{background:#eef2f7;padding:2px 4px;border-radius:3px}
.trend-cards{margin:20px 0 8px}
.window-timeline{margin:12px 0 20px}
.charts{display:grid;grid-gap:16px;margin:16px 0}
.chart{width:100%;background:#fff;border:1px solid #d8dee8;padding:12px;box-sizing:border-box}
.chart-title{font-weight:700;font-size:14px;fill:#17202a}
.chart-label{font-size:12px;fill:#17202a}
.chart-value{font-size:12px;fill:#2b3a4a}
.chart-large{font-size:20px;font-weight:700;fill:#17202a}
.score-hero{background:#fff;border:1px solid #d8dee8;margin:18px 0 24px;padding:18px;text-align:center}
.score-hero-label{font-size:12px;color:#5d6d7e;text-transform:uppercase;font-weight:700;letter-spacing:0}
.overall-gauge{width:220px;max-width:70vw;height:165px;margin:0 auto -8px;display:block}
.overall-gauge-track{fill:none;stroke:#e5eaf1;stroke-width:14;stroke-linecap:round}
.overall-gauge-fill{fill:none;stroke:#2474a6;stroke-width:14;stroke-linecap:round}
.overall-gauge-metric{font-size:46px;font-weight:700;fill:#17202a;dominant-baseline:middle}
.score-delta-up{font-size:15px;font-weight:700;color:#1f8f3a;text-align:center}
.score-delta-down{font-size:15px;font-weight:700;color:#b4232f;text-align:center}
.score-delta-neutral{font-size:15px;font-weight:700;color:#5d6d7e;text-align:center}
.entity-identity{background:#fff;border:1px solid #d8dee8;padding:16px;margin:0 0 20px}
.entity-dimension{font-size:12px;color:#5d6d7e;text-transform:uppercase;font-weight:700}
.entity-name{font-size:26px;font-weight:700;color:#17202a;margin:4px 0;overflow-wrap:anywhere}
.entity-identity p{margin:0 0 12px;color:#2b3a4a}
.entity-metadata-row{display:flex;flex-wrap:wrap;align-items:center;row-gap:6px;margin-top:2px}
.entity-metadata-item{display:inline-flex;gap:6px;align-items:baseline;padding:0 12px 0 0;margin-right:12px;color:#17202a}
.entity-metadata-item + .entity-metadata-item{border-left:1px solid #cfd7e2;padding-left:12px}
.entity-metadata-label{font-size:11px;color:#5d6d7e;text-transform:uppercase;font-weight:700}
.entity-metadata-value{font-size:13px;color:#17202a;font-weight:700}
.rule-matrix{background:#fff;border:1px solid #d8dee8;padding:16px}
.rule-matrix h2{border:0;margin:0 0 14px;padding:0;font-size:18px}
.rule-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}
.rule-card{border:1px solid #d8dee8;border-radius:6px;padding:12px;min-height:132px;background:#fff;display:flex;flex-direction:column;gap:6px}
.rule-card-top{display:flex;align-items:center;justify-content:space-between;gap:8px}
.rule-domain,.rule-status{font-size:11px;color:#5d6d7e;text-transform:uppercase}
.rule-status{text-align:center}
.rule-status-triggered{color:#b4232f;font-weight:700}
.rule-name{font-size:13px;font-weight:700;color:#17202a}
.rule-condition{font-size:12px;color:#5d6d7e;min-height:16px}
.rule-gauge{width:120px;height:90px;margin:-6px 0 -10px;align-self:center}
.gauge-track{fill:none;stroke:#e5eaf1;stroke-width:8;stroke-linecap:round}
.gauge-fill{fill:none;stroke:#2474a6;stroke-width:8;stroke-linecap:round}
.gauge-metric{font-size:20px;font-weight:700;fill:#17202a;dominant-baseline:middle}
.rule-points{border:1px solid #cfd7e2;border-radius:999px;padding:2px 7px;font-size:12px;font-weight:700;color:#17202a;background:#f7f8fa;white-space:nowrap}
.rule-delta-up{font-size:13px;font-weight:700;color:#1f8f3a;text-align:center}
.rule-delta-down{font-size:13px;font-weight:700;color:#b4232f;text-align:center}
.rule-delta-neutral{font-size:13px;font-weight:700;color:#5d6d7e;text-align:center}
.chart-bar{fill:#2474a6}
.chart-current{fill:#2474a6}
.chart-baseline{fill:#85c1e9}
.chart-before{fill:#f5b041}
.chart-after{fill:#2474a6}
.chart-expected{fill:#7fb3d5}
.chart-card{fill:#fff;stroke:#d8dee8}
.chart-cell{fill:#2474a6}
.timeline-baseline{fill:#85c1e9}
.timeline-current{fill:#2474a6}
.chart-skip{background:#fff3cd;border:1px solid #f0d27a;padding:10px;color:#5a4412;margin:12px 0}
.fleet-header{background:#fff;border:1px solid #d8dee8;padding:14px 16px;margin:14px 0 16px;display:flex;flex-wrap:wrap;gap:8px}
.fleet-kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px;margin:16px 0 20px}
.fleet-kpi{background:#fff;border:1px solid #d8dee8;padding:14px}
.fleet-kpi-label{font-size:11px;color:#5d6d7e;text-transform:uppercase;font-weight:700}
.fleet-kpi-value{font-size:24px;font-weight:700;color:#17202a;margin-top:4px}
.fleet-findings ul{background:#fff;border:1px solid #d8dee8;padding:14px 18px 14px 32px}
.coverage-bar{display:flex;height:14px;min-width:120px;background:#eef2f7;border:1px solid #d8dee8}
.coverage-segment{display:block;height:14px}
.coverage-triggered{background:#b4232f}
.coverage-evaluated-zero{background:#85c1e9}
.coverage-missing-input{background:#f5b041}
""".strip()
    return (
        '<!doctype html><html><head><meta charset="utf-8">'
        f"<title>{h_escape(title)}</title><style>{css}</style></head><body><main>"
        + body
        + chart_html
        + "</main></body></html>\n"
    )


def html_metric_delta_cards(
    posture: dict[str, Any], limit: int, ctx: ReportContext
) -> str:
    heading = "Metric Delta Cards"
    metrics = posture.get("metrics") or []
    if not isinstance(metrics, list) or not metrics:
        return _chart_skip(heading, "no metrics available", ctx)
    metrics = metrics[:limit] if limit else metrics
    card_w, card_h, gap = 240, 140, 14
    cols = 3
    rows_count = (len(metrics) + cols - 1) // cols
    width = cols * card_w + (cols + 1) * gap
    height = 48 + rows_count * (card_h + gap)
    parts = [_chart_open(heading, width, height)]
    for idx, metric in enumerate(metrics):
        col = idx % cols
        row = idx // cols
        x = gap + col * (card_w + gap)
        y = 40 + row * (card_h + gap)
        parts.append(
            f'<rect class="chart-card" x="{x}" y="{y}"'
            f' width="{card_w}" height="{card_h}" rx="4"></rect>'
        )
        parts.append(
            f'<text class="chart-label" x="{x + 12}" y="{y + 22}">'
            f"{h_escape(human_metric_name(metric.get('name')))}</text>"
        )
        parts.append(
            f'<text class="chart-value" x="{x + 12}" y="{y + 46}">'
            f"Current: {h_escape(human_number(metric.get('current')))}</text>"
        )
        parts.append(
            f'<text class="chart-value" x="{x + 12}" y="{y + 64}">'
            f"Baseline: {h_escape(human_number(metric.get('baseline')))}</text>"
        )
        parts.append(
            f'<text class="chart-value" x="{x + 12}" y="{y + 82}">'
            f"Delta: {h_escape(human_delta(metric.get('absolute_delta')))}</text>"
        )
        parts.append(
            f'<text class="chart-value" x="{x + 12}" y="{y + 100}">'
            f"Change: {h_escape(human_number(metric.get('pct_change'), percent=True))}</text>"
        )
        parts.append(
            f'<text class="chart-value" x="{x + 12}" y="{y + 120}">'
            f"{h_escape(metric.get('direction'))} /"
            f" {h_escape(metric.get('confidence'))}</text>"
        )
    parts.append("</svg>")
    return "".join(parts)


def html_current_baseline_bars(
    posture: dict[str, Any], limit: int, ctx: ReportContext
) -> str:
    heading = "Current Versus Baseline Bars"
    metrics = posture.get("metrics") or []
    usable: list[tuple[dict[str, Any], float | None, float | None]] = []
    for metric in metrics:
        current = _chart_numeric(metric.get("current"))
        baseline = _chart_numeric(metric.get("baseline"))
        if current is None and baseline is None:
            continue
        usable.append((metric, current, baseline))
    if not usable:
        return _chart_skip(
            heading, "no numeric current or baseline values available", ctx
        )
    usable = usable[:limit] if limit else usable
    width = 720
    label_w = 180
    row_height = 72
    bar_max = width - label_w - 140
    height = 40 + row_height * len(usable)
    parts = [_chart_open(heading, width, height)]
    for idx, (metric, current, baseline) in enumerate(usable):
        y = 32 + idx * row_height
        parts.append(
            f'<text class="chart-label" x="0" y="{y + 14}">'
            f"{h_escape(human_metric_name(metric.get('name')))}</text>"
        )
        local_max = max(abs(current or 0.0), abs(baseline or 0.0)) or 1.0
        cur_w = (
            max(1, int(abs(current) / local_max * bar_max))
            if current is not None
            else 0
        )
        base_w = (
            max(1, int(abs(baseline) / local_max * bar_max))
            if baseline is not None
            else 0
        )
        parts.append(
            f'<rect class="chart-bar chart-current" x="{label_w}" y="{y}"'
            f' width="{cur_w}" height="16" rx="2"></rect>'
        )
        parts.append(
            f'<text class="chart-value" x="{label_w + cur_w + 8}" y="{y + 13}">'
            f"current {h_escape(human_number(metric.get('current')))}</text>"
        )
        parts.append(
            f'<rect class="chart-bar chart-baseline" x="{label_w}" y="{y + 22}"'
            f' width="{base_w}" height="16" rx="2"></rect>'
        )
        parts.append(
            f'<text class="chart-value" x="{label_w + base_w + 8}" y="{y + 35}">'
            f"baseline {h_escape(human_number(metric.get('baseline')))}</text>"
        )
        parts.append(
            f'<text class="chart-value" x="{label_w}" y="{y + 57}">'
            f"direction {h_escape(metric.get('direction'))} · "
            f"confidence {h_escape(metric.get('confidence'))}</text>"
        )
    parts.append("</svg>")
    return "".join(parts)


def html_ranking_bars(index: dict[str, Any], limit: int, ctx: ReportContext) -> str:
    heading = "Scorecard Ranking Bars"
    ranked = index.get("ranked_entities") or []
    rows: list[tuple[str, float, str]] = []
    for entity in ranked:
        score = _chart_numeric(entity.get("score"))
        if score is None:
            continue
        rank = entity.get("rank")
        rank_prefix = f"Rank {stringify(rank)}: " if rank is not None else ""
        label = (
            f"{rank_prefix}{stringify(entity.get('entity'))}"
            f" ({stringify(entity.get('entity_type'))})"
        )
        display = (
            f"score {stringify(entity.get('score'))}"
            f" · band {stringify(entity.get('band'))}"
            f" · primary {stringify(entity.get('primary_domain'))}"
            f" · confidence {stringify(entity.get('confidence'))}"
        )
        rows.append((label, score, display))
    if not rows:
        return _chart_skip(heading, "no numeric ranked scores available", ctx)
    rows = rows[:limit] if limit else rows
    return _horizontal_bars_svg(heading, rows)


def html_scorecard_score_bars(
    scorecards: list[dict[str, Any]], limit: int, ctx: ReportContext
) -> str:
    heading = "Scorecard Ranking Bars"
    rows: list[tuple[str, float, str]] = []
    for card in scorecards:
        score = _chart_numeric(card.get("score"))
        if score is None:
            continue
        label = (
            f"{stringify(card.get('entity'))} ({stringify(card.get('entity_type'))})"
        )
        display = (
            f"sorted by lower health score · score {stringify(card.get('score'))}"
            f" · band {stringify(card.get('band'))}"
            f" · primary {stringify(card.get('primary_domain'))}"
            f" · confidence {stringify(card.get('confidence'))}"
        )
        rows.append((label, score, display))
    if not rows:
        return _chart_skip(heading, "no numeric scorecard scores available", ctx)
    rows.sort(key=lambda item: (item[1], item[0]))
    rows = rows[:limit] if limit else rows
    return _horizontal_bars_svg(heading, rows)


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


def html_mover_bars(mover: dict[str, Any], limit: int, ctx: ReportContext) -> str:
    heading = "Mover Contribution Bars"
    movers = mover.get("movers") or []
    use_contribution = any(
        _chart_numeric(row.get("contribution_pct")) is not None for row in movers
    )
    rows: list[tuple[int, str, float, str]] = []
    total_delta = mover.get("total_delta")
    total_delta_text = (
        f" · total delta {stringify(total_delta)}" if total_delta is not None else ""
    )
    for index, row in enumerate(movers):
        if use_contribution:
            value = _chart_numeric(row.get("contribution_pct"))
            display = (
                f"contribution {stringify(row.get('contribution_pct'))}"
                f" · confidence {stringify(row.get('confidence'))}"
                f"{total_delta_text}"
            )
        else:
            value = _chart_numeric(row.get("absolute_delta"))
            display = (
                f"delta {stringify(row.get('absolute_delta'))}"
                f" · confidence {stringify(row.get('confidence'))}"
                f"{total_delta_text}"
            )
        if value is None:
            continue
        label = f"{stringify(row.get('value'))} ({stringify(row.get('metric'))})"
        rows.append((index, label, value, display))
    if not rows:
        return _chart_skip(
            heading,
            "no numeric contribution_pct or absolute_delta values available",
            ctx,
        )
    rows.sort(key=lambda item: (-abs(item[2]), item[0]))
    limited = rows[:limit] if limit else rows
    return _horizontal_bars_svg(
        heading, [(label, value, display) for _, label, value, display in limited]
    )


def html_scorecard_domain_bars(card: dict[str, Any], ctx: ReportContext) -> str:
    heading = "Domain Scores"
    domain_scores = card.get("domain_scores") or {}
    rows: list[tuple[str, float, str]] = []
    for domain in sorted(domain_scores):
        value = _chart_numeric(domain_scores[domain])
        if value is None:
            continue
        rows.append(
            (
                stringify(domain),
                value,
                f"score {stringify(domain_scores[domain])}",
            )
        )
    if not rows:
        return _chart_skip(heading, "no numeric domain scores available", ctx)
    return _horizontal_bars_svg(heading, rows)


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


def html_domain_matrix(
    scorecards: list[dict[str, Any]], limit: int, ctx: ReportContext
) -> str:
    heading = "Domain Score Matrix"
    if not scorecards:
        return _chart_skip(heading, "no scorecards available", ctx)
    cards = scorecards[:limit] if limit else scorecards
    domain_order = _domain_matrix_order(cards)
    if not domain_order:
        return _chart_skip(heading, "no domain scores on scorecards", ctx)
    label_w = 220
    cell_w = 110
    row_h = 36
    width = label_w + len(domain_order) * cell_w + 20
    height = 72 + len(cards) * row_h
    max_score = _domain_matrix_max_score(cards, domain_order)
    parts = [_chart_open(heading, width, height)]
    for idx, domain in enumerate(domain_order):
        x = label_w + idx * cell_w + cell_w // 2
        parts.append(
            f'<text class="chart-label" x="{x}" y="50" text-anchor="middle">'
            f"{h_escape(domain)}</text>"
        )
    for row_idx, card in enumerate(cards):
        y = 64 + row_idx * row_h
        parts.append(
            f'<text class="chart-label" x="0" y="{y + 22}">'
            f"{h_escape(card.get('entity'))}</text>"
        )
        parts.extend(
            _domain_matrix_cells(
                card, domain_order, label_w, cell_w, row_h, y, max_score
            )
        )
    parts.append("</svg>")
    return "".join(parts)


def _domain_matrix_order(cards: list[dict[str, Any]]) -> list[str]:
    domain_order: list[str] = []
    seen: set[str] = set()
    for card in cards:
        for domain in (card.get("domain_scores") or {}).keys():
            if domain not in seen:
                seen.add(domain)
                domain_order.append(domain)
    return domain_order


def _domain_matrix_max_score(
    cards: list[dict[str, Any]], domain_order: list[str]
) -> float:
    max_score = 1.0
    for card in cards:
        for domain in domain_order:
            value = _chart_numeric((card.get("domain_scores") or {}).get(domain))
            if value is not None and abs(value) > max_score:
                max_score = abs(value)
    return max_score


def _domain_matrix_cells(
    card: dict[str, Any],
    domain_order: list[str],
    label_w: int,
    cell_w: int,
    row_h: int,
    y: int,
    max_score: float,
) -> list[str]:
    domain_scores = card.get("domain_scores") or {}
    parts: list[str] = []
    for idx, domain in enumerate(domain_order):
        x = label_w + idx * cell_w
        value = _chart_numeric(domain_scores.get(domain))
        intensity = 0.15 if value is None else min(1.0, max(0.15, abs(value) / max_score))
        display = "unavailable" if value is None else stringify(domain_scores.get(domain))
        parts.extend(
            [
                f'<rect class="chart-cell" x="{x + 4}" y="{y + 4}"'
                f' width="{cell_w - 8}" height="{row_h - 8}" rx="2"'
                f' fill-opacity="{intensity:.2f}"></rect>',
                f'<text class="chart-value" x="{x + cell_w // 2}" y="{y + 24}"'
                f' text-anchor="middle">{h_escape(display)}</text>',
            ]
        )
    return parts


def html_control_bars(control: dict[str, Any], limit: int, ctx: ReportContext) -> str:
    heading = "Control Before/After/Expected Bars"
    effects = control.get("target_effects") or []
    usable: list[tuple[dict[str, Any], float | None, float | None, float | None]] = []
    for effect in effects:
        before = _chart_numeric(effect.get("before"))
        after = _chart_numeric(effect.get("after"))
        expected = _chart_numeric(effect.get("expected"))
        if before is None and after is None and expected is None:
            continue
        usable.append((effect, before, after, expected))
    if not usable:
        return _chart_skip(
            heading, "no numeric before/after/expected values available", ctx
        )
    usable = usable[:limit] if limit else usable
    width = 760
    label_w = 180
    row_height = 96
    bar_max = width - label_w - 140
    height = 40 + row_height * len(usable)
    parts = [_chart_open(heading, width, height)]
    for idx, (effect, before, after, expected) in enumerate(usable):
        y = 32 + idx * row_height
        parts.append(
            f'<text class="chart-label" x="0" y="{y + 14}">'
            f"{h_escape(human_metric_name(effect.get('metric')))}</text>"
        )
        numeric_values = [v for v in (before, after, expected) if v is not None]
        local_max = max((abs(v) for v in numeric_values), default=1.0) or 1.0
        sub_rows = [
            ("before", before, effect.get("before"), "chart-before"),
            ("after", after, effect.get("after"), "chart-after"),
            ("expected", expected, effect.get("expected"), "chart-expected"),
        ]
        for sub_idx, (sub_label, sub_value, sub_raw, sub_class) in enumerate(sub_rows):
            row_y = y + sub_idx * 22
            if sub_value is None:
                parts.append(
                    f'<text class="chart-value" x="{label_w}" y="{row_y + 13}">'
                    f"{sub_label}: unavailable</text>"
                )
                continue
            bar_w = max(1, int(abs(sub_value) / local_max * bar_max))
            parts.append(
                f'<rect class="chart-bar {sub_class}" x="{label_w}" y="{row_y}"'
                f' width="{bar_w}" height="14" rx="2"></rect>'
            )
            parts.append(
                f'<text class="chart-value" x="{label_w + bar_w + 8}" y="{row_y + 12}">'
                f"{sub_label} {h_escape(human_number(sub_raw))}</text>"
            )
        parts.append(
            f'<text class="chart-value" x="{label_w}" y="{y + 74}">'
            f"status {h_escape(effect.get('status'))} · "
            f"confidence {h_escape(effect.get('confidence'))}</text>"
        )
    parts.append("</svg>")
    return "".join(parts)


def html_timeseries_cards(
    artifacts: list[dict[str, Any]],
    limit: int,
    ctx: ReportContext,
    report_type: str,
) -> str:
    metrics = _timeseries_metrics(artifacts)
    if not metrics:
        return ""
    metrics = metrics[:limit] if limit else metrics
    card_w = 340
    card_h = 138
    gap = 16
    cols = 2
    rows = (len(metrics) + cols - 1) // cols
    width = cols * card_w + (cols - 1) * gap
    height = 40 + rows * card_h + (rows - 1) * gap
    is_control = report_type == "control_review"
    heading = "Control Review Trend Cards" if is_control else "Posture Trend Cards"
    current_label = "After" if is_control else "Current"
    baseline_label = "Expected" if is_control else "Prior"
    section_label = (
        "Control review trend cards" if is_control else "Posture trend cards"
    )
    parts = [_chart_open(heading, width, height)]
    for index, metric in enumerate(metrics):
        col = index % cols
        row = index // cols
        x = col * (card_w + gap)
        y = 34 + row * (card_h + gap)
        current_values, baseline_values = _timeseries_metric_values(metric, ctx)
        if current_values is None:
            continue
        if not current_values and not baseline_values:
            ctx.warn(
                "Trend card skipped a metric because no numeric values were available."
            )
            continue
        parts.extend(
            _timeseries_card_parts(
                metric,
                current_values,
                baseline_values,
                x=x,
                y=y,
                card_w=card_w,
                card_h=card_h,
                current_label=current_label,
                baseline_label=baseline_label,
            )
        )
    parts.append("</svg>")
    return (
        f'<section class="trend-cards" aria-label="{h_escape(section_label)}">'
        + "".join(parts)
        + "</section>"
    )


def _timeseries_metrics(artifacts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    metrics: list[dict[str, Any]] = []
    for artifact in timeseries_artifacts(artifacts):
        for metric in artifact.get("metrics", []):
            if isinstance(metric, dict):
                metrics.append(metric)
    return metrics


def _timeseries_metric_values(
    metric: dict[str, Any], ctx: ReportContext
) -> tuple[list[float], list[float]] | tuple[None, None]:
    points = metric.get("points")
    if not isinstance(points, list):
        ctx.warn("Trend card skipped a metric because points were unavailable.")
        return None, None
    current_values = [
        value
        for point in points
        if isinstance(point, dict)
        and (value := _chart_numeric(point.get("current"))) is not None
    ]
    baseline_values = [
        value
        for point in points
        if isinstance(point, dict)
        and (value := _chart_numeric(point.get("baseline"))) is not None
    ]
    return current_values, baseline_values


def _timeseries_card_parts(
    metric: dict[str, Any],
    current_values: list[float],
    baseline_values: list[float],
    *,
    x: int,
    y: int,
    card_w: int,
    card_h: int,
    current_label: str,
    baseline_label: str,
) -> list[str]:
    label = metric.get("label") or human_metric_name(metric.get("name"))
    spark = _sparkline_parts(current_values, baseline_values, x, y, card_w)
    return [
        f'<rect class="chart-card" x="{x}" y="{y}" width="{card_w}" height="{card_h}" rx="4"></rect>',
        f'<text class="chart-label" x="{x + 12}" y="{y + 22}">{h_escape(label)}</text>',
        f'<text class="chart-value" x="{x + 12}" y="{y + 44}">'
        f"{current_label} {h_escape(human_number(metric.get('current')))} vs "
        f"{baseline_label.lower()} {h_escape(human_number(metric.get('baseline')))}"
        "</text>",
        f'<text class="chart-value" x="{x + 12}" y="{y + 62}">'
        f"Delta vs {h_escape(baseline_label.lower())} "
        f"{h_escape(human_number(metric.get('pct_change'), percent=True))}</text>",
        *spark,
    ]


def _sparkline_parts(
    current_values: list[float], baseline_values: list[float], x: int, y: int, card_w: int
) -> list[str]:
    spark_x = x + 14
    spark_y = y + 78
    spark_w = card_w - 28
    spark_h = 42
    all_values = current_values + baseline_values
    min_value = min(all_values)
    span = max(max(all_values) - min_value, 1.0)
    return [
        f'<polyline points="{_scaled_sparkline(baseline_values, spark_x, spark_y, spark_w, spark_h, min_value, span)}" fill="none" stroke="#85c1e9" stroke-width="2"></polyline>',
        f'<polyline points="{_scaled_sparkline(current_values, spark_x, spark_y, spark_w, spark_h, min_value, span)}" fill="none" stroke="#2474a6" stroke-width="2.5"></polyline>',
    ]


def _scaled_sparkline(
    values: list[float],
    spark_x: int,
    spark_y: int,
    spark_w: int,
    spark_h: int,
    min_value: float,
    span: float,
) -> str:
    if not values:
        return ""
    if len(values) == 1:
        return f"{spark_x},{spark_y + spark_h / 2:.1f}"
    pts: list[str] = []
    for idx, value in enumerate(values):
        px = spark_x + (idx / (len(values) - 1)) * spark_w
        py = spark_y + spark_h - ((value - min_value) / span) * spark_h
        pts.append(f"{px:.1f},{py:.1f}")
    return " ".join(pts)


def html_window_timeline(artifacts: list[dict[str, Any]], report_type: str) -> str:
    rows: list[dict[str, Any]] = []
    is_control_report = report_type == "control_review"
    for artifact in artifacts:
        row = _timeline_row(artifact, is_control_report)
        if row:
            rows.append(row)
    if not rows:
        return ""
    rows = _collapse_timeline_rows(rows)
    min_start = min(row["baseline_start"] for row in rows)
    max_end = max(row["current_end"] for row in rows)
    total_seconds = max((max_end - min_start).total_seconds(), 1.0)
    width = 760
    label_w = 150
    plot_w = 560
    row_h = 50
    height = 54 + row_h * len(rows)

    def x_for(moment: datetime) -> int:
        return int(
            label_w + ((moment - min_start).total_seconds() / total_seconds) * plot_w
        )

    parts = [
        '<section class="window-timeline" aria-label="Evidence window timeline">',
        _chart_open("Evidence Window Timeline", width, height),
        f'<text class="chart-value" x="{label_w}" y="38">{h_escape(human_timestamp(min_start.isoformat().replace("+00:00", "Z")))}</text>',
        f'<text class="chart-value" x="{label_w + plot_w}" y="38" text-anchor="end">{h_escape(human_timestamp(max_end.isoformat().replace("+00:00", "Z")))}</text>',
    ]
    for index, row in enumerate(rows):
        y = 58 + index * row_h
        base_x = x_for(row["baseline_start"])
        base_w = max(2, x_for(row["baseline_end"]) - base_x)
        cur_x = x_for(row["current_start"])
        cur_w = max(2, x_for(row["current_end"]) - cur_x)
        parts.extend(
            [
                f'<text class="chart-label" x="0" y="{y + 17}">{h_escape(row["label"])}</text>',
                f'<line x1="{label_w}" y1="{y + 10}" x2="{label_w + plot_w}" y2="{y + 10}" stroke="#d8dee8" stroke-width="1"></line>',
                f'<rect class="timeline-baseline" x="{base_x}" y="{y}" width="{base_w}" height="20" rx="3"></rect>',
                f'<rect class="timeline-current" x="{cur_x}" y="{y}" width="{cur_w}" height="20" rx="3"></rect>',
                f'<text class="chart-value" x="{base_x + base_w / 2:.1f}" y="{y + 36}" text-anchor="middle">{h_escape(row.get("baseline_label", "Baseline"))}</text>',
                f'<text class="chart-value" x="{cur_x + cur_w / 2:.1f}" y="{y + 36}" text-anchor="middle">{h_escape(row.get("current_label", "Current"))}</text>',
            ]
        )
    parts.append("</svg></section>")
    return "".join(parts)


def _timeline_row(
    artifact: dict[str, Any], is_control_report: bool
) -> dict[str, Any] | None:
    schema = artifact.get("schema_version")
    if schema not in {POSTURE_SCHEMA, TIMESERIES_SCHEMA, CONTROL_SCHEMA, SCORECARD_SCHEMA}:
        return None
    current, baseline = _timeline_windows(artifact, schema)
    if not isinstance(current, dict) or not isinstance(baseline, dict):
        return None
    current_start = parse_utc_timestamp(current.get("start"))
    current_end = parse_utc_timestamp(current.get("end"))
    baseline_start = parse_utc_timestamp(baseline.get("start"))
    baseline_end = parse_utc_timestamp(baseline.get("end"))
    if not all((current_start, current_end, baseline_start, baseline_end)):
        return None
    is_control_row = schema == CONTROL_SCHEMA or (
        is_control_report and schema == TIMESERIES_SCHEMA
    )
    return {
        "label": artifact_display_name(artifact),
        "baseline_start": baseline_start,
        "baseline_end": baseline_end,
        "current_start": current_start,
        "current_end": current_end,
        "baseline_label": "Expected" if is_control_row else "Baseline",
        "current_label": "After" if is_control_row else "Current",
    }


def _timeline_windows(
    artifact: dict[str, Any], schema: Any
) -> tuple[Any, Any]:
    if schema == CONTROL_SCHEMA:
        return artifact.get("after_window"), artifact.get("before_window")
    baselines = artifact.get("baseline_windows")
    if not isinstance(baselines, list) or not baselines:
        return None, None
    return artifact.get("current_window"), baselines[0]


def _collapse_timeline_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if len(rows) <= 1:
        return rows
    endpoints = ("baseline_start", "baseline_end", "current_start", "current_end")
    first = rows[0]
    max_drift_seconds = max(
        abs((row[field] - first[field]).total_seconds())
        for row in rows[1:]
        for field in endpoints
    )
    if max_drift_seconds >= 3600:
        return rows
    return [
        {
            "label": "Report comparison window",
            "baseline_start": min(row["baseline_start"] for row in rows),
            "baseline_end": max(row["baseline_end"] for row in rows),
            "current_start": min(row["current_start"] for row in rows),
            "current_end": max(row["current_end"] for row in rows),
            "baseline_label": rows[0].get("baseline_label", "Baseline"),
            "current_label": rows[0].get("current_label", "Current"),
        }
    ]


def html_chart_sections(
    report_type: str,
    selected: dict[str, Any],
    limit: int,
    ctx: ReportContext,
) -> str:
    builder = _HTML_CHART_BUILDERS.get(report_type)
    pieces = builder(selected, limit, ctx) if builder else []
    body = "".join(piece for piece in pieces if piece)
    if not body:
        return ""
    return '<section class="charts" aria-label="Charts">' + body + "</section>"


def _executive_chart_pieces(
    selected: dict[str, Any], limit: int, ctx: ReportContext
) -> list[str]:
    posture = selected["posture"]
    pieces = [
        html_metric_delta_cards(posture, limit, ctx),
        html_current_baseline_bars(posture, limit, ctx),
    ]
    if selected.get("index"):
        pieces.append(html_ranking_bars(selected["index"], limit, ctx))
    if selected.get("mover"):
        pieces.append(html_mover_bars(selected["mover"], limit, ctx))
    scorecards = selected.get("scorecards") or []
    if scorecards:
        pieces.append(html_domain_matrix(scorecards, limit, ctx))
    return pieces


def _soc_chart_pieces(
    selected: dict[str, Any], limit: int, ctx: ReportContext
) -> list[str]:
    pieces = [html_ranking_bars(selected["index"], limit, ctx)]
    scorecards = selected.get("scorecards") or []
    if scorecards:
        pieces.append(html_domain_matrix(scorecards, limit, ctx))
    else:
        pieces.append(
            _chart_skip(
                "Domain Score Matrix",
                "degraded SOC mode has no compatible scorecards",
                ctx,
            )
        )
    if selected.get("mover"):
        pieces.append(html_mover_bars(selected["mover"], limit, ctx))
    return pieces


def _control_chart_pieces(
    selected: dict[str, Any], limit: int, ctx: ReportContext
) -> list[str]:
    return [html_control_bars(selected["control"], limit, ctx)]


def _scorecard_chart_pieces(
    selected: dict[str, Any], limit: int, ctx: ReportContext
) -> list[str]:
    return [html_scorecard_feature_cards(selected["scorecard"], limit, ctx)]


def _scorecard_family_chart_pieces(
    selected: dict[str, Any], limit: int, ctx: ReportContext
) -> list[str]:
    scorecards = selected.get("scorecards") or []
    return [
        html_ranking_bars(selected["index"], limit, ctx)
        if selected.get("index")
        else html_scorecard_score_bars(scorecards, limit, ctx),
        html_domain_matrix(scorecards, limit, ctx),
    ]


def _edge_ops_chart_pieces(
    selected: dict[str, Any], limit: int, ctx: ReportContext
) -> list[str]:
    scorecards = selected.get("scorecards") or []
    pieces = [
        html_ranking_bars(selected["index"], limit, ctx)
        if selected.get("index")
        else html_scorecard_score_bars(scorecards, limit, ctx),
        html_domain_matrix(scorecards, limit, ctx),
    ]
    if selected.get("posture"):
        pieces.append(html_current_baseline_bars(selected["posture"], limit, ctx))
    if selected.get("mover"):
        pieces.append(html_mover_bars(selected["mover"], limit, ctx))
    return pieces


_HTML_CHART_BUILDERS = {
    "executive_posture": _executive_chart_pieces,
    "soc_triage": _soc_chart_pieces,
    "control_review": _control_chart_pieces,
    "scorecard_brief": _scorecard_chart_pieces,
    "crawler_governance": _scorecard_family_chart_pieces,
    "edge_ops_impact": _edge_ops_chart_pieces,
}


def markdown_to_simple_html(markdown: str) -> str:
    lines = markdown.splitlines()
    output: list[str] = []
    table_lines: list[str] = []
    list_open = False

    def flush_table() -> None:
        nonlocal table_lines
        if not table_lines:
            return
        output.append(table_to_html(table_lines))
        table_lines = []

    def close_list() -> None:
        nonlocal list_open
        if list_open:
            output.append("</ul>")
            list_open = False

    for line in lines:
        if line.startswith("|"):
            close_list()
            table_lines.append(line)
            continue
        flush_table()
        rendered = _simple_html_line(line)
        if rendered is None:
            close_list()
            continue
        if rendered[0] == "li":
            if not list_open:
                output.append("<ul>")
                list_open = True
            output.append(rendered[1])
        else:
            close_list()
            output.append(rendered[1])
    flush_table()
    close_list()
    return "".join(output)


def _simple_html_line(line: str) -> tuple[str, str] | None:
    if not line.strip():
        return None
    for marker, tag in (("# ", "h1"), ("## ", "h2"), ("### ", "h3")):
        if line.startswith(marker):
            return tag, f"<{tag}>{h_escape(_demd(line[len(marker):]))}</{tag}>"
    if line.startswith("- "):
        return "li", f"<li>{inline_html(line[2:])}</li>"
    return "p", f"<p>{inline_html(line)}</p>"


def inline_html(text: str) -> str:
    parts: list[str] = []

    def append_text(segment: str) -> None:
        cursor = 0
        while cursor < len(segment):
            start = _find_unescaped(segment, "_", cursor)
            if start == -1:
                parts.append(h_escape(_demd(segment[cursor:])))
                return
            end = _find_unescaped(segment, "_", start + 1)
            if end == -1:
                parts.append(h_escape(_demd(segment[cursor:])))
                return
            parts.append(h_escape(_demd(segment[cursor:start])))
            parts.append(f"<em>{h_escape(_demd(segment[start + 1 : end]))}</em>")
            cursor = end + 1

    cursor = 0
    while cursor < len(text):
        start = _find_unescaped(text, "`", cursor)
        if start == -1:
            append_text(text[cursor:])
            break
        end = _find_unescaped(text, "`", start + 1)
        if end == -1:
            append_text(text[cursor:])
            break
        append_text(text[cursor:start])
        parts.append(f"<code>{h_escape(_demd(text[start + 1 : end]))}</code>")
        cursor = end + 1
    return "".join(parts)


def _split_table_row(line: str) -> list[str]:
    body = line.strip()
    if body.startswith("|"):
        body = body[1:]
    if body.endswith("|"):
        body = body[:-1]
    cells: list[str] = []
    buffer: list[str] = []
    index = 0
    while index < len(body):
        ch = body[index]
        if ch == "\\" and index + 1 < len(body):
            buffer.append(body[index])
            buffer.append(body[index + 1])
            index += 2
            continue
        if ch == "|":
            cells.append("".join(buffer).strip())
            buffer = []
            index += 1
            continue
        buffer.append(ch)
        index += 1
    cells.append("".join(buffer).strip())
    return cells


def table_to_html(lines: list[str]) -> str:
    rows = []
    for line in lines:
        cells = _split_table_row(line)
        if cells and all(set(cell) <= {"-"} for cell in cells):
            continue
        rows.append(cells)
    if not rows:
        return ""
    header = rows[0]
    body = rows[1:]
    output = ["<table><thead><tr>"]
    output.extend(f"<th>{h_escape(_demd(cell))}</th>" for cell in header)
    output.append("</tr></thead><tbody>")
    for row in body:
        output.append("<tr>")
        output.extend(f"<td>{inline_html(cell)}</td>" for cell in row)
        output.append("</tr>")
    output.append("</tbody></table>")
    return "".join(output)
