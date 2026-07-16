"""Legacy HTML body builders + post-processing (test infrastructure only)."""

from __future__ import annotations

import re
from typing import Any

from .errors import ReportContext
from .formatters import h_escape
from .legacy_html_chart_sections import html_chart_sections
from .legacy_html_charts import (
    html_control_bars,
    html_current_baseline_bars,
    html_domain_matrix,
    html_metric_delta_cards,
    html_mover_bars,
    html_ranking_bars,
    html_scorecard_domain_bars,
    html_scorecard_score_bars,
)
from .legacy_html_fleet import (
    html_fleet_coverage,
    html_fleet_findings,
    html_fleet_kpis,
    html_fleet_method,
    html_fleet_next_steps,
    html_fleet_ranked_entities,
    html_scorecard_fleet_report,
)
from .legacy_html_markdown import (
    _split_table_row,
    inline_html,
    markdown_to_simple_html,
    table_to_html,
)
from .legacy_html_scorecards import (
    html_scorecard_context_panel,
    html_scorecard_feature_cards,
    html_scorecard_overall_gauge,
)
from .legacy_html_time import (
    html_timeseries_cards,
    html_window_timeline,
)
from .legacy_markdown import render_markdown

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
