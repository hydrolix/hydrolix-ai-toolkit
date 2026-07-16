"""Legacy HTML chart section orchestration."""

from __future__ import annotations

from typing import Any

from .charts import _chart_skip
from .errors import ReportContext
from .legacy_html_charts import (
    html_control_bars,
    html_current_baseline_bars,
    html_domain_matrix,
    html_metric_delta_cards,
    html_mover_bars,
    html_ranking_bars,
    html_scorecard_score_bars,
)
from .legacy_html_scorecards import html_scorecard_feature_cards

__all__ = [
    'html_chart_sections',
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


