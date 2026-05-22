"""Legacy HTML chart builders."""

from __future__ import annotations

from typing import Any

from report_engine.humanize import human_metric_name
from report_engine.humanize import stringify

from .charts import (
    _chart_numeric,
    _chart_open,
    _chart_skip,
    _horizontal_bars_svg,
)
from .errors import ReportContext
from .formatters import (
    h_escape,
    human_delta,
    human_number,
)

__all__ = [
    'html_metric_delta_cards',
    'html_current_baseline_bars',
    'html_ranking_bars',
    'html_scorecard_score_bars',
    'html_mover_bars',
    'html_scorecard_domain_bars',
    'html_domain_matrix',
    'html_control_bars',
]


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



