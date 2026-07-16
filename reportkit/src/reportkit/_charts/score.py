"""Score chart helpers."""

from __future__ import annotations

import math

from ..theme import PALETTE, band_for_score


def score_gauge_svg(score: int, delta_pct: float | None = None) -> str:
    """Half-circle arc gauge with band-zoned arc, big-number readout, and an
    optional delta indicator (`↑ 5.00%` / `↓ 1.00%` / `— 0.00%`) directly
    under the number. The delta is the percent change of THIS host's score
    versus its prior equivalent window."""
    width, height = 280, 195
    cx, cy, r = 140, 130, 95
    stroke = 18

    def arc_path(v1: float, v2: float) -> str:
        th1 = math.pi * (1 - v1 / 100)
        th2 = math.pi * (1 - v2 / 100)
        x1, y1 = cx + r * math.cos(th1), cy - r * math.sin(th1)
        x2, y2 = cx + r * math.cos(th2), cy - r * math.sin(th2)
        return f"M {x1:.2f} {y1:.2f} A {r} {r} 0 0 1 {x2:.2f} {y2:.2f}"

    th_p = math.pi * (1 - max(0, min(100, score)) / 100)
    px = cx + r * math.cos(th_p)
    py = cy - r * math.sin(th_p)
    pxi = cx + (r - stroke - 6) * math.cos(th_p)
    pyi = cy - (r - stroke - 6) * math.sin(th_p)

    band_label, score_color = band_for_score(score)

    # Delta: rendered just under the big number. Higher score = healthier,
    # so a positive percent change is an improvement (green ↑); a negative
    # change is a degradation (red ↓); near-zero shows an em-dash + 0.00%.
    delta_text = ""
    if delta_pct is not None:
        if delta_pct > 0.005:
            delta_color = PALETTE["delta_down"]
            delta_text = f"↑ {delta_pct:.2f}%"
        elif delta_pct < -0.005:
            delta_color = PALETTE["escalate"]
            delta_text = f"↓ {abs(delta_pct):.2f}%"
        else:
            delta_color = PALETTE["muted"]
            delta_text = "Unchanged"

    delta_svg = ""
    if delta_text:
        delta_svg = (
            f'<text x="{cx}" y="158" text-anchor="middle" '
            f'class="gauge-delta" fill="{delta_color}">{delta_text}</text>'
        )

    return (
        f'<svg viewBox="0 0 {width} {height}" class="gauge-svg" '
        f'role="img" aria-label="Score {score}: {band_label}">'
        f'<path d="{arc_path(0, 40)}" stroke="{PALETTE["escalate_fill"]}" '
        f'stroke-width="{stroke}" fill="none" />'
        f'<path d="{arc_path(40, 70)}" stroke="{PALETTE["monitor_fill"]}" '
        f'stroke-width="{stroke}" fill="none" />'
        f'<path d="{arc_path(70, 100)}" stroke="{PALETTE["observe_fill"]}" '
        f'stroke-width="{stroke}" fill="none" />'
        f'<line x1="{pxi:.2f}" y1="{pyi:.2f}" x2="{px:.2f}" y2="{py:.2f}" '
        f'stroke="{score_color}" stroke-width="3" stroke-linecap="round" />'
        f'<circle cx="{px:.2f}" cy="{py:.2f}" r="6" '
        f'fill="{score_color}" stroke="#fff" stroke-width="2" />'
        f'<text x="{cx - r + 4}" y="{cy + 16}" text-anchor="start" '
        f'class="gauge-tick">0</text>'
        f'<text x="{cx + r - 4}" y="{cy + 16}" text-anchor="end" '
        f'class="gauge-tick">100</text>'
        f'<text x="{cx}" y="{cy - 18}" text-anchor="middle" '
        f'class="gauge-number">{score}</text>'
        f"{delta_svg}"
        f'<text x="{cx}" y="180" text-anchor="middle" '
        f'class="gauge-band" fill="{score_color}">{band_label}</text>'
        "</svg>"
    )


def score_bar_svg(score: int, max_score: int = 100) -> str:
    """Compact horizontal score bar for use inside table rows."""
    width, height = 88, 8
    pct = max(0, min(score, max_score)) / max_score
    fill_w = pct * width
    _, color = band_for_score(score)
    return (
        f'<svg viewBox="0 0 {width} {height}" class="score-bar" '
        f'role="img" aria-label="Score {score}">'
        f'<rect x="0" y="0" width="{width}" height="{height}" rx="2" fill="#f4f4f5" />'
        f'<rect x="0" y="0" width="{fill_w:.1f}" height="{height}" rx="2" fill="{color}" />'
        "</svg>"
    )


def band_distribution_bar_svg(
    bands: dict[str, int], width: int = 280, height: int = 44
) -> str:
    """Horizontal stacked bar showing fleet distribution across health bands.

    Order is escalate (worst, left) → monitor → observe (best, right) so the
    visual gradient reads "concern" on the left, "healthy" on the right —
    matching the gauge's arc convention. Below-bar labels carry the counts.
    """
    ordered = (
        ("escalate", bands.get("escalate", 0), PALETTE["escalate"]),
        ("monitor", bands.get("monitor", 0), PALETTE["monitor"]),
        ("observe", bands.get("observe", 0), PALETTE["observe"]),
    )
    total = sum(count for _, count, _ in ordered)
    if total == 0:
        return ""

    bar_h = 16
    bar_y = 2
    label_y = bar_h + bar_y + 14
    parts = [
        f'<svg viewBox="0 0 {width} {height}" class="band-dist-bar" '
        f'role="img" aria-label="Band distribution">'
    ]

    x = 0.0
    label_xs: list[tuple[str, int, float]] = []
    for name, count, color in ordered:
        if count == 0:
            continue
        w = (count / total) * width
        parts.append(
            f'<rect x="{x:.1f}" y="{bar_y}" width="{w:.1f}" '
            f'height="{bar_h}" fill="{color}" rx="2" />'
        )
        label_xs.append((name, count, x + w / 2))
        x += w

    # Labels below: positioned at each segment's center if there's room,
    # else collapsed to a single centered label.
    if len(label_xs) == 1:
        name, count, _ = label_xs[0]
        parts.append(
            f'<text x="{width / 2:.1f}" y="{label_y}" text-anchor="middle" '
            f'class="band-dist-label">{count} {name.capitalize()}</text>'
        )
    else:
        for name, count, cx in label_xs:
            parts.append(
                f'<text x="{cx:.1f}" y="{label_y}" text-anchor="middle" '
                f'class="band-dist-label">{count} {name.capitalize()}</text>'
            )
    parts.append("</svg>")
    return "".join(parts)


def score_histogram_svg(
    scores: list[int],
    lowest: int,
    median: int,
    bin_size: int = 5,
    width: int = 660,
    height: int = 200,
) -> str:
    """Score-distribution histogram with band-zoned background.

    The chart simultaneously communicates *where* the fleet sits (the bars)
    and *what that means* in severity terms (the colored zones behind them).
    Annotations: lowest score and median plotted on the x-axis as ticks. When
    lowest and median coincide they collapse into a single combined label.
    """
    if not scores:
        return ""
    pad_l, pad_r, pad_t, pad_b = 36, 20, 26, 44
    plot_w = width - pad_l - pad_r
    plot_h = height - pad_t - pad_b

    # Bucket scores. Score=100 collapses into the 90 bucket so the chart
    # caps at the visible 0..100 range.
    buckets: dict[int, int] = {}
    for s in scores:
        bin_key = (min(s, 99) // bin_size) * bin_size
        buckets[bin_key] = buckets.get(bin_key, 0) + 1
    max_count = max(buckets.values())

    def color_for_score(s: int) -> str:
        if s < 40:
            return PALETTE["escalate"]
        if s < 70:
            return PALETTE["monitor"]
        return PALETTE["observe"]

    parts = [
        f'<svg viewBox="0 0 {width} {height}" class="score-hist" '
        f'role="img" aria-label="Score distribution">'
    ]
    x_for_score = lambda s: pad_l + (s / 100) * plot_w

    _append_score_histogram_zones(parts, x_for_score, pad_t, plot_h)
    _append_score_histogram_bars(
        parts, buckets, max_count, bin_size, x_for_score, color_for_score, pad_t, plot_h
    )
    axis_y = pad_t + plot_h
    _append_score_histogram_axis(parts, x_for_score, pad_l, pad_r, width, axis_y)
    _append_score_histogram_annotations(parts, x_for_score, axis_y, lowest, median)

    parts.append("</svg>")
    return "".join(parts)


def _append_score_histogram_zones(parts: list[str], x_for_score, pad_t: int, plot_h: int) -> None:
    zones = (
        ("Escalate", 0, 40, PALETTE["escalate_fill"]),
        ("Monitor", 40, 70, PALETTE["monitor_fill"]),
        ("Observe", 70, 100, PALETTE["observe_fill"]),
    )
    for label, lo, hi, fill in zones:
        zx = x_for_score(lo)
        zw = x_for_score(hi) - zx
        parts.append(
            f'<rect x="{zx:.1f}" y="{pad_t}" width="{zw:.1f}" '
            f'height="{plot_h}" fill="{fill}" fill-opacity="0.40" />'
        )
        parts.append(
            f'<text x="{zx + zw / 2:.1f}" y="{pad_t - 8}" '
            f'text-anchor="middle" class="hist-zone-label">{label}</text>'
        )


def _append_score_histogram_bars(
    parts: list[str],
    buckets: dict[int, int],
    max_count: int,
    bin_size: int,
    x_for_score,
    color_for_score,
    pad_t: int,
    plot_h: int,
) -> None:
    bar_top_pad = 10
    for bin_key, count in sorted(buckets.items()):
        bx = x_for_score(bin_key)
        bx_end = x_for_score(bin_key + bin_size)
        bar_w = max(1.0, bx_end - bx - 2)
        bar_h = (count / max_count) * (plot_h - bar_top_pad)
        bar_y = pad_t + plot_h - bar_h
        color = color_for_score(bin_key)
        parts.append(
            f'<rect x="{bx + 1:.1f}" y="{bar_y:.1f}" '
            f'width="{bar_w:.1f}" height="{bar_h:.1f}" '
            f'fill="{color}" rx="2" />'
        )
        parts.append(
            f'<text x="{(bx + bx_end) / 2:.1f}" y="{bar_y - 4:.1f}" '
            f'text-anchor="middle" class="hist-bar-count">{count}</text>'
        )


def _append_score_histogram_axis(
    parts: list[str],
    x_for_score,
    pad_l: int,
    pad_r: int,
    width: int,
    axis_y: int,
) -> None:
    parts.append(
        f'<line x1="{pad_l}" y1="{axis_y}" x2="{width - pad_r}" y2="{axis_y}" '
        f'stroke="#d4d4d8" stroke-width="1" />'
    )
    for tick in (0, 25, 50, 75, 100):
        tx = x_for_score(tick)
        parts.append(
            f'<line x1="{tx:.1f}" y1="{axis_y}" x2="{tx:.1f}" y2="{axis_y + 4}" '
            f'stroke="#a1a1aa" stroke-width="1" />'
        )
        parts.append(
            f'<text x="{tx:.1f}" y="{axis_y + 18}" text-anchor="middle" '
            f'class="hist-axis-tick">{tick}</text>'
        )


def _append_score_histogram_annotations(
    parts: list[str],
    x_for_score,
    axis_y: int,
    lowest: int,
    median: int,
) -> None:
    annot_y = axis_y + 36
    if lowest == median:
        ax = x_for_score(lowest)
        parts.append(
            f'<line x1="{ax:.1f}" y1="{axis_y - 6}" x2="{ax:.1f}" '
            f'y2="{axis_y + 6}" stroke="#18181b" stroke-width="2" />'
        )
        parts.append(
            f'<text x="{ax:.1f}" y="{annot_y}" text-anchor="middle" '
            f'class="hist-annotation">Lowest = Median = {lowest}</text>'
        )
    else:
        for label, value, color, dash in (
            ("Lowest", lowest, "#18181b", ""),
            ("Median", median, "#71717a", 'stroke-dasharray="3,2"'),
        ):
            ax = x_for_score(value)
            parts.append(
                f'<line x1="{ax:.1f}" y1="{axis_y - 6}" x2="{ax:.1f}" '
                f'y2="{axis_y + 6}" stroke="{color}" stroke-width="2" {dash} />'
            )
            parts.append(
                f'<text x="{ax:.1f}" y="{annot_y}" text-anchor="middle" '
                f'class="hist-annotation">{label} {value}</text>'
            )
