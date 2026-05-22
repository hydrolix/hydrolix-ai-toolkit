"""Comparison chart helpers."""

from __future__ import annotations

from ..theme import PALETTE, band_for_score


def bullet_chart_svg(
    actual: float,
    comparison: float,
    ranges: list[tuple[float, str]] | None = None,
    label: str = "",
    width: int = 360,
    height: int = 36,
) -> str:
    """Stephen Few bullet chart — actual bar over qualitative band background,
    with a vertical tick marking the comparison value.

    ranges: list of (upper_bound, fill_color) sorted ascending. If omitted,
            uses the score-band defaults (escalate 0-40, monitor 40-70,
            observe 70-100).
    """
    if ranges is None:
        ranges = [
            (40, PALETTE["escalate_fill"]),
            (70, PALETTE["monitor_fill"]),
            (100, PALETTE["observe_fill"]),
        ]

    band_h = height - 14  # leave room for label below
    parts = [
        f'<svg viewBox="0 0 {width} {height}" class="bullet-chart" '
        f'role="img" aria-label="{label or "bullet chart"}">'
    ]
    prev_x = 0.0
    for upper, color in ranges:
        x_end = (upper / 100) * width
        parts.append(
            f'<rect x="{prev_x:.1f}" y="0" '
            f'width="{(x_end - prev_x):.1f}" height="{band_h}" fill="{color}" />'
        )
        prev_x = x_end

    actual_w = max(0, min(actual, 100)) / 100 * width
    actual_color = band_for_score(int(actual))[1]
    actual_h = max(8, band_h - 14)
    actual_y = (band_h - actual_h) / 2
    parts.append(
        f'<rect x="0" y="{actual_y:.1f}" '
        f'width="{actual_w:.1f}" height="{actual_h:.1f}" fill="{actual_color}" />'
    )

    comp_x = max(0, min(comparison, 100)) / 100 * width
    parts.append(
        f'<line x1="{comp_x:.1f}" y1="2" x2="{comp_x:.1f}" '
        f'y2="{band_h - 2:.1f}" stroke="#18181b" stroke-width="2.5" />'
    )

    if label:
        parts.append(
            f'<text x="0" y="{height - 2}" class="bullet-label">{label}</text>'
        )
    parts.append("</svg>")
    return "".join(parts)


def slopegraph_svg(
    entities: list[dict],
    label_left: str = "baseline",
    label_right: str = "current",
    width: int = 540,
    height: int = 280,
) -> str:
    """Two-column slopegraph for scoreable entities with a delta.

    Each entity is a dict with `entity`, `score`, `delta`. We plot
    (score - delta) on the left, score on the right.
    """
    if not entities:
        return ""

    pairs = [(e["entity"], e["score"] - e["delta"], e["score"]) for e in entities]
    pad_l, pad_r, pad_t, pad_b = 80, 200, 36, 30
    plot_w = width - pad_l - pad_r
    plot_h = height - pad_t - pad_b

    all_values = [v for _, b, a in pairs for v in (b, a)]
    vmin, vmax = min(all_values), max(all_values)
    span = max(vmax - vmin, 1.0)

    def y_for(v: float) -> float:
        return pad_t + (1 - (v - vmin) / span) * plot_h

    x_left = pad_l
    x_right = pad_l + plot_w

    parts = [
        f'<svg viewBox="0 0 {width} {height}" class="slopegraph" '
        f'role="img" aria-label="Score movement">'
    ]
    # Column headers
    parts.append(
        f'<text x="{x_left}" y="{pad_t - 14}" text-anchor="middle" '
        f'class="slope-axis-label">{label_left}</text>'
    )
    parts.append(
        f'<text x="{x_right}" y="{pad_t - 14}" text-anchor="middle" '
        f'class="slope-axis-label">{label_right}</text>'
    )

    for entity, before, after in pairs:
        y_b = y_for(before)
        y_a = y_for(after)
        if after < before:
            color = PALETTE["escalate"]
        elif after > before:
            color = PALETTE["delta_down"]  # green tone (improvement)
        else:
            color = PALETTE["muted_2"]
        parts.append(
            f'<line x1="{x_left}" y1="{y_b:.1f}" x2="{x_right}" y2="{y_a:.1f}" '
            f'stroke="{color}" stroke-width="1.5" stroke-opacity="0.65" />'
        )
        parts.append(f'<circle cx="{x_left}" cy="{y_b:.1f}" r="4" fill="{color}" />')
        parts.append(f'<circle cx="{x_right}" cy="{y_a:.1f}" r="4" fill="{color}" />')
        parts.append(
            f'<text x="{x_right + 8}" y="{y_a + 4:.1f}" class="slope-entity-label">'
            f"{entity}: {before:.0f} → {after:.0f}</text>"
        )

    parts.append("</svg>")
    return "".join(parts)
