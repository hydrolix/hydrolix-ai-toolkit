"""Triage chart helpers."""

from __future__ import annotations

from ..theme import BAND_COLORS, PALETTE


def triage_histogram_svg(
    counts: dict[str, int],
    width: int = 660,
    height: int = 200,
) -> str:
    """4-bar histogram bucketed by triage verdict state.

    Replaces the score-distribution histogram in the brief landscape — the
    question shifts from "where do scores sit on the 0–100 scale" (which
    reads as reassuring when most hosts are in the blue zone even if they
    triggered something) to "where does the work sit in the queue."
    Bar order: Assign → Watch → Insufficient → Close. Bar color matches
    the triage pill tone for visual continuity with the strip.
    """
    order = (
        ("assign", "Assign", PALETTE["escalate"]),
        ("watch", "Watch", PALETTE["monitor"]),
        ("insufficient_data", "Insufficient", PALETTE["muted"]),
        ("close_as_expected", "Close — expected", PALETTE["observe"]),
    )
    values = [(label, counts.get(state, 0), color) for state, label, color in order]
    total = sum(v for _, v, _ in values)
    if total == 0:
        return ""

    pad_l, pad_r, pad_t, pad_b = 36, 20, 18, 44
    plot_w = width - pad_l - pad_r
    plot_h = height - pad_t - pad_b
    max_count = max((v for _, v, _ in values), default=1) or 1
    n = len(values)
    gap = 18
    bar_w = (plot_w - gap * (n - 1)) / n

    parts = [
        f'<svg viewBox="0 0 {width} {height}" class="triage-hist" '
        f'role="img" aria-label="Triage state distribution">'
    ]

    axis_y = pad_t + plot_h
    parts.append(
        f'<line x1="{pad_l}" y1="{axis_y}" x2="{width - pad_r}" y2="{axis_y}" '
        f'stroke="#d4d4d8" stroke-width="1" />'
    )

    bar_top_pad = 14
    for i, (label, count, color) in enumerate(values):
        bx = pad_l + i * (bar_w + gap)
        bar_height = (count / max_count) * (plot_h - bar_top_pad)
        by = axis_y - bar_height
        opacity = "0.35" if count == 0 else "1"
        parts.append(
            f'<rect x="{bx:.1f}" y="{by:.1f}" width="{bar_w:.1f}" '
            f'height="{bar_height:.1f}" fill="{color}" fill-opacity="{opacity}" '
            f'rx="3" />'
        )
        parts.append(
            f'<text x="{bx + bar_w / 2:.1f}" y="{by - 6:.1f}" '
            f'text-anchor="middle" class="hist-bar-count">{count}</text>'
        )
        parts.append(
            f'<text x="{bx + bar_w / 2:.1f}" y="{axis_y + 18:.1f}" '
            f'text-anchor="middle" class="hist-axis-tick">{label}</text>'
        )

    parts.append("</svg>")
    return "".join(parts)


def coverage_bar_svg(triggered: int, evaluated_zero: int, missing: int) -> str:
    """Stacked horizontal bar: triggered / evaluated_zero / missing_input."""
    total = triggered + evaluated_zero + missing
    if total == 0:
        return ""
    width, height = 360, 14
    parts = [
        f'<svg viewBox="0 0 {width} {height}" class="coverage-bar" '
        f'role="img" aria-label="Rule coverage">'
    ]
    x = 0.0
    segments = (
        (triggered, BAND_COLORS["observe"]),
        (evaluated_zero, PALETTE["coverage_evaluated_zero"]),
        (missing, PALETTE["coverage_missing"]),
    )
    for count, color in segments:
        if count == 0:
            continue
        w = (count / total) * width
        parts.append(
            f'<rect x="{x:.1f}" y="0" width="{w:.1f}" height="{height}" '
            f'fill="{color}" />'
        )
        x += w
    parts.append("</svg>")
    return "".join(parts)
