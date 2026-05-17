"""Visual palette and label constants for the report engine.

Single source of truth for colors, band thresholds, and human-readable domain
labels. `PALETTE` is exposed to Jinja as a global, so both Python helpers
(`charts.py`) and the stylesheet (`_styles.css`) read from it. Retune here.
"""

from __future__ import annotations

# Tableau 10 base hues for severity bands, plus derived tints/borders/text
# colors for pills and large fills. Neutral chrome (bg/text/border) keeps
# zinc grays since neutrals don't compete with the warm accents.
PALETTE = {
    # Band primaries. Tableau 10 hues for the lower three tiers; `critical`
    # is a darkened `escalate` to give incident reporting an industry-style
    # 4-tier severity scheme (Critical / High / Medium / Low) without
    # leaving the Tableau 10 family. `critical` ≈ `escalate` darkened ~30%,
    # in the same hue neighborhood as AWS Security Hub's critical (#9F0500).
    "observe": "#4E79A7",
    "monitor": "#F28E2B",
    "escalate": "#E15759",
    "critical": "#9F2C2D",
    # Large fill tints (used for the gauge arc zones)
    "observe_fill": "#C9D5E5",
    "monitor_fill": "#FAD9B6",
    "escalate_fill": "#F4C8C9",
    "critical_fill": "#E0B0B1",
    # Pill colors — pale bg, mid border, deep text
    "observe_pill_bg": "#EDF2F8",
    "observe_pill_border": "#B5C7DC",
    "observe_pill_text": "#2D4A6B",
    "monitor_pill_bg": "#FDF1E2",
    "monitor_pill_border": "#F8C58A",
    "monitor_pill_text": "#8C4A0A",
    "escalate_pill_bg": "#FBE7E7",
    "escalate_pill_border": "#F0A8A9",
    "escalate_pill_text": "#8B2728",
    "critical_pill_bg": "#F3DADA",
    "critical_pill_border": "#C26F6F",
    "critical_pill_text": "#5F1314",
    # Chrome / neutrals
    "bg": "#fafaf9",
    "surface": "#ffffff",
    "surface_2": "#f4f4f5",
    "text": "#18181b",
    "muted": "#71717a",
    "muted_2": "#a1a1aa",
    "border": "#e4e4e7",
    # Coverage-bar segments (triggered = observe accent, missing = warm tint)
    "coverage_evaluated_zero": "#a1a1aa",
    "coverage_missing": "#F8C58A",
    # Improvement (down/green) for delta arrows in entity tables
    "delta_down": "#3F8C5A",
}

# Dark-mode pairs for the same semantic tokens. Strategy: shift accents
# lighter and slightly desaturated so they pop against dark chrome,
# matching the IBM Carbon / AWS Cloudscape approach to dark-mode
# severity tokens. Chrome moves to dark-but-not-black (Carbon-style
# #161616 region) — pure black is hard on eyes for sustained reading,
# which matters for 2am incident-response use.
#
# Hex values picked so that:
#   - Each tier stays visibly distinct in dark mode (critical ≠ escalate).
#   - Contrast against the dark surface meets WCAG AA for text.
#   - The four-tier ordering (critical > escalate > monitor > observe)
#     reads the same direction it does in light mode.
DARK_PALETTE = {
    # Band primaries — lifted from the Tableau 10 base hues
    "observe": "#7AA5D2",
    "monitor": "#F5B872",
    "escalate": "#FA8587",
    "critical": "#E54E4F",
    # Large fill tints
    "observe_fill": "#2D4A6B",
    "monitor_fill": "#6B4A1E",
    "escalate_fill": "#6B2728",
    "critical_fill": "#4F1314",
    # Pill colors — subtle dark tint background, bright border, light text
    "observe_pill_bg": "#1F2D3E",
    "observe_pill_border": "#7AA5D2",
    "observe_pill_text": "#C9D5E5",
    "monitor_pill_bg": "#3D2D17",
    "monitor_pill_border": "#F5B872",
    "monitor_pill_text": "#FAD9B6",
    "escalate_pill_bg": "#3D1B1C",
    "escalate_pill_border": "#FA8587",
    "escalate_pill_text": "#F4C8C9",
    "critical_pill_bg": "#4A1A1B",
    "critical_pill_border": "#E54E4F",
    "critical_pill_text": "#F3DADA",
    # Chrome / neutrals — Carbon-style dark surfaces
    "bg": "#161616",
    "surface": "#1f1f1f",
    "surface_2": "#2a2a2a",
    "text": "#e6e6e6",
    "muted": "#a0a0a0",
    "muted_2": "#888888",
    "border": "#363636",
    # Coverage-bar segments
    "coverage_evaluated_zero": "#525252",
    "coverage_missing": "#6B4A1E",
    # Improvement delta arrows
    "delta_down": "#6BC089",
}


# ---- Alternative palettes ----------------------------------------------
#
# Same semantic token slots, different hex values. Selectable via
# render_report.py's --palette flag so the same wrapper can be re-rendered
# in three visual languages without touching the templates.
#
# The semantic mapping is fixed (observe = lowest, critical = highest); only
# the hex values change. The chrome (bg / surface / text / border) shifts
# with the palette since each design system has its own neutral choices.


# AWS Cloudscape Design System — open-sourced from the AWS Console in 2022,
# specifically designed for cloud-operations and incident-response surfaces.
# Punchier reds and oranges than Tableau 10; reads as "command center"
# rather than "BI dashboard." Hex values from Cloudscape's published
# severity / status design tokens.
CLOUDSCAPE_PALETTE = {
    "observe": "#0972d3",  # status-info blue
    "monitor": "#b2911c",  # status-warning amber-yellow
    "escalate": "#dc7609",  # status-warning-dark orange (= "high")
    "critical": "#d91515",  # status-error red (= "critical")
    "observe_fill": "#cfe0f5",
    "monitor_fill": "#f0e3b8",
    "escalate_fill": "#f5d4b8",
    "critical_fill": "#f5b8b8",
    "observe_pill_bg": "#eff5fc",
    "observe_pill_border": "#7eb1e2",
    "observe_pill_text": "#033160",
    "monitor_pill_bg": "#fdf6e0",
    "monitor_pill_border": "#d9bd5e",
    "monitor_pill_text": "#5c4806",
    "escalate_pill_bg": "#fdf0e2",
    "escalate_pill_border": "#e8a45e",
    "escalate_pill_text": "#5c3406",
    "critical_pill_bg": "#fce8e8",
    "critical_pill_border": "#e87a7a",
    "critical_pill_text": "#5c0808",
    "bg": "#f2f3f3",
    "surface": "#ffffff",
    "surface_2": "#fafafa",
    "text": "#000716",
    "muted": "#414d5c",
    "muted_2": "#7d8998",
    "border": "#d1d5db",
    "coverage_evaluated_zero": "#7d8998",
    "coverage_missing": "#d9bd5e",
    "delta_down": "#037f0c",
}


# Cloudscape dark mode — published as part of the design system.
DARK_CLOUDSCAPE = {
    "observe": "#539fe5",
    "monitor": "#dfb537",
    "escalate": "#f5a165",
    "critical": "#ff7a7a",
    "observe_fill": "#0a2540",
    "monitor_fill": "#3d3214",
    "escalate_fill": "#3d2614",
    "critical_fill": "#3d1414",
    "observe_pill_bg": "#0a2540",
    "observe_pill_border": "#539fe5",
    "observe_pill_text": "#cfe0f5",
    "monitor_pill_bg": "#3d3214",
    "monitor_pill_border": "#dfb537",
    "monitor_pill_text": "#f0e3b8",
    "escalate_pill_bg": "#3d2614",
    "escalate_pill_border": "#f5a165",
    "escalate_pill_text": "#f5d4b8",
    "critical_pill_bg": "#4d1a1a",
    "critical_pill_border": "#ff7a7a",
    "critical_pill_text": "#fce8e8",
    "bg": "#0f1b2a",
    "surface": "#161e2d",
    "surface_2": "#1f2937",
    "text": "#fbfbfb",
    "muted": "#9da7b3",
    "muted_2": "#7d8998",
    "border": "#293440",
    "coverage_evaluated_zero": "#525252",
    "coverage_missing": "#3d3214",
    "delta_down": "#6cb47c",
}


# IBM Carbon Design System — enterprise-grade, designed for B2B platform
# tooling. Quieter than Cloudscape, more "sophisticated/boardroom" feel.
# Hex values from Carbon v11 color tokens. Carbon's native severity scheme
# is 3-tier (support-error / support-warning / support-info); the 4-tier
# critical-vs-high split below uses Carbon's red-80 + red-60 pair, which
# is how IBM Cloud's own incident-severity tokens are derived.
CARBON_PALETTE = {
    "observe": "#0f62fe",  # blue-60 (link / info)
    "monitor": "#f1c21b",  # yellow-30 (support-warning)
    "escalate": "#da1e28",  # red-60 (support-error / high)
    "critical": "#750e13",  # red-80 (escalated severity)
    "observe_fill": "#d0e2ff",
    "monitor_fill": "#fcf4d6",
    "escalate_fill": "#ffd7d9",
    "critical_fill": "#e6b9bc",
    "observe_pill_bg": "#edf5ff",
    "observe_pill_border": "#78a9ff",
    "observe_pill_text": "#002d9c",
    "monitor_pill_bg": "#fcf4d6",
    "monitor_pill_border": "#d5b827",
    "monitor_pill_text": "#684e00",
    "escalate_pill_bg": "#fff1f1",
    "escalate_pill_border": "#fa4d56",
    "escalate_pill_text": "#750e13",
    "critical_pill_bg": "#ffd7d9",
    "critical_pill_border": "#a2191f",
    "critical_pill_text": "#520408",
    "bg": "#f4f4f4",  # gray-10
    "surface": "#ffffff",
    "surface_2": "#e0e0e0",  # gray-20
    "text": "#161616",  # gray-100
    "muted": "#525252",  # gray-70
    "muted_2": "#8d8d8d",  # gray-50
    "border": "#c6c6c6",  # gray-30
    "coverage_evaluated_zero": "#8d8d8d",
    "coverage_missing": "#d5b827",
    "delta_down": "#198038",  # green-60
}


# Carbon dark mode — uses Carbon's gray-100 surface and lifted accents.
DARK_CARBON = {
    "observe": "#78a9ff",  # blue-40
    "monitor": "#f1c21b",  # yellow-30 (stays bright)
    "escalate": "#fa4d56",  # red-50
    "critical": "#ff8389",  # red-40 (lighter to differentiate from escalate)
    "observe_fill": "#0043ce",
    "monitor_fill": "#684e00",
    "escalate_fill": "#570408",
    "critical_fill": "#750e13",
    "observe_pill_bg": "#001141",
    "observe_pill_border": "#78a9ff",
    "observe_pill_text": "#d0e2ff",
    "monitor_pill_bg": "#3d2d00",
    "monitor_pill_border": "#f1c21b",
    "monitor_pill_text": "#fcf4d6",
    "escalate_pill_bg": "#520408",
    "escalate_pill_border": "#fa4d56",
    "escalate_pill_text": "#ffd7d9",
    "critical_pill_bg": "#750e13",
    "critical_pill_border": "#ff8389",
    "critical_pill_text": "#ffd7d9",
    "bg": "#161616",  # gray-100
    "surface": "#262626",  # gray-90
    "surface_2": "#393939",  # gray-80
    "text": "#f4f4f4",  # gray-10
    "muted": "#a8a8a8",  # gray-40
    "muted_2": "#6f6f6f",  # gray-60
    "border": "#525252",  # gray-70
    "coverage_evaluated_zero": "#525252",
    "coverage_missing": "#3d2d00",
    "delta_down": "#42be65",  # green-40
}


# Palette registry — selectable by name via the renderer's --palette flag.
# Each entry is a (light, dark) pair. New palettes drop in by adding a
# constant pair above and one line below.
PALETTES = {
    "tableau": (PALETTE, DARK_PALETTE),
    "cloudscape": (CLOUDSCAPE_PALETTE, DARK_CLOUDSCAPE),
    "carbon": (CARBON_PALETTE, DARK_CARBON),
}


# Convenience: just the band-primary hues, by band name
BAND_COLORS = {
    "observe": PALETTE["observe"],
    "monitor": PALETTE["monitor"],
    "escalate": PALETTE["escalate"],
}

# Score thresholds for arc-zone coloring on the gauge.
BAND_THRESHOLDS = {
    "observe": 70,
    "monitor": 40,
    "escalate": 0,
}

DOMAIN_LABELS = {
    "cache_busting": "Cache busting",
    "crawler_governance": "Crawler governance",
    "movement": "Movement",
    "origin_impact": "Origin impact",
    "policy_collateral": "Policy collateral",
    "security_evidence": "Security evidence",
    "none": "No domain triggered",
}

DOMAIN_ORDER = [
    "cache_busting",
    "crawler_governance",
    "movement",
    "origin_impact",
    "policy_collateral",
    "security_evidence",
]


def band_for_score(score: int) -> tuple[str, str]:
    """Return (band, hex_color) for a score under the default thresholds."""
    if score >= BAND_THRESHOLDS["observe"]:
        return "observe", BAND_COLORS["observe"]
    if score >= BAND_THRESHOLDS["monitor"]:
        return "monitor", BAND_COLORS["monitor"]
    return "escalate", BAND_COLORS["escalate"]


# Editorial palette — additive, mirrors the :root tokens in
# templates/_styles.css under .brief-incident. Exposed so Python chart
# helpers (charts.incident_volume_chart_svg) can pull the same colors
# the CSS uses. Light-only in v1; dark editorial is deferred to a
# follow-up plan.
EDITORIAL_PALETTE = {
    # ------------------------------------------------------------------
    # Two-palette split — keep semantic meaning OFF the Hydrolix brand
    # hexes (see :root tokens in _styles_editorial.css for the full
    # rationale).
    #
    # SEMANTIC channel:  severity ramp, hot stats, KPI deltas, critical
    #                    action chips. Hexes deliberately chosen to NOT
    #                    match any value in the Hydrolix extended brand
    #                    palette so a "red pill" never reads as a brand
    #                    accent.
    # BRAND channel:     ``brand_*`` keys below. Used only for
    #                    decoration / distinction (top bars, focus
    #                    rings, CTA accents, Actor-vs-Target axis).
    # NEUTRAL channel:   safe on either side; grayscale doesn't compete
    #                    with hue-coded meaning.
    # ------------------------------------------------------------------
    # Neutrals
    "paper": "#FAFBFC",
    "surface": "#FFFFFF",
    "panel": "#F4F6F8",
    "rule_soft": "#DEE3E6",
    "rule": "#B8C3CB",
    "faint": "#8B9FAD",
    "mute": "#4A5A73",
    "body": "#424D57",
    "ink": "#0A1E2E",
    # Semantic accents — Tableau 10 hues. See _styles_editorial.css
    # for the design rationale; Tableau 10 was chosen because every
    # hex is distinct from the Hydrolix brand palette AND readers
    # already pattern-match the colors as severity / alert signals
    # from FT, Economist, and Tableau Public conventions.
    "red": "#E15759",         # Tableau Red
    "red_ink": "#6B1F22",
    "red_bg": "#FBE5E6",
    "red_text": "#A4373A",
    "orange": "#F28E2B",      # Tableau Orange
    "orange_ink": "#6B3A0E",
    "orange_bg": "#FCEBD5",
    "gold": "#EDC948",        # Tableau Yellow
    "gold_ink": "#66541C",
    "gold_bg": "#FBF5D8",
    "teal": "#4E79A7",        # Tableau Blue (semantic "observe" anchor)
    "burgundy": "#9F2C2D",    # darkened Tableau Red
    "blue": "#4E79A7",        # Tableau Blue
    # 5-tier severity ramp (lines up with deterministic_summary.level)
    "sev_observe": "#4E79A7",   # Tableau Blue
    "sev_monitor": "#EDC948",   # Tableau Yellow
    "sev_elevated": "#F28E2B",  # Tableau Orange
    "sev_high": "#E15759",      # Tableau Red
    "sev_critical": "#9F2C2D",  # darkened Tableau Red
    # Hydrolix brand palette (2026 Brand Guidelines) — decoration /
    # distinction ONLY. Never use a ``brand_*`` value to encode
    # severity, alerts, or any other meaning-bearing axis.
    #
    # WCAG (brand-guidelines p.14): the primary teal #00A99D fails
    # contrast on white (2.93:1) and is non-text-only on light
    # backgrounds. For teal-toned text on paper, use brand_teal_deep
    # (AAA at 7.47:1) or brand_teal_darker (AAA at 10.83:1).
    "brand_teal": "#00A99D",
    "brand_teal_soft": "#6EF6D9",
    "brand_teal_deep": "#035F60",
    "brand_teal_darker": "#024545",
    "brand_navy": "#003D66",
    "brand_navy_deep": "#092747",
    "brand_yellow": "#FFB800",
    "brand_purple": "#5749A1",
    "brand_purple_soft": "#C285FF",
    "brand_cyan": "#00BCE2",
}


def editorial_palette() -> dict[str, str]:
    """Return the editorial light palette tokens.

    Mirrors the CSS :root vars scoped under ``.brief-incident`` so a
    chart drawn in Python and a pill drawn in CSS share the same hex.
    Read-only dict — callers should not mutate.
    """
    return dict(EDITORIAL_PALETTE)
