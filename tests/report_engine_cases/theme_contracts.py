from __future__ import annotations

from tests.report_engine_helpers import *

def test_palette_file_registers_palette_with_extends(tmp_path):
    """``theme.load_palette_file`` registers a palette so subsequent
    ``--palette <name>`` lookups succeed; ``extends`` overlays over a
    base palette so a brand kit only has to spell out the tokens it
    actually overrides."""
    import json

    from report_engine import theme

    palette_file = tmp_path / "brand.json"
    palette_file.write_text(
        json.dumps(
            {
                "name": "brand-test",
                "extends": "tableau",
                "light": {"observe": "#abcdef"},
            }
        )
    )
    try:
        name = theme.load_palette_file(palette_file)
        assert name == "brand-test"
        assert "brand-test" in theme.PALETTES
        light, _dark = theme.PALETTES["brand-test"]
        # Overridden token sticks.
        assert light["observe"] == "#abcdef"
        # Non-overridden tokens fall through to the tableau base.
        assert light["bg"] == theme.PALETTES["tableau"][0]["bg"]
    finally:
        theme.PALETTES.pop("brand-test", None)

def test_palette_file_rejects_unknown_extends(tmp_path):
    import json

    from report_engine import theme

    palette_file = tmp_path / "bad.json"
    palette_file.write_text(
        json.dumps(
            {
                "name": "x",
                "extends": "no-such-palette",
                "light": {"observe": "#000"},
            }
        )
    )
    with pytest.raises(ValueError, match="unknown palette"):
        theme.load_palette_file(palette_file)

def _load_reportkit_theme_module():
    spec = importlib.util.spec_from_file_location(
        "reportkit_theme_contract", REPORTKIT_THEME
    )
    if spec is None or spec.loader is None:
        pytest.fail(f"could not load reportkit theme module from {REPORTKIT_THEME}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def _css_without_comments(path: Path) -> str:
    css = path.read_text(encoding="utf-8")
    return re.sub(r"/\*.*?\*/", "", css, flags=re.S)

def _css_blocks(css: str) -> list[tuple[str, str]]:
    return [
        (selector.strip(), declarations)
        for selector, declarations in re.findall(r"([^{}]+)\{([^{}]*)\}", css)
    ]

def _contrast_ratio(foreground: str, background: str) -> float:
    def channel(value: int) -> float:
        srgb = value / 255
        if srgb <= 0.03928:
            return srgb / 12.92
        return ((srgb + 0.055) / 1.055) ** 2.4

    def luminance(hex_color: str) -> float:
        raw = hex_color.lstrip("#")
        red = channel(int(raw[0:2], 16))
        green = channel(int(raw[2:4], 16))
        blue = channel(int(raw[4:6], 16))
        return 0.2126 * red + 0.7152 * green + 0.0722 * blue

    lighter, darker = sorted(
        (luminance(foreground), luminance(background)), reverse=True
    )
    return (lighter + 0.05) / (darker + 0.05)

def test_reportkit_and_bot_insights_editorial_theme_tokens_stay_in_sync():
    """The standalone reportkit theme and Bot Insights renderer should not
    drift on editorial brand/semantic tokens."""
    from report_engine import theme as bot_theme

    reportkit_theme = _load_reportkit_theme_module()

    assert reportkit_theme.EDITORIAL_PALETTE == bot_theme.EDITORIAL_PALETTE
    assert reportkit_theme.PALETTES == bot_theme.PALETTES

def test_editorial_semantic_tokens_do_not_use_hydrolix_brand_hexes():
    from report_engine import theme

    brand_values = {
        value.lower()
        for key, value in theme.EDITORIAL_PALETTE.items()
        if key.startswith("brand_")
    }
    semantic_keys = {
        "red",
        "red_ink",
        "red_bg",
        "red_text",
        "orange",
        "orange_ink",
        "orange_bg",
        "gold",
        "gold_ink",
        "gold_bg",
        "teal",
        "burgundy",
        "blue",
        "sev_observe",
        "sev_monitor",
        "sev_elevated",
        "sev_high",
        "sev_critical",
    }

    collisions = {
        key: theme.EDITORIAL_PALETTE[key]
        for key in semantic_keys
        if theme.EDITORIAL_PALETTE[key].lower() in brand_values
    }

    assert collisions == {}

def test_default_semantic_palette_tokens_do_not_use_hydrolix_brand_hexes():
    from report_engine import theme

    brand_values = {
        value.lower()
        for key, value in theme.EDITORIAL_PALETTE.items()
        if key.startswith("brand_")
    }
    semantic_keys = {
        "observe",
        "monitor",
        "escalate",
        "critical",
        "observe_fill",
        "monitor_fill",
        "escalate_fill",
        "critical_fill",
        "observe_pill_bg",
        "observe_pill_border",
        "observe_pill_text",
        "monitor_pill_bg",
        "monitor_pill_border",
        "monitor_pill_text",
        "escalate_pill_bg",
        "escalate_pill_border",
        "escalate_pill_text",
        "critical_pill_bg",
        "critical_pill_border",
        "critical_pill_text",
        "coverage_missing",
        "delta_down",
    }

    collisions = {}
    for palette_name, (light, dark) in theme.PALETTES.items():
        for mode, palette in (("light", light), ("dark", dark)):
            for key in semantic_keys:
                if palette[key].lower() in brand_values:
                    collisions[f"{palette_name}.{mode}.{key}"] = palette[key]

    assert collisions == {}


def test_primary_brand_teal_is_not_used_as_text_on_editorial_light_surfaces():
    from report_engine import theme

    css = _css_without_comments(ENGINE_DIR / "templates/_styles_editorial.css")
    text_color_declarations = []
    for selector, declarations in _css_blocks(css):
        if re.search(r"(?<!-)color\s*:\s*var\(--brand-teal(?:-soft)?\)", declarations):
            text_color_declarations.append(selector.strip())

    assert text_color_declarations == []
    assert _contrast_ratio(theme.EDITORIAL_PALETTE["brand_teal"], "#FFFFFF") < 4.5
    assert _contrast_ratio(theme.EDITORIAL_PALETTE["brand_teal_deep"], "#FFFFFF") >= 7
    assert _contrast_ratio(theme.EDITORIAL_PALETTE["brand_teal_darker"], "#FFFFFF") >= 7
