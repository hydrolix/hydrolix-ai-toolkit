#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "jinja2>=3.1",
#   "markdown-it-py>=3.0",
#   "bleach>=6.1",
# ]
# ///
"""Render a Bot Insights artifact or wrapper to self-contained HTML.

Accepts either a raw artifact (e.g. `bot_scorecard_artifacts.v1`) or a
`bot_report_input.v1` wrapper. Wrappers may carry `analyst_notes[]` whose
`note_id` values route into named narrative slots; deterministic content
fills the slots when notes are absent.

Usage:
  uv run report_engine/render.py --artifact path/to/artifact.json --out report.html
  uv run report_engine/render.py --artifact path/to/wrapper.json --out report.html
  uv run report_engine/render.py --input wrapper --artifact ... --out ...
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape
from markupsafe import Markup

# Allow running as a script *or* as a module
if __package__ is None or __package__ == "":
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from report_engine import charts, findings as findings_mod, formatters
    from report_engine import humanize as humanize_mod
    from report_engine import markdown as md_mod
    from report_engine import theme
    from report_engine.contexts import REPORT_TYPE_REGISTRY, SCHEMA_REGISTRY
else:
    from . import charts, findings as findings_mod, formatters
    from . import humanize as humanize_mod
    from . import markdown as md_mod
    from . import theme
    from .contexts import REPORT_TYPE_REGISTRY, SCHEMA_REGISTRY


TEMPLATES_DIR = Path(__file__).parent / "templates"
ASSETS_DIR = TEMPLATES_DIR / "assets"

WRAPPER_SCHEMA = "bot_report_input.v1"


def _load_asset(name: str) -> str:
    """Read a templates/assets/<name> file as text.

    Brand SVGs live under ``templates/assets/`` and are inlined into
    the rendered HTML at build time so the report stays a single
    self-contained file. The XML declaration (``<?xml ... ?>``) and
    any Adobe Illustrator generator comments at the top are stripped
    — they're only valid at the start of an XML document and would
    render as literal text noise when embedded in HTML. Falls back
    to empty string when the asset is missing rather than raising —
    render must not hard-fail when a decorative logo isn't on disk.
    """
    path = ASSETS_DIR / name
    if not path.exists():
        return ""
    raw = path.read_text()
    # Strip XML prolog and editor-generator comments before the first
    # ``<svg``. Anything outside the root SVG element is safe to drop.
    svg_idx = raw.find("<svg")
    if svg_idx > 0:
        raw = raw[svg_idx:]
    return raw


def build_env(
    output_format: str = "html",
    palette: str = "tableau",
    theme_mode: str = "auto",
    clock: str = "12",
) -> Environment:
    """Build a Jinja2 environment for ``output_format`` rendering.

    HTML mode keeps the default autoescape policy (escape ``<``, ``>``,
    ``&``, etc. in interpolated values so producer-supplied text can't
    inject markup). Markdown mode disables autoescape — escaping
    HTML entities into a Markdown source document would render as
    literal ``&amp;`` in the final reading. Markdown templates are
    expected to apply the ``md_escape`` filter at every
    user/producer-controlled interpolation site instead.

    ``palette`` selects one of the registered palettes in
    :data:`theme.PALETTES`. The token names (observe / monitor /
    escalate / critical, plus the pill triplets and chrome) stay the
    same; only the hex values differ. Default ``tableau`` matches
    the historic palette.

    ``theme_mode`` controls light/dark behavior:
      - ``"auto"`` (default) — ship both palettes; the viewer's
        ``prefers-color-scheme`` picks at render time.
      - ``"light"`` — ship the light palette only; the rendered HTML
        stays light regardless of the viewer's OS theme. Use for
        projector demos where you can't rely on the meeting machine
        being in light mode.
      - ``"dark"`` — ship the dark palette inline; the rendered HTML
        stays dark regardless of viewer.
    The print stylesheet always pins light, regardless of ``theme_mode``,
    so a PDF produced from any of the three reads identically.
    """
    if theme_mode not in ("auto", "light", "dark"):
        raise SystemExit(
            f"Unknown theme {theme_mode!r}. Expected one of: auto, light, dark."
        )
    if output_format == "markdown":
        autoescape = False  # md_escape filter is the escaping boundary
    else:
        autoescape = select_autoescape(["html"])
    # Resolve the Jinja2 search path. Out-of-tree template overrides
    # may be prepended via the ``BOT_INSIGHTS_TEMPLATES_PATH`` env var
    # (colon-separated list); the first match wins, so a brand kit can
    # shadow a built-in template by exposing the same relative name.
    template_dirs: list[str] = []
    oot_templates = os.environ.get("BOT_INSIGHTS_TEMPLATES_PATH", "").strip()
    if oot_templates:
        for entry in oot_templates.split(":"):
            entry = entry.strip()
            if entry:
                template_dirs.append(str(Path(entry).expanduser()))
    template_dirs.append(str(TEMPLATES_DIR))
    env = Environment(
        loader=FileSystemLoader(template_dirs),
        autoescape=autoescape,
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    # Charts return raw SVG — wrap in Markup so autoescape leaves them alone.
    env.globals["score_gauge"] = lambda *a, **kw: Markup(
        charts.score_gauge_svg(*a, **kw)
    )
    env.globals["score_bar"] = lambda *a, **kw: Markup(charts.score_bar_svg(*a, **kw))
    env.globals["coverage_bar"] = lambda *a, **kw: Markup(
        charts.coverage_bar_svg(*a, **kw)
    )
    env.globals["band_distribution_bar"] = lambda *a, **kw: Markup(
        charts.band_distribution_bar_svg(*a, **kw)
    )
    env.globals["score_histogram"] = lambda *a, **kw: Markup(
        charts.score_histogram_svg(*a, **kw)
    )
    env.globals["triage_histogram"] = lambda *a, **kw: Markup(
        charts.triage_histogram_svg(*a, **kw)
    )
    env.globals["sparkline"] = lambda *a, **kw: Markup(charts.sparkline_svg(*a, **kw))
    env.globals["incident_volume_chart"] = lambda *a, **kw: Markup(
        charts.incident_volume_chart_svg(*a, **kw)
    )
    env.globals["bullet_chart"] = lambda *a, **kw: Markup(
        charts.bullet_chart_svg(*a, **kw)
    )
    env.globals["slopegraph"] = lambda *a, **kw: Markup(charts.slopegraph_svg(*a, **kw))
    # Hydrolix brand logotype — inlined SVG, light-background variant.
    # Marked safe so autoescape leaves the markup intact. Decorative
    # use only; the wordmark replaces the editorial "The Incident
    # Brief" placeholder in the masthead.
    env.globals["hydrolix_logotype_svg"] = Markup(
        _load_asset("hydrolix_logotype.svg")
    )
    try:
        light_palette, dark_palette = theme.PALETTES[palette]
    except KeyError as exc:
        raise SystemExit(
            f"Unknown palette {palette!r}. Available: {sorted(theme.PALETTES)}"
        ) from exc
    # ``palette`` is whatever goes into the unconditional :root rule —
    # the light pair for auto/light modes, the dark pair when forced
    # dark. ``dark_palette`` is what fills the @media override block;
    # ``emit_dark_media`` controls whether that block is emitted at all.
    if theme_mode == "dark":
        env.globals["palette"] = dark_palette
    else:
        env.globals["palette"] = light_palette
    env.globals["dark_palette"] = dark_palette
    env.globals["light_palette"] = light_palette
    env.globals["palette_name"] = palette
    env.globals["theme_mode"] = theme_mode
    env.globals["emit_dark_media"] = theme_mode == "auto"
    # Clock-format preference; consumed by the headline_window_fmt
    # filter so the H1 parenthetical matches the operator's locale
    # convention. Defaults to 12-hour at the CLI layer.
    env.globals["clock"] = clock
    # Markdown → safe HTML for analyst_notes prose
    env.globals["markdown_render"] = md_mod.render_safe

    # Inline-code filter: convert ``backtick spans`` inside short
    # producer-authored strings (e.g. a recommended-action ``step``
    # field carrying an IP or path identifier) into proper ``<code>``
    # HTML so they don't render as literal backticks. Lighter-weight
    # than ``markdown_render`` — no block wrapper, no bleach pass,
    # safe to apply per-cell inside list/table templates.
    import html as _html_mod
    import re as _re_mod

    def _inline_code(text: object) -> Any:
        s = "" if text is None else str(text)
        if not s:
            return Markup("")
        escaped = _html_mod.escape(s)
        return Markup(_re_mod.sub(r"`([^`]+)`", r"<code>\1</code>", escaped))

    env.filters["inline_code"] = _inline_code

    # Formatters as filters
    env.filters["window_fmt"] = formatters.window_fmt
    env.filters["headline_window_fmt"] = formatters.headline_window_fmt
    env.filters["big_number"] = formatters.big_number
    env.filters["signed_pct"] = formatters.signed_pct
    env.filters["signed_pp"] = formatters.signed_pp
    env.filters["pct2"] = formatters.pct2
    env.filters["normalize_percents"] = formatters.normalize_percents
    # Humanization filters — apply to any snake_case identifier surfaced as a label.
    env.filters["humanize_band"] = humanize_mod.humanize_band
    env.filters["humanize_confidence"] = humanize_mod.humanize_confidence
    env.filters["humanize_author"] = humanize_mod.humanize_author_type
    env.filters["humanize_reason"] = humanize_mod.humanize_confidence_reason
    env.filters["humanize_comparison"] = humanize_mod.humanize_comparison_type
    env.filters["humanize_constraint"] = humanize_mod.humanize_constraint
    env.filters["humanize_status"] = humanize_mod.humanize_status
    env.filters["humanize"] = humanize_mod.humanize_identifier
    env.filters["attack_url"] = humanize_mod.attack_url
    env.filters["humanize_entity_type"] = humanize_mod.humanize_entity_type
    env.filters["humanize_entity_type_plural"] = (
        humanize_mod.humanize_entity_type_plural
    )
    env.filters["title_case_label"] = humanize_mod.title_case_label
    env.filters["cluster_display"] = humanize_mod.cluster_display
    # md_escape escapes Markdown-syntactic characters in producer-supplied
    # strings. Available in both HTML and Markdown envs (HTML templates
    # never need it, but registering it keeps the filter set consistent
    # so an accidental .md.j2 → .html template move doesn't break).
    env.filters["md_escape"] = md_mod.md_escape
    return env


def _build_notes_by_slot(
    notes: list[dict], note_id_to_slot: dict[str, str]
) -> dict[str, dict]:
    """Project wrapper analyst_notes into a slot-keyed dict via note_id."""
    out: dict[str, dict] = {}
    for note in notes or []:
        slot = note_id_to_slot.get(note.get("note_id", ""))
        if slot:
            # First-write wins; later notes with the same slot are ignored.
            out.setdefault(slot, note)
    return out


def _detect_input_kind(data: dict, override: str) -> str:
    if override != "auto":
        return override
    if data.get("schema_version") == WRAPPER_SCHEMA:
        return "wrapper"
    return "artifact"


def _maybe_promote_singleton(module, artifact: dict):
    """Promote a singleton scorecard_brief bundle to scorecard_entity_review.

    Returns (new_module, new_artifact) or None if no promotion applies.
    """
    if module.REPORT_TYPE != "scorecard_brief":
        return None
    if len(artifact.get("scorecards") or []) != 1:
        return None
    target = REPORT_TYPE_REGISTRY.get("scorecard_entity_review")
    if target is None:
        return None
    return target, target.assemble(artifact)


def _resolve_module_from_wrapper(data: dict):
    report_type = data.get("report_type")
    if report_type not in REPORT_TYPE_REGISTRY:
        raise SystemExit(
            f"No context preparer for report_type {report_type!r}. "
            f"Known: {sorted(REPORT_TYPE_REGISTRY)}"
        )
    return REPORT_TYPE_REGISTRY[report_type]


def _resolve_module_from_artifact(data: dict, schema_override: str | None):
    schema = schema_override or data.get("schema_version")
    if schema not in SCHEMA_REGISTRY:
        raise SystemExit(
            f"No context preparer for schema {schema!r}. "
            f"Known: {sorted(SCHEMA_REGISTRY)}"
        )
    return SCHEMA_REGISTRY[schema]


def template_for(module, output_format: str) -> str:
    """Pick the template path for ``module`` in ``output_format``.

    Each context module exposes ``TEMPLATE`` pointing at the HTML
    template (e.g. ``reports/executive_posture.html``). The Markdown
    sibling lives next to it with the ``.md.j2`` suffix. M3.1 selects
    by filename suffix per plan v3 (no separate registry needed).
    """
    if output_format == "markdown":
        # Replace the .html suffix with .md.j2. The TEMPLATE constant
        # always ends in .html across the existing context modules.
        if not module.TEMPLATE.endswith(".html"):
            raise ValueError(
                f"{module.REPORT_TYPE} TEMPLATE {module.TEMPLATE!r} does not "
                "end in .html; cannot derive a .md.j2 sibling."
            )
        return module.TEMPLATE[: -len(".html")] + ".md.j2"
    return module.TEMPLATE


def render(
    artifact_path: Path,
    out_path: Path,
    schema_override: str | None = None,
    input_kind: str = "auto",
    mode: str = "full",
    output_format: str = "html",
    palette: str = "tableau",
    theme_mode: str = "auto",
    clock: str = "12",
) -> None:
    """Render an artifact or wrapper to ``output_format``.

    ``output_format`` is ``"html"`` (default) or ``"markdown"``.
    Markdown mode renders the sibling ``.md.j2`` template via a
    Markdown-flavored Jinja2 env (autoescape off; ``md_escape``
    filter on). The context the templates consume is format-agnostic
    — ``module.prepare()`` is called once and the same dict feeds
    either renderer.
    """
    data = json.loads(artifact_path.read_text())
    kind = _detect_input_kind(data, input_kind)

    if kind == "wrapper":
        module = _resolve_module_from_wrapper(data)
        artifact = module.assemble(data["artifacts"])
        # Auto-promote a singleton scorecard_brief wrapper to the entity-review
        # report type so the renderer surfaces per-host evidence rather than
        # fleet aggregates collapsed to N=1. Producers don't need to know
        # about the new report_type.
        promoted = _maybe_promote_singleton(module, artifact)
        if promoted is not None:
            module, artifact = promoted
        notes_by_slot = _build_notes_by_slot(
            data.get("analyst_notes", []),
            getattr(module, "NOTE_ID_TO_SLOT", {}),
        )
    else:
        module = _resolve_module_from_artifact(data, schema_override)
        artifact = data
        notes_by_slot = {}

    ctx = module.prepare(artifact)
    ctx["notes_by_slot"] = notes_by_slot
    if hasattr(module, "post_prepare"):
        module.post_prepare(ctx)
    ctx["mode"] = mode
    # ``report_type`` lets shared templates (e.g. ``base.html``) include
    # report-type-specific stylesheet partials without leaking those
    # rules into other reports. Set here so every render carries it,
    # regardless of which context module produced the artifact.
    ctx["report_type"] = module.REPORT_TYPE

    # Apply per-finding LLM overrides if the wrapper carried any.
    overrides_note = notes_by_slot.get("finding_overrides")
    if overrides_note and "findings" in ctx:
        ctx["findings"] = findings_mod.apply_finding_overrides(
            ctx["findings"],
            overrides_note.get("text"),
        )

    env = build_env(
        output_format=output_format,
        palette=palette,
        theme_mode=theme_mode,
        clock=clock,
    )
    template_path = template_for(module, output_format)
    template = env.get_template(template_path)
    out_path.write_text(template.render(**ctx))
    print(f"wrote {out_path}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--artifact",
        type=Path,
        required=True,
        help="Path to the artifact or wrapper JSON.",
    )
    ap.add_argument(
        "--out", type=Path, required=True, help="Path to write the HTML output."
    )
    ap.add_argument(
        "--schema",
        default=None,
        help="Override schema_version detection (raw artifact only).",
    )
    ap.add_argument(
        "--input",
        choices=["auto", "wrapper", "artifact"],
        default="auto",
        help="Force input shape; default auto-detects via schema_version.",
    )
    ap.add_argument(
        "--mode",
        choices=["brief", "full"],
        default="full",
        help="brief = exec one-pager; full = analyst exhibit (default).",
    )
    ap.add_argument(
        "--format",
        choices=["html", "markdown"],
        default="html",
        help="Output format. Markdown renders the sibling .md.j2 template.",
    )
    ap.add_argument(
        "--palette",
        default="tableau",
        help=(
            "Visual palette. tableau (default) is the historic Tableau-10 "
            "BI palette; cloudscape is AWS Cloudscape's incident-console "
            "palette; carbon is IBM Carbon's enterprise palette. Custom "
            "palettes loaded via --palette-file become selectable here by "
            "their registered name. Each ships light + dark variants."
        ),
    )
    ap.add_argument(
        "--palette-file",
        type=Path,
        default=None,
        help=(
            "Path to a JSON palette descriptor "
            "(``{\"name\": ..., \"light\": {...}, \"dark\": {...}}``). The "
            "file's declared name is registered in the palette registry "
            "before ``--palette`` is resolved, so out-of-tree brand kits "
            "can be referenced by name without editing the report engine."
        ),
    )
    ap.add_argument(
        "--theme",
        choices=["auto", "light", "dark"],
        default="auto",
        help=(
            "Theme mode. auto (default) ships both palettes and lets the "
            "viewer's prefers-color-scheme pick. light forces the light "
            "palette regardless of OS theme — use for projector demos. "
            "dark forces the dark palette. Print stylesheet always pins "
            "light regardless of theme."
        ),
    )
    ap.add_argument(
        "--clock",
        choices=["12", "24"],
        default="12",
        help=(
            "Clock format for the headline incident window. 12 "
            "(default) renders \"3:00–4:00 PM UTC\"; 24 renders "
            "\"15:00–16:00 UTC\". UTC labelling is fixed because the "
            "underlying timestamps are stored in UTC."
        ),
    )
    ap.add_argument(
        "--config",
        type=Path,
        default=None,
        help=(
            "Path to a threshold-override file (YAML/TOML/JSON). Loaded "
            "into the active-thresholds singleton before render runs so "
            "display caps (suspicious_targets_cap, exec_actions_cap, "
            "exec_impact_tiles_cap) and risk-score bands honor the "
            "override. See skills/bot-insights/config/defaults.yaml for "
            "the full tunable surface."
        ),
    )
    args = ap.parse_args()
    if args.config is not None:
        import sys as _sys
        _SCRIPTS_DIR = Path(__file__).resolve().parents[1]
        if str(_SCRIPTS_DIR) not in _sys.path:
            _sys.path.insert(0, str(_SCRIPTS_DIR))
        from config import load_thresholds, set_active_thresholds

        set_active_thresholds(load_thresholds(args.config))
    if args.palette_file is not None:
        theme.load_palette_file(args.palette_file)
    if args.palette not in theme.PALETTES:
        raise SystemExit(
            f"Unknown palette {args.palette!r}. Available: "
            f"{sorted(theme.PALETTES)}"
        )
    render(
        args.artifact,
        args.out,
        args.schema,
        args.input,
        args.mode,
        args.format,
        args.palette,
        args.theme,
        args.clock,
    )


if __name__ == "__main__":
    main()
