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

_REPORTKIT_SRC = Path(__file__).resolve().parents[4] / "reportkit" / "src"
if str(_REPORTKIT_SRC) not in sys.path:
    sys.path.insert(0, str(_REPORTKIT_SRC))

from jinja2 import Environment

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

from reportkit.artifacts import (
    ReportRegistry,
    detect_input_kind,
    project_notes_by_slot,
    template_for as _reportkit_template_for,
)
from reportkit.render import ReportRenderer, build_env as _reportkit_build_env


TEMPLATES_DIR = Path(__file__).parent / "templates"
ASSETS_DIR = TEMPLATES_DIR / "assets"

WRAPPER_SCHEMA = "bot_report_input.v1"


def _bot_filters() -> dict:
    return {
        "humanize_band": humanize_mod.humanize_band,
        "humanize_confidence": humanize_mod.humanize_confidence,
        "humanize_author": humanize_mod.humanize_author_type,
        "humanize_reason": humanize_mod.humanize_confidence_reason,
        "humanize_comparison": humanize_mod.humanize_comparison_type,
        "humanize_constraint": humanize_mod.humanize_constraint,
        "humanize_status": humanize_mod.humanize_status,
        "humanize": humanize_mod.humanize_identifier,
        "attack_url": humanize_mod.attack_url,
        "humanize_entity_type": humanize_mod.humanize_entity_type,
        "humanize_entity_type_plural": humanize_mod.humanize_entity_type_plural,
        "title_case_label": humanize_mod.title_case_label,
        "cluster_display": humanize_mod.cluster_display,
    }


def build_env(
    output_format: str = "html",
    palette: str = "tableau",
    theme_mode: str = "auto",
    clock: str = "12",
) -> Environment:
    """Build the Bot Insights Jinja2 environment."""
    template_dirs: list[str] = []
    oot_templates = os.environ.get("BOT_INSIGHTS_TEMPLATES_PATH", "").strip()
    if oot_templates:
        for entry in oot_templates.split(":"):
            entry = entry.strip()
            if entry:
                template_dirs.append(str(Path(entry).expanduser()))
    template_dirs.append(str(TEMPLATES_DIR))
    try:
        return _reportkit_build_env(
            template_paths=template_dirs,
            asset_path=ASSETS_DIR,
            output_format=output_format,
            palette=palette,
            theme_mode=theme_mode,
            clock=clock,
            filters=_bot_filters(),
            palette_registry=theme.PALETTES,
            chart_module=charts,
        )
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc


def _build_notes_by_slot(
    notes: list[dict], note_id_to_slot: dict[str, str]
) -> dict[str, dict]:
    """Project wrapper analyst_notes into a slot-keyed dict via note_id."""
    return project_notes_by_slot(notes, note_id_to_slot)


def _detect_input_kind(data: dict, override: str) -> str:
    return detect_input_kind(data, override, wrapper_schema=WRAPPER_SCHEMA)


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
    return _reportkit_template_for(module, output_format)


def _registry() -> ReportRegistry:
    return ReportRegistry(
        modules=list(REPORT_TYPE_REGISTRY.values()),
        schema_exclusions={
            report_type
            for report_type, module in REPORT_TYPE_REGISTRY.items()
            if SCHEMA_REGISTRY.get(module.SCHEMA) is not module
        },
    )


def _promote_singleton_for_reportkit(module, artifact: dict, registry: ReportRegistry):
    if module.REPORT_TYPE != "scorecard_brief":
        return None
    if len(artifact.get("scorecards") or []) != 1:
        return None
    target = registry.report_type_registry.get("scorecard_entity_review")
    if target is None:
        return None
    return target, target.assemble(artifact)


def _renderer() -> ReportRenderer:
    template_dirs: list[str] = []
    oot_templates = os.environ.get("BOT_INSIGHTS_TEMPLATES_PATH", "").strip()
    if oot_templates:
        for entry in oot_templates.split(":"):
            entry = entry.strip()
            if entry:
                template_dirs.append(str(Path(entry).expanduser()))
    template_dirs.append(str(TEMPLATES_DIR))
    return ReportRenderer(
        registry=_registry(),
        template_paths=template_dirs,
        asset_path=ASSETS_DIR,
        filters=_bot_filters(),
        palette_registry=theme.PALETTES,
        chart_module=charts,
        wrapper_schema=WRAPPER_SCHEMA,
        finding_override_applier=findings_mod.apply_finding_overrides,
        singleton_promoter=_promote_singleton_for_reportkit,
    )


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
    try:
        rendered = _renderer().render_payload(
            data,
            schema_override=schema_override,
            input_kind=input_kind,
            mode=mode,
            output_format=output_format,
            palette=palette,
            theme_mode=theme_mode,
            clock=clock,
        )
    except KeyError as exc:
        raise SystemExit(str(exc)) from exc
    out_path.write_text(rendered)
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
