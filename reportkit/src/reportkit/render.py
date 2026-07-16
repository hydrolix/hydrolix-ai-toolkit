"""Generic Jinja report renderer."""

from __future__ import annotations

import html as html_mod
import os
import re
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape
from markupsafe import Markup

from . import charts, formatters, markdown, theme
from .artifacts import (
    ReportRegistry,
    detect_input_kind,
    project_notes_by_slot,
    template_for,
)


FilterMap = Mapping[str, Callable[..., Any]]
GlobalMap = Mapping[str, Any]


def load_asset(asset_dir: Path | None, name: str) -> str:
    """Read and sanitize an embeddable text asset."""

    if asset_dir is None:
        return ""
    path = asset_dir / name
    if not path.exists():
        return ""
    raw = path.read_text()
    svg_idx = raw.find("<svg")
    if svg_idx > 0:
        raw = raw[svg_idx:]
    return raw


def _inline_code(text: object) -> Any:
    value = "" if text is None else str(text)
    if not value:
        return Markup("")
    escaped = html_mod.escape(value)
    return Markup(re.sub(r"`([^`]+)`", r"<code>\1</code>", escaped))


def _chart_globals(chart_module: Any = charts) -> dict[str, Any]:
    names = {
        "score_gauge": "score_gauge_svg",
        "score_bar": "score_bar_svg",
        "coverage_bar": "coverage_bar_svg",
        "band_distribution_bar": "band_distribution_bar_svg",
        "score_histogram": "score_histogram_svg",
        "triage_histogram": "triage_histogram_svg",
        "sparkline": "sparkline_svg",
        "incident_volume_chart": "incident_volume_chart_svg",
        "bullet_chart": "bullet_chart_svg",
        "slopegraph": "slopegraph_svg",
    }
    out: dict[str, Any] = {}
    for global_name, func_name in names.items():
        func = getattr(chart_module, func_name, None)
        if func is not None:
            out[global_name] = lambda *a, _func=func, **kw: Markup(_func(*a, **kw))
    return out


def build_env(
    *,
    template_paths: Sequence[str | Path],
    asset_path: str | Path | None = None,
    output_format: str = "html",
    palette: str = "tableau",
    theme_mode: str = "auto",
    clock: str = "12",
    filters: FilterMap | None = None,
    globals: GlobalMap | None = None,
    palette_registry: Mapping[str, tuple[dict[str, str], dict[str, str]]] | None = None,
    chart_module: Any = charts,
) -> Environment:
    """Build a Jinja2 environment for report rendering."""

    if theme_mode not in ("auto", "light", "dark"):
        raise ValueError(f"Unknown theme {theme_mode!r}. Expected auto, light, or dark.")
    autoescape: bool | Callable[[str | None], bool]
    autoescape = False if output_format == "markdown" else select_autoescape(["html"])
    env = Environment(
        loader=FileSystemLoader([str(Path(path)) for path in template_paths]),
        autoescape=autoescape,
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )

    env.globals.update(_chart_globals(chart_module))
    env.globals["markdown_render"] = markdown.render_safe
    env.globals["clock"] = clock

    registry = palette_registry or theme.PALETTES
    try:
        light_palette, dark_palette = registry[palette]
    except KeyError as exc:
        raise ValueError(
            f"Unknown palette {palette!r}. Available: {sorted(registry)}"
        ) from exc
    env.globals["palette"] = dark_palette if theme_mode == "dark" else light_palette
    env.globals["dark_palette"] = dark_palette
    env.globals["light_palette"] = light_palette
    env.globals["palette_name"] = palette
    env.globals["theme_mode"] = theme_mode
    env.globals["emit_dark_media"] = theme_mode == "auto"

    assets = Path(asset_path) if asset_path is not None else None
    env.globals["hydrolix_logotype_svg"] = Markup(load_asset(assets, "hydrolix_logotype.svg"))

    env.filters.update(
        {
            "inline_code": _inline_code,
            "window_fmt": formatters.window_fmt,
            "headline_window_fmt": formatters.headline_window_fmt,
            "big_number": formatters.big_number,
            "signed_pct": formatters.signed_pct,
            "signed_pp": formatters.signed_pp,
            "pct2": formatters.pct2,
            "normalize_percents": formatters.normalize_percents,
            "md_escape": markdown.md_escape,
        }
    )
    if filters:
        env.filters.update(filters)
    if globals:
        env.globals.update(globals)
    return env


class ReportRenderer:
    """Render raw report artifacts or wrapper payloads."""

    def __init__(
        self,
        *,
        registry: ReportRegistry,
        template_paths: Sequence[str | Path],
        asset_path: str | Path | None = None,
        filters: FilterMap | None = None,
        globals: GlobalMap | None = None,
        palette_registry: Mapping[str, tuple[dict[str, str], dict[str, str]]] | None = None,
        chart_module: Any = charts,
        wrapper_schema: str = "report_input.v1",
        finding_override_applier: Callable[[Any, str | None], Any] | None = None,
        singleton_promoter: Callable[[Any, dict[str, Any], ReportRegistry], tuple[Any, dict[str, Any]] | None] | None = None,
        system_template_env_var: str | None = None,
    ) -> None:
        self.registry = registry
        self.template_paths = [Path(path) for path in template_paths]
        if system_template_env_var:
            extra = os.environ.get(system_template_env_var, "").strip()
            for entry in reversed([p.strip() for p in extra.split(":") if p.strip()]):
                self.template_paths.insert(0, Path(entry).expanduser())
        self.asset_path = Path(asset_path) if asset_path is not None else None
        self.filters = filters
        self.globals = globals
        self.palette_registry = palette_registry
        self.chart_module = chart_module
        self.wrapper_schema = wrapper_schema
        self.finding_override_applier = finding_override_applier
        self.singleton_promoter = singleton_promoter

    def resolve(
        self,
        data: dict[str, Any],
        *,
        schema_override: str | None = None,
        input_kind: str = "auto",
    ) -> tuple[Any, dict[str, Any], dict[str, dict[str, Any]]]:
        kind = detect_input_kind(data, input_kind, wrapper_schema=self.wrapper_schema)
        if kind == "wrapper":
            module = self.registry.by_report_type(data.get("report_type"))
            artifact = module.assemble(data["artifacts"])
            if self.singleton_promoter is not None:
                promoted = self.singleton_promoter(module, artifact, self.registry)
                if promoted is not None:
                    module, artifact = promoted
            notes_by_slot = project_notes_by_slot(
                data.get("analyst_notes", []),
                getattr(module, "NOTE_ID_TO_SLOT", {}),
            )
            return module, artifact, notes_by_slot

        schema = schema_override or data.get("schema_version")
        module = self.registry.by_schema(schema)
        return module, data, {}

    def prepare_context(
        self,
        module: Any,
        artifact: dict[str, Any],
        notes_by_slot: dict[str, dict[str, Any]],
        *,
        mode: str = "full",
        profile: str = "screen",
    ) -> dict[str, Any]:
        ctx = module.prepare(artifact)
        ctx["notes_by_slot"] = notes_by_slot
        ctx["mode"] = mode
        ctx["profile"] = profile
        ctx["report_type"] = module.REPORT_TYPE
        if hasattr(module, "post_prepare"):
            module.post_prepare(ctx)
        overrides_note = notes_by_slot.get("finding_overrides")
        if (
            self.finding_override_applier is not None
            and overrides_note
            and "findings" in ctx
        ):
            ctx["findings"] = self.finding_override_applier(
                ctx["findings"],
                overrides_note.get("text"),
            )
        return ctx

    def render_payload(
        self,
        data: dict[str, Any],
        *,
        schema_override: str | None = None,
        input_kind: str = "auto",
        mode: str = "full",
        output_format: str = "html",
        palette: str = "tableau",
        theme_mode: str = "auto",
        clock: str = "12",
        profile: str = "screen",
    ) -> str:
        module, artifact, notes_by_slot = self.resolve(
            data,
            schema_override=schema_override,
            input_kind=input_kind,
        )
        ctx = self.prepare_context(
            module,
            artifact,
            notes_by_slot,
            mode=mode,
            profile=profile,
        )
        env = build_env(
            template_paths=self.template_paths,
            asset_path=self.asset_path,
            output_format=output_format,
            palette=palette,
            theme_mode=theme_mode,
            clock=clock,
            filters=self.filters,
            globals=self.globals,
            palette_registry=self.palette_registry,
            chart_module=self.chart_module,
        )
        template_name = template_for(module, output_format)
        if output_format == "html" and profile == "print":
            template_name = getattr(module, "PRINT_TEMPLATE", template_name)
        return env.get_template(template_name).render(**ctx)
