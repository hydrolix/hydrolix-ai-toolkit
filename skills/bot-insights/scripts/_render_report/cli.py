"""CLI entry: parse_args / read_input / render / main."""

from __future__ import annotations

import argparse
import copy
import importlib.util
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any

from .constants import REPORT_TYPES
from .engine_bridge import _render_via_engine
from .errors import (
    ReportContext,
    ReportError,
)
from .legacy_html import render_html
from .legacy_markdown import (
    render_markdown,
    validate_analyst_notes,
)
from .validators import (
    dedupe_artifact_bodies,
    load_report_input,
    resolve_options,
    scan_metadata_warnings,
    validate_report_artifacts,
)

_REPORTKIT_SRC = Path(__file__).resolve().parents[4] / "reportkit" / "src"
if str(_REPORTKIT_SRC) not in sys.path:
    sys.path.insert(0, str(_REPORTKIT_SRC))

__all__ = [
    'parse_args',
    'read_input',
    'render',
    'main',
]

BOOTSTRAP_ENV = "BOT_INSIGHTS_RENDER_DEPS_BOOTSTRAPPED"
BASE_RENDER_DEPS = (
    ("jinja2", "jinja2"),
    ("markdown-it-py", "markdown_it"),
    ("bleach", "bleach"),
)
PDF_RENDER_DEPS = (("playwright", "playwright"),)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Render Bot Insights artifacts as Markdown or self-contained HTML."
    )
    parser.add_argument(
        "text",
        nargs="*",
        help="Artifact JSON. If omitted, stdin is read.",
    )
    parser.add_argument(
        "-f",
        "--file",
        type=Path,
        help="Read artifact JSON from a file instead of positional arguments/stdin.",
    )
    parser.add_argument(
        "--format",
        choices=("markdown", "html", "pdf"),
        default="markdown",
        help="Output format. PDF renders print-profile HTML through optional Playwright.",
    )
    parser.add_argument(
        "--profile",
        choices=("screen", "print"),
        default="screen",
        help="Rendering profile. PDF implies print.",
    )
    parser.add_argument(
        "--analysis-mode",
        choices=("llm", "deterministic", "both"),
        default="llm",
        help=(
            "Render LLM-inclusive notes, deterministic evidence-only output, "
            "or both as sibling files."
        ),
    )
    parser.add_argument(
        "--report-type",
        choices=sorted(REPORT_TYPES),
        help="Report type to render.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Write the report to this path instead of stdout.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        help="Display row/card limit. Does not affect artifact validation.",
    )
    parser.add_argument(
        "--allow-unknown",
        action="store_true",
        help="Skip unknown artifact schemas instead of failing.",
    )
    parser.add_argument(
        "--title",
        help="Presentation title override.",
    )
    parser.add_argument(
        "--palette",
        choices=("tableau", "cloudscape", "carbon"),
        default="tableau",
        help=(
            "Visual palette. tableau (default) is the Tableau-10 BI "
            "palette; cloudscape is AWS Cloudscape's command-center "
            "palette; carbon is IBM Carbon's enterprise palette. Each "
            "ships matched light + dark variants — the browser picks "
            "based on prefers-color-scheme by default; see --theme to "
            "force one."
        ),
    )
    parser.add_argument(
        "--theme",
        choices=("auto", "light", "dark"),
        default="auto",
        help=(
            "Theme mode. auto (default) emits both palettes and lets the "
            "viewer's prefers-color-scheme pick. light forces the light "
            "palette — use when projecting in a meeting room where the "
            "presenter machine may be in dark mode but you want a "
            "light-rendered report. dark forces dark. Print stylesheet "
            "always pins light regardless of --theme."
        ),
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help=(
            "Path to a threshold/enrichment override file (YAML/TOML/JSON). "
            "Loaded into the active config singleton before render runs."
        ),
    )
    return parser.parse_args()


def read_input(args: argparse.Namespace) -> str:
    if args.file:
        return args.file.read_text(encoding="utf-8")
    if args.text:
        return " ".join(args.text)
    return sys.stdin.read()


def _render_deps_for_format(output_format: str) -> tuple[tuple[str, str], ...]:
    deps = BASE_RENDER_DEPS
    if output_format == "pdf":
        deps += PDF_RENDER_DEPS
    return deps


def _missing_render_deps(output_format: str) -> list[str]:
    missing: list[str] = []
    for package_name, module_name in _render_deps_for_format(output_format):
        if importlib.util.find_spec(module_name) is None:
            missing.append(package_name)
    return missing


def _render_dep_packages_for_format(output_format: str) -> list[str]:
    return [package_name for package_name, _ in _render_deps_for_format(output_format)]


def _bootstrap_render_deps(args: argparse.Namespace) -> None:
    missing = _missing_render_deps(args.format)
    if not missing:
        return
    if os.environ.get(BOOTSTRAP_ENV):
        return
    if shutil.which("uv") is None:
        return

    os.environ[BOOTSTRAP_ENV] = "1"
    script_path = Path(__file__).resolve().parents[1] / "render_report.py"
    cmd = ["uv", "run"]
    for dep in _render_dep_packages_for_format(args.format):
        cmd.extend(["--with", dep])
    cmd.extend(["python", str(script_path), *sys.argv[1:]])
    os.execvp("uv", cmd)


def render(
    value: Any,
    args: argparse.Namespace,
) -> tuple[str, list[str]]:
    ctx = ReportContext()
    (
        artifacts,
        notes,
        wrapper_report_type,
        wrapper_title,
        wrapper_limit,
        scope_label,
        raw_mode,
    ) = load_report_input(value, args, ctx)
    report_type, title, limit, resolved_scope_label = resolve_options(
        artifacts,
        wrapper_report_type=wrapper_report_type,
        wrapper_title=wrapper_title,
        wrapper_limit=wrapper_limit,
        scope_label=scope_label,
        raw_mode=raw_mode,
        args=args,
        ctx=ctx,
    )
    artifacts = dedupe_artifact_bodies(artifacts, notes, report_type, ctx)
    selected = validate_report_artifacts(report_type, artifacts, ctx)
    scan_metadata_warnings(artifacts, ctx)
    validate_analyst_notes(notes, artifacts)
    # Wrapper inputs route through the report_engine by default. The
    # legacy renderer for wrappers stays reachable via the
    # ``BOT_INSIGHTS_RENDER_PATH=legacy`` test override; M4.5 retired
    # the parity gates that previously consumed the override but the
    # mechanism survives as test infrastructure for the wrapper-mode
    # legacy regression tests in ``tests/test_skill_scripts.py``
    # (``BotInsightsScriptTests``). Removing the override would
    # require rewriting ~28 tests against engine output, deferred to
    # a follow-up PR (see plan.md M4.5 trailer). Plan v3 M4.1
    # confirmed Path B (raw-mode preserved) which the
    # raw-artifact short-circuit at the top of ``_render_via_engine``
    # also depends on.
    render_path = os.environ.get("BOT_INSIGHTS_RENDER_PATH", "auto").lower()
    output_format = "html" if args.format == "pdf" else args.format
    profile = "print" if args.format == "pdf" else getattr(args, "profile", "screen")
    theme_mode = getattr(args, "theme", "auto")
    if profile == "print" and theme_mode == "auto":
        theme_mode = "light"

    if render_path != "legacy":
        engine_output = _render_via_engine(
            report_type=report_type,
            value=value,
            artifacts=artifacts,
            notes=notes,
            ctx=ctx,
            output_format=output_format,
            palette=getattr(args, "palette", "tableau"),
            theme_mode=theme_mode,
            profile=profile,
        )
        if engine_output is not None:
            return engine_output, ctx.warnings
        # ``None`` here means the raw-artifact short-circuit fired:
        # the input is not a ``bot_report_input.v1`` wrapper. M3.3
        # tightened the engine bridge so wrapper inputs always
        # either return a rendered string or raise ``ReportError``.
        if render_path == "engine":
            raise ReportError(
                f"BOT_INSIGHTS_RENDER_PATH=engine but engine returned "
                f"None for report_type {report_type!r} — input is not "
                "a wrapper or engine deps unavailable."
            )
    if output_format == "html":
        return (
            render_html(
                title,
                report_type,
                selected,
                artifacts,
                notes,
                limit,
                ctx,
                scope_label=resolved_scope_label,
            ),
            ctx.warnings,
        )
    return (
        render_markdown(
            title,
            report_type,
            selected,
            artifacts,
            notes,
            limit,
            ctx,
            scope_label=resolved_scope_label,
        ),
        ctx.warnings,
    )


def main() -> int:
    args = parse_args()
    try:
        if args.format == "pdf" and args.output is None:
            raise ReportError("--format pdf requires --output.")
        if args.analysis_mode == "both" and args.output is None:
            raise ReportError("--analysis-mode both requires --output.")
        if args.output is not None and not args.output.parent.exists():
            raise ReportError(
                f"Output directory does not exist: {args.output.parent}"
            )
        _bootstrap_render_deps(args)
        if args.config is not None:
            from config import load_thresholds, set_active_thresholds

            set_active_thresholds(load_thresholds(args.config))
        value = json.loads(read_input(args))

        render_jobs = _render_jobs(value, args)
        all_warnings: list[str] = []
        for job_value, job_args, output_path in render_jobs:
            output, warnings = render(job_value, job_args)
            all_warnings.extend(warnings)
            if job_args.format == "pdf":
                from reportkit.print_export import (
                    PrintExportError,
                    render_pdf_from_html,
                )

                try:
                    render_pdf_from_html(
                        output,
                        output_path,
                        title=getattr(job_args, "title", None),
                        full_bleed='data-pdf-layout="fixed-letter"' in output,
                    )
                except PrintExportError as exc:
                    raise ReportError(str(exc)) from exc
            elif output_path:
                output_path.write_text(output, encoding="utf-8")
            else:
                print(output, end="")
        for warning in all_warnings:
            print(f"WARNING: {warning}", file=sys.stderr)
    except (OSError, ReportError, json.JSONDecodeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


def _without_analyst_notes(value: Any) -> Any:
    deterministic = copy.deepcopy(value)
    if (
        isinstance(deterministic, dict)
        and deterministic.get("schema_version") == "bot_report_input.v1"
    ):
        deterministic.pop("analyst_notes", None)
    return deterministic


def _mode_output_path(base: Path, mode: str) -> Path:
    return base.with_name(f"{base.stem}_{mode}{base.suffix}")


def _render_jobs(
    value: Any,
    args: argparse.Namespace,
) -> list[tuple[Any, argparse.Namespace, Path | None]]:
    if args.analysis_mode == "llm":
        return [(value, args, args.output)]
    if args.analysis_mode == "deterministic":
        return [(_without_analyst_notes(value), args, args.output)]

    llm_args = copy.copy(args)
    deterministic_args = copy.copy(args)
    llm_args.analysis_mode = "llm"
    deterministic_args.analysis_mode = "deterministic"
    llm_args.output = _mode_output_path(args.output, "llm")
    deterministic_args.output = _mode_output_path(args.output, "deterministic")
    return [
        (value, llm_args, llm_args.output),
        (_without_analyst_notes(value), deterministic_args, deterministic_args.output),
    ]
