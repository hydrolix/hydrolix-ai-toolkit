"""CLI entry: parse_args / read_input / render / main."""

from __future__ import annotations

import argparse
import json
import os
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

__all__ = [
    'parse_args',
    'read_input',
    'render',
    'main',
]


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
        choices=("markdown", "html"),
        default="markdown",
        help="Output format.",
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
    return parser.parse_args()


def read_input(args: argparse.Namespace) -> str:
    if args.file:
        return args.file.read_text(encoding="utf-8")
    if args.text:
        return " ".join(args.text)
    return sys.stdin.read()


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
    if render_path != "legacy":
        engine_output = _render_via_engine(
            report_type=report_type,
            value=value,
            artifacts=artifacts,
            notes=notes,
            ctx=ctx,
            output_format=args.format,
            palette=getattr(args, "palette", "tableau"),
            theme_mode=getattr(args, "theme", "auto"),
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
    if args.format == "html":
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
        value = json.loads(read_input(args))
        output, warnings = render(value, args)
        if args.output:
            args.output.write_text(output, encoding="utf-8")
        else:
            print(output, end="")
        for warning in warnings:
            print(f"WARNING: {warning}", file=sys.stderr)
    except (OSError, ReportError, json.JSONDecodeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0
