"""Shared renderer invocation for producer report mode."""

from __future__ import annotations

from pathlib import Path


BASE_RENDER_DEPS = ("jinja2", "markdown-it-py", "bleach")
PDF_RENDER_DEPS = ("playwright",)


def render_deps_for_format(output_format: str) -> tuple[str, ...]:
    deps = BASE_RENDER_DEPS
    if output_format == "pdf":
        deps += PDF_RENDER_DEPS
    return deps


def render_report_command(
    *,
    wrapper_path: Path,
    output_path: Path,
    output_format: str,
    config_path: Path | None = None,
    title: str | None = None,
) -> list[str]:
    """Build the dependency-safe renderer command used by producers."""
    cmd = ["uv", "run"]
    for dep in render_deps_for_format(output_format):
        cmd.extend(["--with", dep])
    cmd.extend(
        [
            "python",
            "skills/bot-insights/scripts/render_report.py",
            "--file",
            str(wrapper_path),
            "--format",
            output_format,
            "--output",
            str(output_path),
        ]
    )
    if config_path is not None:
        cmd.extend(["--config", str(config_path)])
    if title:
        cmd.extend(["--title", title])
    return cmd
