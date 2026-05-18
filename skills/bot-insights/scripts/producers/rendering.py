"""Shared renderer invocation for producer report mode."""

from __future__ import annotations

from pathlib import Path


RENDER_DEPS = ("jinja2", "markdown-it-py", "bleach")


def render_report_command(
    *,
    wrapper_path: Path,
    output_path: Path,
    output_format: str,
    title: str | None = None,
) -> list[str]:
    """Build the dependency-safe renderer command used by producers."""
    cmd = ["uv", "run"]
    for dep in RENDER_DEPS:
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
    if title:
        cmd.extend(["--title", title])
    return cmd
