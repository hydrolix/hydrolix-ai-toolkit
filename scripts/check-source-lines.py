#!/usr/bin/env python
"""Enforce bounded Python source files for normal edited code."""

from __future__ import annotations

from pathlib import Path


MAX_LINES = 500
ROOT = Path(__file__).resolve().parents[1]

ALLOWED_OVERSIZED = {
    "packages/bot-insights/src/bot_insights/_render_report/legacy_html.py",
    "packages/bot-insights/src/bot_insights/_render_report/legacy_markdown.py",
    "packages/bot-insights/src/bot_insights/_render_report/validators.py",
    "scripts/validate-skill-examples.py",
    "tests/test_skill_scripts.py",
}


def line_count(path: Path) -> int:
    with path.open(encoding="utf-8") as handle:
        return sum(1 for _ in handle)


def rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def main() -> int:
    pyfrags = sorted(rel(path) for path in ROOT.rglob("*.pyfrag"))
    oversized = []
    for base in ("packages", "tests", "scripts"):
        for path in (ROOT / base).rglob("*.py"):
            if "__pycache__" in path.parts:
                continue
            relative = rel(path)
            lines = line_count(path)
            if lines > MAX_LINES and relative not in ALLOWED_OVERSIZED:
                oversized.append((relative, lines))

    if pyfrags or oversized:
        if pyfrags:
            print("Unexpected .pyfrag files:")
            for path in pyfrags:
                print(f"  {path}")
        if oversized:
            print(f"Python files over {MAX_LINES} lines:")
            for path, lines in oversized:
                print(f"  {path}: {lines}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
