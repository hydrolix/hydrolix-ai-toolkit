"""Shared helpers for Bot Insights report engine tests."""

from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
ENGINE_DIR = ROOT / "skills/bot-insights/scripts/report_engine"
REPORTKIT_THEME = ROOT / "reportkit/src/reportkit/theme.py"
RENDER_PY = ENGINE_DIR / "render.py"
FIXTURES = Path(__file__).parent / "fixtures/report_engine"
SNAPSHOTS = Path(__file__).parent / "snapshots/report_engine"

# Make charts/findings/theme importable for direct unit tests.
# (markdown.py needs markdown_it + bleach which may be absent — those tests use importorskip.)
sys.path.insert(0, str(ENGINE_DIR.parent))

UPDATE_SNAPSHOTS = os.environ.get("REPORT_ENGINE_UPDATE_SNAPSHOTS") == "1"

VOLATILE_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # Footer "Generated 2026-05-09 12:34 UTC ·" — render time changes per run.
    (re.compile(r"Generated \d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC"), "Generated <FROZEN>"),
)


def _normalize(html: str) -> str:
    """Strip render-time volatility so snapshots are stable across runs."""
    for pattern, replacement in VOLATILE_PATTERNS:
        html = pattern.sub(replacement, html)
    return html


def _render(artifact: Path, *extra: str) -> str:
    """Invoke render.py via uv and return the rendered HTML string."""
    if shutil.which("uv") is None:
        pytest.skip("uv not available")
    with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
        out_path = Path(f.name)
    try:
        subprocess.run(
            [
                "uv",
                "run",
                "--quiet",
                str(RENDER_PY),
                "--artifact",
                str(artifact),
                "--out",
                str(out_path),
                *extra,
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        return out_path.read_text()
    finally:
        out_path.unlink(missing_ok=True)


def _assert_snapshot(actual: str, snapshot_path: Path) -> None:
    """Compare against a committed snapshot, or write one on first run."""
    snapshot_path.parent.mkdir(parents=True, exist_ok=True)
    if UPDATE_SNAPSHOTS or not snapshot_path.exists():
        snapshot_path.write_text(actual)
        if not UPDATE_SNAPSHOTS:
            pytest.skip(f"wrote initial snapshot to {snapshot_path}")
        return
    expected = snapshot_path.read_text()
    if actual != expected:
        diff_path = snapshot_path.with_suffix(".html.actual")
        diff_path.write_text(actual)
        pytest.fail(
            f"snapshot mismatch vs {snapshot_path}.\n"
            f"actual written to {diff_path} for inspection.\n"
            f"if the change is intentional, update with: "
            f"REPORT_ENGINE_UPDATE_SNAPSHOTS=1 uv run pytest "
            f"{Path(__file__).relative_to(ROOT)} -v"
        )



__all__ = [name for name in globals() if not name.startswith("__")]
