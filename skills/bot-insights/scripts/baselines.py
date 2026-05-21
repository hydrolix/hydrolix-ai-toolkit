"""Compatibility wrapper for ``bot_insights.baselines``."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _package_bootstrap import reexport  # noqa: E402

reexport("baselines", globals())
