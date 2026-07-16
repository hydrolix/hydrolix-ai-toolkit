#!/usr/bin/env python3
"""Compatibility wrapper for ``bot_insights.bot_insights_report``."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _package_bootstrap import main_proxy, reexport  # noqa: E402

_module = reexport("bot_insights_report", globals())
main = main_proxy(_module, globals())


if __name__ == "__main__":
    raise SystemExit(main())
