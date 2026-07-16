#!/usr/bin/env python3
"""Compatibility wrapper for ``bot_insights.report_engine.render``."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from _package_bootstrap import reexport  # noqa: E402

_module = reexport("report_engine.render", globals())
main = _module.main


if __name__ == "__main__":
    raise SystemExit(main())
