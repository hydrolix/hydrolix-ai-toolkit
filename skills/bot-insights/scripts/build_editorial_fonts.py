#!/usr/bin/env python3
"""Compatibility wrapper for ``bot_insights.build_editorial_fonts``."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _package_bootstrap import reexport  # noqa: E402

_module = reexport("build_editorial_fonts", globals())
main = _module.main


if __name__ == "__main__":
    raise SystemExit(main())
