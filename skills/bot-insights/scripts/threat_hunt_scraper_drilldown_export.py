#!/usr/bin/env python3
"""Compatibility wrapper for ``bot_insights.threat_hunt_scraper_drilldown_export``."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _package_bootstrap import main_proxy, reexport  # noqa: E402

_module = reexport("threat_hunt_scraper_drilldown_export", globals())
main = main_proxy(_module, globals())


if __name__ == "__main__":
    raise SystemExit(main())
