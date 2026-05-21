"""Bot Insights package.

The first package slice keeps legacy intra-package import names registered
(`config`, `producers`, `report_engine`, and `_render_report`) so existing
skill scripts and tests continue to work while new callers import through
`bot_insights`.
"""

from __future__ import annotations

import importlib
import sys
from types import ModuleType


def _alias(public_name: str, package_name: str | None = None) -> ModuleType:
    module = importlib.import_module(f".{package_name or public_name}", __name__)
    sys.modules[public_name] = module
    globals()[package_name or public_name] = module
    return module


for _name in ("config", "baselines", "heuristics"):
    _alias(_name)

for _name in ("report_engine", "producers", "_render_report"):
    _alias(_name)


__all__ = ["config", "baselines", "heuristics", "report_engine", "producers"]
