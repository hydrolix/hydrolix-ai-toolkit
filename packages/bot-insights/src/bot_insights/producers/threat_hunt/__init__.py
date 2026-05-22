"""Threat-hunt artifact producer package.

This package preserves the historical ``producers.threat_hunt`` import
surface while keeping implementation modules small and focused.
"""

from __future__ import annotations

import sys
from importlib import import_module
from types import ModuleType

_MODULE_NAMES = (
    "_shared",
    "rows",
    "sql_exports",
    "actor_merge",
    "raw_exports",
    "drilldowns",
    "fanout",
    "impact_inputs",
    "impact_assessment",
    "impact_lanes",
    "entities",
    "timing",
    "summaries",
    "scoring",
    "evidence_families",
    "confidence",
    "actions",
    "scraper_cases",
    "build",
 )
_MODULES = [import_module(f"{__name__}.{name}") for name in _MODULE_NAMES]

for _module in _MODULES:
    for _name, _value in vars(_module).items():
        if not _name.startswith("__"):
            globals()[_name] = _value

_EXPORTS = {name: value for name, value in globals().items() if not name.startswith("__")}
for _module in _MODULES:
    _module.__dict__.update(_EXPORTS)

__all__ = sorted(_EXPORTS)


class _ThreatHuntModule(ModuleType):
    def __setattr__(self, name: str, value: object) -> None:
        super().__setattr__(name, value)
        for module in _MODULES:
            module.__dict__[name] = value


sys.modules[__name__].__class__ = _ThreatHuntModule

del ModuleType, import_module, sys, _module, _name, _value
