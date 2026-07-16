"""Compatibility package for the former monolithic module."""

from __future__ import annotations

import sys
from importlib import import_module
from types import ModuleType

_MODULE_NAMES = (
    "_shared",
    "part_01",
    "part_02",
    "part_03",
    "part_04",
    "part_05",
    "part_06",
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


class _CompatModule(ModuleType):
    def __setattr__(self, name: str, value: object) -> None:
        super().__setattr__(name, value)
        for module in _MODULES:
            module.__dict__[name] = value


sys.modules[__name__].__class__ = _CompatModule

del ModuleType, import_module, sys, _module, _name, _value
