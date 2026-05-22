"""Compatibility package for the producer CLI module."""

from __future__ import annotations

import importlib.util
import sys
from types import ModuleType

_SOURCE_PATH = __file__.rsplit("/cli/__init__.py", 1)[0] + "/cli.py"
_SPEC = importlib.util.spec_from_file_location(f"{__name__}._compat_source", _SOURCE_PATH)
if _SPEC is None or _SPEC.loader is None:  # pragma: no cover - importlib guard
    raise ImportError(f"Cannot load CLI compatibility source: {_SOURCE_PATH}")
_MODULE = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _MODULE
_SPEC.loader.exec_module(_MODULE)

for _name, _value in vars(_MODULE).items():
    if not _name.startswith("__"):
        globals()[_name] = _value

__all__ = sorted(name for name in vars(_MODULE) if not name.startswith("__"))


class _CompatModule(ModuleType):
    def __setattr__(self, name: str, value: object) -> None:
        super().__setattr__(name, value)
        setattr(_MODULE, name, value)


sys.modules[__name__].__class__ = _CompatModule

del importlib, ModuleType, sys, _name, _value
