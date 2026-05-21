"""Bootstrap the standalone Bot Insights package for legacy script paths."""

from __future__ import annotations

import sys
from importlib import import_module
from pathlib import Path
from types import ModuleType


def bootstrap() -> None:
    package_src = Path(__file__).resolve().parents[3] / "packages" / "bot-insights" / "src"
    if str(package_src) not in sys.path:
        sys.path.insert(0, str(package_src))


def reexport(module_name: str, namespace: dict[str, object]) -> ModuleType:
    bootstrap()
    module = import_module(f"bot_insights.{module_name}")
    namespace.update(
        {
            name: value
            for name, value in module.__dict__.items()
            if name not in {"__name__", "__package__", "__loader__", "__spec__"}
        }
    )
    return module


def main_proxy(module: ModuleType, namespace: dict[str, object]):
    def _main(*args, **kwargs):
        for name, value in namespace.items():
            if name.startswith("__") or name in {
                "bootstrap",
                "main",
                "main_proxy",
                "module",
                "namespace",
                "reexport",
                "_module",
            }:
                continue
            module.__dict__[name] = value
        return module.main(*args, **kwargs)

    return _main
