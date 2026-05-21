"""Compatibility package for ``bot_insights._render_report``."""

from __future__ import annotations

from _package_bootstrap import bootstrap

bootstrap()

from bot_insights import _render_report as _pkg_render_report  # noqa: E402

__path__ = list(_pkg_render_report.__path__)
globals().update(
    {
        name: value
        for name, value in _pkg_render_report.__dict__.items()
        if name not in {"__name__", "__package__", "__loader__", "__spec__"}
    }
)
