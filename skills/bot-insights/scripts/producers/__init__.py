"""Compatibility package for ``bot_insights.producers``."""

from __future__ import annotations

from _package_bootstrap import bootstrap

bootstrap()

from bot_insights import producers as _pkg_producers  # noqa: E402

__path__ = list(_pkg_producers.__path__)
globals().update(
    {
        name: value
        for name, value in _pkg_producers.__dict__.items()
        if name not in {"__name__", "__package__", "__loader__", "__spec__"}
    }
)
