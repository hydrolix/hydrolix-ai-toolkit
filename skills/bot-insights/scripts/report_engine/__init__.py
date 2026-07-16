"""Compatibility package for ``bot_insights.report_engine``."""

from __future__ import annotations

from _package_bootstrap import bootstrap

bootstrap()

from bot_insights import report_engine as _pkg_report_engine  # noqa: E402

__path__ = list(_pkg_report_engine.__path__)
globals().update(
    {
        name: value
        for name, value in _pkg_report_engine.__dict__.items()
        if name not in {"__name__", "__package__", "__loader__", "__spec__"}
    }
)
