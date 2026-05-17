"""Reusable report rendering and capture primitives."""

__all__ = ["ReportRenderer", "build_env"]


def __getattr__(name: str):
    if name in __all__:
        from .render import ReportRenderer, build_env

        return {"ReportRenderer": ReportRenderer, "build_env": build_env}[name]
    raise AttributeError(name)
