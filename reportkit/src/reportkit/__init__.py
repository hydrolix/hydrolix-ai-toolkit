"""Reusable report rendering and capture primitives."""

__all__ = ["PrintExportError", "ReportRenderer", "build_env", "render_pdf_from_html"]


def __getattr__(name: str):
    if name in ("ReportRenderer", "build_env"):
        from .render import ReportRenderer, build_env

        return {"ReportRenderer": ReportRenderer, "build_env": build_env}[name]
    if name in ("PrintExportError", "render_pdf_from_html"):
        from .print_export import PrintExportError, render_pdf_from_html

        return {
            "PrintExportError": PrintExportError,
            "render_pdf_from_html": render_pdf_from_html,
        }[name]
    raise AttributeError(name)
