"""Bridge from the legacy entry path to the report_engine renderer."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .errors import (
    ReportContext,
    ReportError,
)

__all__ = [
    '_render_via_engine',
]


def _render_via_engine(
    *,
    report_type: str,
    value: Any,
    artifacts: list[dict[str, Any]],
    notes: list[dict[str, Any]],
    ctx: ReportContext,
    output_format: str = "html",
    palette: str = "tableau",
    theme_mode: str = "auto",
) -> str | None:
    """Route rendering through the report_engine for a given wrapper
    ``report_type`` and ``output_format`` (``"html"`` or ``"markdown"``).

    Returns ``None`` only for the raw-artifact short-circuit (the
    caller's signal to fall through to the raw-mode path). For a
    recognized wrapper that the engine cannot service — unknown
    ``report_type`` in the registry, or assembly raising
    ``ValueError``/``KeyError`` — this raises ``ReportError`` rather
    than silently falling back to the legacy path.

    M2.3 tightened HTML fallback behavior; M3.3 (this commit)
    extends the same routing to Markdown by adding ``output_format``.
    Both formats now reach legacy only via the
    ``BOT_INSIGHTS_RENDER_PATH=legacy`` test override or for raw-mode
    inputs.
    """
    is_wrapper = (
        isinstance(value, dict)
        and value.get("schema_version") == "bot_report_input.v1"
        and value.get("report_type") == report_type
    )
    if not is_wrapper:
        # Raw-artifact short-circuit. M4.1 confirmed Path B (preserve
        # raw-artifact mode) as the committed default for this plan —
        # no telemetry source was named and signed off ahead of M4 to
        # justify Path A's retirement of raw mode. Raw mode never needs
        # jinja2, so we don't probe the engine import here. Migrating
        # raw-mode to the engine is tracked as a follow-up plan.
        return None

    try:
        from report_engine import render as engine_render
        from report_engine.contexts import REPORT_TYPE_REGISTRY
    except ImportError as exc:
        # For wrappers, missing engine dependencies are a deploy-time
        # bug, not a silent fallback to legacy. Returning None here
        # would route wrapper traffic into the legacy renderer without
        # any signal — that masks a real misconfiguration. Raise so the
        # operator sees the broken state explicitly.
        raise ReportError(
            f"Engine dependencies unavailable for wrapper-mode "
            f"{report_type!r} (output_format={output_format!r}): {exc}"
        ) from exc

    module = REPORT_TYPE_REGISTRY.get(report_type)
    if module is None:
        raise ReportError(
            f"Engine has no context preparer for report_type "
            f"{report_type!r}; registry knows "
            f"{sorted(REPORT_TYPE_REGISTRY)}."
        )

    try:
        renderer = engine_render._renderer()
        artifact = module.assemble(artifacts)
    except (ValueError, KeyError) as exc:
        raise ReportError(f"{report_type} engine assembly failed: {exc}") from exc

    notes_by_slot = engine_render._build_notes_by_slot(
        notes,
        getattr(module, "NOTE_ID_TO_SLOT", {}),
    )
    template_ctx = renderer.prepare_context(
        module,
        artifact,
        notes_by_slot,
        mode="full",
    )
    env = engine_render.build_env(
        output_format=output_format,
        palette=palette,
        theme_mode=theme_mode,
    )
    template = env.get_template(engine_render.template_for(module, output_format))
    return template.render(**template_ctx)
