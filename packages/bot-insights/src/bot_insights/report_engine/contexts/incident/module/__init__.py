"""Incident report module package public API and compatibility helpers."""

from __future__ import annotations

from .constants import (
    NOTE_ID_TO_SLOT,
    PRINT_TEMPLATE,
    PURPOSE,
    REPORT_TYPE,
    SCHEMA,
    TEMPLATE,
)
from .assemble import assemble
from .scope import (
    _build_headline,
    _build_orientation_block,
    _build_scope_block,
    _build_scope_view_rows,
    _build_siem_view_rows,
    _build_suspicious_targets_visible,
    _build_windows_block,
    _humanize_edge_action_rows,
    _sum_numeric,
)
from .baseline import (
    _baseline_strategy,
    _build_baseline_context,
    _series_current_baseline_rows,
)
from .soc_evidence import (
    _action_target_soc_rows,
    _build_method_block,
    _build_soc_evidence_block,
    _evidence_ref_text,
    _raw_actor_soc_rows,
    _target_by_value,
)
from .availability import _analysis_availability_context, _collect_limitations
from .editorial import _build_editorial_extensions
from .prepare import post_prepare, prepare
from ..targets import SUSPICIOUS_TARGETS_DISPLAY_CAP  # noqa: F401

__all__ = [
    "SCHEMA",
    "REPORT_TYPE",
    "TEMPLATE",
    "PRINT_TEMPLATE",
    "PURPOSE",
    "NOTE_ID_TO_SLOT",
    "assemble",
    "prepare",
    "post_prepare",
]
