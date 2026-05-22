"""Suspicious-target row builders + per-indicator scope qualifiers."""

from __future__ import annotations

from .attack import _attack_aggregation
from .constants import SUSPICIOUS_TARGETS_DISPLAY_CAP, _IOC_SCOPE_VIEW_TOP_N
from .edge_actions import _compute_edge_action_for_indicator
from .provenance import _compute_provenance_for_indicator
from .rows import _suspicious_targets_view
from .scope_views import _scope_views_for_indicator

__all__ = [
    "SUSPICIOUS_TARGETS_DISPLAY_CAP",
    "_IOC_SCOPE_VIEW_TOP_N",
    "_compute_edge_action_for_indicator",
    "_compute_provenance_for_indicator",
    "_scope_views_for_indicator",
    "_attack_aggregation",
    "_suspicious_targets_view",
]
