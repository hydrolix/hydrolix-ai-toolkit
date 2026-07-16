"""Sub-package: re-exports the public API of ``contexts/edge_ops_impact.py``."""

from __future__ import annotations

from .entity_view import *  # noqa: F401, F403
from .scorecard_view import *  # noqa: F401, F403
from .cache_view import *  # noqa: F401, F403
from .origin_view import *  # noqa: F401, F403
from .path_candidates import *  # noqa: F401, F403
from .module import *  # noqa: F401, F403

__all__ = [
    '_resolve_entity_type',
    '_entity_display',
    '_coverage_rows',
    '_domain_score_matrix',
    '_entity_actions',
    '_EDGE_RULE_ORDER',
    '_edge_evidence_cards',
    '_sort_edge_rules',
    '_cost_share_from_scorecard',
    '_edge_lead_clause',
    '_rule_based_lead_clause',
    '_actionable_summary',
    '_path_primary_label',
    '_miss_share',
    '_origin_share',
    '_path_evidence_line',
    '_build_path_candidates',
    'SCHEMA',
    'REPORT_TYPE',
    'TEMPLATE',
    'NOTE_ID_TO_SLOT',
    'PURPOSE',
    'assemble',
    'prepare',
]
