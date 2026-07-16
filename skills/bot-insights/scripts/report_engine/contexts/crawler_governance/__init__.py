"""Sub-package: re-exports the public API of ``contexts/crawler_governance.py``."""

from __future__ import annotations

from .entity_view import *  # noqa: F401, F403
from .evidence_view import *  # noqa: F401, F403
from .narrative import *  # noqa: F401, F403
from .module import *  # noqa: F401, F403

__all__ = [
    '_resolve_entity_type',
    '_entity_display',
    '_CRAWLER_RULE_ORDER',
    '_coverage_rows',
    '_crawler_evidence_cards',
    '_sort_crawler_rules',
    '_domain_score_matrix',
    '_entity_actions',
    '_actionable_summary',
    '_crawler_lead_clause',
    '_fallback_lead_clause',
    'SCHEMA',
    'REPORT_TYPE',
    'TEMPLATE',
    'NOTE_ID_TO_SLOT',
    'PURPOSE',
    'assemble',
    'prepare',
]
