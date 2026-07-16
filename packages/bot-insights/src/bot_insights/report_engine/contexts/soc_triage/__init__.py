"""Sub-package: re-exports the public API of ``contexts/soc_triage.py``."""

from __future__ import annotations

from .entity_view import *  # noqa: F401, F403
from .triage_queue import *  # noqa: F401, F403
from .evidence_view import *  # noqa: F401, F403
from .narrative import *  # noqa: F401, F403
from .module import *  # noqa: F401, F403

__all__ = [
    '_resolve_entity_type',
    '_entity_display',
    '_coverage_rows',
    '_domain_score_matrix',
    '_entity_actions',
    '_SECURITY_RULE_ORDER',
    '_security_evidence_cards',
    '_sort_security_rules',
    '_actionable_summary',
    '_routing_clause',
    '_security_lead_clause',
    '_movement_lead_clause',
    'SCHEMA',
    'REPORT_TYPE',
    'TEMPLATE',
    'NOTE_ID_TO_SLOT',
    'PURPOSE',
    'assemble',
    'prepare',
]
