"""Sub-package: re-exports the public API of ``contexts/scorecard_brief.py``."""

from __future__ import annotations

from .fleet_view import *  # noqa: F401, F403
from .queue_view import *  # noqa: F401, F403
from .coverage_view import *  # noqa: F401, F403
from .entity_groups import *  # noqa: F401, F403
from .verdict_strip import *  # noqa: F401, F403
from .module import *  # noqa: F401, F403

__all__ = [
    '_shared_signal',
    '_fleet_coverage_detail',
    '_QUEUE_ORDER',
    '_queue_rows',
    '_entity_row',
    '_lowest_host_callout',
    '_lowest_delta_pct',
    '_aggregate_coverage',
    '_coverage_rows',
    '_normalize_step',
    '_aggregate_actions',
    '_rule_counts',
    '_GROUP_THRESHOLD',
    '_entity_signature',
    '_group_entities',
    '_triage_strip',
    '_actionable_summary',
    '_compute_dek',
    'SCHEMA',
    'REPORT_TYPE',
    'TEMPLATE',
    'NOTE_ID_TO_SLOT',
    'PURPOSE',
    'assemble',
    'prepare',
]
