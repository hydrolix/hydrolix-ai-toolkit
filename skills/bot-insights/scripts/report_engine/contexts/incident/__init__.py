"""Incident-report context: split sub-package.

Re-exports the public API previously housed in
``contexts/incident_report.py``. The thin
``contexts/incident_report.py`` shim above star-imports from
this package so existing callers see no shape change.
"""

from __future__ import annotations

from .labels import *  # noqa: F401, F403
from .formatters import *  # noqa: F401, F403
from .risk import *  # noqa: F401, F403
from .cohorts import *  # noqa: F401, F403
from .impact import *  # noqa: F401, F403
from .findings import *  # noqa: F401, F403
from .actions import *  # noqa: F401, F403
from .concentration import *  # noqa: F401, F403
from .targets import *  # noqa: F401, F403
from .iocs import *  # noqa: F401, F403
from .windows import *  # noqa: F401, F403
from .views import *  # noqa: F401, F403
from .module import *  # noqa: F401, F403

__all__ = [
    'SPIKE_FLAG_LABELS',
    'REASON_FLAG_LABELS',
    'TARGET_TYPE_LABELS',
    'ACTION_CLASS_LABELS',
    'ACTION_CLASS_TONE',
    'SEVERITY_TONE',
    'CRITICALITY_TONE',
    'IOC_TYPE_MAP',
    '_DEFAULT_FIELD_LABELS',
    '_default_field_label',
    '_EDGE_ACTION_LABELS',
    '_safe_number',
    '_format_count',
    '_format_int',
    '_format_pct',
    '_format_signed_pct',
    '_top_delta',
    '_short_iso',
    '_SEVERITY_ORDER',
    '_RISK_WEIGHTS',
    '_RISK_BANDS',
    '_SEVERITY_LADDER_STEPS',
    '_SEVERITY_LADDER_LABELS',
    '_SEVERITY_LADDER_CSS_VARS',
    '_deterministic_summary',
    '_risk_score',
    '_severity_ladder',
    'COHORT_DISJOINT_OVERLAP_FLOOR_PCT',
    '_compute_actor_cohort_overlap',
    '_compute_actor_cohort_topology',
    '_CHART_SELECTION_RULE',
    '_CHART_SELECTION_REASONS',
    '_impact_view',
    '_volume_chart_view',
    '_interpolate_time_label',
    '_duration_display',
    '_select_chart_series',
    '_finding_entity',
    '_incident_findings',
    '_ACTION_URGENCY_NOW',
    '_recommended_actions_view',
    '_action_effect_block',
    '_action_effect_rate_limit',
    '_concentration_chart_view',
    'SUSPICIOUS_TARGETS_DISPLAY_CAP',
    '_IOC_SCOPE_VIEW_TOP_N',
    '_compute_edge_action_for_indicator',
    '_scope_views_for_indicator',
    '_attack_aggregation',
    '_suspicious_targets_view',
    '_ioc_view',
    '_ioc_json_text',
    '_window_confirmation_view',
    '_scope_filters',
    '_short_window',
    '_cohort_mix_rows',
    '_scope_rows',
    '_top_raw_paths_rows',
    '_status_mix_rows',
    '_actor_rankings_view',
    'SCHEMA',
    'REPORT_TYPE',
    'TEMPLATE',
    'PURPOSE',
    'NOTE_ID_TO_SLOT',
    'assemble',
    'prepare',
]
