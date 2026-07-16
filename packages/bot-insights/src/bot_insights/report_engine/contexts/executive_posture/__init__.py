"""Sub-package: re-exports the public API of ``contexts/executive_posture.py``."""

from __future__ import annotations

from .constants import *  # noqa: F401, F403
from .formatters import *  # noqa: F401, F403
from .metric_rows import *  # noqa: F401, F403
from .movers import *  # noqa: F401, F403
from .triage import *  # noqa: F401, F403
from .narrative import *  # noqa: F401, F403
from .module import *  # noqa: F401, F403

__all__ = [
    '_VOLUME_METRICS',
    '_WATCH_PCT',
    '_STABLE_PCT',
    '_STATE_ORDER',
    '_STATE_LABELS',
    '_STATE_TONE',
    '_to_float',
    '_cluster_label',
    '_short_window',
    '_metric_label',
    '_confidence_chip',
    '_band_verdict_label',
    '_band_verdict_tone',
    '_classify_metric',
    '_metric_recommendation',
    '_metric_row',
    '_top_priority_metric',
    '_top_mover',
    '_triage_strip',
    '_embedded_scorecards',
    '_actions',
    '_actionable_summary',
    '_headline_for',
    '_coverage_caveat',
    'SCHEMA',
    'REPORT_TYPE',
    'TEMPLATE',
    'NOTE_ID_TO_SLOT',
    'PURPOSE',
    'assemble',
    'prepare',
]
