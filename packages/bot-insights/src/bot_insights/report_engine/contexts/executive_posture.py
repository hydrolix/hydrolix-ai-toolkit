"""Context preparer for `bot_posture_movement.v1` — the Bot & Edge
Movement brief.

Mirrors the patterns in ``scorecard_brief.py``: per-item verdict (here
per-metric, not per-host), traffic-weighted lead, italicized clarification
under the bold lead, recommendation/caveat callouts, triage strip with
muted zero-count pills, single source of truth for action selection.

The implementation lives under the ``.executive_posture``
sub-package; this module re-exports the public API so callers
continue to import from ``report_engine.contexts.executive_posture``.
"""

from __future__ import annotations

from .executive_posture import *  # noqa: F401, F403
