"""Constants for suspicious-target rendering."""

from __future__ import annotations

import sys
from pathlib import Path

# Make ``config`` importable when this package is loaded from
# report_engine.contexts.incident.
_BOT_INSIGHTS_DIR = Path(__file__).resolve().parents[4]
if str(_BOT_INSIGHTS_DIR) not in sys.path:
    sys.path.insert(0, str(_BOT_INSIGHTS_DIR))

from config import DEFAULT_THRESHOLDS  # noqa: E402


# Default surfaces here for legacy importers; the renderer reads
# ``active_thresholds().display.suspicious_targets_cap`` at call time
# so a ``--config`` override picks up without re-importing the module.
SUSPICIOUS_TARGETS_DISPLAY_CAP = DEFAULT_THRESHOLDS.display.suspicious_targets_cap

_IOC_SCOPE_VIEW_TOP_N = 3  # entries per seen_at / seen_with list
