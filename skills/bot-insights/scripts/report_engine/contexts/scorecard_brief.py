"""Context preparer for `bot_scorecard_artifacts.v1` artifacts.

The implementation lives under the ``.scorecard_brief`` sub-package;
this module re-exports the public API so callers continue to import
from ``report_engine.contexts.scorecard_brief``.
"""

from __future__ import annotations

from .scorecard_brief import *  # noqa: F401, F403
