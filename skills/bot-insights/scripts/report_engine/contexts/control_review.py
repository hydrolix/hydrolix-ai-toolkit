"""Context preparer for `bot_control_review.v1`.

A control evaluation report — the analyst declares a control change,
the artifact attests the change happened and quantifies its primary
effect plus side-effects. Reads as a verdict ("delivered as expected",
"overshot the bar", "under-delivered") with effect bars, a side-effect
table, and a small findings strip.

The implementation lives under the ``.control_review`` sub-package;
this module re-exports the public API so callers continue to import
from ``report_engine.contexts.control_review``.
"""

from __future__ import annotations

from .control_review import *  # noqa: F401, F403
