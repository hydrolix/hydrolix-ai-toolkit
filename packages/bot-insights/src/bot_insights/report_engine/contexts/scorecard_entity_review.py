"""Context preparer for the entity-scoped scorecard review.

Surfaces a single ``bot_entity_scorecard.v1`` packet — typically a
single host or ASN that was selected from a previous brief — and
re-renders it as an analyst-style review with the full triggered-rule
list, sub-domain breakdown, evidence cards, recommended actions, and
optional analyst notes.

The implementation lives under the ``.scorecard_entity_review``
sub-package; this module re-exports the public API so callers
continue to import from
``report_engine.contexts.scorecard_entity_review``.
"""

from __future__ import annotations

from .scorecard_entity_review import *  # noqa: F401, F403
