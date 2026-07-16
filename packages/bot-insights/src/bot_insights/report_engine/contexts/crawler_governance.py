"""Context preparer for the crawler governance report.

The crawler governance lens scores ranked entities (typically
``ai_category``, ``bot_class``, or ``request_host``) on the
``crawler_governance`` domain — good-bot 429 / error rates, AI-crawler
growth, and governance-surface failures — plus rate-delta context when
the producer ranked on a crawler-specific population.

The wrapper's ``report_type: "crawler_governance"`` routes here. The
packet's ``schema_version: "bot_scorecard_artifacts.v1"`` keeps its
schema-registry mapping to ``scorecard_brief`` for raw-artifact mode —
``crawler_governance`` is a wrapper-only report.

The implementation lives under the ``.crawler_governance``
sub-package; this module re-exports the public API so callers
continue to import from ``report_engine.contexts.crawler_governance``.
"""

from __future__ import annotations

from .crawler_governance import *  # noqa: F401, F403
