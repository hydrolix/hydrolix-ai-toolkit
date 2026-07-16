"""Context preparer for the edge ops impact report.

The edge ops impact lens scores ranked entities (typically ``client_asn``,
``request_host``, or ``bot_class``) on the ``cache_busting`` and
``origin_impact`` domains — cache-miss rate / delta, query-string diversity,
origin p95 delta, and origin-cost contribution share — then optionally
enriches the report with path-grain candidates from a
``cache_origin_impact_report.v1`` artifact when present in the wrapper.

The wrapper's ``report_type: "edge_ops_impact"`` routes here. The packet's
``schema_version: "bot_scorecard_artifacts.v1"`` keeps its schema-registry
mapping to ``scorecard_brief`` for raw-artifact mode — ``edge_ops_impact``
is a wrapper-only report.

The implementation lives under the ``.edge_ops_impact`` sub-package;
this module re-exports the public API so callers continue to import
from ``report_engine.contexts.edge_ops_impact``.
"""

from __future__ import annotations

from .edge_ops_impact import *  # noqa: F401, F403
