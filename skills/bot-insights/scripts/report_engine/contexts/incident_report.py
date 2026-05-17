"""Context preparer for the Incident Report.

Sits between a top-N panel and a full RCA: confirms an incident window
from summary tables (`bi_summary_*`, `bi_siem_policy_summary_*`), drills
to the cluster's raw `akamai.logs` for actor-level detail, and hands off
to a Grafana dashboard for further exploration.

The three artifacts the wrapper carries —
``bot_incident_scope.v1`` (scope confirmation),
``bot_incident_actors.v1`` (actor rankings), and
``bot_incident_action_targets.v1`` (suspicious-target rows, possibly
empty) — are produced mechanically by the orchestrator. The LLM's only
output is prose into three named slots: ``executive_summary``,
``operational_interpretation``, and ``next_steps``. Everything else on
this page is deterministic.

The implementation lives under the ``.incident`` sub-package; this
module re-exports the public API so callers continue to import from
``report_engine.contexts.incident_report``.
"""

from __future__ import annotations

from ..humanize import cluster_display  # re-exported for parity (used by incident_executive_view)
from .incident import *  # noqa: F401, F403
