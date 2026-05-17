"""Context preparer for the SOC triage report.

A SOC analyst lens over the same ``bot_scorecard_artifacts.v1`` packet
that ``scorecard_brief`` reads, but reframed:

- The fleet axis is whatever entity dimension the producer ranked on
  (typically ``client_asn``), not request hosts.
- Lead with the security-evidence domain — bad-bot share, SIEM auth-fail
  and blocked counts — then volume movement as a secondary lens.
- Show a per-entity domain score matrix so the analyst can see where
  the points landed without reading every triggered-feature card.

The wrapper's ``report_type: "soc_triage"`` routes here. The packet's
``schema_version: "bot_scorecard_artifacts.v1"`` keeps its
schema-registry mapping to ``scorecard_brief`` for raw-artifact mode —
SOC is a wrapper-only report.

The implementation lives under the ``.soc_triage`` sub-package; this
module re-exports the public API so callers continue to import from
``report_engine.contexts.soc_triage``.
"""

from __future__ import annotations

from .soc_triage import *  # noqa: F401, F403
