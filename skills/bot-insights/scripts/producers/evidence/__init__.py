"""Evidence-packet builders, one submodule per report family.

Each builder lifts the deterministic artifact a producer-side capture
produced into a ``bot_report_evidence.v1`` packet shaped for the
interpretation step (and the engine's prompt template). Builders are
pure projections — no I/O, no network, no environment reads.

Modules:
  - ``metrics``: shared metric helpers (``metric_by_name``,
    ``metric_card_from_metric``, ``standard_derived_rates``, ...).
    Used by every other builder; kept underscored on import where
    they're not part of the public producer surface.
  - ``posture``: ``build_evidence_packet`` for ``executive_posture``.
  - ``control``: ``build_control_evidence_packet`` +
    ``control_followups`` for ``control_review``.
  - ``scorecard``: ``build_scorecard_evidence_packet`` + the fleet
    variant + selection helpers for the four scorecard reports
    (``scorecard_brief``, ``soc_triage``, ``crawler_governance``,
    ``edge_ops_impact``).
"""
