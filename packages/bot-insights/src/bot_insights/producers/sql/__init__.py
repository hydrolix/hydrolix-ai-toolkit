"""Per-report SQL builders.

Submodules emit the ClickHouse SQL the orchestrator hands to
``bot_insights_capture.py``. Every builder is a pure string
generator — no I/O, no environment reads. Time-window inputs and
identifier interpolation route through ``producers.formatting``
helpers (``sql_ts``, ``sql_literal``, ``bucket_expr``,
``choose_granularity``) so each module stays focused on its
report's query shape.

Modules:
  - ``executive_posture``: fleet-level posture snapshot.
  - ``control_review``: scalar + timeseries pairs against either
    ``bi_summary_*`` (posture source) or
    ``bi_siem_policy_summary_*`` (siem-policy source).
  - ``scorecard``: scorecard_brief, soc_triage, crawler_governance,
    edge_ops_impact, plus the optional ``cache_origin_path_sql``
    drill-down used by edge_ops_impact.
"""
