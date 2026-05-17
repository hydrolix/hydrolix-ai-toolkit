"""Per-report orchestrators that drive bot_insights_capture.py.

One submodule per report type. The incident_report orchestrator
(``incident_report.py``) is the only one currently moved; the
``executive_posture`` / ``control_review`` / ``scorecard_brief`` /
``soc_triage`` / ``crawler_governance`` / ``edge_ops_impact`` flows
still dispatch directly from ``main()`` in ``producers.cli`` (or
its shim, ``bot_insights_report``).
"""
