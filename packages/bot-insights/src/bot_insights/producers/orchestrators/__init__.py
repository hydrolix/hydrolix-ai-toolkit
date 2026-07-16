"""Per-report orchestrators that drive bot_insights_capture.py.

No per-report orchestrator is currently extracted here. All supported report
types (``executive_posture`` / ``control_review`` / ``scorecard_brief`` /
``soc_triage`` / ``crawler_governance`` / ``edge_ops_impact``) dispatch inline
from ``main()`` in ``producers.cli`` (or its shim, ``bot_insights_report``).
"""
