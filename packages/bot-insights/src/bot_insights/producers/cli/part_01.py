from __future__ import annotations

from ._shared import *

"""argparse setup + main() dispatch for ``bot_insights_report``.

This module is the script's CLI surface. The original
``bot_insights_report.py`` is now a 60-line shim that re-exports
everything here under its historical name.

Layout:
  - ``parse_args``: argparse setup. Every report-type-specific flag
    (``--policy-id`` for control_review, ``--entity-type`` for the
    scorecard family, ``--host`` for host-scoped posture, etc.) lives
    here.
  - ``main``: validates the parsed args, picks the right SQL +
    table + evidence builder per ``--report``, runs capture, and
    branches to either evidence-packet emission (``--mode evidence``)
    or the renderer (``--mode html`` / ``--mode markdown``). All
    supported report types (executive_posture, control_review,
    scorecard_brief, soc_triage, crawler_governance, edge_ops_impact)
    are dispatched inline.

Document the full CC + ≤500-line guideline deviations for this
module in the verification commit; both apply because ``main`` is
~700 lines and CC-monster until per-report orchestrator extraction
lands.
"""


import argparse

import json

import sys

from pathlib import Path

from producers.evidence.control import build_control_evidence_packet

from producers.evidence.labeling import humanize_evidence_packet

from producers.evidence.posture import build_evidence_packet

from producers.evidence.scorecard import (
    build_scorecard_evidence_packet,
    build_scorecard_fleet_evidence_packet,
    select_scorecard,
)

from producers.formatting import choose_granularity, parse_time

from producers.runtime import (
    CAPTURE,
    DEFAULT_SAMPLE_ROOT,
    HANDOFF_SCHEMA,
    NEEDS_MCP_EXIT,
    PUBLIC_SKILLS,
    load_raw_query_result,
    run,
)

from producers.rendering import render_report_command

from producers.sql.control_review import (
    control_review_sql,
    control_review_timeseries_sql,
)

from producers.sql.executive_posture import executive_posture_sql

from producers.sql.scorecard import (
    CRAWLER_ENTITY_SQL,
    EDGE_OPS_ENTITY_SQL,
    SCORECARD_ENTITY_SQL,
    SOC_ENTITY_SQL,
    cache_origin_path_sql,
    scorecard_crawler_sql,
    scorecard_edge_ops_sql,
    scorecard_soc_sql,
    scorecard_sql,
)

from producers.wrapper import (
    add_control_metadata,
    add_report_metadata,
    add_scorecard_metadata,
    analyst_note_from_args,
    build_report_wrapper,
    build_timeseries_artifact,
    render_template_packet,
)

__all__ = [name for name in globals() if not name.startswith("__")]
