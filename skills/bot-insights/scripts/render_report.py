#!/usr/bin/env python3
"""Render Bot Insights artifacts as Markdown or self-contained HTML.

This script is a deterministic view layer over existing Bot Insights
artifacts. It does not query Hydrolix, recompute scores, or infer
metrics beyond the fields already present in the input JSON.

For wrapper inputs the entry path now delegates to ``report_engine``
(the modern path). The legacy Markdown / HTML body builders survive
under ``_render_report.legacy_markdown`` and
``_render_report.legacy_html`` as test infrastructure for the
``BOT_INSIGHTS_RENDER_PATH=legacy`` regression tests in
``tests/test_skill_scripts.py``. The plan trailer (M4.5) tracks
rewriting those tests against engine output; until that lands, the
legacy renderers stay reachable through this module's public API.

The implementation now lives under the ``_render_report`` sub-package
alongside this file; the public symbols (``render``, ``main``,
``ReportError``, ``default_limit``, ``normalize_artifacts``, every
``md_*`` / ``html_*`` body builder, plus the re-exports from
``report_engine.humanize``) are star-imported below so callers and
tests continue to reach them at ``render_report.<name>``.
"""

from __future__ import annotations

# Re-exports from the report_engine humanize module — callers and
# legacy tests reach these via ``render_report.<name>``.
from report_engine.humanize import (  # noqa: F401
    METRIC_LABELS,
    display_label,
    human_metric_name,
    rule_label_parts,
    stringify,
)

from _render_report import *  # noqa: F401, F403
from _render_report.cli import main  # noqa: F401


if __name__ == "__main__":
    raise SystemExit(main())
