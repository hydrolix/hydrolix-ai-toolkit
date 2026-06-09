"""Compatibility collector for split Bot Insights report engine tests.

Run all tests:
    uv run pytest tests/test_report_engine.py -v

Update snapshots after an intentional rendering change:
    REPORT_ENGINE_UPDATE_SNAPSHOTS=1 uv run pytest tests/test_report_engine.py
"""

from tests.report_engine_cases.scorecard import *  # noqa: F401,F403
from tests.report_engine_cases.executive_posture import *  # noqa: F401,F403
from tests.report_engine_cases.soc_crawler_edge import *  # noqa: F401,F403
from tests.report_engine_cases.charts_findings import *  # noqa: F401,F403
from tests.report_engine_cases.control_review import *  # noqa: F401,F403
from tests.report_engine_cases.markdown_rendering import *  # noqa: F401,F403
from tests.report_engine_cases.theme_contracts import *  # noqa: F401,F403
from tests.report_engine_cases.registry_cli import *  # noqa: F401,F403
