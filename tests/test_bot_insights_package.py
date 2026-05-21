from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PACKAGE_SRC = ROOT / "packages/bot-insights/src/bot_insights"
LEGACY_SCRIPTS = ROOT / "skills/bot-insights/scripts"


def _rel(path: Path) -> str:
    return path.relative_to(PACKAGE_SRC).as_posix()


def test_bot_insights_imports_are_package_first() -> None:
    from bot_insights.config import DEFAULT_THRESHOLDS
    from bot_insights.models import CaptureQueryConfigModel, ReportInputModel
    from bot_insights.report_engine.charts import bullet_chart_svg

    assert ReportInputModel.model_validate(
        {
            "schema_version": "bot_report_input.v1",
            "report_type": "scorecard_brief",
            "artifacts": [],
        }
    ).report_type == "scorecard_brief"
    assert CaptureQueryConfigModel(database="akamai").granularity == "auto"
    assert Path(DEFAULT_THRESHOLDS.browser_version_history.snapshot_path).exists()
    assert bullet_chart_svg(0.5, 1.0)


def test_legacy_script_path_reexports_package_module() -> None:
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import sys; "
                f"sys.path.insert(0, {str(LEGACY_SCRIPTS)!r}); "
                "import heuristics, report_engine.charts, producers.formatting; "
                "print(heuristics._SUSPICIOUS_VOLUME_SHARE_MIN)"
            ),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    assert completed.stdout.strip() == "0.05"


def test_bot_insights_package_file_length_audit() -> None:
    allowed = {
        "_render_report/legacy_html.py",
        "_render_report/legacy_markdown.py",
        "_render_report/validators.py",
        "attribution.py",
        "bot_insights_capture.py",
        "cache_origin_impact.py",
        "producers/cli.py",
        "producers/evidence/incident.py",
        "producers/orchestrators/incident_report.py",
        "producers/sql/incident.py",
        "producers/threat_hunt.py",
        "report_engine/contexts/incident/module.py",
        "report_engine/contexts/incident/print_adapter.py",
        "report_engine/contexts/threat_hunt.py",
        "scorecard.py",
    }
    oversized = {
        _rel(path)
        for path in PACKAGE_SRC.rglob("*.py")
        if sum(1 for _ in path.open(encoding="utf-8")) > 800
    }
    assert oversized == allowed


def test_bot_insights_complexity_allowlist_tracks_legacy_hotspots() -> None:
    required_hotspots = {
        "src/bot_insights/attribution.py",
        "src/bot_insights/producers/threat_hunt.py",
        "src/bot_insights/report_engine/contexts/threat_hunt.py",
    }
    pyproject = (ROOT / "packages/bot-insights/pyproject.toml").read_text(encoding="utf-8")
    assert 'select = ["C901"]' in pyproject
    assert "max-complexity = 12" in pyproject
    for hotspot in required_hotspots:
        assert f'"{hotspot}" = ["C901"]' in pyproject
