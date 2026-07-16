from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


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


def test_chart_helpers_reexport_reportkit_outputs() -> None:
    import bot_insights.report_engine.charts as package_charts
    import reportkit.charts as reportkit_charts

    legacy_spec = importlib.util.spec_from_file_location(
        "legacy_report_engine_charts",
        LEGACY_SCRIPTS / "report_engine" / "charts.py",
    )
    assert legacy_spec is not None
    assert legacy_spec.loader is not None
    legacy_charts = importlib.util.module_from_spec(legacy_spec)
    legacy_spec.loader.exec_module(legacy_charts)

    cases = [
        ("score_gauge_svg", (85, 1.25), {}),
        ("score_bar_svg", (37,), {}),
        (
            "band_distribution_bar_svg",
            ({"escalate": 1, "monitor": 2, "observe": 3},),
            {},
        ),
        ("score_histogram_svg", ([10, 20, 45, 75, 99], 10, 45), {}),
        (
            "triage_histogram_svg",
            (
                {
                    "assign": 2,
                    "watch": 3,
                    "insufficient_data": 1,
                    "close_as_expected": 4,
                },
            ),
            {},
        ),
        ("coverage_bar_svg", (1, 2, 3), {}),
        ("bullet_chart_svg", (85, 70), {"label": "Score"}),
        (
            "slopegraph_svg",
            ([{"entity": "api.example", "score": 80, "delta": -5}],),
            {},
        ),
        (
            "incident_volume_chart_svg",
            ([10, 25, 90, 20],),
            {
                "baseline": [8, 9, 10, 9],
                "peak_label": "Peak 90",
                "highlight_start_fraction": 0.25,
                "highlight_end_fraction": 0.75,
            },
        ),
        ("sparkline_svg", ([1, 3, 2],), {}),
    ]

    for helper_name, args, kwargs in cases:
        expected = getattr(reportkit_charts, helper_name)(*args, **kwargs)
        assert getattr(package_charts, helper_name)(*args, **kwargs) == expected
        assert getattr(legacy_charts, helper_name)(*args, **kwargs) == expected

    assert package_charts.CURRENT_SERIES_COLOR == reportkit_charts.CURRENT_SERIES_COLOR
    assert legacy_charts.CURRENT_SERIES_COLOR == reportkit_charts.CURRENT_SERIES_COLOR
    assert package_charts._fmt_compact(1234) == reportkit_charts._fmt_compact(1234)
    assert legacy_charts._fmt_compact(1234) == reportkit_charts._fmt_compact(1234)












def _write_usagemeter(tmp_path: Path) -> Path:
    path = tmp_path / "usagemeter.json"
    path.write_text(json.dumps([{"rows": 1000, "billing_bytes": 10000}]), encoding="utf-8")
    return path




def _planner_args(**overrides):
    values = {
        "cluster": "local",
        "database": "akamai",
        "start": "2026-05-01T00:00:00Z",
        "end": "2026-05-02T00:00:00Z",
        "top_n": 10,
        "fanout_strategy": "auto",
        "ua_fanout_query": "auto",
        "raw_actor_extraction_mode": "topk",
        "raw_actor_chunk_seconds": 3600,
        "raw_actor_hash_buckets": 16,
        "raw_actor_topk_candidate_multiplier": 5,
        "hydrolix_log_ingest_bytes_column": None,
        "hydrolix_log_ingest_usagemeter_project_deployment_id": None,
        "hydrolix_log_ingest_usagemeter_table_name": "logs",
    }
    values.update(overrides)
    return SimpleNamespace(**values)






















































































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
    allowed: set[str] = set()
    oversized = {
        _rel(path)
        for path in PACKAGE_SRC.rglob("*.py")
        if sum(1 for _ in path.open(encoding="utf-8")) > 800
    }
    assert oversized == allowed


def test_bot_insights_complexity_allowlist_tracks_legacy_hotspots() -> None:
    required_hotspots = {
        "src/bot_insights/attribution.py",
        "src/bot_insights/producers/cli.py",
    }
    pyproject = (ROOT / "packages/bot-insights/pyproject.toml").read_text(encoding="utf-8")
    assert 'select = ["C901"]' in pyproject
    assert "max-complexity = 10" in pyproject
    for hotspot in required_hotspots:
        assert f'"{hotspot}" = ["C901"]' in pyproject
