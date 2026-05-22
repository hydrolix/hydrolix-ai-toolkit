from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
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


def test_threat_hunt_hunt_impact_scopes_to_high_and_partial_confidence(tmp_path, monkeypatch) -> None:
    from bot_insights.producers import threat_hunt

    summary = tmp_path / "summary.json"
    summary.write_text(
        json.dumps(
            [
                {"period": "current", "request_path": "/api/catalog", "requests": 1000, "bytes": 10000},
                {"period": "baseline", "request_path": "/api/catalog", "requests": 100, "bytes": 1000},
            ]
        ),
        encoding="utf-8",
    )
    actor_dir = tmp_path / "actors"
    actor_dir.mkdir()
    current_rows = [
        {"user_agent": "HighLead/1.0", "requests": 400, "bytes": 4000},
        {"user_agent": "PartialLead/1.0", "requests": 300, "bytes": 3000},
        {"user_agent": "LowLead/1.0", "requests": 200, "bytes": 2000},
        {"user_agent": "UnavailableLead/1.0", "requests": 100, "bytes": 1000},
    ]
    baseline_rows = [
        {"user_agent": "HighLead/1.0", "requests": 40, "bytes": 400},
        {"user_agent": "PartialLead/1.0", "requests": 30, "bytes": 300},
        {"user_agent": "LowLead/1.0", "requests": 20, "bytes": 200},
        {"user_agent": "UnavailableLead/1.0", "requests": 10, "bytes": 100},
    ]
    (actor_dir / "expedia-actors-current-user_agent.json").write_text(
        json.dumps(current_rows),
        encoding="utf-8",
    )
    (actor_dir / "expedia-actors-baseline-user_agent.json").write_text(
        json.dumps(baseline_rows),
        encoding="utf-8",
    )

    qualifiers = {
        "HighLead/1.0": "high",
        "PartialLead/1.0": "partial",
        "LowLead/1.0": "low",
        "UnavailableLead/1.0": "unavailable",
    }

    def attach_controlled_confidence(
        scraper_cases: list[dict[str, object]],
        campaigns: list[dict[str, object]],
        *,
        background: dict[str, object],
        baseline_by_ua: dict[str, dict[str, object]],
    ) -> None:
        del campaigns, background, baseline_by_ua
        for case in scraper_cases:
            qualifier = qualifiers[str(case["user_agent"])]
            case["confidence_assessment"] = {"qualifier": qualifier}

    monkeypatch.setattr(threat_hunt, "_attach_confidence_assessments", attach_controlled_confidence)

    artifact = threat_hunt.build_threat_hunt_artifact(
        cluster="local",
        database="akamai",
        summary_parquet_glob=str(summary),
        start="2026-05-01T00:00:00Z",
        end="2026-05-02T00:00:00Z",
        baseline_start="2026-04-30T00:00:00Z",
        baseline_end="2026-05-01T00:00:00Z",
        raw_actor_dir=str(actor_dir),
        fanout_strategy="skip",
        background_query="off",
        baseline_significance_query="off",
        ua_fanout_query="skip",
    )

    impact = artifact["impact_assessment"]
    assert impact["impact_scope"] == {
        "included_confidence_qualifiers": ["high", "partial"],
        "excluded_confidence_qualifiers": ["low", "unavailable"],
        "included_user_agent_count": 2,
        "note": threat_hunt.HUNT_IMPACT_SCOPE_NOTE,
    }
    assert impact["hunt"]["user_agents"] == ["HighLead/1.0", "PartialLead/1.0"]
    assert impact["hunt"]["requests"] == 700
    assert impact["hunt"]["baseline_requests"] == 70
    assert impact["hunt"]["impact_scope_note"] == threat_hunt.HUNT_IMPACT_SCOPE_NOTE
    assert {case["user_agent"] for case in artifact["scraper_cases"]} == set(qualifiers)


def test_threat_hunt_impact_lane_rows_parse_and_aggregate(tmp_path) -> None:
    from bot_insights.producers.threat_hunt import read_impact_lane_rows

    columns_path = tmp_path / "columns.json"
    columns_path.write_text(
        json.dumps(
            {
                "columns": ["scope", "requests", "response_body_bytes", "akamai_billed_bytes"],
                "rows": [
                    ["current_total", 10, 100, 150],
                    ["current_total", 5, 50, 75],
                    ["baseline_total", 8, 80, 120],
                ],
            }
        ),
        encoding="utf-8",
    )
    list_path = tmp_path / "rows.json"
    list_path.write_text(
        json.dumps(
            [
                {
                    "scope": "current_high_partial",
                    "requests": 3,
                    "response_body_bytes": 30,
                    "akamai_billed_bytes": 45,
                },
                {
                    "scope": "baseline_high_partial",
                    "requests": 2,
                    "response_body_bytes": 20,
                    "akamai_billed_bytes": 25,
                },
            ]
        ),
        encoding="utf-8",
    )

    assert read_impact_lane_rows(str(columns_path)) == [
        {
            "scope": "current_total",
            "requests": 15,
            "response_body_bytes": 150,
            "akamai_billed_bytes": 225,
        },
        {
            "scope": "baseline_total",
            "requests": 8,
            "response_body_bytes": 80,
            "akamai_billed_bytes": 120,
        },
    ]
    assert read_impact_lane_rows(str(list_path)) == [
        {
            "scope": "current_high_partial",
            "requests": 3,
            "response_body_bytes": 30,
            "akamai_billed_bytes": 45,
        },
        {
            "scope": "baseline_high_partial",
            "requests": 2,
            "response_body_bytes": 20,
            "akamai_billed_bytes": 25,
        },
    ]


def test_threat_hunt_impact_lane_merge_recomputes_top_level_lanes(tmp_path, monkeypatch) -> None:
    from bot_insights.producers import threat_hunt

    artifact = _threat_hunt_lane_artifact(tmp_path, monkeypatch)

    threat_hunt.merge_impact_lanes_into_artifact(
        artifact,
        total_rows=[
            {
                "scope": "current_total",
                "requests": 1000,
                "response_body_bytes": 10_000,
                "akamai_billed_bytes": 30_000,
            },
            {
                "scope": "baseline_total",
                "requests": 500,
                "response_body_bytes": 5_000,
                "akamai_billed_bytes": 15_000,
            },
        ],
        scoped_hunt_rows=[
            {
                "scope": "current_high_partial",
                "requests": 400,
                "response_body_bytes": 2_500,
                "akamai_billed_bytes": 9_000,
            },
            {
                "scope": "baseline_high_partial",
                "requests": 50,
                "response_body_bytes": 250,
                "akamai_billed_bytes": 900,
            },
        ],
        required=True,
    )

    impact = artifact["impact_assessment"]
    assert impact["totals"]["current"]["response_body_bytes"] == 10_000
    assert impact["totals"]["current"]["akamai_billed_bytes"] == 30_000
    assert impact["hunt"]["response_body_bytes"] == 2_500
    assert impact["hunt"]["akamai_billed_bytes"] == 9_000
    assert impact["hunt"]["response_body_byte_share"] == 0.25
    assert impact["hunt"]["akamai_billed_byte_share"] == 0.3
    assert impact["hunt"]["hydrolix_log_ingest_bytes"] == 4_000
    assert impact["hunt"]["hydrolix_log_ingest_byte_share"] == 0.4
    assert impact["hunt"]["impact_scope_note"] == threat_hunt.HUNT_IMPACT_SCOPE_NOTE


def test_threat_hunt_cli_supplied_impact_lanes_write_wrapper(tmp_path, monkeypatch) -> None:
    import bot_insights.bot_insights_report as bir
    import bot_insights.producers.cli as cli
    from bot_insights.producers import threat_hunt

    artifact = _threat_hunt_lane_artifact(tmp_path, monkeypatch)
    totals = tmp_path / "totals.json"
    scoped = tmp_path / "scoped.json"
    totals.write_text(
        json.dumps(
            [
                {
                    "scope": "current_total",
                    "requests": 1000,
                    "response_body_bytes": 10_000,
                    "akamai_billed_bytes": 30_000,
                },
                {
                    "scope": "baseline_total",
                    "requests": 500,
                    "response_body_bytes": 5_000,
                    "akamai_billed_bytes": 15_000,
                },
            ]
        ),
        encoding="utf-8",
    )
    scoped.write_text(
        json.dumps(
            [
                {
                    "scope": "current_high_partial",
                    "requests": 400,
                    "response_body_bytes": 2_500,
                    "akamai_billed_bytes": 9_000,
                },
                {
                    "scope": "baseline_high_partial",
                    "requests": 50,
                    "response_body_bytes": 250,
                    "akamai_billed_bytes": 900,
                },
            ]
        ),
        encoding="utf-8",
    )
    summary_path = Path(artifact["_test_summary_path"])
    actor_dir = Path(artifact["_test_actor_dir"])
    output = tmp_path / "out.html"
    sample_dir = tmp_path / "sample"
    argv = [
        "bot-insights-report",
        "--cluster",
        "local",
        "--database",
        "akamai",
        "--report",
        "threat_hunt",
        "--mode",
        "report",
        "--format",
        "html",
        "--start",
        "2026-05-01T00:00:00Z",
        "--end",
        "2026-05-02T00:00:00Z",
        "--baseline-start",
        "2026-04-30T00:00:00Z",
        "--baseline-end",
        "2026-05-01T00:00:00Z",
        "--summary-parquet-glob",
        str(summary_path),
        "--raw-actor-dir",
        str(actor_dir),
        "--sample-dir",
        str(sample_dir),
        "--background-query",
        "off",
        "--baseline-significance-query",
        "off",
        "--ua-fanout-query",
        "skip",
        "--impact-lane-query",
        "required",
        "--impact-lane-totals-in",
        str(totals),
        "--impact-lane-scoped-hunt-in",
        str(scoped),
        "--hydrolix-log-ingest-usagemeter-in",
        str(tmp_path / "usagemeter.json"),
        "--output",
        str(output),
    ]
    (tmp_path / "usagemeter.json").write_text(
        json.dumps([{"rows": 1000, "billing_bytes": 10000}]),
        encoding="utf-8",
    )

    with (
        mock.patch.object(sys, "argv", argv),
        mock.patch.object(cli, "run", return_value=""),
        mock.patch.object(bir, "run", return_value=""),
    ):
        assert bir.main() == 0

    wrapper = json.loads((sample_dir / "threat_hunt-wrapper.json").read_text(encoding="utf-8"))
    embedded = wrapper["artifacts"][0]
    assert embedded["impact_assessment"]["hunt"]["akamai_billed_bytes"] == 9_000
    assert embedded["impact_assessment"]["hunt"]["response_body_byte_share"] == 0.25
    assert embedded["impact_assessment"]["hunt"]["impact_scope_note"] == threat_hunt.HUNT_IMPACT_SCOPE_NOTE


def _threat_hunt_lane_artifact(tmp_path, monkeypatch) -> dict:
    from bot_insights.producers import threat_hunt

    summary = tmp_path / "summary.json"
    summary.write_text(
        json.dumps(
            [
                {"period": "current", "request_path": "/api/catalog", "requests": 1000, "bytes": 0},
                {"period": "baseline", "request_path": "/api/catalog", "requests": 500, "bytes": 0},
            ]
        ),
        encoding="utf-8",
    )
    actor_dir = tmp_path / "actors"
    actor_dir.mkdir(exist_ok=True)
    (actor_dir / "expedia-actors-current-user_agent.json").write_text(
        json.dumps([{"user_agent": "HighLead/1.0", "requests": 400, "bytes": 0}]),
        encoding="utf-8",
    )
    (actor_dir / "expedia-actors-baseline-user_agent.json").write_text(
        json.dumps([{"user_agent": "HighLead/1.0", "requests": 50, "bytes": 0}]),
        encoding="utf-8",
    )

    def attach_high_confidence(scraper_cases, campaigns, *, background, baseline_by_ua):
        del campaigns, background, baseline_by_ua
        for case in scraper_cases:
            case["confidence_assessment"] = {"qualifier": "high"}

    monkeypatch.setattr(threat_hunt, "_attach_confidence_assessments", attach_high_confidence)
    artifact = threat_hunt.build_threat_hunt_artifact(
        cluster="local",
        database="akamai",
        summary_parquet_glob=str(summary),
        start="2026-05-01T00:00:00Z",
        end="2026-05-02T00:00:00Z",
        baseline_start="2026-04-30T00:00:00Z",
        baseline_end="2026-05-01T00:00:00Z",
        raw_actor_dir=str(actor_dir),
        fanout_strategy="skip",
        background_query="off",
        baseline_significance_query="off",
        ua_fanout_query="skip",
        hydrolix_log_ingest_usagemeter_in=str(_write_usagemeter(tmp_path)),
    )
    artifact["_test_summary_path"] = str(summary)
    artifact["_test_actor_dir"] = str(actor_dir)
    return artifact


def _write_usagemeter(tmp_path: Path) -> Path:
    path = tmp_path / "usagemeter.json"
    path.write_text(json.dumps([{"rows": 1000, "billing_bytes": 10000}]), encoding="utf-8")
    return path


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
        "producers/threat_hunt_campaigns.py",
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
        "src/bot_insights/producers/cli.py",
    }
    pyproject = (ROOT / "packages/bot-insights/pyproject.toml").read_text(encoding="utf-8")
    assert 'select = ["C901"]' in pyproject
    assert "max-complexity = 10" in pyproject
    for hotspot in required_hotspots:
        assert f'"{hotspot}" = ["C901"]' in pyproject
