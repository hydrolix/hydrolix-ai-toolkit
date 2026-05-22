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
    assert artifact["artifact_metadata"]["summary_evidence"]["evidence_role"] == "selected_summary_evidence"
    assert artifact["artifact_metadata"]["summary_evidence"]["population_complete"] is False
    assert artifact["artifact_metadata"]["population_totals"]["population_complete"] is False
    assert impact["totals_source"] == "selected_summary_evidence"
    assert impact["totals_population_complete"] is False
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
    assert impact["totals_source"] == "raw_log_impact_lanes"
    assert impact["totals_population_complete"] is True
    assert impact["totals_evidence_role"] == "population_complete_raw_log_totals"
    assert artifact["artifact_metadata"]["population_totals"] == {
        "source": "raw_log_impact_lanes",
        "population_complete": True,
        "evidence_role": "population_complete_raw_log_totals",
        "current_scope": "current_total",
        "baseline_scope": "baseline_total",
    }
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
    assert wrapper["input_manifest"]["schema_version"] == "threat_hunt_input_manifest.v1"
    assert embedded["artifact_metadata"]["input_manifest"]["schema_version"] == "threat_hunt_input_manifest.v1"
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


def _minimal_harvest_plan(cli, *, hash_value: str = "planhash") -> dict:
    return {
        "schema_version": cli.THREAT_HUNT_HARVEST_PLAN_VERSION,
        "hash": hash_value,
        "hash_algorithm": "sha256",
        "required_stages": sorted(cli.THREAT_HUNT_HARVEST_PLAN_REQUIRED_STAGE_IDS),
        "dynamic_selectors": [
            {"family": family}
            for family in sorted(cli.THREAT_HUNT_HARVEST_PLAN_DYNAMIC_SELECTOR_FAMILIES)
        ],
    }


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


def _catalog_inspection(cli, *, include_bi_summary: bool = True, summary_hour_ua: bool = True, raw_missing: set[str] | None = None) -> dict:
    raw_columns = set(cli.THREAT_HUNT_RAW_LOG_REQUIRED_COLUMNS) - (raw_missing or set())
    summary_columns = set(cli.THREAT_HUNT_BI_SUMMARY_REQUIRED_COLUMNS)
    summary_hour_columns = set(cli.THREAT_HUNT_SUMMARY_HOUR_FANOUT_REQUIRED_COLUMNS) if summary_hour_ua else {"reqTimeSec"}
    tables = ["akamai.logs", "akamai.summary_hour", "hydro.logs"]
    columns = {
        "akamai.logs": sorted(raw_columns),
        "akamai.summary_hour": sorted(summary_hour_columns | set(cli.THREAT_HUNT_LEGACY_SUMMARY_REQUIRED_COLUMNS)),
        "hydro.logs": sorted(cli.THREAT_HUNT_HYDRO_LOGS_REQUIRED_COLUMNS),
    }
    if include_bi_summary:
        tables.append("akamai.bi_summary_hour")
        columns["akamai.bi_summary_hour"] = sorted(summary_columns)
    return {
        "mode": "live_metadata",
        "catalog_queries": [{"purpose": "test", "sql_sha256": "abc"}],
        "inspected_tables": sorted(tables),
        "columns": columns,
        "column_types": {},
    }


def test_harvest_plan_uses_live_metadata_and_resolves_fanout(monkeypatch) -> None:
    from bot_insights.producers import cli
    from bot_insights.producers.formatting import parse_time

    monkeypatch.setattr(
        cli,
        "inspect_threat_hunt_catalog",
        lambda **_kwargs: _catalog_inspection(cli, summary_hour_ua=False),
    )
    args = _planner_args()
    plan = cli.build_threat_hunt_harvest_plan(
        args=args,
        start=parse_time(args.start, "start"),
        end=parse_time(args.end, "end"),
        baseline_start=parse_time("2026-04-30T00:00:00Z", "baseline-start"),
        baseline_end=parse_time("2026-05-01T00:00:00Z", "baseline-end"),
    )

    assert plan["inspection"]["mode"] == "live_metadata"
    assert plan["summary"]["table"] == "akamai.bi_summary_hour"
    assert plan["fanout"]["strategy"] == "logs_probe"
    assert plan["planner_decisions"]["usagemeter_policy"] == "discovery_then_export"
    assert all(stage["missing_columns"] == [] for stage in plan["stages"])
    cli.validate_threat_hunt_harvest_plan(plan)


def test_harvest_plan_fails_when_raw_required_column_missing(monkeypatch) -> None:
    from bot_insights.producers import cli
    from bot_insights.producers.formatting import parse_time

    monkeypatch.setattr(
        cli,
        "inspect_threat_hunt_catalog",
        lambda **_kwargs: _catalog_inspection(cli, raw_missing={"totalBytes"}),
    )
    args = _planner_args()
    try:
        cli.build_threat_hunt_harvest_plan(
            args=args,
            start=parse_time(args.start, "start"),
            end=parse_time(args.end, "end"),
            baseline_start=parse_time("2026-04-30T00:00:00Z", "baseline-start"),
            baseline_end=parse_time("2026-05-01T00:00:00Z", "baseline-end"),
        )
    except SystemExit as exc:
        assert "totalBytes" in str(exc)
    else:
        raise AssertionError("expected missing raw column to fail plan generation")


def test_harvest_plan_selects_legacy_summary_with_synthetic_fields(monkeypatch) -> None:
    from bot_insights.producers import cli
    from bot_insights.producers.formatting import parse_time

    monkeypatch.setattr(
        cli,
        "inspect_threat_hunt_catalog",
        lambda **_kwargs: _catalog_inspection(cli, include_bi_summary=False),
    )
    args = _planner_args()
    plan = cli.build_threat_hunt_harvest_plan(
        args=args,
        start=parse_time(args.start, "start"),
        end=parse_time(args.end, "end"),
        baseline_start=parse_time("2026-04-30T00:00:00Z", "baseline-start"),
        baseline_end=parse_time("2026-05-01T00:00:00Z", "baseline-end"),
    )

    assert plan["summary"]["table"] == "akamai.summary_hour"
    assert plan["summary"]["source"] == "legacy_akamai_summary"
    assert plan["summary"]["field_provenance_overrides"]["traffic_cohort"] == "synthetic_unavailable"


def test_threat_hunt_plan_out_inspects_metadata_without_report_artifacts(tmp_path, monkeypatch) -> None:
    from bot_insights.producers import cli

    calls: list[dict[str, object]] = []

    def fake_inspect(**kwargs):
        calls.append(kwargs)
        return _catalog_inspection(cli)

    monkeypatch.setattr(cli, "inspect_threat_hunt_catalog", fake_inspect)
    plan_path = tmp_path / "plan.json"
    sample_dir = tmp_path / "sample"
    argv = [
        "bot-insights-report",
        "--cluster",
        "local",
        "--database",
        "akamai",
        "--report",
        "threat_hunt",
        "--threat-hunt-harvest-plan-out",
        str(plan_path),
        "--sample-dir",
        str(sample_dir),
        "--start",
        "2026-05-01T00:00:00Z",
        "--end",
        "2026-05-02T00:00:00Z",
        "--baseline-start",
        "2026-04-30T00:00:00Z",
        "--baseline-end",
        "2026-05-01T00:00:00Z",
    ]

    with mock.patch.object(sys, "argv", argv):
        assert cli.main() == 0

    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    assert calls == [{"cluster": "local", "database": "akamai"}]
    assert plan["inspection"]["mode"] == "live_metadata"
    assert plan["planner_decisions"]["selected_summary_table"] == "akamai.bi_summary_hour"
    assert not (sample_dir / "threat_hunt-artifact.json").exists()


def test_threat_hunt_input_manifest_expands_glob_and_actor_dir_deterministically(tmp_path) -> None:
    from bot_insights.producers import cli, threat_hunt

    summary_b = tmp_path / "summary-b.json"
    summary_a = tmp_path / "summary-a.json"
    actor_dir = tmp_path / "actors"
    actor_dir.mkdir()
    summary_metadata = {
        "population_complete": False,
        "evidence_role": "selected_summary_evidence",
        "selection": {
            "mode": "top_n_by_period",
            "limit_per_period": threat_hunt.SUMMARY_EXPORT_ROWS_PER_PERIOD,
            "population_complete": False,
            "evidence_role": "selected_summary_evidence",
            "order_by": [
                "period",
                "requests DESC",
                "request_path ASC",
                "country ASC",
                "traffic_cohort ASC",
            ],
            "candidate_rows_by_period": {"current": 1, "baseline": 1},
            "candidate_row_count": 2,
            "selected_row_count": 2,
            "selection_sql_sha256": "abc",
            "candidate_count_sql_sha256": "def",
        },
    }
    for path, stage_id, rows in (
        (summary_b, "summary_export", [{"period": "current", "requests": 2}]),
        (summary_a, "summary_export", [{"period": "baseline", "requests": 1}]),
        (actor_dir / "b.json", "raw_actor", [{"user_agent": "B", "requests": 2}]),
        (actor_dir / "a.json", "raw_actor", [{"user_agent": "A", "requests": 1}]),
    ):
        threat_hunt.write_threat_hunt_dataset(
            path,
            stage_id=stage_id,
            cluster="local",
            database="akamai",
            source_table="akamai.logs",
            query_sql="SELECT 1",
            rows=rows,
            total_row_count=2 if stage_id == "summary_export" else None,
            metadata=summary_metadata if stage_id == "summary_export" else None,
        )

    manifest = cli.build_threat_hunt_input_manifest(
        summary_parquet_glob=str(tmp_path / "summary-*.json"),
        raw_actor_dir=str(actor_dir),
    )

    assert manifest["schema_version"] == "threat_hunt_input_manifest.v1"
    assert [
        (entry["role"], Path(str(entry["path"])).name)
        for entry in manifest["inputs"]
    ] == [
        ("raw_actor", "a.json"),
        ("raw_actor", "b.json"),
        ("summary", "summary-a.json"),
        ("summary", "summary-b.json"),
    ]


def test_threat_hunt_input_manifest_records_hash_rows_and_dataset_metadata(tmp_path) -> None:
    from bot_insights.producers import cli, threat_hunt

    wrapped = tmp_path / "cooccurrence.json"
    threat_hunt.write_threat_hunt_dataset(
        wrapped,
        stage_id="cooccurrence",
        cluster="local",
        database="akamai",
        source_table="akamai.logs",
        query_sql="SELECT cooccurrence",
        rows=[{"client_ip": "8.8.8.8", "user_agent": "UA", "requests": 10}],
    )

    manifest = cli.build_threat_hunt_input_manifest(
        summary_parquet_glob=None,
        raw_actor_dir=None,
        cooccurrence_in=str(wrapped),
    )

    entry = manifest["inputs"][0]
    assert entry["role"] == "cooccurrence"
    assert entry["exists"] is True
    assert entry["sha256"] == cli._sha256_file(wrapped)
    assert entry["row_count"] == 1
    assert entry["threat_hunt_dataset"]["schema_version"] == "threat_hunt_dataset.v1"
    assert entry["threat_hunt_dataset"]["stage_id"] == "cooccurrence"
    assert entry["threat_hunt_dataset"]["query_sha256"]


def test_rendered_threat_hunt_export_json_includes_input_manifest() -> None:
    from bot_insights.report_engine.contexts import threat_hunt as context

    artifact = {
        "schema_version": "bot_threat_hunt.v3",
        "scope": {"cluster": "local", "current_window": {}, "baseline_window": {}},
        "artifact_metadata": {
            "input_manifest": {
                "schema_version": "threat_hunt_input_manifest.v1",
                "inputs": [
                    {"role": "summary", "path": "/tmp/summary.json", "exists": True, "sha256": "abc"}
                ],
            },
            "harvest_plan": {
                "schema_version": "threat_hunt_harvest_plan.v1",
                "hash": "planhash",
            },
        },
        "module_scorecards": [],
        "baseline_movement": {"metric_deltas": []},
        "scraper_cases": [],
        "campaigns": [],
        "recommended_actions": [],
        "impact_assessment": {},
        "limitations": [],
        "interpretation_constraints": [],
    }

    prepared = context.prepare(artifact)
    export_payload = json.loads(prepared["threat_hunt_ui"]["exports"]["json"])

    assert export_payload["source"]["input_manifest"]["schema_version"] == "threat_hunt_input_manifest.v1"
    assert export_payload["harvest_plan"]["schema_version"] == "threat_hunt_harvest_plan.v1"


def test_hydrolix_usagemeter_discovery_selects_database_suffix() -> None:
    from bot_insights.producers.threat_hunt import select_hydrolix_usagemeter_project_deployment_id

    rows = [
        {"project_deployment_id": "westernunion__hydro", "table_name": "logs", "rows": 10, "billing_bytes": 20},
        {"project_deployment_id": "westernunion__akamai", "table_name": "logs", "rows": 12, "billing_bytes": 24},
        {"project_deployment_id": "westernunion__akamai", "table_name": "metrics", "rows": 100, "billing_bytes": 200},
    ]

    assert (
        select_hydrolix_usagemeter_project_deployment_id(rows, database="akamai", table_name="logs")
        == "westernunion__akamai"
    )


def test_hydrolix_usagemeter_discovery_rejects_missing_or_ambiguous_suffix() -> None:
    from bot_insights.producers.threat_hunt import select_hydrolix_usagemeter_project_deployment_id

    missing = [{"project_deployment_id": "westernunion__hydro", "table_name": "logs", "rows": 10, "billing_bytes": 20}]
    with mock.patch("sys.stderr"):
        try:
            select_hydrolix_usagemeter_project_deployment_id(missing, database="akamai", table_name="logs")
        except SystemExit as exc:
            assert "No hydro.logs usagemeter deployment matched" in str(exc)
        else:
            raise AssertionError("expected missing suffix to fail")

    ambiguous = [
        {"project_deployment_id": "wu__akamai", "table_name": "logs", "rows": 10, "billing_bytes": 20},
        {"project_deployment_id": "westernunion__akamai", "table_name": "logs", "rows": 10, "billing_bytes": 20},
    ]
    try:
        select_hydrolix_usagemeter_project_deployment_id(ambiguous, database="akamai", table_name="logs")
    except SystemExit as exc:
        assert "Multiple hydro.logs usagemeter deployments matched" in str(exc)
    else:
        raise AssertionError("expected ambiguous suffix to fail")


def test_hydrolix_usagemeter_export_chunks_current_and_baseline(tmp_path, monkeypatch) -> None:
    from bot_insights.producers import threat_hunt

    queries: list[str] = []

    def fake_export(cluster: str, sql: str, output: Path) -> None:
        queries.append(sql)
        output.write_text(
            json.dumps(
                [
                    {
                        "project_deployment_id": "westernunion__akamai",
                        "table_name": "logs",
                        "metadata_window_start": "2026-04-30 00:00:00",
                        "metadata_window_end": "2026-05-02 00:00:00",
                        "rows": 6,
                        "billing_bytes": 60,
                        "raw_usage_bytes": 30,
                    }
                ]
            ),
            encoding="utf-8",
        )

    monkeypatch.setattr(threat_hunt, "_run_mux_export", fake_export)
    output = tmp_path / "usagemeter.json"

    threat_hunt.export_hydrolix_usagemeter_ingest_estimate(
        output=str(output),
        start="2026-05-01T00:00:00Z",
        end="2026-05-02T00:00:00Z",
        baseline_start="2026-04-30T00:00:00Z",
        baseline_end="2026-05-01T00:00:00Z",
        cluster="local",
        project_deployment_id="westernunion__akamai",
        table_name="logs",
    )

    dataset = json.loads(output.read_text(encoding="utf-8"))
    rows = dataset["rows"]
    assert len(queries) == 8
    assert dataset["schema_version"] == "threat_hunt_dataset.v1"
    assert dataset["query_sql"]
    assert dataset["query_sha256"]
    assert dataset["field_provenance"]["billing_bytes_per_row"] == "estimated"
    assert dataset["metadata"]["formula_provenance"]["billing_bytes_per_row"] == {
        "formula": "billing_bytes / rows",
        "source_fields": ["billing_bytes", "rows"],
        "source_table": "hydro.logs",
    }
    assert rows == [
        {
            "billing_bytes": 480,
            "billing_bytes_per_row": 10.0,
            "metadata_window_end": "2026-05-02 00:00:00",
            "metadata_window_start": "2026-04-30 00:00:00",
            "project_deployment_id": "westernunion__akamai",
            "raw_usage_bytes": 240,
            "raw_usage_bytes_per_row": 5.0,
            "rows": 48,
            "source": "hydro.logs usagemeter",
            "table_name": "logs",
        }
    ]


def test_hydrolix_usagemeter_export_discovers_database_deployment(tmp_path, monkeypatch) -> None:
    from bot_insights.producers import threat_hunt

    queries: list[str] = []

    def fake_export(cluster: str, sql: str, output: Path) -> None:
        queries.append(sql)
        if "GROUP BY project_deployment_id, table_name" in sql:
            output.write_text(
                json.dumps(
                    [
                        {"project_deployment_id": "westernunion__hydro", "table_name": "logs", "rows": 6, "billing_bytes": 60},
                        {"project_deployment_id": "westernunion__akamai", "table_name": "logs", "rows": 8, "billing_bytes": 80},
                    ]
                ),
                encoding="utf-8",
            )
            return
        assert "westernunion__akamai" in sql
        assert "westernunion__hydro" not in sql
        output.write_text(
            json.dumps(
                [
                    {
                        "project_deployment_id": "westernunion__akamai",
                        "table_name": "logs",
                        "rows": 8,
                        "billing_bytes": 80,
                        "raw_usage_bytes": 40,
                    }
                ]
            ),
            encoding="utf-8",
        )

    monkeypatch.setattr(threat_hunt, "_run_mux_export", fake_export)
    output = tmp_path / "usagemeter.json"

    threat_hunt.export_hydrolix_usagemeter_ingest_estimate(
        output=str(output),
        start="2026-05-01T00:00:00Z",
        end="2026-05-01T06:00:00Z",
        baseline_start="2026-04-30T00:00:00Z",
        baseline_end="2026-04-30T06:00:00Z",
        cluster="local",
        database="akamai",
        table_name="logs",
    )

    rows = json.loads(output.read_text(encoding="utf-8"))["rows"]
    assert len(queries) == 4
    assert rows[0]["project_deployment_id"] == "westernunion__akamai"
    assert rows[0]["billing_bytes_per_row"] == 10.0


def test_threat_hunt_summary_export_wraps_legacy_unavailable_fields(tmp_path, monkeypatch) -> None:
    from bot_insights.producers import threat_hunt

    def fake_export(cluster: str, sql: str, output: Path) -> None:
        if "FROM system.tables" in sql:
            count = 1 if "name = 'summary_hour'" in sql else 0
            output.write_text(json.dumps([{"table_count": count}]), encoding="utf-8")
            return
        if "candidate_rows" in sql:
            output.write_text(
                json.dumps(
                    [
                        {"period": "current", "candidate_rows": 1},
                        {"period": "baseline", "candidate_rows": 1},
                    ]
                ),
                encoding="utf-8",
            )
            return
        output.write_text(
            json.dumps(
                [
                    {"period": "current", "request_path": "/api", "country": "US", "requests": 10, "akamai_billed_bytes": 100},
                    {"period": "baseline", "request_path": "/api", "country": "US", "requests": 5, "akamai_billed_bytes": 50},
                ]
            ),
            encoding="utf-8",
        )

    monkeypatch.setattr(threat_hunt, "_run_mux_export", fake_export)
    output = tmp_path / "summary.json"

    threat_hunt.export_threat_hunt_summary(
        output=str(output),
        start="2026-05-01T00:00:00Z",
        end="2026-05-01T01:00:00Z",
        baseline_start="2026-04-30T00:00:00Z",
        baseline_end="2026-04-30T01:00:00Z",
        cluster="local",
        database="akamai",
        granularity="hour",
    )

    dataset = json.loads(output.read_text(encoding="utf-8"))
    assert dataset["schema_version"] == "threat_hunt_dataset.v1"
    assert dataset["source_table"] == "akamai.summary_hour"
    assert dataset["truncated"] is False
    assert dataset["row_count"] == dataset["total_row_count"] == 2
    for field in ("traffic_cohort", "bot_requests", "human_requests", "response_body_bytes", "status_429"):
        assert dataset["field_provenance"][field] == "synthetic_unavailable"

    rows = [threat_hunt._normalize_summary_row(row) for row in threat_hunt._read_json_rows(output)]
    assert rows[0]["traffic_cohort"] == ""
    assert rows[0]["bot_requests"] == 0
    assert rows[0]["response_body_bytes"] == 0


def test_threat_hunt_summary_export_uses_legacy_hour_for_minute_fallback(tmp_path, monkeypatch) -> None:
    from bot_insights.producers import threat_hunt

    exported_sql: list[str] = []

    def fake_export(cluster: str, sql: str, output: Path) -> None:
        exported_sql.append(sql)
        if "FROM system.tables" in sql:
            count = 1 if "name = 'summary_hour'" in sql else 0
            output.write_text(json.dumps([{"table_count": count}]), encoding="utf-8")
            return
        if "candidate_rows" in sql:
            output.write_text(
                json.dumps(
                    [
                        {"period": "current", "candidate_rows": 1},
                        {"period": "baseline", "candidate_rows": 1},
                    ]
                ),
                encoding="utf-8",
            )
            return
        output.write_text(
            json.dumps(
                [
                    {"period": "current", "request_path": "/api", "country": "US", "requests": 10, "akamai_billed_bytes": 100},
                    {"period": "baseline", "request_path": "/api", "country": "US", "requests": 5, "akamai_billed_bytes": 50},
                ]
            ),
            encoding="utf-8",
        )

    monkeypatch.setattr(threat_hunt, "_run_mux_export", fake_export)
    output = tmp_path / "summary.json"

    threat_hunt.export_threat_hunt_summary(
        output=str(output),
        start="2026-05-01T00:00:00Z",
        end="2026-05-01T01:00:00Z",
        baseline_start="2026-04-30T00:00:00Z",
        baseline_end="2026-04-30T01:00:00Z",
        cluster="local",
        database="akamai",
        granularity="minute",
    )

    dataset = json.loads(output.read_text(encoding="utf-8"))
    assert dataset["source_table"] == "akamai.summary_hour"
    assert any("name = 'summary_hour'" in sql for sql in exported_sql)
    assert not any("name = 'summary'" in sql for sql in exported_sql)
    assert "LIMIT 2000 BY period" in exported_sql[-1]
    assert dataset["metadata"]["selection"]["mode"] == "top_n_by_period"
    assert dataset["metadata"]["selection"]["limit_per_period"] == 2000
    assert dataset["metadata"]["population_complete"] is False
    assert dataset["metadata"]["evidence_role"] == "selected_summary_evidence"


def test_threat_hunt_summary_sql_uses_stable_top_n_tie_breakers() -> None:
    from bot_insights.producers import threat_hunt

    start = threat_hunt.parse_time("2026-05-01T00:00:00Z", "start")
    end = threat_hunt.parse_time("2026-05-01T01:00:00Z", "end")
    baseline_start = threat_hunt.parse_time("2026-04-30T00:00:00Z", "baseline-start")
    baseline_end = threat_hunt.parse_time("2026-04-30T01:00:00Z", "baseline-end")

    for builder in (
        threat_hunt._threat_hunt_summary_sql,
        threat_hunt._threat_hunt_legacy_summary_sql,
    ):
        sql = builder(
            database="akamai",
            table_name="summary_hour",
            start=start,
            end=end,
            baseline_start=baseline_start,
            baseline_end=baseline_end,
        )
        assert (
            "ORDER BY period, requests DESC, request_path ASC, country ASC, traffic_cohort ASC"
            in sql
        )


def test_threat_hunt_summary_export_metadata_records_stable_selection_order(tmp_path, monkeypatch) -> None:
    from bot_insights.producers import threat_hunt

    def fake_export(cluster: str, sql: str, output: Path) -> None:
        if "FROM system.tables" in sql:
            output.write_text(json.dumps([{"table_count": 1}]), encoding="utf-8")
            return
        if "candidate_rows" in sql:
            output.write_text(
                json.dumps(
                    [
                        {"period": "current", "candidate_rows": 2},
                        {"period": "baseline", "candidate_rows": 2},
                    ]
                ),
                encoding="utf-8",
            )
            return
        output.write_text(
            json.dumps(
                [
                    {
                        "period": "current",
                        "request_path": "/api",
                        "country": "US",
                        "traffic_cohort": "Bot",
                        "requests": 10,
                    },
                    {
                        "period": "baseline",
                        "request_path": "/api",
                        "country": "US",
                        "traffic_cohort": "Bot",
                        "requests": 5,
                    },
                ]
            ),
            encoding="utf-8",
        )

    monkeypatch.setattr(threat_hunt, "_run_mux_export", fake_export)
    output = tmp_path / "summary.json"

    threat_hunt.export_threat_hunt_summary(
        output=str(output),
        start="2026-05-01T00:00:00Z",
        end="2026-05-01T01:00:00Z",
        baseline_start="2026-04-30T00:00:00Z",
        baseline_end="2026-04-30T01:00:00Z",
        cluster="local",
        database="akamai",
        granularity="hour",
    )

    dataset = json.loads(output.read_text(encoding="utf-8"))
    assert dataset["metadata"]["selection"]["order_by"] == [
        "period",
        "requests DESC",
        "request_path ASC",
        "country ASC",
        "traffic_cohort ASC",
    ]


def test_threat_hunt_summary_export_marks_selected_top_n_when_bounded(tmp_path, monkeypatch) -> None:
    from bot_insights.producers import threat_hunt

    def fake_export(cluster: str, sql: str, output: Path) -> None:
        if "FROM system.tables" in sql:
            output.write_text(json.dumps([{"table_count": 1}]), encoding="utf-8")
            return
        if "candidate_rows" in sql:
            output.write_text(
                json.dumps(
                    [
                        {"period": "current", "candidate_rows": 2500},
                        {"period": "baseline", "candidate_rows": 2500},
                    ]
                ),
                encoding="utf-8",
            )
            return
        rows = [
            {
                "period": "current" if index < 2000 else "baseline",
                "request_path": f"/api/{index}",
                "country": "US",
                "traffic_cohort": "Bot",
                "requests": 10_000 - index,
            }
            for index in range(4000)
        ]
        output.write_text(json.dumps(rows), encoding="utf-8")

    monkeypatch.setattr(threat_hunt, "_run_mux_export", fake_export)
    output = tmp_path / "summary.json"

    threat_hunt.export_threat_hunt_summary(
        output=str(output),
        start="2026-05-01T00:00:00Z",
        end="2026-05-01T01:00:00Z",
        baseline_start="2026-04-30T00:00:00Z",
        baseline_end="2026-04-30T01:00:00Z",
        cluster="local",
        database="akamai",
        granularity="hour",
    )

    dataset = json.loads(output.read_text(encoding="utf-8"))
    selection = dataset["metadata"]["selection"]
    assert dataset["row_count"] == 4000
    assert dataset["total_row_count"] == 5000
    assert dataset["truncated"] is True
    assert selection["candidate_row_count"] == 5000
    assert selection["selected_row_count"] == 4000
    assert selection["candidate_rows_by_period"] == {"baseline": 2500, "current": 2500}
    assert selection["population_complete"] is False
    assert selection["evidence_role"] == "selected_summary_evidence"


def test_full_required_accepts_selected_summary_but_rejects_truncated_non_summary(tmp_path) -> None:
    from bot_insights.producers import threat_hunt

    summary = tmp_path / "summary.json"
    threat_hunt.write_threat_hunt_dataset(
        summary,
        stage_id="summary_export",
        cluster="local",
        database="akamai",
        source_table="akamai.bi_summary_hour",
        query_sql="SELECT summary",
        rows=[
            {"period": "current", "request_path": "/api/current", "requests": 10},
            {"period": "baseline", "request_path": "/api/baseline", "requests": 5},
        ],
        total_row_count=4,
        truncated=True,
        metadata={
            "population_complete": False,
            "evidence_role": "selected_summary_evidence",
            "selection": {
                "mode": "top_n_by_period",
                "limit_per_period": threat_hunt.SUMMARY_EXPORT_ROWS_PER_PERIOD,
                "population_complete": False,
                "evidence_role": "selected_summary_evidence",
                "order_by": [
                    "period",
                    "requests DESC",
                    "request_path ASC",
                    "country ASC",
                    "traffic_cohort ASC",
                ],
                "candidate_rows_by_period": {"current": 2, "baseline": 2},
                "candidate_row_count": 4,
                "selected_row_count": 2,
                "selection_sql_sha256": "abc",
                "candidate_count_sql_sha256": "def",
            },
        },
    )
    assert threat_hunt.validate_replay_grade_dataset(summary, role="summary")["truncated"] is True

    cooccurrence = tmp_path / "cooccurrence.json"
    threat_hunt.write_threat_hunt_dataset(
        cooccurrence,
        stage_id="cooccurrence",
        cluster="local",
        database="akamai",
        source_table="akamai.logs",
        query_sql="SELECT cooccurrence",
        rows=[{"client_ip": "8.8.8.8", "user_agent": "UA", "requests": 1}],
        total_row_count=2,
        truncated=True,
    )
    try:
        threat_hunt.validate_replay_grade_dataset(cooccurrence, role="cooccurrence")
    except SystemExit as exc:
        assert "truncated=false" in str(exc)
    else:
        raise AssertionError("expected truncated non-summary artifact to fail")


def test_full_required_rejects_malformed_selected_summary_metadata(tmp_path) -> None:
    from bot_insights.producers import threat_hunt

    summary = tmp_path / "summary.json"
    threat_hunt.write_threat_hunt_dataset(
        summary,
        stage_id="summary_export",
        cluster="local",
        database="akamai",
        source_table="akamai.bi_summary_hour",
        query_sql="SELECT summary",
        rows=[{"period": "current", "request_path": "/api", "requests": 10}],
        total_row_count=2,
        truncated=True,
        metadata={"selection": {"mode": "top_n_by_period"}},
    )
    try:
        threat_hunt.validate_replay_grade_dataset(summary, role="summary")
    except SystemExit as exc:
        assert "population_complete=false" in str(exc)
    else:
        raise AssertionError("expected malformed summary metadata to fail")


def _write_replay_local_inputs(tmp_path: Path) -> dict[str, str]:
    from bot_insights.producers import threat_hunt

    def write_dataset(name: str, role: str, rows: list[dict[str, object]]) -> Path:
        path = tmp_path / name
        metadata = None
        total_row_count = None
        truncated = False
        source_table = "akamai.logs"
        if role == "summary":
            source_table = "akamai.bi_summary_hour"
            total_row_count = len(rows)
            metadata = {
                "population_complete": False,
                "evidence_role": "selected_summary_evidence",
                "selection": {
                    "mode": "top_n_by_period",
                    "limit_per_period": threat_hunt.SUMMARY_EXPORT_ROWS_PER_PERIOD,
                    "population_complete": False,
                    "evidence_role": "selected_summary_evidence",
                    "order_by": [
                        "period",
                        "requests DESC",
                        "request_path ASC",
                        "country ASC",
                        "traffic_cohort ASC",
                    ],
                    "candidate_rows_by_period": {"current": 1, "baseline": 1},
                    "candidate_row_count": len(rows),
                    "selected_row_count": len(rows),
                    "selection_sql_sha256": "abc",
                    "candidate_count_sql_sha256": "def",
                },
            }
        threat_hunt.write_threat_hunt_dataset(
            path,
            stage_id=role,
            cluster="local",
            database="akamai",
            source_table=source_table,
            query_sql=f"SELECT {role}",
            rows=rows,
            total_row_count=total_row_count,
            truncated=truncated,
            metadata=metadata,
        )
        return path

    actor_dir = tmp_path / "actors"
    actor_dir.mkdir()
    for name, rows in {
        "expedia-actors-current-user_agent.json": [{"user_agent": "HighLead/1.0", "requests": 100}],
        "expedia-actors-baseline-user_agent.json": [{"user_agent": "HighLead/1.0", "requests": 10}],
        "expedia-actors-current-client_ip.json": [{"client_ip": "8.8.8.8", "requests": 100}],
        "expedia-actors-baseline-client_ip.json": [{"client_ip": "8.8.8.8", "requests": 10}],
    }.items():
        threat_hunt.write_threat_hunt_dataset(
            actor_dir / name,
            stage_id="raw_actor",
            cluster="local",
            database="akamai",
            source_table="akamai.logs",
            query_sql="SELECT raw_actor",
            rows=rows,
        )

    return {
        "--summary-parquet-glob": str(write_dataset("summary.json", "summary", [
            {"period": "current", "request_path": "/api", "requests": 100},
            {"period": "baseline", "request_path": "/api", "requests": 10},
        ])),
        "--raw-actor-dir": str(actor_dir),
        "--hydrolix-log-ingest-usagemeter-in": str(write_dataset("usagemeter.json", "hydrolix_usagemeter", [{"rows": 10, "billing_bytes": 100, "project_deployment_id": "local__akamai", "table_name": "logs"}])),
        "--cooccurrence-in": str(write_dataset("cooccurrence.json", "cooccurrence", [{"client_ip": "8.8.8.8", "user_agent": "HighLead/1.0", "requests": 100}])),
        "--scraper-drilldown-in": str(write_dataset("scraper-drilldown.json", "scraper_drilldown", [{"client_ip": "8.8.8.8", "user_agent": "HighLead/1.0", "request_path": "/api", "requests": 100}])),
        "--scraper-hourly-in": str(write_dataset("scraper-hourly.json", "scraper_hourly", [{"user_agent": "HighLead/1.0", "hour": "2026-05-01T00:00:00Z", "requests": 100}])),
        "--fanout-in": str(write_dataset("fanout.json", "fanout", [{"user_agent": "HighLead/1.0", "unique_ips": 1, "hits": 100}])),
        "--background-ua-sample-in": str(write_dataset("background.json", "background_ua_sample", [{"user_agent": "Organic/1.0", "requests": 100}])),
        "--baseline-ua-timeseries-in": str(write_dataset("baseline-ua.json", "baseline_ua_timeseries", [{"user_agent": "HighLead/1.0", "bucket": "2026-04-30T00:00:00Z", "requests": 10}])),
        "--impact-lane-totals-in": str(write_dataset("impact-totals.json", "impact_lane_totals", [{"scope": "current_total", "requests": 100, "response_body_bytes": 10, "akamai_billed_bytes": 20}, {"scope": "baseline_total", "requests": 10, "response_body_bytes": 1, "akamai_billed_bytes": 2}])),
        "--impact-lane-scoped-hunt-in": str(write_dataset("impact-scoped.json", "impact_lane_scoped_hunt", [{"scope": "current_high_partial", "requests": 50, "response_body_bytes": 5, "akamai_billed_bytes": 10}, {"scope": "baseline_high_partial", "requests": 5, "response_body_bytes": 1, "akamai_billed_bytes": 2}])),
    }


def _replay_local_argv(tmp_path: Path, inputs: dict[str, str]) -> list[str]:
    argv = [
        "bot-insights-report",
        "--cluster",
        "local",
        "--database",
        "akamai",
        "--report",
        "threat_hunt",
        "--mode",
        "evidence",
        "--threat-hunt-harvest",
        "replay-local",
        "--start",
        "2026-05-01T00:00:00Z",
        "--end",
        "2026-05-01T01:00:00Z",
        "--baseline-start",
        "2026-04-30T00:00:00Z",
        "--baseline-end",
        "2026-04-30T01:00:00Z",
        "--sample-dir",
        str(tmp_path / "sample"),
        "--output",
        str(tmp_path / "out.json"),
    ]
    for flag, value in inputs.items():
        argv.extend([flag, value])
    return argv


def test_replay_local_rejects_missing_required_local_inputs(tmp_path) -> None:
    from bot_insights.producers import cli

    inputs = _write_replay_local_inputs(tmp_path)
    for missing_flag in sorted(inputs):
        argv = _replay_local_argv(tmp_path, {key: value for key, value in inputs.items() if key != missing_flag})
        with mock.patch.object(sys, "argv", argv):
            try:
                cli.main()
            except SystemExit as exc:
                assert missing_flag in str(exc)
            else:
                raise AssertionError(f"expected missing {missing_flag} to fail")


def test_replay_local_rejects_unwrapped_required_input(tmp_path) -> None:
    from bot_insights.producers import cli

    inputs = _write_replay_local_inputs(tmp_path)
    unwrapped = tmp_path / "unwrapped-cooccurrence.json"
    unwrapped.write_text(json.dumps([{"client_ip": "8.8.8.8", "user_agent": "HighLead/1.0"}]), encoding="utf-8")
    inputs["--cooccurrence-in"] = str(unwrapped)

    with mock.patch.object(sys, "argv", _replay_local_argv(tmp_path, inputs)):
        try:
            cli.main()
        except SystemExit as exc:
            assert "lacks threat_hunt_dataset.v1" in str(exc)
        else:
            raise AssertionError("expected unwrapped replay-local input to fail")


def test_replay_local_uses_only_supplied_inputs_and_writes_policy(tmp_path, monkeypatch) -> None:
    from bot_insights.producers import cli

    inputs = _write_replay_local_inputs(tmp_path)
    called_exports: list[str] = []
    for name in (
        "export_threat_hunt_summary",
        "export_raw_actor_fixtures",
        "export_hydrolix_usagemeter_ingest_estimate",
        "export_raw_ua_cooccurrence",
        "export_scraper_drilldowns",
        "export_scraper_hourly_profiles",
        "export_fanout_enrichment",
        "export_background_ua_sample",
        "export_baseline_ua_timeseries",
        "export_impact_lane_totals",
        "export_impact_lane_scoped_hunt",
    ):
        monkeypatch.setattr(cli, name, lambda *args, _name=name, **kwargs: called_exports.append(_name))
    build_calls: list[dict[str, object]] = []

    def fake_build(**kwargs):
        build_calls.append(kwargs)
        return {
            "schema_version": "bot_threat_hunt.v3",
            "endpoints": [],
            "artifact_metadata": {},
            "impact_assessment": {"hunt": {"user_agents": ["HighLead/1.0"]}},
        }

    monkeypatch.setattr(cli, "build_threat_hunt_artifact", fake_build)
    monkeypatch.setattr(cli, "merge_impact_lanes_into_artifact", lambda *args, **kwargs: None)

    with mock.patch.object(sys, "argv", _replay_local_argv(tmp_path, inputs)):
        assert cli.main() == 0

    assert called_exports == []
    assert build_calls[0]["require_replay_grade"] is True
    artifact = json.loads((tmp_path / "sample" / "threat_hunt-artifact.json").read_text(encoding="utf-8"))
    policy = artifact["artifact_metadata"]["replay_policy"]
    assert policy["schema_version"] == "threat_hunt_replay_policy.v1"
    assert policy["mode"] == "local_only"
    assert policy["live_hydrolix_queries_allowed"] is False
    assert policy["validation"]["status"] == "passed"
    assert policy["input_manifest"]["schema_version"] == "threat_hunt_input_manifest.v1"


def test_rendered_threat_hunt_export_json_includes_replay_policy() -> None:
    from bot_insights.report_engine.contexts import threat_hunt as context

    artifact = {
        "schema_version": "bot_threat_hunt.v3",
        "scope": {"cluster": "local", "current_window": {}, "baseline_window": {}},
        "artifact_metadata": {
            "replay_policy": {
                "schema_version": "threat_hunt_replay_policy.v1",
                "mode": "local_only",
                "live_hydrolix_queries_allowed": False,
                "validation": {"status": "passed"},
                "input_manifest": {"schema_version": "threat_hunt_input_manifest.v1"},
            }
        },
        "module_scorecards": [],
        "baseline_movement": {"metric_deltas": []},
        "scraper_cases": [],
        "campaigns": [],
        "recommended_actions": [],
        "impact_assessment": {},
        "limitations": [],
        "interpretation_constraints": [],
    }

    prepared = context.prepare(artifact)
    export_payload = json.loads(prepared["threat_hunt_ui"]["exports"]["json"])

    assert export_payload["replay_policy"]["mode"] == "local_only"
    assert export_payload["replay_policy"]["live_hydrolix_queries_allowed"] is False


def test_full_required_provenance_rejects_replay_local_missing_manifest_role(tmp_path) -> None:
    from bot_insights.producers import cli

    inputs = _write_replay_local_inputs(tmp_path)
    input_manifest = cli.build_threat_hunt_input_manifest(
        summary_parquet_glob=inputs["--summary-parquet-glob"],
        raw_actor_dir=inputs["--raw-actor-dir"],
        hydrolix_log_ingest_usagemeter_in=inputs["--hydrolix-log-ingest-usagemeter-in"],
        cooccurrence_in=None,
        scraper_drilldown_in=inputs["--scraper-drilldown-in"],
        scraper_hourly_in=inputs["--scraper-hourly-in"],
        fanout_in=inputs["--fanout-in"],
        background_ua_sample_in=inputs["--background-ua-sample-in"],
        baseline_ua_timeseries_in=inputs["--baseline-ua-timeseries-in"],
        impact_lane_totals_in=inputs["--impact-lane-totals-in"],
        impact_lane_scoped_hunt_in=inputs["--impact-lane-scoped-hunt-in"],
    )
    artifact_path = tmp_path / "artifact.json"
    artifact_path.write_text(
        json.dumps(
            {
                "schema_version": "bot_threat_hunt.v3",
                "artifact_metadata": {
                    "input_manifest": input_manifest,
                    "replay_policy": {
                        "schema_version": "threat_hunt_replay_policy.v1",
                        "mode": "local_only",
                        "live_hydrolix_queries_allowed": False,
                    },
                },
            }
        ),
        encoding="utf-8",
    )
    complete_manifest = cli.build_threat_hunt_input_manifest(
        summary_parquet_glob=inputs["--summary-parquet-glob"],
        raw_actor_dir=inputs["--raw-actor-dir"],
        hydrolix_log_ingest_usagemeter_in=inputs["--hydrolix-log-ingest-usagemeter-in"],
        cooccurrence_in=inputs["--cooccurrence-in"],
        scraper_drilldown_in=inputs["--scraper-drilldown-in"],
        scraper_hourly_in=inputs["--scraper-hourly-in"],
        fanout_in=inputs["--fanout-in"],
        background_ua_sample_in=inputs["--background-ua-sample-in"],
        baseline_ua_timeseries_in=inputs["--baseline-ua-timeseries-in"],
        impact_lane_totals_in=inputs["--impact-lane-totals-in"],
        impact_lane_scoped_hunt_in=inputs["--impact-lane-scoped-hunt-in"],
    )
    role_stage = {
        "summary": "summary_export",
        "raw_actor": "raw_actor_fixtures",
        "hydrolix_usagemeter": "hydrolix_usagemeter",
        "cooccurrence": "cooccurrence",
        "scraper_drilldown": "scraper_drilldown",
        "scraper_hourly": "scraper_hourly",
        "fanout": "fanout",
        "background_ua_sample": "background_ua_sample",
        "baseline_ua_timeseries": "baseline_ua_timeseries",
        "impact_lane_totals": "impact_lane_totals",
        "impact_lane_scoped_hunt": "impact_lane_scoped_hunt",
    }
    replay_artifacts = [
        {
            "role": entry["role"],
            "path": entry["path"],
            "exists": True,
            "planned": True,
            "plan_hash": "planhash",
            "plan_stage_id": role_stage[entry["role"]],
            "dataset_query_sha256": entry["threat_hunt_dataset"]["query_sha256"],
            "dataset_output_sha256": entry["threat_hunt_dataset"]["output_sha256"],
        }
        for entry in complete_manifest["inputs"]
        if entry["role"] in cli.THREAT_HUNT_FULL_REQUIRED_REPLAY_ROLES
    ]
    replay_artifacts.append({"role": "threat_hunt_artifact", "path": str(artifact_path), "exists": True})
    provenance = tmp_path / "provenance.json"
    provenance.write_text(
        json.dumps(
            {
                "schema_version": "threat_hunt_full_required.v1",
                "harvest_plan": _minimal_harvest_plan(cli),
                "replay_context": {
                    "audit_events": [{"sequence": 1, "event_type": "workflow_start"}],
                    "artifacts": replay_artifacts,
                },
            }
        ),
        encoding="utf-8",
    )

    try:
        cli.validate_threat_hunt_full_required_provenance(provenance)
    except SystemExit as exc:
        assert "cooccurrence" in str(exc)
    else:
        raise AssertionError("expected incomplete replay-local manifest to fail")


def test_threat_hunt_ranked_sql_uses_stable_tie_breakers() -> None:
    from bot_insights.producers import threat_hunt

    start = threat_hunt.parse_time("2026-05-01T00:00:00Z", "start")
    end = threat_hunt.parse_time("2026-05-01T01:00:00Z", "end")

    assert "ORDER BY requests DESC, user_agent ASC" in threat_hunt._raw_actor_sql(
        database="akamai",
        actor_type="user_agent",
        start=start,
        end=end,
        top_n=5,
    )
    assert "ORDER BY requests DESC, client_ip ASC" in threat_hunt._raw_actor_sql(
        database="akamai",
        actor_type="client_ip",
        start=start,
        end=end,
        top_n=5,
    )
    assert (
        "ORDER BY requests DESC, client_ip ASC, user_agent ASC"
        in threat_hunt._raw_cooccurrence_sql(
            database="akamai",
            start=start,
            end=end,
            client_ips=["1.1.1.1"],
            user_agents=["UA/1.0"],
        )
    )
    assert (
        "ORDER BY requests DESC, user_agent ASC, client_ip ASC, request_path ASC, hour ASC\nLIMIT 10"
        in threat_hunt._raw_scraper_drilldown_sql(
            database="akamai",
            start=start,
            end=end,
            client_ips=["1.1.1.1"],
            user_agents=["UA/1.0"],
            row_limit=10,
        )
    )
    assert (
        "ORDER BY unique_ips DESC, hits DESC, user_agent ASC"
        in threat_hunt._raw_ua_fanout_sql(
            database="akamai",
            start=start,
            end=end,
            user_agents=["UA/1.0"],
        )
    )
    assert (
        "ORDER BY unique_ips DESC, hits DESC, user_agent ASC"
        in threat_hunt._summary_hour_fanout_sql(
            database="akamai",
            start=start,
            end=end,
            user_agent="UA/1.0",
        )
    )
    assert (
        "ORDER BY unique_ips DESC, hits DESC, user_agent ASC"
        in threat_hunt._logs_probe_fanout_sql(
            database="akamai",
            start=start,
            end=end,
            user_agent="UA/1.0",
        )
    )
    assert (
        "ORDER BY cityHash64(user_agent), user_agent ASC"
        in threat_hunt._raw_background_ua_sample_sql(
            database="akamai",
            start=start,
            end=end,
            excluded_user_agents=[],
        )
    )

    iat_sql = threat_hunt._raw_iat_sample_sql(
        database="akamai",
        start=start,
        end=end,
        client_ips=["1.1.1.1"],
        user_agents=["UA/1.0"],
    )
    assert (
        "ORDER BY reqTimeSec, toString(cliIP), toString(reqPath), statusCode"
        in iat_sql
    )
    assert "ORDER BY user_agent, reqTimeSec, client_ip, request_path, status_code" in iat_sql


def test_threat_hunt_summary_export_rejects_one_sided_period_coverage(tmp_path, monkeypatch) -> None:
    from bot_insights.producers import threat_hunt

    def fake_export(cluster: str, sql: str, output: Path) -> None:
        if "FROM system.tables" in sql:
            output.write_text(json.dumps([{"table_count": 1}]), encoding="utf-8")
            return
        output.write_text(
            json.dumps([{"period": "current", "request_path": "/api", "requests": 10}]),
            encoding="utf-8",
        )

    monkeypatch.setattr(threat_hunt, "_run_mux_export", fake_export)
    try:
        threat_hunt.export_threat_hunt_summary(
            output=str(tmp_path / "summary.json"),
            start="2026-05-01T00:00:00Z",
            end="2026-05-01T01:00:00Z",
            baseline_start="2026-04-30T00:00:00Z",
            baseline_end="2026-04-30T01:00:00Z",
            cluster="local",
            database="akamai",
            granularity="hour",
        )
    except SystemExit as exc:
        assert "both current and baseline rows" in str(exc)
    else:
        raise AssertionError("expected one-sided summary export to fail")


def test_full_required_rejects_unwrapped_summary_input(tmp_path, monkeypatch) -> None:
    from bot_insights.producers import threat_hunt

    summary = tmp_path / "summary.json"
    summary.write_text(
        json.dumps(
            [
                {"period": "current", "request_path": "/api", "requests": 10},
                {"period": "baseline", "request_path": "/api", "requests": 5},
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(threat_hunt, "load_raw_actor_rows", lambda raw_actor_dir: [])

    try:
        threat_hunt.build_threat_hunt_artifact(
            cluster="local",
            database="akamai",
            summary_parquet_glob=str(summary),
            start="2026-05-01T00:00:00Z",
            end="2026-05-01T01:00:00Z",
            baseline_start="2026-04-30T00:00:00Z",
            baseline_end="2026-04-30T01:00:00Z",
            require_replay_grade=True,
        )
    except SystemExit as exc:
        assert "lacks threat_hunt_dataset.v1" in str(exc)
    else:
        raise AssertionError("expected full-required unwrapped summary to fail")


def test_summary_sidecar_manifest_imports_field_provenance(tmp_path) -> None:
    from bot_insights.producers import threat_hunt

    summary = tmp_path / "summary.json"
    summary.write_text(
        json.dumps([{"period": "current", "request_path": "/api", "requests": 10, "bot_requests": 0}]),
        encoding="utf-8",
    )
    (tmp_path / "summary.json.manifest.json").write_text(
        json.dumps(
            {
                "schema_version": "threat_hunt_dataset.v1",
                "stage_id": "summary_supplied",
                "cluster": "local",
                "database": "akamai",
                "source_table": "akamai.summary_hour",
                "row_count": 1,
                "total_row_count": 1,
                "truncated": False,
                "field_provenance": {"bot_requests": "synthetic_unavailable"},
                "metadata": {
                    "population_complete": False,
                    "evidence_role": "selected_summary_evidence",
                    "selection": {
                        "mode": "top_n_by_period",
                        "limit_per_period": 2000,
                        "population_complete": False,
                        "evidence_role": "selected_summary_evidence",
                        "order_by": [
                            "period",
                            "requests DESC",
                            "request_path ASC",
                            "country ASC",
                            "traffic_cohort ASC",
                        ],
                        "candidate_rows_by_period": {"current": 1, "baseline": 0},
                        "candidate_row_count": 1,
                        "selected_row_count": 1,
                        "selection_sql_sha256": "abc",
                        "candidate_count_sql_sha256": "def",
                    },
                },
            }
        ),
        encoding="utf-8",
    )

    threat_hunt.validate_replay_grade_dataset(summary, role="summary")
    raw_rows = threat_hunt.read_rows_from_glob(str(summary))
    rows = [threat_hunt._normalize_summary_row(row) for row in raw_rows]
    assert rows[0]["bot_requests"] == 0
    assert raw_rows[0]["__field_provenance"]["bot_requests"] == "synthetic_unavailable"


def test_threat_hunt_cli_auto_exports_hydrolix_usagemeter(tmp_path, monkeypatch) -> None:
    from bot_insights.producers import cli

    artifact = _threat_hunt_lane_artifact(tmp_path, monkeypatch)
    output = tmp_path / "out.json"
    sample_dir = tmp_path / "sample"
    calls: list[dict[str, object]] = []

    def fake_export(**kwargs):
        calls.append(kwargs)
        Path(str(kwargs["output"])).write_text(
            json.dumps([{"project_deployment_id": "westernunion__akamai", "table_name": "logs", "rows": 100, "billing_bytes": 1000}]),
            encoding="utf-8",
        )
        return Path(str(kwargs["output"]))

    monkeypatch.setattr(cli, "export_hydrolix_usagemeter_ingest_estimate", fake_export)
    argv = [
        "bot-insights-report",
        "--cluster",
        "local",
        "--database",
        "akamai",
        "--report",
        "threat_hunt",
        "--mode",
        "evidence",
        "--start",
        "2026-05-01T00:00:00Z",
        "--end",
        "2026-05-02T00:00:00Z",
        "--baseline-start",
        "2026-04-30T00:00:00Z",
        "--baseline-end",
        "2026-05-01T00:00:00Z",
        "--summary-parquet-glob",
        str(artifact["_test_summary_path"]),
        "--raw-actor-dir",
        str(artifact["_test_actor_dir"]),
        "--sample-dir",
        str(sample_dir),
        "--background-query",
        "off",
        "--baseline-significance-query",
        "off",
        "--ua-fanout-query",
        "skip",
        "--impact-lane-query",
        "off",
        "--output",
        str(output),
    ]

    with mock.patch.object(sys, "argv", argv):
        assert cli.main() == 0

    assert calls
    assert calls[0]["database"] == "akamai"
    assert calls[0]["project_deployment_id"] is None
    embedded = json.loads(output.read_text(encoding="utf-8"))
    assert embedded["impact_assessment"]["hydrolix_log_ingest_metadata"]["availability"] == "available"


def test_threat_hunt_cli_usagemeter_off_and_input_skip_auto_export(tmp_path, monkeypatch) -> None:
    from bot_insights.producers import cli

    artifact = _threat_hunt_lane_artifact(tmp_path, monkeypatch)
    calls: list[dict[str, object]] = []

    def fake_export(**kwargs):
        calls.append(kwargs)
        return Path(str(kwargs["output"]))

    monkeypatch.setattr(cli, "export_hydrolix_usagemeter_ingest_estimate", fake_export)
    base_argv = [
        "bot-insights-report",
        "--cluster",
        "local",
        "--database",
        "akamai",
        "--report",
        "threat_hunt",
        "--mode",
        "evidence",
        "--start",
        "2026-05-01T00:00:00Z",
        "--end",
        "2026-05-02T00:00:00Z",
        "--baseline-start",
        "2026-04-30T00:00:00Z",
        "--baseline-end",
        "2026-05-01T00:00:00Z",
        "--summary-parquet-glob",
        str(artifact["_test_summary_path"]),
        "--raw-actor-dir",
        str(artifact["_test_actor_dir"]),
        "--sample-dir",
        str(tmp_path / "sample"),
        "--background-query",
        "off",
        "--baseline-significance-query",
        "off",
        "--ua-fanout-query",
        "skip",
        "--impact-lane-query",
        "off",
    ]

    with mock.patch.object(sys, "argv", [*base_argv, "--hydrolix-log-ingest-usagemeter-query", "off", "--output", str(tmp_path / "off.json")]):
        assert cli.main() == 0
    with mock.patch.object(
        sys,
        "argv",
        [
            *base_argv,
            "--hydrolix-log-ingest-usagemeter-in",
            str(_write_usagemeter(tmp_path)),
            "--output",
            str(tmp_path / "input.json"),
        ],
    ):
        assert cli.main() == 0

    assert calls == []


def test_threat_hunt_cli_required_usagemeter_query_propagates_failure(tmp_path, monkeypatch) -> None:
    from bot_insights.producers import cli

    artifact = _threat_hunt_lane_artifact(tmp_path, monkeypatch)

    def fake_export(**kwargs):
        raise SystemExit("ambiguous usagemeter deployment")

    monkeypatch.setattr(cli, "export_hydrolix_usagemeter_ingest_estimate", fake_export)
    argv = [
        "bot-insights-report",
        "--cluster",
        "local",
        "--database",
        "akamai",
        "--report",
        "threat_hunt",
        "--mode",
        "evidence",
        "--start",
        "2026-05-01T00:00:00Z",
        "--end",
        "2026-05-02T00:00:00Z",
        "--baseline-start",
        "2026-04-30T00:00:00Z",
        "--baseline-end",
        "2026-05-01T00:00:00Z",
        "--summary-parquet-glob",
        str(artifact["_test_summary_path"]),
        "--raw-actor-dir",
        str(artifact["_test_actor_dir"]),
        "--sample-dir",
        str(tmp_path / "sample"),
        "--background-query",
        "off",
        "--baseline-significance-query",
        "off",
        "--ua-fanout-query",
        "skip",
        "--impact-lane-query",
        "off",
        "--hydrolix-log-ingest-usagemeter-query",
        "required",
        "--output",
        str(tmp_path / "required.json"),
    ]

    with mock.patch.object(sys, "argv", argv):
        try:
            cli.main()
        except SystemExit as exc:
            assert str(exc) == "ambiguous usagemeter deployment"
        else:
            raise AssertionError("expected required usagemeter query failure to propagate")


def test_threat_hunt_cli_full_required_harvests_summary_and_writes_provenance(tmp_path, monkeypatch) -> None:
    from bot_insights.producers import cli
    from bot_insights.producers import threat_hunt

    sample_dir = tmp_path / "sample"
    output = tmp_path / "out.json"
    build_calls: list[dict[str, object]] = []

    def write_json(path_value, rows):
        path = Path(str(path_value))
        path.parent.mkdir(parents=True, exist_ok=True)
        stage_by_name = {
            "threat_hunt-summary.json": "summary_export",
            "threat_hunt-hydrolix-usagemeter.json": "hydrolix_usagemeter",
            "threat_hunt-cooccurrence.json": "cooccurrence",
            "threat_hunt-scraper-drilldown.json": "scraper_drilldown",
            "threat_hunt-scraper-hourly.json": "scraper_hourly",
            "threat_hunt-fanout.json": "fanout",
            "threat_hunt-background-ua-sample.json": "background_ua_sample",
            "threat_hunt-baseline-ua-timeseries.json": "baseline_ua_timeseries",
            "threat_hunt-impact-lane-totals.json": "impact_lane_totals",
            "threat_hunt-impact-lane-scoped-hunt.json": "impact_lane_scoped_hunt",
            "expedia-actors-current-user_agent.json": "raw_actor",
            "expedia-actors-baseline-user_agent.json": "raw_actor",
            "expedia-actors-current-client_ip.json": "raw_actor",
            "expedia-actors-baseline-client_ip.json": "raw_actor",
        }
        metadata = None
        total_row_count = len(rows)
        truncated = False
        if stage_by_name.get(path.name) == "summary_export":
            current_count = sum(1 for row in rows if str(row.get("period", "")).lower() == "current")
            baseline_count = sum(1 for row in rows if str(row.get("period", "")).lower() == "baseline")
            metadata = {
                "population_complete": False,
                "evidence_role": "selected_summary_evidence",
                "selection": {
                    "mode": "top_n_by_period",
                    "limit_per_period": threat_hunt.SUMMARY_EXPORT_ROWS_PER_PERIOD,
                    "population_complete": False,
                    "evidence_role": "selected_summary_evidence",
                    "order_by": [
                        "period",
                        "requests DESC",
                        "request_path ASC",
                        "country ASC",
                        "traffic_cohort ASC",
                    ],
                    "candidate_rows_by_period": {
                        "current": current_count,
                        "baseline": baseline_count,
                    },
                    "candidate_row_count": len(rows),
                    "selected_row_count": len(rows),
                    "selection_sql_sha256": "abc",
                    "candidate_count_sql_sha256": "def",
                },
            }
        stage_id = stage_by_name.get(path.name, "test_stage")
        source_table = "akamai.logs"
        if stage_id == "summary_export":
            source_table = "akamai.bi_summary_hour"
        elif stage_id == "hydrolix_usagemeter":
            source_table = "hydro.logs"
        elif stage_id == "fanout":
            source_table = "akamai.summary_hour"
        threat_hunt.write_threat_hunt_dataset(
            path,
            stage_id=stage_id,
            cluster="local",
            database="akamai",
            source_table=source_table,
            query_sql="SELECT test",
            rows=rows,
            total_row_count=total_row_count,
            truncated=truncated,
            metadata=metadata,
        )
        return path

    def fake_summary(**kwargs):
        return write_json(
            kwargs["output"],
            [
                {"period": "current", "request_path": "/api/catalog", "requests": 1000, "bytes": 1},
                {"period": "baseline", "request_path": "/api/catalog", "requests": 100, "bytes": 1},
            ],
        )

    def fake_actors(**kwargs):
        actor_dir = Path(str(kwargs["actor_dir"]))
        write_json(actor_dir / "expedia-actors-current-user_agent.json", [{"user_agent": "HighLead/1.0", "requests": 400}])
        write_json(actor_dir / "expedia-actors-baseline-user_agent.json", [{"user_agent": "HighLead/1.0", "requests": 40}])
        write_json(actor_dir / "expedia-actors-current-client_ip.json", [{"client_ip": "8.8.8.8", "requests": 400}])
        write_json(actor_dir / "expedia-actors-baseline-client_ip.json", [{"client_ip": "8.8.8.8", "requests": 40}])
        return actor_dir

    monkeypatch.setattr(cli, "export_threat_hunt_summary", fake_summary)
    monkeypatch.setattr(cli, "export_raw_actor_fixtures", fake_actors)
    monkeypatch.setattr(
        cli,
        "export_hydrolix_usagemeter_ingest_estimate",
        lambda **kwargs: write_json(kwargs["output"], [{"project_deployment_id": "westernunion__akamai", "table_name": "logs", "rows": 100, "billing_bytes": 1000}]),
    )
    monkeypatch.setattr(
        cli,
        "export_raw_ua_cooccurrence",
        lambda **kwargs: [
            write_json(kwargs["output"], [{"client_ip": "8.8.8.8", "user_agent": "HighLead/1.0", "requests": 400}])
            and {"client_ip": "8.8.8.8", "user_agent": "HighLead/1.0", "requests": 400}
        ],
    )
    monkeypatch.setattr(
        cli,
        "scraper_drilldown_scope",
        lambda **kwargs: {
            "selected_user_agents": ["HighLead/1.0"],
            "selected_client_ips": ["8.8.8.8"],
            "excluded_non_public_client_ips": [],
            "chunks": [{"start": kwargs["start"], "end": kwargs["end"]}],
            "first_sql": "SELECT 1",
        },
    )
    monkeypatch.setattr(
        cli,
        "export_scraper_drilldowns",
        lambda **kwargs: [
            write_json(kwargs["output"], [{"client_ip": "8.8.8.8", "user_agent": "HighLead/1.0", "requests": 400}])
            and {"client_ip": "8.8.8.8", "user_agent": "HighLead/1.0", "requests": 400}
        ],
    )
    monkeypatch.setattr(
        cli,
        "export_scraper_hourly_profiles",
        lambda **kwargs: [
            write_json(kwargs["output"], [{"hour": "2026-05-01T00:00:00Z", "user_agent": "HighLead/1.0", "requests": 400}])
            and {"hour": "2026-05-01T00:00:00Z", "user_agent": "HighLead/1.0", "requests": 400}
        ],
    )
    monkeypatch.setattr(
        cli,
        "export_fanout_enrichment",
        lambda **kwargs: [
            write_json(kwargs["output"], [{"user_agent": "HighLead/1.0", "unique_ips": 1, "hits": 400}])
            and {"user_agent": "HighLead/1.0", "unique_ips": 1, "hits": 400}
        ],
    )
    monkeypatch.setattr(
        cli,
        "export_background_ua_sample",
        lambda **kwargs: [
            write_json(kwargs["output"], [{"user_agent": "Organic/1.0", "requests": 200}])
            and {"user_agent": "Organic/1.0", "requests": 200}
        ],
    )
    monkeypatch.setattr(
        cli,
        "export_baseline_ua_timeseries",
        lambda **kwargs: [
            write_json(kwargs["output"], [{"user_agent": "HighLead/1.0", "bucket": "2026-04-30", "requests": 40}])
            and {"user_agent": "HighLead/1.0", "bucket": "2026-04-30", "requests": 40}
        ],
    )
    monkeypatch.setattr(
        cli,
        "export_impact_lane_totals",
        lambda **kwargs: [
            write_json(kwargs["output"], [{"scope": "current_total", "requests": 1000, "response_body_bytes": 1, "akamai_billed_bytes": 1}, {"scope": "baseline_total", "requests": 100, "response_body_bytes": 1, "akamai_billed_bytes": 1}])
            and {"scope": "current_total", "requests": 1000, "response_body_bytes": 1, "akamai_billed_bytes": 1}
        ],
    )
    monkeypatch.setattr(
        cli,
        "export_impact_lane_scoped_hunt",
        lambda **kwargs: [
            write_json(kwargs["output"], [{"scope": "current_high_partial", "requests": 400, "response_body_bytes": 1, "akamai_billed_bytes": 1}, {"scope": "baseline_high_partial", "requests": 40, "response_body_bytes": 1, "akamai_billed_bytes": 1}])
            and {"scope": "current_high_partial", "requests": 400, "response_body_bytes": 1, "akamai_billed_bytes": 1}
        ],
    )

    def fake_build(**kwargs):
        build_calls.append(kwargs)
        return {
            "schema_version": "bot_threat_hunt.v3",
            "endpoints": [{"value": "/api/catalog"}],
            "impact_assessment": {
                "totals": {"current": {"requests": 1000}, "baseline": {"requests": 100}},
                "hunt": {"user_agents": ["HighLead/1.0"]},
            },
        }

    monkeypatch.setattr(cli, "build_threat_hunt_artifact", fake_build)
    plan_path = tmp_path / "harvest-plan.json"
    plan_argv = [
        "bot-insights-report",
        "--cluster",
        "local",
        "--database",
        "akamai",
        "--report",
        "threat_hunt",
        "--threat-hunt-harvest-plan-out",
        str(plan_path),
        "--threat-hunt-harvest-plan-offline",
        "--start",
        "2026-05-01T00:00:00Z",
        "--end",
        "2026-05-02T00:00:00Z",
        "--baseline-start",
        "2026-04-30T00:00:00Z",
        "--baseline-end",
        "2026-05-01T00:00:00Z",
    ]
    with mock.patch.object(sys, "argv", plan_argv):
        assert cli.main() == 0
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    assert plan["schema_version"] == "threat_hunt_harvest_plan.v1"
    assert plan["hash"]
    argv = [
        "bot-insights-report",
        "--cluster",
        "local",
        "--database",
        "akamai",
        "--report",
        "threat_hunt",
        "--mode",
        "evidence",
        "--threat-hunt-harvest",
        "full-required",
        "--threat-hunt-harvest-plan",
        str(plan_path),
        "--start",
        "2026-05-01T00:00:00Z",
        "--end",
        "2026-05-02T00:00:00Z",
        "--baseline-start",
        "2026-04-30T00:00:00Z",
        "--baseline-end",
        "2026-05-01T00:00:00Z",
        "--sample-dir",
        str(sample_dir),
        "--output",
        str(output),
    ]

    with mock.patch.object(sys, "argv", argv):
        assert cli.main() == 0

    assert build_calls[0]["summary_parquet_glob"] == str(sample_dir / "threat_hunt-summary.json")
    assert build_calls[0]["cooccurrence_in"] == str(sample_dir / "threat_hunt-cooccurrence.json")
    assert build_calls[0]["scraper_drilldown_in"] == str(sample_dir / "threat_hunt-scraper-drilldown.json")
    assert build_calls[0]["scraper_hourly_in"] == str(sample_dir / "threat_hunt-scraper-hourly.json")
    assert (sample_dir / "threat_hunt-audit.jsonl").exists()
    manifest = json.loads((sample_dir / "threat_hunt-provenance.json").read_text(encoding="utf-8"))
    assert manifest["schema_version"] == "threat_hunt_full_required.v1"
    assert manifest["harvest_plan"]["schema_version"] == "threat_hunt_harvest_plan.v1"
    assert manifest["harvest_plan"]["hash"] == plan["hash"]
    artifact_json = json.loads((sample_dir / "threat_hunt-artifact.json").read_text(encoding="utf-8"))
    assert artifact_json["artifact_metadata"]["input_manifest"]["schema_version"] == "threat_hunt_input_manifest.v1"
    assert artifact_json["artifact_metadata"]["harvest_plan"]["hash"] == plan["hash"]
    assert any(item["role"] == "summary" and item["source"] == "generated" for item in manifest["artifacts"])
    generated = {
        item["role"]: item
        for item in manifest["artifacts"]
        if item["source"] == "generated" and item["role"] != "selected_output"
    }
    expected_dataset_roles = {
        "summary",
        "raw_actor",
        "hydrolix_usagemeter",
        "cooccurrence",
        "scraper_drilldown",
        "scraper_hourly",
        "fanout",
        "background_ua_sample",
        "baseline_ua_timeseries",
        "impact_lane_totals",
        "impact_lane_scoped_hunt",
    }
    for role in expected_dataset_roles:
        assert generated[role]["dataset_schema_version"] == "threat_hunt_dataset.v1"
        assert generated[role]["dataset_truncated"] is False
        assert generated[role]["dataset_query_sql"] == "SELECT test"
        assert generated[role]["dataset_query_sha256"]
        assert generated[role]["dataset_output_sha256"]
        assert generated[role]["planned"] is True
        assert generated[role]["plan_hash"] == plan["hash"]
        assert generated[role]["plan_stage_id"]
    replay_context = manifest["replay_context"]
    assert replay_context["schema_version"] == "threat_hunt_replay_context.v1"
    assert replay_context["validation"]["audit_jsonl_required"] is False
    assert replay_context["audit_events"]
    assert replay_context["artifact_roles"]
    for role in expected_dataset_roles:
        assert role in replay_context["artifact_roles"]
    (sample_dir / "threat_hunt-audit.jsonl").unlink()
    cli.validate_threat_hunt_full_required_provenance(sample_dir / "threat_hunt-provenance.json")


def test_threat_hunt_audit_manifest_embeds_replay_events(tmp_path) -> None:
    from bot_insights.producers.cli import ThreatHuntAudit

    audit = ThreatHuntAudit(
        audit_path=tmp_path / "threat_hunt-audit.jsonl",
        manifest_path=tmp_path / "threat_hunt-provenance.json",
        argv=["bot-insights-report", "--api-token", "secret-token"],
    )
    audit(
        {
            "event_type": "mux_export",
            "stage_id": "summary_export",
            "argv": ["mcp-hydrolix-mux", "--api-token", "secret-token"],
            "sql": "SELECT 1",
            "output_path": str(tmp_path / "summary.json"),
            "output_rows": 1,
            "output_sha256": "abc",
        }
    )
    audit.decision(
        stage_id="summary_export",
        decision="resolved_summary_table",
        rationale="test",
        table="akamai.bi_summary_hour",
    )
    audit.manifest(status="ok", outputs={"output": str(tmp_path / "out.html")})

    manifest = json.loads((tmp_path / "threat_hunt-provenance.json").read_text(encoding="utf-8"))
    replay_context = manifest["replay_context"]
    assert manifest["argv"] == ["bot-insights-report", "--api-token", "<redacted>"]
    assert replay_context["audit_events"][0]["event_type"] == "mux_export"
    assert replay_context["audit_events"][0]["argv"] == [
        "mcp-hydrolix-mux",
        "--api-token",
        "<redacted>",
    ]
    assert replay_context["audit_events"][0]["sql"] == "SELECT 1"
    assert replay_context["audit_events"][0]["sql_sha256"]
    assert replay_context["export_events"][0]["output_rows"] == 1
    assert replay_context["stage_decisions"][0]["decision"] == "resolved_summary_table"


def test_full_required_provenance_validation_rejects_audit_jsonl_side_channel(tmp_path) -> None:
    from bot_insights.producers import cli

    manifest_path = tmp_path / "threat_hunt-provenance.json"
    audit_path = tmp_path / "threat_hunt-audit.jsonl"
    audit_path.write_text('{"event_type":"artifact"}\n', encoding="utf-8")
    manifest_path.write_text(
        json.dumps(
            {
                "schema_version": "threat_hunt_full_required.v1",
                "status": "ok",
                "audit_jsonl": str(audit_path),
                "artifacts": [],
            }
        ),
        encoding="utf-8",
    )

    try:
        cli.validate_threat_hunt_full_required_provenance(manifest_path)
    except SystemExit as exc:
        assert "threat_hunt_harvest_plan.v1" in str(exc)
    else:
        raise AssertionError("expected missing harvest plan to fail")


def test_full_required_requires_harvest_plan_before_execution(tmp_path) -> None:
    from bot_insights.producers import cli

    argv = [
        "bot-insights-report",
        "--cluster",
        "local",
        "--database",
        "akamai",
        "--report",
        "threat_hunt",
        "--mode",
        "evidence",
        "--threat-hunt-harvest",
        "full-required",
        "--start",
        "2026-05-01T00:00:00Z",
        "--end",
        "2026-05-02T00:00:00Z",
        "--baseline-start",
        "2026-04-30T00:00:00Z",
        "--baseline-end",
        "2026-05-01T00:00:00Z",
        "--output",
        str(tmp_path / "out.json"),
    ]

    with mock.patch.object(sys, "argv", argv):
        try:
            cli.main()
        except SystemExit as exc:
            assert "--threat-hunt-harvest-plan" in str(exc)
        else:
            raise AssertionError("expected full-required without harvest plan to fail")


def test_harvest_plan_validation_rejects_unresolved_auto() -> None:
    from bot_insights.producers import cli

    plan = _minimal_harvest_plan(cli)
    plan.update(
        {
            "cluster": "local",
            "database": "akamai",
            "current_window": {"start": "2026-05-01T00:00:00Z", "end": "2026-05-02T00:00:00Z"},
            "top_n": 10,
            "stages": [
                {
                    "stage_id": stage_id,
                    "required": True,
                    "output_role": cli.THREAT_HUNT_HARVEST_STAGE_ROLES[stage_id],
                    "sql_hash_policy": "required_recorded",
                    "output_hash_policy": "required_recorded",
                }
                for stage_id in sorted(cli.THREAT_HUNT_HARVEST_PLAN_REQUIRED_STAGE_IDS)
            ],
            "fanout": {"strategy": "auto", "fallback_allowed": False},
            "fallback_policy": {
                "mode": "fail_closed",
                "silent_fanout_fallback": False,
                "auto_usagemeter_ambiguity": False,
                "optional_enrichment_downgrade": False,
            },
        }
    )
    plan = cli._attach_harvest_plan_hash(plan)

    try:
        cli.validate_threat_hunt_harvest_plan(plan)
    except SystemExit as exc:
        assert "fanout.strategy" in str(exc)
    else:
        raise AssertionError("expected unresolved auto strategy to fail")


def _assert_replay_dataset(path: Path, stage_id: str) -> dict:
    dataset = json.loads(path.read_text(encoding="utf-8"))
    assert dataset["schema_version"] == "threat_hunt_dataset.v1"
    assert dataset["stage_id"] == stage_id
    assert dataset["truncated"] is False
    assert dataset["row_count"] == dataset["total_row_count"] == len(dataset["rows"])
    assert dataset["field_provenance"]
    assert dataset["output_sha256"]
    return dataset


def _write_replay_actor_inputs(threat_hunt, actor_dir: Path) -> None:
    actor_dir.mkdir()
    actor_specs = {
        "expedia-actors-current-client_ip.json": ("raw_actor", [{"client_ip": "8.8.8.8", "requests": 100}]),
        "expedia-actors-baseline-client_ip.json": ("raw_actor", [{"client_ip": "8.8.8.8", "requests": 10}]),
        "expedia-actors-current-user_agent.json": ("raw_actor", [{"user_agent": "HighLead/1.0", "requests": 100}]),
        "expedia-actors-baseline-user_agent.json": ("raw_actor", [{"user_agent": "HighLead/1.0", "requests": 10}]),
    }
    for filename, (stage_id, rows) in actor_specs.items():
        threat_hunt.write_threat_hunt_dataset(
            actor_dir / filename,
            stage_id=stage_id,
            cluster="local",
            database="akamai",
            source_table="akamai.logs",
            query_sql="SELECT actor",
            rows=rows,
        )


def test_raw_actor_export_can_write_replay_dataset_wrappers(tmp_path, monkeypatch) -> None:
    from bot_insights.producers import threat_hunt

    def fake_export(_cluster: str, sql: str, output: Path) -> None:
        row = (
            {"client_ip": "8.8.8.8", "requests": 100}
            if "cliIP" in sql
            else {"user_agent": "HighLead/1.0", "requests": 100}
        )
        output.write_text(json.dumps([row]), encoding="utf-8")

    monkeypatch.setattr(threat_hunt, "_run_mux_export", fake_export)
    actor_dir = tmp_path / "actors"
    threat_hunt.export_raw_actor_fixtures(
        actor_dir=str(actor_dir),
        start="2026-05-01T00:00:00Z",
        end="2026-05-01T01:00:00Z",
        baseline_start="2026-04-30T00:00:00Z",
        baseline_end="2026-04-30T01:00:00Z",
        cluster="local",
        database="akamai",
        replay_grade=True,
    )

    for path in actor_dir.glob("*.json"):
        _assert_replay_dataset(path, "raw_actor")


def test_generated_intermediate_exporters_can_write_replay_datasets(tmp_path, monkeypatch) -> None:
    from bot_insights.producers import threat_hunt

    actor_dir = tmp_path / "actors"
    _write_replay_actor_inputs(threat_hunt, actor_dir)
    cooccurrence = tmp_path / "cooccurrence.json"
    threat_hunt.write_threat_hunt_dataset(
        cooccurrence,
        stage_id="cooccurrence",
        cluster="local",
        database="akamai",
        source_table="akamai.logs",
        query_sql="SELECT cooccurrence",
        rows=[{"client_ip": "8.8.8.8", "user_agent": "HighLead/1.0", "requests": 100}],
    )

    def fake_export(_cluster: str, sql: str, output: Path) -> None:
        if "GROUP BY client_ip, user_agent" in sql:
            rows = [{"client_ip": "8.8.8.8", "user_agent": "HighLead/1.0", "country": "US", "requests": 100}]
        elif "request_path" in sql and "toStartOfHour" in sql:
            rows = [{"client_ip": "8.8.8.8", "user_agent": "HighLead/1.0", "request_path": "/api", "hour": "2026-05-01 00:00:00", "requests": 100}]
        elif "GROUP BY user_agent, hour" in sql:
            rows = [{"user_agent": "HighLead/1.0", "hour": "2026-05-01T00:00:00Z", "requests": 100}]
        elif "targeted_endpoint_requests" in sql:
            rows = [{"user_agent": "Organic/1.0", "requests": 200, "unique_client_ips": 2, "targeted_endpoint_requests": 20, "status_429": 0, "status_5xx": 0}]
        elif "uniqExact" in sql:
            rows = [{"user_agent": "HighLead/1.0", "unique_ips": 1, "hits": 100, "bytes": 10}]
        elif " AS bucket" in sql:
            rows = [{"user_agent": "HighLead/1.0", "bucket": "2026-04-30", "requests": 10}]
        elif " AS scope" in sql:
            scope = "current_total" if "current_total" in sql else "baseline_total"
            if "current_high_partial" in sql:
                scope = "current_high_partial"
            elif "baseline_high_partial" in sql:
                scope = "baseline_high_partial"
            rows = [{"scope": scope, "requests": 100, "response_body_bytes": 10, "akamai_billed_bytes": 20}]
        else:
            rows = [{"requests": 1}]
        output.write_text(json.dumps(rows), encoding="utf-8")

    monkeypatch.setattr(threat_hunt, "_run_mux_export", fake_export)
    monkeypatch.setattr(threat_hunt, "_summary_hour_supports_ua", lambda **_kwargs: False)

    outputs = {
        "cooccurrence": tmp_path / "out-cooccurrence.json",
        "scraper_drilldown": tmp_path / "out-drilldown.json",
        "scraper_hourly": tmp_path / "out-hourly.json",
        "fanout": tmp_path / "out-fanout.json",
        "background_ua_sample": tmp_path / "out-background.json",
        "baseline_ua_timeseries": tmp_path / "out-baseline.json",
        "impact_lane_totals": tmp_path / "out-impact-total.json",
        "impact_lane_scoped_hunt": tmp_path / "out-impact-scoped.json",
    }
    threat_hunt.export_raw_ua_cooccurrence(actor_dir=str(actor_dir), start="2026-05-01T00:00:00Z", end="2026-05-01T01:00:00Z", cluster="local", output=str(outputs["cooccurrence"]), replay_grade=True)
    threat_hunt.export_scraper_drilldowns(actor_dir=str(actor_dir), cooccurrence_in=str(cooccurrence), start="2026-05-01T00:00:00Z", end="2026-05-01T01:00:00Z", cluster="local", output=str(outputs["scraper_drilldown"]), replay_grade=True)
    threat_hunt.export_scraper_hourly_profiles(actor_dir=str(actor_dir), cooccurrence_in=str(cooccurrence), start="2026-05-01T00:00:00Z", end="2026-05-01T01:00:00Z", cluster="local", output=str(outputs["scraper_hourly"]), replay_grade=True)
    threat_hunt.export_fanout_enrichment(actor_dir=str(actor_dir), start="2026-05-01T00:00:00Z", end="2026-05-01T01:00:00Z", cluster="local", output=str(outputs["fanout"]), strategy="logs_probe", scraper_hourly_in=str(outputs["scraper_hourly"]), replay_grade=True)
    threat_hunt.export_background_ua_sample(start="2026-05-01T00:00:00Z", end="2026-05-01T01:00:00Z", cluster="local", output=str(outputs["background_ua_sample"]), replay_grade=True)
    threat_hunt.export_baseline_ua_timeseries(baseline_start="2026-04-30T00:00:00Z", baseline_end="2026-04-30T01:00:00Z", user_agents=["HighLead/1.0"], cluster="local", output=str(outputs["baseline_ua_timeseries"]), replay_grade=True)
    threat_hunt.export_impact_lane_totals(output=str(outputs["impact_lane_totals"]), start="2026-05-01T00:00:00Z", end="2026-05-01T01:00:00Z", baseline_start="2026-04-30T00:00:00Z", baseline_end="2026-04-30T01:00:00Z", cluster="local", replay_grade=True)
    threat_hunt.export_impact_lane_scoped_hunt(output=str(outputs["impact_lane_scoped_hunt"]), start="2026-05-01T00:00:00Z", end="2026-05-01T01:00:00Z", baseline_start="2026-04-30T00:00:00Z", baseline_end="2026-04-30T01:00:00Z", cluster="local", user_agents=["HighLead/1.0"], replay_grade=True)

    for stage_id, path in outputs.items():
        _assert_replay_dataset(path, stage_id)


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
    allowed: set[str] = {
        "producers/cli.py",
        "producers/threat_hunt.py",
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
