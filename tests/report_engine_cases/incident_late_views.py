from __future__ import annotations

from tests.report_engine_helpers import *

def test_incident_report_print_degraded_fixture_renders_missing_data_states():
    fixture = ROOT / "skills/bot-insights/examples/incident-report-degraded.json"
    actual = _normalize(_render(fixture, "--profile", "print"))

    assert 'data-pdf-layout="fixed-letter"' in actual
    assert actual.count('<section class="page') == 10
    assert "raw drilldown is degraded" in actual or "Rows are truncated" in actual
    assert "No ATT&amp;CK mapping available" in actual or "Technique mapping" in actual

def test_incident_print_adapter_maps_series_and_limits_rows():
    from report_engine.contexts.incident.print_adapter import (
        build_print_report,
        series_to_svg_path,
        severity_band,
        volume_chart,
    )

    fixture = ROOT / "skills/bot-insights/examples/incident-report.json"
    data = json.loads(fixture.read_text())
    from report_engine.contexts.incident import module

    ctx = module.prepare(module.assemble(data["artifacts"]))
    ctx["notes_by_slot"] = {}
    adapted = build_print_report(ctx)

    assert (
        series_to_svg_path([0, 50, 100])
        == "M 56.0,196.0 L 284.0,118.0 L 512.0,40.0"
    )
    assert severity_band("critical", 75)["band"] == "critical"
    assert adapted["verdict"]["band"] == "critical"
    assert len(adapted["actors"]) == 10
    assert len(adapted["actions"]) == 5
    assert adapted["finding_ip_cluster"]["kicker"] == ""
    assert [chip["text"] for chip in adapted["finding_ip_cluster"]["chips"]] == [
        "Client IP"
    ]
    assert adapted["finding_ip_cluster"]["ips"][:1][0]["ip"] == "203.0.113.10"
    phases = [stop["phase"] for stop in adapted["attack_shape"]["timeline"]]
    assert "Ramp begins" in phases
    assert "Highest pressure" in phases
    cover_actions = adapted["at_a_glance"]["do_now"]["items"]
    assert cover_actions[1]["team"] == "Intel"
    assert "case mgmt" in cover_actions[1]["action_html"]
    assert "203.0.113.10" not in cover_actions[1]["action_html"]

    missing = volume_chart({"impact": {"volume_chart": {}}})
    assert missing["missing"] is True
    assert missing["spike_path"]

def test_incident_report_temporal_progression_bucket_fallback_without_timestamps():
    from report_engine.contexts import incident_report as ir

    view = ir._temporal_progression_view(
        {
            "volume_timeseries": {
                "series": {
                    "requests_per_minute": {
                        "current": [0, 10, 40, 30, 5],
                    }
                }
            }
        }
    )

    assert view["available"] is True
    assert any("Peak bucket was bucket 3" in bullet for bullet in view["bullets"])
    assert not any("UTC" in bullet for bullet in view["bullets"])

def test_incident_action_reasons_do_not_sum_overlapping_shares():
    from report_engine.contexts import incident_report as ir

    actions = ir._recommended_actions_view(
        [
            {
                "target_type": "client_ip",
                "target_type_label": "Client IP",
                "target_value": "203.0.113.10",
                "severity": "critical",
                "severity_label": "Critical",
                "share_pct": 95.0,
                "share_pct_display": "95%",
                "requests_display": "950K",
                "reason_flag_labels": ["high volume share"],
            },
            {
                "target_type": "user_agent",
                "target_type_label": "User Agent",
                "target_value": "curl",
                "severity": "critical",
                "severity_label": "Critical",
                "share_pct": 92.0,
                "share_pct_display": "92%",
                "requests_display": "920K",
                "reason_flag_labels": ["automation user-agent"],
            },
        ],
        "",
    )
    reasons = " ".join(action.get("reason") or "" for action in actions)

    assert "187% of window traffic" not in reasons
    assert "top rows account for" not in reasons
    assert "strongest individual share was 95%" in reasons

def test_incident_attack_aggregation_includes_supporting_evidence():
    from report_engine.contexts import incident_report as ir

    rows = ir._attack_aggregation(
        [
            {
                "target_type": "client_ip",
                "target_value": "203.0.113.10",
                "severity": "critical",
                "reason_flags": ["high_429_share", "single_path_concentration"],
                "supporting": {
                    "requests": 120000,
                    "share_pct": 12.5,
                    "req_429_share_pct": 42.0,
                },
                "attack_techniques": [
                    {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"}
                ],
            }
        ]
    )

    assert rows[0]["id"] == "T1110"
    assert rows[0]["mapping_class"] == "possible investigation lead"
    assert "Client IP `203.0.113.10`" in rows[0]["supporting_evidence_text"]
    assert "auth-specific telemetry" in rows[0]["supporting_evidence_text"]
    assert "path concentration" in rows[0]["supporting_evidence_text"]
    assert len(rows[0]["metric_chips"]) <= 2
    assert "120.00K requests" in rows[0]["metric_chips"]
    assert "12.5% of incident requests" in rows[0]["metric_chips"]

def test_incident_executive_view_no_notes_html():
    """Empty ``analyst_notes`` exercises the graceful-degradation
    strings — every analyst slot has a fallback."""
    fixture = FIXTURES / "incident_executive_view_no_notes.json"
    actual = _normalize(_render(fixture))
    snapshot = SNAPSHOTS / "incident_executive_view_no_notes.html"
    _assert_snapshot(actual, snapshot)
    assert "Analyst summary pending" in actual
    assert "Not assessed from logs" in actual
    assert "no root-cause or intent attribution" in actual
    # Status pill falls back to the default ``Active`` label.
    assert ">Active<" in actual

def test_incident_executive_view_markdown():
    """Markdown sibling renders the same seven sections plus the
    status / window header line."""
    fixture = FIXTURES / "incident_executive_view_full.json"
    actual = _render(fixture, "--format", "markdown")
    snapshot = SNAPSHOTS / "incident_executive_view_full.md"
    _assert_snapshot(actual, snapshot)
    for line in (
        "# www.example.com — Incident Executive View",
        "**Status:** Active",
        "## What happened",
        "## Measured impact",
        "## Business / customer impact",
        "## Response taken / recommended",
        "## Decision needed",
        "## Confidence and caveat",
    ):
        assert line in actual, f"markdown line missing: {line}"

@pytest.mark.parametrize(
    ("fixture_name", "snapshot_name", "markers"),
    [
        (
            "incident_soc_action_packet.json",
            "incident_soc_action_packet.html",
            ("SOC Action Packet", "Suspicious actors", "IOC handoff", "Evidence caveats"),
        ),
        (
            "incident_edge_platform_brief_no_notes.json",
            "incident_edge_platform_brief_no_notes.html",
            ("Edge Platform Brief", "Request impact", "429 / 5xx shape", "Policy assessment", "Operational caveats"),
        ),
        (
            "incident_edge_platform_brief_full.json",
            "incident_edge_platform_brief_full.html",
            ("Edge Platform Brief", "Request impact", "429 / 5xx shape", "Policy assessment", "Operational caveats"),
        ),
        (
            "incident_detection_engineering_no_notes.json",
            "incident_detection_engineering_no_notes.html",
            (
                "Detection Engineering Review",
                "Mechanical rules fired",
                "Fields driving confidence",
                "Calibration calls",
                "Follow-up instrumentation",
            ),
        ),
        (
            "incident_detection_engineering_full.json",
            "incident_detection_engineering_full.html",
            (
                "Detection Engineering Review",
                "Mechanical rules fired",
                "Fields driving confidence",
                "Calibration calls",
                "Follow-up instrumentation",
            ),
        ),
    ],
)
def test_incident_stakeholder_view_html(fixture_name, snapshot_name, markers):
    fixture = FIXTURES / fixture_name
    actual = _normalize(_render(fixture))
    _assert_snapshot(actual, SNAPSHOTS / snapshot_name)
    for marker in markers:
        assert marker in actual
    assert "unavailable" in actual or "No " in actual

@pytest.mark.parametrize(
    ("fixture_name", "snapshot_name", "heading"),
    [
        (
            "incident_soc_action_packet.json",
            "incident_soc_action_packet.md",
            "# www.example.com — SOC Action Packet",
        ),
        (
            "incident_edge_platform_brief_no_notes.json",
            "incident_edge_platform_brief_no_notes.md",
            "# www.example.com — Edge Platform Brief",
        ),
        (
            "incident_edge_platform_brief_full.json",
            "incident_edge_platform_brief_full.md",
            "# www.example.com — Edge Platform Brief",
        ),
        (
            "incident_detection_engineering_no_notes.json",
            "incident_detection_engineering_no_notes.md",
            "# www.example.com — Detection Engineering Review",
        ),
        (
            "incident_detection_engineering_full.json",
            "incident_detection_engineering_full.md",
            "# www.example.com — Detection Engineering Review",
        ),
    ],
)
def test_incident_stakeholder_view_markdown(fixture_name, snapshot_name, heading):
    fixture = FIXTURES / fixture_name
    actual = _render(fixture, "--format", "markdown")
    _assert_snapshot(actual, SNAPSHOTS / snapshot_name)
    assert heading in actual
    assert "## " in actual

def test_incident_stakeholder_views_registered_and_legacy_accepted():
    import render_report
    from report_engine.contexts import REPORT_TYPE_REGISTRY, incident_report

    expected = {
        "incident_soc_action_packet",
        "incident_edge_platform_brief",
        "incident_detection_engineering",
    }
    assert expected <= set(REPORT_TYPE_REGISTRY)
    assert expected <= set(render_report.REPORT_TYPES)
    wrapper = json.loads((FIXTURES / "incident_soc_action_packet.json").read_text())
    args = SimpleNamespace(
        text=[],
        file=None,
        format="markdown",
        report_type=None,
        output=None,
        limit=None,
        allow_unknown=False,
        title=None,
        palette="tableau",
        theme="auto",
    )
    ctx = render_report.ReportContext()
    artifacts, notes, wrapper_report_type, wrapper_title, wrapper_limit, scope_label, raw_mode = (
        render_report.load_report_input(wrapper, args, ctx)
    )
    report_type, _title, _limit, _scope = render_report.resolve_options(
        artifacts,
        wrapper_report_type=wrapper_report_type,
        wrapper_title=wrapper_title,
        wrapper_limit=wrapper_limit,
        scope_label=scope_label,
        raw_mode=raw_mode,
        args=args,
        ctx=ctx,
    )
    selected = render_report.validate_report_artifacts(report_type, artifacts, ctx)
    assert report_type == "incident_soc_action_packet"
    assert set(selected) == {"scope", "actors", "action_targets"}
    assert (
        REPORT_TYPE_REGISTRY["incident_soc_action_packet"].assemble(
            wrapper["artifacts"]
        )
        == incident_report.assemble(wrapper["artifacts"])
    )
