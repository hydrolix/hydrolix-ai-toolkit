from __future__ import annotations

from tests.report_engine_helpers import *

def test_incident_browser_user_agent_parser_precedence():
    from report_engine.contexts.incident.browser_versions import parse_browser_user_agent

    edge = parse_browser_user_agent(
        "Mozilla/5.0 AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36 Edg/121.0"
    )
    firefox = parse_browser_user_agent("Mozilla/5.0 Firefox/115.0")
    chrome = parse_browser_user_agent("Mozilla/5.0 CriOS/96.0 Mobile/15E148 Safari/604.1")
    safari = parse_browser_user_agent("Mozilla/5.0 Version/17.3 Safari/605.1.15")
    unknown = parse_browser_user_agent("curl/8.5.0")

    assert edge["family"] == "Edge"
    assert edge["major_version"] == 121
    assert firefox["family"] == "Firefox"
    assert chrome["family"] == "Chrome"
    assert "Chromium-compatible" in chrome["caveat"]
    assert safari["family"] == "Safari"
    assert unknown["family"] == "Unknown"

def test_incident_browser_version_context_stale_recent_unknown_and_comparison(
    tmp_path: Path,
):
    from config import BrowserVersionHistoryConfig, Thresholds, active_thresholds, set_active_thresholds
    from report_engine.contexts.incident.browser_versions import (
        build_browser_version_context,
    )

    snapshot = tmp_path / "browser-history.json"
    snapshot.write_text(
        json.dumps(
            {
                "rows": [
                    {
                        "family": "Chrome",
                        "major_version": 90,
                        "release_date": "2021-04-14",
                        "channel": "stable",
                        "source_name": "Chrome VersionHistory API",
                        "source_url": "https://versionhistory.googleapis.com/v1",
                    },
                    {
                        "family": "Edge",
                        "major_version": 121,
                        "release_date": "2024-01-25",
                        "channel": "stable",
                        "source_name": "Microsoft Learn",
                        "source_url": "https://learn.microsoft.com/en-us/deployedge/microsoft-edge-release-schedule",
                    },
                    {
                        "family": "Firefox",
                        "major_version": 126,
                        "release_date": "2026-04-01",
                        "channel": "stable",
                        "source_name": "Mozilla Product Details",
                        "source_url": "https://docs.telemetry.mozilla.org/datasets/releases",
                    },
                ]
            }
        )
    )
    original = active_thresholds()
    try:
        set_active_thresholds(
            Thresholds(
                browser_version_history=BrowserVersionHistoryConfig(
                    snapshot_path=str(snapshot),
                    stale_months=18,
                )
            )
        )
        actors = {
            "actor_rankings": [
                {
                    "field": "user_agent",
                    "rows": [
                        {"value": "Mozilla/5.0 Firefox/126.0", "requests": 300},
                        {"value": "Mozilla/5.0 Edg/121.0 Chrome/120.0", "requests": 200},
                        {"value": "UnknownAgent/1.0", "requests": 100},
                    ],
                }
            ]
        }
        targets = [
            {
                "target_type": "user_agent",
                "target_value": "Mozilla/5.0 Chrome/90.0.4430.85 Safari/537.36",
                "supporting": {"requests": 500, "share_pct": 50.0},
            },
            {
                "target_type": "user_agent",
                "target_value": "UnknownAgent/1.0",
                "supporting": {"requests": 100, "share_pct": 10.0},
            },
        ]

        ctx = build_browser_version_context(
            actors,
            targets,
            {"end": "2026-05-13T17:00:00Z"},
        )
    finally:
        set_active_thresholds(original)

    assert ctx["available"] is True
    assert ctx["rows"][0]["status"] == "stale"
    assert ctx["rows"][0]["source_name"] == "Chrome VersionHistory API"
    assert ctx["rows"][1]["status"] == "unknown"
    assert [row["browser_family"] for row in ctx["comparison_rows"]] == [
        "Firefox",
        "Edge",
    ]
    assert all(row["user_agent"] != "UnknownAgent/1.0" for row in ctx["comparison_rows"])

def test_incident_browser_version_render_uses_local_snapshot(tmp_path: Path):
    fixture = FIXTURES / "incident_report_deterministic_only.json"
    data = deepcopy(json.loads(fixture.read_text()))
    actors = data["artifacts"][1]
    action_targets = data["artifacts"][2]
    ua_old = "Mozilla/5.0 Chrome/90.0.4430.85 Safari/537.36"
    ua_edge = "Mozilla/5.0 AppleWebKit/537.36 Chrome/120.0 Safari/537.36 Edg/121.0"
    ua_firefox = "Mozilla/5.0 Firefox/126.0"
    action_targets.setdefault("targets", []).insert(
        0,
        {
            "target_type": "user_agent",
            "target_value": ua_old,
            "severity": "high",
            "kind": "actor",
            "action_class": "watch",
            "confidence": "medium",
            "reason_flags": ["automation_user_agent"],
            "supporting": {"requests": 500000, "share_pct": 11.7},
        },
    )
    actors.setdefault("actor_rankings", []).append(
        {
            "field": "user_agent",
            "rows": [
                {"value": ua_edge, "requests": 400000000},
                {"value": ua_firefox, "requests": 300000000},
                {"value": "UnknownAgent/1.0", "requests": 200000000},
            ],
        }
    )
    snapshot = tmp_path / "browser-history.json"
    snapshot.write_text(
        json.dumps(
            {
                "rows": [
                    {
                        "family": "Chrome",
                        "major_version": 90,
                        "release_date": "2021-04-14",
                        "channel": "stable",
                        "source_name": "Chrome VersionHistory API",
                        "source_url": "https://versionhistory.googleapis.com/v1",
                    },
                    {
                        "family": "Edge",
                        "major_version": 121,
                        "release_date": "2024-01-25",
                        "channel": "stable",
                        "source_name": "Microsoft Learn",
                        "source_url": "https://learn.microsoft.com/en-us/deployedge/microsoft-edge-release-schedule",
                    },
                    {
                        "family": "Firefox",
                        "major_version": 126,
                        "release_date": "2026-04-01",
                        "channel": "stable",
                        "source_name": "Mozilla Product Details",
                        "source_url": "https://docs.telemetry.mozilla.org/datasets/releases",
                    },
                ]
            }
        )
    )
    config = tmp_path / "config.json"
    config.write_text(
        json.dumps({"browser_version_history": {"snapshot_path": str(snapshot)}})
    )

    with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
        wrapper_path = Path(f.name)
        json.dump(data, f)
    try:
        actual = _normalize(_render(wrapper_path, "--config", str(config)))
    finally:
        wrapper_path.unlink(missing_ok=True)

    assert "Browser UA Age" in actual
    assert "Chrome/Chromium token" in actual
    assert "Stale" in actual
    assert "Comparison rows" in actual
    assert "Firefox 126" in actual
    assert "Edge 121" in actual
    assert "intentionally configured, pinned, spoofed, or non-updating clients" in actual

def test_incident_analysis_availability_renders_limitations_without_claims():
    fixture = FIXTURES / "incident_report_deterministic_only.json"
    data = deepcopy(json.loads(fixture.read_text()))
    data["artifacts"][0]["edge_action_mix"] = [
        {"value": "Allow", "requests": 100, "share_pct": 80.0},
        {"value": "Deny", "requests": 25, "share_pct": 20.0},
    ]
    with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
        wrapper_path = Path(f.name)
        json.dump(data, f)
    try:
        actual = _normalize(_render(wrapper_path))
    finally:
        wrapper_path.unlink(missing_ok=True)

    assert "Analysis Availability" in actual
    assert "What the bundled artifacts can support" in actual
    assert "Protected-population / counterfactual check" in actual
    assert "cannot evaluate collateral impact or counterfactual outcomes" in actual
    assert "do not include before/after evidence needed to claim mitigation effectiveness" in actual
