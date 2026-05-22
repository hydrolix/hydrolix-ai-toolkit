from __future__ import annotations

from tests.report_engine_helpers import *

def test_incident_report_verdict_falls_back_to_deterministic_summary_without_note():
    fixture = FIXTURES / "incident_report_deterministic_only.json"
    actual = _normalize(_render(fixture, "--profile", "print"))

    assert 'data-pdf-layout="fixed-letter"' in actual
    assert "Analyst Assessment" in actual
    assert "high-severity targeted incident" not in actual
    assert "This window shows a high-severity traffic anomaly" in actual
    assert "Highest signals:" in actual
    assert "Requests:" in actual
    assert "Top path share 68.2%" in actual
    assert "LLM-driven interpretation" not in actual

def test_incident_report_deterministic_assessment_omits_empty_signal_clause():
    from report_engine.contexts.incident import module

    fixture = FIXTURES / "incident_report_deterministic_only.json"
    data = deepcopy(json.loads(fixture.read_text()))
    scope = data["artifacts"][0]
    scope["window_confirmation"] = {
        "requests": 0,
        "bot_share_pct": 0,
        "rate_429_pct": 0,
        "rate_5xx_pct": 0,
        "blocked_share_pct": 0,
        "spike_flags": [],
    }
    scope["top_targeted_hosts"] = []
    scope["top_targeted_path_patterns"] = []

    ctx = module.prepare(module.assemble(data["artifacts"]))
    ctx["profile"] = "print"
    module.post_prepare(ctx)

    prose = ctx["print_report"]["analyst_assessment"]["prose_html"]
    assert "Highest signals:" not in prose

def test_incident_claim_profile_same_hour_prior_day_is_medium_for_targeted_hypothesis():
    from report_engine.contexts.incident import module

    fixture = FIXTURES / "incident_report_deterministic_only.json"
    data = json.loads(fixture.read_text())
    scope = data["artifacts"][0]
    scope["scope"]["baseline_start"] = "2026-05-12T14:00:00Z"
    scope["scope"]["baseline_end"] = "2026-05-12T17:00:00Z"
    scope["volume_timeseries"]["baseline_start"] = "2026-05-12T14:00:00Z"
    scope["volume_timeseries"]["baseline_end"] = "2026-05-12T17:00:00Z"

    ctx = module.prepare(module.assemble(data["artifacts"]))
    profile = ctx["claim_profile"]

    assert profile["baseline_strength"] == "single_prior_day"
    assert profile["traffic_anomaly_confidence"] == "high"
    assert profile["targeted_automation_confidence"] == "medium"
    assert profile["credential_access_allowed"] is False
    assert "Targeted automation remains a medium-confidence hypothesis" in profile["hero_summary"]

def test_incident_claim_profile_rolling_baseline_allows_high_targeted_hypothesis():
    from report_engine.contexts.incident import module

    fixture = FIXTURES / "incident_report_deterministic_only.json"
    data = json.loads(fixture.read_text())
    scope = data["artifacts"][0]
    scope["scope"]["baseline_start"] = "2026-05-10T14:00:00Z"
    scope["scope"]["baseline_end"] = "2026-05-13T14:00:00Z"
    scope["volume_timeseries"]["baseline_start"] = "2026-05-10T14:00:00Z"
    scope["volume_timeseries"]["baseline_end"] = "2026-05-13T14:00:00Z"
    scope.setdefault("top_raw_paths", []).insert(
        0,
        {
            "value": "/login/submit",
            "requests": 100000,
            "share_pct": 50.0,
            "distinct_actors": 3,
        },
    )

    profile = module.prepare(module.assemble(data["artifacts"]))["claim_profile"]

    assert profile["baseline_strength"] == "rolling_multi_day"
    assert profile["targeted_automation_confidence"] == "high"
    assert "rolling baseline validation" in profile["hero_summary"]

def test_incident_claim_profile_missing_raw_or_edge_lowers_confidence():
    from report_engine.contexts.incident import module

    fixture = FIXTURES / "incident_report_deterministic_only.json"
    data = deepcopy(json.loads(fixture.read_text()))
    data["artifacts"][0]["window_confirmation"].pop("blocked_share_pct", None)
    data["artifacts"][1]["raw_drilldown_available"] = False

    profile = module.prepare(module.assemble(data["artifacts"]))["claim_profile"]

    assert profile["traffic_anomaly_confidence"] == "low"
    assert profile["targeted_automation_confidence"] == "low"

def test_incident_provenance_absent_is_silent():
    from report_engine.contexts.incident import module

    fixture = FIXTURES / "incident_report_deterministic_only.json"
    data = deepcopy(json.loads(fixture.read_text()))

    ctx = module.prepare(module.assemble(data["artifacts"]))
    profile = ctx["claim_profile"]

    assert ctx["bot_source_rows"] == []
    assert ctx["proxy_classification_rows"] == []
    assert all(not row.get("provenance_display") for row in ctx["suspicious_targets"])
    assert profile["provenance_overlap"]["available"] is False
    assert profile["traffic_anomaly_confidence"] == "high"
    assert profile["targeted_automation_confidence"] == "medium"
    assert "corroborated by source bot/proxy metadata" not in profile["hero_summary"]
    assert "flagged client-IP traffic overlapped" not in _normalize(_render(fixture))

def test_incident_provenance_overlap_scores_flagged_client_ip_share():
    from report_engine.contexts.incident.claim_gates import compute_provenance_overlap

    targets = [
        {
            "target_type": "client_ip",
            "target_value": "203.0.113.10",
            "supporting": {"requests": 40},
        },
        {
            "target_type": "client_ip",
            "target_value": "198.51.100.42",
            "supporting": {"requests": 60},
        },
    ]
    actors = {
        "actor_cooccurrence": {
            "client_ip__bot_source": [
                {"ip": "203.0.113.10", "bot_category": "HTTP Libraries", "requests": 40}
            ]
        }
    }

    overlap = compute_provenance_overlap(actors, targets)

    assert overlap["available"] is True
    assert overlap["flagged_client_ip_requests"] == 100
    assert overlap["overlap_requests"] == 40
    assert overlap["overlap_share"] == pytest.approx(0.4)
    assert overlap["overlap_share_display"] == "40.0%"
    assert overlap["overlapping_target_count"] == 1
    assert overlap["total_client_ip_target_count"] == 2

def test_incident_provenance_overlap_caps_same_ip_bot_and_proxy_cells():
    from report_engine.contexts.incident.claim_gates import compute_provenance_overlap

    targets = [
        {
            "target_type": "client_ip",
            "target_value": "203.0.113.10",
            "supporting": {"requests": 100},
        }
    ]
    actors = {
        "actor_cooccurrence": {
            "client_ip__bot_source": [
                {"ip": "203.0.113.10", "bot_category": "HTTP Libraries", "requests": 80}
            ],
            "client_ip__proxy_classification": [
                {"ip": "203.0.113.10", "epd_Category": "Residential Proxy", "requests": 80}
            ],
        }
    }

    overlap = compute_provenance_overlap(actors, targets)

    assert overlap["available"] is True
    assert overlap["overlap_requests"] == 100
    assert overlap["overlap_share"] == pytest.approx(1.0)
    assert overlap["overlap_share_display"] == "100%"
    assert overlap["overlapping_target_count"] == 1

def test_incident_provenance_overlap_ignores_non_flagged_cells():
    from report_engine.contexts.incident.claim_gates import compute_provenance_overlap

    targets = [
        {
            "target_type": "client_ip",
            "target_value": "203.0.113.10",
            "supporting": {"requests": 100},
        }
    ]
    actors = {
        "actor_cooccurrence": {
            "client_ip__bot_source": [
                {"ip": "198.51.100.42", "bot_category": "HTTP Libraries", "requests": 70}
            ]
        }
    }

    overlap = compute_provenance_overlap(actors, targets)

    assert overlap["available"] is True
    assert overlap["overlap_requests"] == 0
    assert overlap["overlap_share"] == 0
    assert overlap["overlapping_target_count"] == 0

def test_incident_provenance_projects_scope_rows_and_flagged_annotations():
    from report_engine.contexts.incident import module

    fixture = FIXTURES / "incident_report_deterministic_only.json"
    data = deepcopy(json.loads(fixture.read_text()))
    scope = data["artifacts"][0]
    actors = data["artifacts"][1]
    scope["bot_source_mix"] = [
        {
            "value": "Browser Impersonator / HTTP Libraries",
            "requests": 540000,
            "share_pct": 12.7,
            "delta_vs_baseline_pct": 240.0,
        }
    ]
    scope["proxy_classification_mix"] = [
        {
            "value": "Residential Proxy / Public Proxy",
            "requests": 220000,
            "share_pct": 5.2,
            "delta_vs_baseline_pct": 180.0,
        }
    ]
    actors["actor_cooccurrence"] = {
        "client_ip__bot_source": [
            {
                "ip": "203.0.113.10",
                "bot_category": "Browser Impersonator",
                "bot_type": "HTTP Libraries",
                "botnet_id": "",
                "requests": 540000,
            }
        ],
        "client_ip__proxy_classification": [
            {
                "ip": "203.0.113.10",
                "epd_Category": "Residential Proxy",
                "epd_ActionName": "Public Proxy",
                "epd_Match": "",
                "requests": 220000,
            }
        ],
    }

    ctx = module.prepare(module.assemble(data["artifacts"]))
    top_target = ctx["suspicious_targets"][0]

    assert ctx["bot_source_rows"][0]["value"] == "Browser Impersonator / HTTP Libraries"
    assert ctx["proxy_classification_rows"][0]["value"] == "Residential Proxy / Public Proxy"
    assert "Browser Impersonator / HTTP Libraries observed" in top_target["provenance_lines"]
    assert "Residential Proxy / Public Proxy observed" in top_target["provenance_lines"]
    assert ctx["claim_profile"]["traffic_anomaly_confidence"] == "high"
    assert ctx["claim_profile"]["targeted_automation_confidence"] == "medium"
    assert ctx["claim_profile"]["provenance_overlap"]["available"] is True
    assert ctx["claim_profile"]["provenance_overlap"]["overlap_requests"] == 540000
    assert "corroborated by source bot/proxy metadata" in ctx["claim_profile"]["hero_summary"]

def test_incident_provenance_renders_without_root_cause_claims():
    fixture = FIXTURES / "incident_report_deterministic_only.json"
    data = deepcopy(json.loads(fixture.read_text()))
    data["artifacts"][0]["bot_source_mix"] = [
        {
            "value": "Expedia Custom AI Bot",
            "requests": 10000,
            "share_pct": 0.25,
            "delta_vs_baseline_pct": 50.0,
        }
    ]
    data["artifacts"][0]["proxy_classification_mix"] = [
        {
            "value": "Anonymous VPN / Public Proxy",
            "requests": 20000,
            "share_pct": 0.47,
            "delta_vs_baseline_pct": 75.0,
        }
    ]
    data["artifacts"][1]["actor_cooccurrence"] = {
        "client_ip__bot_source": [
            {
                "ip": "203.0.113.10",
                "bot_category": "Expedia Custom AI Bot",
                "bot_type": "",
                "botnet_id": "",
                "requests": 10000,
            },
            {
                "ip": "198.51.100.42",
                "bot_category": "Expedia Custom AI Bot",
                "bot_type": "",
                "botnet_id": "",
                "requests": 420000,
            }
        ],
        "client_ip__proxy_classification": [
            {
                "ip": "203.0.113.10",
                "epd_Category": "Anonymous VPN",
                "epd_ActionName": "Public Proxy",
                "epd_Match": "",
                "requests": 540000,
            }
        ],
    }
    with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
        wrapper_path = Path(f.name)
        json.dump(data, f)
    try:
        actual = _normalize(_render(wrapper_path))
    finally:
        wrapper_path.unlink(missing_ok=True)

    assert "Bot Source Provenance" in actual
    assert "Proxy Classification" in actual
    assert "62.3% of flagged client-IP traffic overlapped bot/proxy provenance metadata." in actual
    assert "Expedia Custom AI Bot observed" in actual
    assert "Anonymous VPN / Public Proxy observed" in actual
    assert "not proof of intent or root cause" in actual
    assert "confirmed credential stuffing" not in actual.lower()
