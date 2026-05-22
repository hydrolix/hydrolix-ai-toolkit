from __future__ import annotations

from tests.report_engine_helpers import *

def test_incident_assessment_explainers_use_flagged_ip_denominator_only():
    from report_engine.contexts.incident.explainers import assessment_explainers

    targets = [
        {
            "target_type": "client_ip",
            "target_value": "203.0.113.10",
            "supporting": {"requests": 100},
        },
        {
            "target_type": "user_agent",
            "target_value": "curl/8",
            "supporting": {"requests": 999},
        },
    ]
    actors = {
        "actor_cooccurrence": {
            "client_ip__request_path": [
                {"ip": "203.0.113.10", "path": "/login", "requests": 60},
                {"ip": "198.51.100.42", "path": "/login", "requests": 1000},
            ]
        }
    }

    explainers = assessment_explainers(actors, {}, targets)
    path = explainers["path_ip_convergence"]

    assert path["available"] is True
    assert path["flagged_client_ip_count"] == 1
    assert path["total_flagged_client_ip_requests"] == 100
    assert path["top_paths"][0]["path"] == "/login"
    assert path["top_paths"][0]["share"] == pytest.approx(0.6)
    assert path["top_paths"][0]["auth_related"] is True

def test_incident_assessment_explainers_timeseries_and_ua_rotation_are_bounded():
    from report_engine.contexts.incident.explainers import assessment_explainers

    targets = [
        {
            "target_type": "client_ip",
            "target_value": "203.0.113.10",
            "supporting": {"requests": 100},
        }
    ]
    actors = {
        "actor_cooccurrence": {
            "client_ip__user_agent": [
                {"ip": "203.0.113.10", "ua": f"ua-{idx}", "requests": 10}
                for idx in range(10)
            ]
        }
    }
    action_targets = {
        "flagged_client_ip_timeseries": [
            {"bucket": "2026-05-01T00:00:00Z", "flagged_requests": 10, "req_429": 1},
            {"bucket": "2026-05-01T00:01:00Z", "flagged_requests": 50, "req_429": 5},
            {"bucket": "2026-05-01T00:02:00Z", "flagged_requests": 20, "req_429": 2},
        ]
    }

    explainers = assessment_explainers(actors, action_targets, targets)
    timeseries = explainers["flagged_ip_timeseries_alignment"]
    rotation = explainers["user_agent_rotation"]

    assert timeseries["available"] is True
    assert timeseries["peak_bucket"] == "2026-05-01T00:01:00Z"
    assert timeseries["peak_signals"] == ["429s"]
    assert timeseries["correlations"][0]["correlation"] == pytest.approx(1.0)
    assert rotation["available"] is True
    assert rotation["rows"][0]["distinct_user_agents"] == 10
    assert rotation["rows"][0]["rotation_label"] == "high"

def test_incident_user_agent_rotation_missing_cells_unavailable():
    from report_engine.contexts.incident.explainers import assessment_explainers

    targets = [
        {
            "target_type": "client_ip",
            "target_value": "203.0.113.10",
            "supporting": {"requests": 100},
        }
    ]

    explainers = assessment_explainers({"actor_cooccurrence": {}}, {}, targets)

    assert explainers["user_agent_rotation"]["available"] is False

def test_incident_user_agent_rotation_labels_are_deterministic():
    from report_engine.contexts.incident.explainers import assessment_explainers

    targets = [
        {"target_type": "client_ip", "target_value": "203.0.113.10", "supporting": {"requests": 100}},
        {"target_type": "client_ip", "target_value": "203.0.113.20", "supporting": {"requests": 80}},
        {"target_type": "client_ip", "target_value": "203.0.113.30", "supporting": {"requests": 60}},
    ]
    actors = {
        "actor_cooccurrence": {
            "client_ip__user_agent": [
                *[
                    {"ip": "203.0.113.10", "ua": f"high-{idx}", "requests": 10}
                    for idx in range(10)
                ],
                {"ip": "203.0.113.20", "ua": "moderate-primary", "requests": 70},
                {"ip": "203.0.113.20", "ua": "moderate-1", "requests": 10},
                {"ip": "203.0.113.20", "ua": "moderate-2", "requests": 10},
                {"ip": "203.0.113.20", "ua": "moderate-3", "requests": 10},
                {"ip": "203.0.113.30", "ua": "low-primary", "requests": 95},
                {"ip": "203.0.113.30", "ua": "low-secondary", "requests": 5},
            ]
        }
    }

    rotation = assessment_explainers(actors, {}, targets)["user_agent_rotation"]
    labels = {row["client_ip"]: row["rotation_label"] for row in rotation["rows"]}

    assert rotation["available"] is True
    assert labels["203.0.113.10"] == "high"
    assert labels["203.0.113.20"] == "moderate"
    assert labels["203.0.113.30"] == "low"

def test_incident_assessment_explainer_rendering_and_gates_are_separate():
    from report_engine.contexts.incident import module

    fixture = FIXTURES / "incident_report_deterministic_only.json"
    data = deepcopy(json.loads(fixture.read_text()))
    actors = data["artifacts"][1]
    action_targets = data["artifacts"][2]
    actors["actor_cooccurrence"] = {
        "client_ip__request_path": [
            {"ip": "203.0.113.10", "path": "/login/submit", "requests": 430000},
            {"ip": "198.51.100.42", "path": "/login/submit", "requests": 330000},
            {"ip": "192.0.2.17", "path": "/graphql", "requests": 250000},
        ],
        "client_ip__user_agent": [
            {"ip": "203.0.113.10", "ua": f"ua-{idx}", "requests": 54000}
            for idx in range(10)
        ],
    }
    action_targets["flagged_client_ip_timeseries"] = [
        {"bucket": "2026-05-13T14:00:00Z", "flagged_requests": 10, "req_429": 1},
        {"bucket": "2026-05-13T14:01:00Z", "flagged_requests": 50, "req_429": 5},
        {"bucket": "2026-05-13T14:02:00Z", "flagged_requests": 20, "req_429": 2},
    ]

    ctx = module.prepare(module.assemble(data["artifacts"]))

    assert ctx["assessment_explainers"]["available"] is True
    assert ctx["claim_profile"]["traffic_anomaly_confidence"] == "high"
    assert ctx["claim_profile"]["targeted_automation_confidence"] == "medium"
    assert ctx["risk_score"]["value"] == module.prepare(
        module.assemble(json.loads(fixture.read_text())["artifacts"])
    )["risk_score"]["value"]

    with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
        wrapper_path = Path(f.name)
        json.dump(data, f)
    try:
        actual = _normalize(_render(wrapper_path))
    finally:
        wrapper_path.unlink(missing_ok=True)

    assert "Assessment Explanation Signals" in actual
    assert "Corroborating signals behind the assessment" in actual
    assert "does not prove operator intent" in actual
    assert "confirmed credential stuffing" not in actual.lower()

def test_incident_assessment_explainer_section_omitted_when_unavailable():
    fixture = FIXTURES / "incident_report_deterministic_only.json"
    actual = _normalize(_render(fixture))

    assert "Assessment Explanation Signals" not in actual
