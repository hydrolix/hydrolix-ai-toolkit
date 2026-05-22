from __future__ import annotations

from tests.report_engine_helpers import *

def test_incident_executive_view_full_html():
    """Full executive render — analyst notes populated, all seven
    sections present, mechanical KPI strip + actions list rendered."""
    fixture = FIXTURES / "incident_executive_view_full.json"
    actual = _normalize(_render(fixture))
    snapshot = SNAPSHOTS / "incident_executive_view_full.html"
    _assert_snapshot(actual, snapshot)
    for header in (
        "Incident status",
        "What happened",
        "Measured impact",
        "Business / customer impact",
        "Response taken / recommended",
        "Decision needed",
        "Confidence and caveat",
    ):
        assert header in actual, f"section header missing: {header}"
    # Status pill renders with the critical tone for "Active".
    assert "pill-critical pill-lg" in actual
    # Recommended actions list shape.
    assert 'class="actions-list"' in actual
    # Editorial chrome we keep on the exec view.
    assert 'class="brief-incident exec-view"' in actual

def test_incident_report_print_uses_fixed_letter_template():
    fixture = ROOT / "skills/bot-insights/examples/incident-report.json"
    actual = _normalize(_render(fixture, "--profile", "print"))

    assert 'class="profile-print"' in actual
    assert 'data-pdf-layout="fixed-letter"' in actual
    assert ".page {" in actual
    assert "width: 8.5in" in actual
    assert "height: 11in" in actual
    assert "@page { size: letter; margin: 0; }" in actual
    assert actual.count('<section class="page') == 10

    cover_end = actual.index('<section class="page" data-screen-label="02 Analyst Assessment">')
    cover_html = actual[:cover_end]
    assert "75<small" in cover_html
    assert 'class="severity-ring"' in cover_html
    assert "At a glance · The lede in three columns" in cover_html
    assert "class=\"hero pf-xl\"" in cover_html
    assert cover_html.count('class="pf pf-sm') >= 3
    assert "START ·" in cover_html
    assert "END ·" in cover_html
    assert "PEAK ·" in cover_html
    assert "targeted surge" not in cover_html
    assert "Targeted automation remains a medium-confidence hypothesis" in cover_html
    assert (
        "Calibration: Critical reflects 9 suspicious targets across 3 severity tiers, "
        "with 7 fired signal types and 22 total signal hits."
    ) in cover_html
    assert "Raw score 75.2/100" in cover_html
    assert "displayed score is bounded to the Critical band" in cover_html
    assert "means the observed signals cleared" not in cover_html
    assert "deterministic action threshold" not in cover_html
    assert "Finding <b>01</b> · Finding 01" not in actual
    assert "Finding <b>02</b> · Finding 02" not in actual
    assert "Finding <b>03</b> · Finding 03" not in actual

    ordered = [
        "Analyst Assessment",
        "Evidence-backed findings",
        "What to do next",
        "Attack Shape",
        "Raw actors and action priority",
        "Classification / Edge Response",
        "ATT&amp;CK / Methodology",
        "Technique mapping and method",
        "How the score was calculated",
        "Analysis Availability",
        "Browser UA Age",
    ]
    positions = [actual.index(label) for label in ordered]
    assert positions == sorted(positions)
    assert "credential-abuse as an investigation lead" in actual
    assert "Metrics and ranks are deterministic" in actual
    assert "Ramp begins" in actual
    assert "Highest pressure" in actual

def test_incident_report_print_includes_user_agent_rotation_when_available():
    fixture = FIXTURES / "incident_report_deterministic_only.json"
    data = deepcopy(json.loads(fixture.read_text()))
    data["artifacts"][1]["actor_cooccurrence"] = {
        "client_ip__user_agent": [
            {"ip": "203.0.113.10", "ua": f"Mozilla/5.0 Chrome/{idx}", "requests": 54000}
            for idx in range(10)
        ]
    }

    with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
        wrapper_path = Path(f.name)
        json.dump(data, f)
    try:
        actual = _normalize(_render(wrapper_path, "--profile", "print"))
    finally:
        wrapper_path.unlink(missing_ok=True)

    assert actual.count('<section class="page') == 11
    assert "Browser UA Age" in actual
    assert "User-Agent Rotation" in actual
    assert "External AS Context" not in actual
    ordered = ["Browser UA Age", "User-Agent Rotation"]
    positions = [actual.index(label) for label in ordered]
    assert positions == sorted(positions)
    assert "UA rotation is consistent with automation or aggregator behavior" in actual
    assert "11 / 11" in actual
    assert "confirmed automation" not in actual.lower()

def test_incident_report_print_omits_user_agent_rotation_when_unavailable():
    fixture = FIXTURES / "incident_report_deterministic_only.json"
    actual = _normalize(_render(fixture, "--profile", "print"))

    assert actual.count('<section class="page') == 10
    assert "User-Agent Rotation" not in actual
    assert "External AS Context" not in actual
    assert "Actor correlations" not in actual
    assert "10 / 10" in actual
