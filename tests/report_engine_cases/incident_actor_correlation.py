from __future__ import annotations

from tests.report_engine_helpers import *

def _incident_print_callout_fixture() -> dict:
    data = deepcopy(
        json.loads((FIXTURES / "incident_report_deterministic_only.json").read_text())
    )
    actors = data["artifacts"][1]
    action_targets = data["artifacts"][2]
    asn_ranking = next(r for r in actors["actor_rankings"] if r["field"] == "asn")
    asn_ranking["rows"][0]["value"] = "44477"
    asn_target = next(t for t in action_targets["targets"] if t["target_type"] == "asn")
    asn_target["target_value"] = "44477"
    actors["actor_cooccurrence"] = {
        "client_ip__user_agent": [
            {"ip": "203.0.113.10", "ua": f"Mozilla/5.0 Chrome/{idx}", "requests": 54000}
            for idx in range(10)
        ]
    }
    return data

def _write_as_reputation_override(tmp_path: Path) -> Path:
    path = tmp_path / "as-reputation.json"
    path.write_text(
        json.dumps(
            {
                "entries": [
                    {
                        "asns": ["44477"],
                        "name": "STARK INDUSTRIES SOLUTIONS LTD",
                        "label": "public_threat_enabler",
                        "confidence": "medium",
                        "sources": [
                            {
                                "title": "Source A",
                                "url": "https://example.test/a",
                                "source_type": "network_intelligence",
                            },
                            {
                                "title": "Source B",
                                "url": "https://example.test/b",
                                "source_type": "security_research",
                            },
                        ],
                    }
                ]
            }
        )
    )
    return path

def test_incident_report_print_actor_correlation_callouts_emit_when_evidence_exists(
    tmp_path,
):
    from config import (
        AsReputationConfig,
        Thresholds,
        active_thresholds,
        set_active_thresholds,
    )
    from report_engine.contexts.incident import module
    from report_engine.contexts.incident.print_adapter import build_print_report

    data = _incident_print_callout_fixture()
    original = active_thresholds()
    try:
        set_active_thresholds(
            Thresholds(
                as_reputation=AsReputationConfig(
                    local_overrides_path=str(_write_as_reputation_override(tmp_path))
                )
            )
        )
        ctx = module.prepare(module.assemble(data["artifacts"]))
        print_ctx = build_print_report(ctx)
    finally:
        set_active_thresholds(original)

    callouts = print_ctx["actor_correlation_callouts"]
    assert [row["kind"] for row in callouts] == ["as-reputation", "ua-rotation"]
    assert "AS44477" in callouts[0]["summary_html"]
    assert "STARK INDUSTRIES SOLUTIONS LTD" in callouts[0]["summary_html"]
    assert "flagged target" in callouts[0]["summary_html"]
    assert "consistent with automation" in callouts[1]["summary_html"]
    assert "malicious" not in " ".join(row["summary_html"] for row in callouts).lower()
    assert print_ctx["risk_explanation"]
    assert print_ctx["ua_rotation_print"]["available"] is True
    assert print_ctx["as_reputation_print"]["available"] is True

def test_incident_print_finding_as_reputation_callout_is_evidence_gated():
    from report_engine.contexts.incident.print_adapter import _findings

    ctx = {
        "incident_findings": [
            {
                "label": "Finding 01",
                "lead": "Critical-tier client IPs coordinated against this window.",
                "body": "These IPs crossed the multi-signal heuristic ladder.",
                "entities": [
                    {
                        "value": "5.180.30.239",
                        "target_type": "client_ip",
                        "target_type_label": "Client IP",
                        "meta": "AS44477 · Stark Industries Solutions Ltd · 0.45% of window",
                        "severity": "critical",
                    }
                ],
            }
        ],
        "as_reputation_context": {
            "available": True,
            "rows": [
                {
                    "asn_display": "AS44477",
                    "name": "Stark Industries Solutions Ltd",
                    "requests_display": "686.87M",
                    "flagged_target_count": 4,
                    "external_reputation_point": (
                        "Multiple public sources describe AS44477/Stark Industries "
                        "Solutions Ltd as associated with threat-enabling infrastructure. "
                        "This context does not imply every IP, customer, or request "
                        "from the AS is malicious."
                    ),
                }
            ],
        },
    }

    findings = _findings(ctx)
    callout = findings[0]["as_callout"]

    assert callout["title"] == "Why AS context is included"
    assert callout["summary_html"] == (
        "Included because AS44477 matched the AS reputation corpus and overlapped "
        "this finding&#x27;s flagged client-IP cluster: 686.87M requests; "
        "4 flagged targets. Multiple public sources describe AS44477/Stark "
        "Industries Solutions Ltd as associated with threat-enabling infrastructure."
    )
    assert "not attribution" in callout["boundary_html"]
    assert "malicious" not in callout["boundary_html"].lower()
    assert findings[0]["ips"][0]["share"] == "AS44477 · 0.45% window"
    assert "Stark Industries Solutions Ltd" not in findings[0]["ips"][0]["share"]
    assert _findings({**ctx, "as_reputation_context": {"available": False, "rows": []}})[
        0
    ]["as_callout"] is None

def test_incident_print_finding_ua_age_callout_is_evidence_gated():
    from report_engine.contexts.incident.print_adapter import _findings

    ua_old = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36"
    )
    ua_new = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36"
    )
    ctx = {
        "incident_findings": [
            {
                "label": "Finding 02",
                "lead": "User agents drawing outsized request share.",
                "body": "UA strings accounted for outsized window share.",
                "entities": [
                    {
                        "value": ua_old,
                        "target_type": "user_agent",
                        "target_type_label": "User Agent",
                        "meta": "2.13% of window",
                    },
                    {
                        "value": ua_new,
                        "target_type": "user_agent",
                        "target_type_label": "User Agent",
                        "meta": "0.29% of window",
                    },
                ],
            }
        ],
        "browser_version_context": {
            "available": True,
            "rows": [
                {
                    "user_agent": ua_old,
                    "browser_label": "Chrome/Chromium token",
                    "version_display": "109",
                    "age_display": "3.3 years old",
                    "stale": True,
                },
                {
                    "user_agent": ua_new,
                    "browser_label": "Chrome/Chromium token",
                    "version_display": "147",
                    "age_display": "25 days old",
                    "stale": False,
                },
            ],
        },
    }

    finding = _findings(ctx)[0]
    callout = finding["ua_age_callout"]

    assert callout["title"] == "Browser age context"
    assert callout["summary_html"] == "Chrome 109 (3.3y) is a stale UA token."
    assert "not identity or intent evidence" in callout["boundary_html"]
    assert finding["uas"][0]["label_html"] == "Chrome 109 / Windows"
    assert finding["uas"][1]["label_html"] == "Chrome 147 / Windows"
    assert ua_old not in finding["uas"][0]["label_html"]
    assert _findings(
        {**ctx, "browser_version_context": {"available": False, "rows": []}}
    )[0]["ua_age_callout"] is None

def test_incident_print_finding_ua_age_callout_summarizes_multiple_stale_tokens():
    from report_engine.contexts.incident.print_adapter import _findings

    ua_109 = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36"
    )
    ua_122 = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
    )
    ctx = {
        "incident_findings": [
            {
                "label": "Finding 02",
                "lead": "User agents drawing outsized request share.",
                "body": "UA strings accounted for outsized window share.",
                "entities": [
                    {
                        "value": ua_109,
                        "target_type": "user_agent",
                        "target_type_label": "User Agent",
                        "meta": "2.13% of window",
                    },
                    {
                        "value": ua_122,
                        "target_type": "user_agent",
                        "target_type_label": "User Agent",
                        "meta": "0.29% of window",
                    },
                ],
            }
        ],
        "browser_version_context": {
            "available": True,
            "rows": [
                {
                    "user_agent": ua_109,
                    "browser_family": "Chrome",
                    "browser_label": "Chrome/Chromium token",
                    "version_display": "109",
                    "age_display": "3.3 years old",
                    "stale": True,
                },
                {
                    "user_agent": ua_122,
                    "browser_family": "Chrome",
                    "browser_label": "Chrome/Chromium token",
                    "version_display": "122",
                    "age_display": "2.2 years old",
                    "stale": True,
                },
            ],
        },
    }

    finding = _findings(ctx)[0]
    callout = finding["ua_age_callout"]

    assert callout["summary_html"] == (
        "Chrome 109 (3.3y) and Chrome 122 (2.2y) are stale UA tokens."
    )
    assert callout["boundary_html"] == (
        "Stale tokens can be pinned, spoofed, or non-updating clients; "
        "not identity or intent evidence."
    )
    assert [row["label_html"] for row in finding["uas"]] == [
        "Chrome 109 / Windows",
        "Chrome 122 / Windows",
    ]

def test_incident_report_print_actor_correlation_callouts_omit_missing_as_evidence():
    from report_engine.contexts.incident import module
    from report_engine.contexts.incident.print_adapter import build_print_report

    data = _incident_print_callout_fixture()
    ctx = module.prepare(module.assemble(data["artifacts"]))
    print_ctx = build_print_report(ctx)

    assert [row["kind"] for row in print_ctx["actor_correlation_callouts"]] == [
        "ua-rotation"
    ]

def test_incident_report_print_actor_correlation_callouts_omit_missing_ua_evidence(
    tmp_path,
):
    from config import (
        AsReputationConfig,
        Thresholds,
        active_thresholds,
        set_active_thresholds,
    )
    from report_engine.contexts.incident import module
    from report_engine.contexts.incident.print_adapter import build_print_report

    data = _incident_print_callout_fixture()
    data["artifacts"][1]["actor_cooccurrence"] = {}
    original = active_thresholds()
    try:
        set_active_thresholds(
            Thresholds(
                as_reputation=AsReputationConfig(
                    local_overrides_path=str(_write_as_reputation_override(tmp_path))
                )
            )
        )
        ctx = module.prepare(module.assemble(data["artifacts"]))
        print_ctx = build_print_report(ctx)
    finally:
        set_active_thresholds(original)

    assert [row["kind"] for row in print_ctx["actor_correlation_callouts"]] == [
        "as-reputation"
    ]

def test_incident_report_print_actor_correlation_callouts_do_not_change_core_context(
    tmp_path,
):
    from config import (
        AsReputationConfig,
        Thresholds,
        active_thresholds,
        set_active_thresholds,
    )
    from report_engine.contexts.incident import module

    fixture = FIXTURES / "incident_report_deterministic_only.json"
    base_data = json.loads(fixture.read_text())
    enriched_data = _incident_print_callout_fixture()
    original = active_thresholds()
    try:
        base_ctx = module.prepare(module.assemble(base_data["artifacts"]))
        set_active_thresholds(
            Thresholds(
                as_reputation=AsReputationConfig(
                    local_overrides_path=str(_write_as_reputation_override(tmp_path))
                )
            )
        )
        enriched_ctx = module.prepare(module.assemble(enriched_data["artifacts"]))
    finally:
        set_active_thresholds(original)

    assert enriched_ctx["risk_score"] == base_ctx["risk_score"]
    assert enriched_ctx["claim_profile"] == base_ctx["claim_profile"]
    assert [
        (row["target_type"], row["severity"], row["requests"])
        for row in enriched_ctx["suspicious_targets"]
    ] == [
        (row["target_type"], row["severity"], row["requests"])
        for row in base_ctx["suspicious_targets"]
    ]
    assert enriched_ctx["assessment_explainers"]["user_agent_rotation"]["available"]
    assert enriched_ctx["as_reputation_context"]["available"]

def test_incident_report_print_template_renders_actor_correlation_callouts(tmp_path):
    data = _incident_print_callout_fixture()
    with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
        wrapper_path = Path(f.name)
        json.dump(data, f)
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps(
            {
                "as_reputation": {
                    "local_overrides_path": str(_write_as_reputation_override(tmp_path))
                }
            }
        )
    )
    try:
        actual = _normalize(
            _render(wrapper_path, "--profile", "print", "--config", str(config_path))
        )
    finally:
        wrapper_path.unlink(missing_ok=True)

    assert "Actor correlations" in actual
    assert "Actor correlations · AS reputation cluster" in actual
    assert "AS44477" in actual
    assert "STARK INDUSTRIES SOLUTIONS LTD" in actual
    assert "Actor correlations · User-Agent rotation" in actual
    assert "consistent with automation" in actual
    assert "User-Agent Rotation" in actual
    assert "External AS Context" in actual
    assert actual.count('<section class="page') == 12
    assert "confirmed automation" not in actual.lower()
    assert "known bad" not in actual.lower()
