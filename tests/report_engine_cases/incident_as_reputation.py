from __future__ import annotations

from tests.report_engine_helpers import *

def test_incident_as_reputation_keeps_external_and_local_points_separate():
    from report_engine.contexts.incident.as_reputation import (
        build_as_reputation_context,
    )

    corpus = [
        {
            "asns": ["64501"],
            "name": "Example Sanctioned Host",
            "label": "sanctioned_bulletproof_hosting",
            "confidence": "high",
            "evidence_grade": "authoritative_plus_public_ti",
            "last_reviewed": "2026-05-20",
            "sources": [
                {
                    "title": "Sanctions source",
                    "url": "https://example.test/sanctions-as64501",
                    "source_type": "sanctions",
                    "summary": "Authoritative sanctions listing.",
                },
                {
                    "title": "Threat intelligence source",
                    "url": "https://example.test/ti-as64501",
                    "source_type": "threat_intelligence",
                    "summary": "Independent threat-intelligence reporting.",
                },
            ],
        }
    ]
    actors = {
        "actor_rankings": [
            {
                "field": "asn",
                "rows": [
                    {"value": "64501", "requests": 250},
                    {"value": "64500", "requests": 750},
                ],
            }
        ]
    }
    targets = [
        {
            "target_type": "asn",
            "target_value": "64501",
            "reason_flags": ["high_volume_share"],
            "supporting": {"requests": 250, "share_pct": 25.0},
        }
    ]

    ctx = build_as_reputation_context(actors, targets, corpus=corpus)
    row = ctx["rows"][0]

    assert ctx["available"] is True
    assert row["asn_display"] == "AS64501"
    assert "public source" in row["external_reputation_point"]
    assert "In this report" in row["report_local_behavior_point"]
    assert row["external_reputation_point"] != row["report_local_behavior_point"]
    assert row["evidence_profile"]["known_bad_wording_allowed"] is True
    assert row["flagged_target_count"] == 1

def test_incident_as_reputation_spamhaus_snapshot_matches_observed_asn(tmp_path):
    from report_engine.contexts.incident.as_reputation import (
        SpamhausAsnDropProvider,
        build_as_reputation_context,
    )

    snapshot = tmp_path / "asndrop.json"
    snapshot.write_text(
        json.dumps(
            {
                "records": [
                    {
                        "asn": "AS64510",
                        "name": "Example Dropped Network",
                        "last_updated": "2026-05-20",
                    }
                ]
            }
        )
    )
    actors = {
        "actor_rankings": [
            {"field": "asn", "rows": [{"value": "64510", "requests": 100}]}
        ]
    }
    targets = [
        {
            "target_type": "asn",
            "target_value": "64510",
            "supporting": {"requests": 100, "share_pct": 10.0},
        }
    ]

    ctx = build_as_reputation_context(
        actors,
        targets,
        providers=[SpamhausAsnDropProvider(snapshot)],
    )
    row = ctx["rows"][0]

    assert ctx["available"] is True
    assert row["asn_display"] == "AS64510"
    assert row["label"] == "public_threat_enabler"
    assert row["sources"][0]["title"] == "Spamhaus ASN-DROP"
    assert "routing and reputation context" in row["external_reputation_point"]
    assert row["evidence_profile"]["bar"] == "provider_snapshot"
    assert row["evidence_profile"]["known_bad_wording_allowed"] is False

def test_incident_as_reputation_spamhaus_unobserved_asn_does_not_render(tmp_path):
    from report_engine.contexts.incident.as_reputation import (
        SpamhausAsnDropProvider,
        build_as_reputation_context,
    )

    snapshot = tmp_path / "asndrop.json"
    snapshot.write_text(
        json.dumps({"records": [{"asn": "64510", "name": "Example Dropped Network"}]})
    )
    actors = {
        "actor_rankings": [
            {"field": "asn", "rows": [{"value": "64511", "requests": 100}]}
        ]
    }

    ctx = build_as_reputation_context(
        actors,
        [],
        providers=[SpamhausAsnDropProvider(snapshot)],
    )

    assert ctx["available"] is False
    assert ctx["rows"] == []

def test_incident_as_reputation_weak_single_source_does_not_qualify():
    from report_engine.contexts.incident.as_reputation import (
        build_as_reputation_context,
        reputation_evidence_profile,
    )

    corpus = {
        "64500": {
            "asn": "64500",
            "name": "Example Transit",
            "label": "reputation_hit",
            "sources": [
                {
                    "title": "Single TI note",
                    "url": "https://example.test/as64500",
                    "source_type": "threat_intelligence",
                    "summary": "One non-authoritative reputation note.",
                }
            ],
        }
    }
    actors = {
        "actor_rankings": [
            {"field": "asn", "rows": [{"value": "64500", "requests": 10}]}
        ]
    }

    profile = reputation_evidence_profile(corpus["64500"])
    ctx = build_as_reputation_context(actors, [], corpus=corpus)

    assert profile["qualifies"] is False
    assert profile["known_bad_wording_allowed"] is False
    assert ctx["available"] is False
    assert "known bad" not in json.dumps(ctx).lower()

def test_incident_as_reputation_local_override_weak_source_does_not_qualify(
    tmp_path,
):
    from report_engine.contexts.incident.as_reputation import (
        LocalAsReputationOverrideProvider,
        build_as_reputation_context,
    )

    overrides = tmp_path / "overrides.json"
    overrides.write_text(
        json.dumps(
            {
                "entries": [
                    {
                        "asns": ["64512"],
                        "name": "Example Override Network",
                        "label": "reputation_hit",
                        "sources": [
                            {
                                "title": "Single research note",
                                "url": "https://example.test/one-note",
                                "source_type": "security_research",
                            }
                        ],
                    }
                ]
            }
        )
    )
    actors = {
        "actor_rankings": [
            {"field": "asn", "rows": [{"value": "64512", "requests": 10}]}
        ]
    }

    ctx = build_as_reputation_context(
        actors,
        [],
        providers=[LocalAsReputationOverrideProvider(overrides)],
    )

    assert ctx["available"] is False

def test_incident_as_reputation_authoritative_source_qualifies_alone():
    from report_engine.contexts.incident.as_reputation import (
        build_as_reputation_context,
    )

    corpus = [
        {
            "asns": ["64502"],
            "name": "Example Sanctioned Host",
            "label": "sanctioned_bulletproof_hosting",
            "confidence": "high",
            "evidence_grade": "authoritative",
            "last_reviewed": "2026-05-20",
            "sources": [
                {
                    "title": "Sanctions source",
                    "url": "https://example.test/sanctions",
                    "source_type": "sanctions",
                    "summary": "Authoritative sanctions listing.",
                }
            ],
        }
    ]
    actors = {
        "actor_rankings": [
            {"field": "asn", "rows": [{"value": "AS64502", "requests": 10}]}
        ]
    }

    ctx = build_as_reputation_context(actors, [], corpus=corpus)

    assert ctx["available"] is True
    assert ctx["rows"][0]["evidence_profile"]["bar"] == "authoritative_source"
    assert ctx["rows"][0]["evidence_profile"]["known_bad_wording_allowed"] is True

def test_incident_as_reputation_local_override_authoritative_qualifies_alone(
    tmp_path,
):
    from report_engine.contexts.incident.as_reputation import (
        LocalAsReputationOverrideProvider,
        build_as_reputation_context,
    )

    overrides = tmp_path / "overrides.json"
    overrides.write_text(
        json.dumps(
            [
                {
                    "asns": ["64513"],
                    "name": "Example Sanctioned Override",
                    "label": "sanctioned_bulletproof_hosting",
                    "confidence": "high",
                    "evidence_grade": "authoritative",
                    "last_reviewed": "2026-05-20",
                    "sources": [
                        {
                            "title": "Sanctions source",
                            "url": "https://example.test/sanctions",
                            "source_type": "sanctions",
                        }
                    ],
                }
            ]
        )
    )
    actors = {
        "actor_rankings": [
            {"field": "asn", "rows": [{"value": "64513", "requests": 10}]}
        ]
    }

    ctx = build_as_reputation_context(
        actors,
        [],
        providers=[LocalAsReputationOverrideProvider(overrides)],
    )

    assert ctx["available"] is True
    assert ctx["rows"][0]["evidence_profile"]["bar"] == "authoritative_source"

def test_incident_as_reputation_omits_when_no_observed_asn_matches_corpus():
    from report_engine.contexts.incident.as_reputation import (
        build_as_reputation_context,
    )

    actors = {
        "actor_rankings": [
            {"field": "asn", "rows": [{"value": "64500", "requests": 10}]}
        ]
    }

    ctx = build_as_reputation_context(actors, [])

    assert ctx == {
        "available": False,
        "rows": [],
        "boundary": (
            "External AS reputation is corroborating context only. It does not "
            "change risk score, confidence gates, target ordering, or incident claims."
        ),
    }

def test_incident_as_reputation_does_not_change_scoring_or_target_order():
    from report_engine.contexts.incident import module
    from config import (
        AsReputationConfig,
        Thresholds,
        active_thresholds,
        set_active_thresholds,
    )

    fixture = FIXTURES / "incident_report_deterministic_only.json"
    base_data = json.loads(fixture.read_text())
    enriched_data = deepcopy(base_data)
    actors = enriched_data["artifacts"][1]
    action_targets = enriched_data["artifacts"][2]
    asn_ranking = next(r for r in actors["actor_rankings"] if r["field"] == "asn")
    asn_ranking["rows"][0]["value"] = "44477"
    asn_target = next(t for t in action_targets["targets"] if t["target_type"] == "asn")
    asn_target["target_value"] = "44477"

    with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
        snapshot_path = Path(f.name)
        json.dump(
            {"records": [{"asn": "44477", "name": "Example Dropped Network"}]},
            f,
        )
    original = active_thresholds()
    try:
        base_ctx = module.prepare(module.assemble(base_data["artifacts"]))
        set_active_thresholds(
            Thresholds(
                as_reputation=AsReputationConfig(
                    spamhaus_asndrop_path=str(snapshot_path)
                )
            )
        )
        enriched_ctx = module.prepare(module.assemble(enriched_data["artifacts"]))
    finally:
        set_active_thresholds(original)
        snapshot_path.unlink(missing_ok=True)

    assert enriched_ctx["as_reputation_context"]["available"] is True
    assert enriched_ctx["risk_score"] == base_ctx["risk_score"]
    assert (
        enriched_ctx["claim_profile"]["traffic_anomaly_confidence"]
        == base_ctx["claim_profile"]["traffic_anomaly_confidence"]
    )
    assert (
        enriched_ctx["claim_profile"]["targeted_automation_confidence"]
        == base_ctx["claim_profile"]["targeted_automation_confidence"]
    )
    assert [
        (row["target_type"], row["severity"], row["requests"])
        for row in enriched_ctx["suspicious_targets"]
    ] == [
        (row["target_type"], row["severity"], row["requests"])
        for row in base_ctx["suspicious_targets"]
    ]

def test_incident_as_reputation_renders_points_and_citations():
    fixture = FIXTURES / "incident_report_deterministic_only.json"
    data = deepcopy(json.loads(fixture.read_text()))
    actors = data["artifacts"][1]
    action_targets = data["artifacts"][2]
    asn_ranking = next(r for r in actors["actor_rankings"] if r["field"] == "asn")
    asn_ranking["rows"][0]["value"] = "44477"
    asn_target = next(t for t in action_targets["targets"] if t["target_type"] == "asn")
    asn_target["target_value"] = "44477"

    with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
        wrapper_path = Path(f.name)
        json.dump(data, f)
    with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
        snapshot_path = Path(f.name)
        json.dump(
            {"records": [{"asn": "44477", "name": "Example Dropped Network"}]},
            f,
        )
    with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
        config_path = Path(f.name)
        json.dump(
            {"as_reputation": {"spamhaus_asndrop_path": str(snapshot_path)}},
            f,
        )
    try:
        actual = _normalize(_render(wrapper_path, "--config", str(config_path)))
    finally:
        wrapper_path.unlink(missing_ok=True)
        snapshot_path.unlink(missing_ok=True)
        config_path.unlink(missing_ok=True)

    assert "External AS Context" in actual
    assert "Public reputation context for observed ASNs" in actual
    assert "AS44477" in actual
    assert "External AS reputation is corroborating context only" in actual
    assert "This context does not imply every IP, customer" in actual
    assert "In this report, AS44477 accounted for" in actual
    assert "Spamhaus ASN-DROP" in actual
    assert "https://www.spamhaus.org/drop/asndrop/" in actual
    assert "known bad" not in actual.lower()

def test_incident_expedia_canonical_wrapper_keeps_expected_incident_context():
    from report_engine.contexts.incident import module
    from report_engine.contexts.incident.print_adapter import build_print_report

    fixture = Path(
        "/Users/turtlebender/src/expedia-analysis/reports/"
        "incident_canonical_2026-04-19/sample/incident_wrapper_canonical.json"
    )
    if not fixture.exists():
        pytest.skip("canonical Expedia incident wrapper not available")
    data = json.loads(fixture.read_text())

    ctx = module.prepare(module.assemble(data["artifacts"]))
    scope_art = data["artifacts"][0]
    action_art = data["artifacts"][2]

    assert ctx["deterministic_summary"]
    assert ctx["deterministic_summary"]["level"] in {"high", "critical"}
    assert ctx["risk_score"]["value"] >= 75
    assert ctx["analyst_assessment"]["conclusion"]
    assert scope_art["scope"]["start"] == "2026-04-19T10:00:00Z"
    assert scope_art["scope"]["end"] == "2026-04-19T17:00:00Z"
    assert scope_art["window_confirmation"]["spike_flags"] == [
        "volume_up",
        "rate_429_up",
        "rate_5xx_up",
    ]
    assert scope_art["top_targeted_hosts"][0]["value"] == "api.expedia.com"
    top_paths = {row["value"] for row in scope_art["top_targeted_path_patterns"]}
    assert {"/:slug", "/graphql"} <= top_paths
    target_values = {target["target_value"] for target in action_art["targets"]}
    assert {"5.180.30.239", "5.180.30.203", "5.180.30.200"} <= target_values
    finding_text = "\n".join(
        f"{finding.get('lead', '')} {finding.get('body', '')}"
        for finding in ctx["incident_findings"]
    )
    assert "Human-classified behavioral anomaly needs validation" in finding_text
    assert "classification mismatch or behavioral anomaly" in finding_text
    assert "not proof of malicious intent" in finding_text
    action_text = "\n".join(
        f"{action.get('step', '')} {action.get('reason', '')} {action.get('validation', '')}"
        for action in ctx["recommended_actions"]
    )
    assert "Test narrow guardrail for /:slug" not in action_text
    assert (
        "Validate route normalization and owner telemetry for `/:slug` before any control change"
        in action_text
    )
    assert "route normalization" in action_text
    assert "business-critical flow ownership" in action_text
    slug_action = next(
        action for action in ctx["recommended_actions"]
        if "`/:slug`" in action.get("step", "")
    )
    assert "rate-limit pressure" not in (slug_action.get("reason") or "")
    print_ctx = build_print_report(ctx)
    calibration = print_ctx["verdict"]["calibration_html"]
    assert (
        "Calibration: Critical reflects 187 suspicious targets across 3 severity tiers, "
        "with 8 fired signal types and 272 total signal hits."
    ) in calibration
    assert "Raw score 97.9/100" in calibration
    assert "displayed score is bounded to the Critical band" in calibration
    assert "means the observed signals cleared" not in calibration
    assert "deterministic action threshold" not in calibration
