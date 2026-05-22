from __future__ import annotations

from tests.report_engine_helpers import *

def test_threat_hunt_impact_rows_render_explicit_byte_lanes():
    from report_engine.contexts import threat_hunt

    artifact = {
        "schema_version": "bot_threat_hunt.v3",
        "scope": {
            "cluster": "local",
            "database": "akamai",
            "current_window": {
                "start": "2026-05-01T00:00:00Z",
                "end": "2026-05-02T00:00:00Z",
            },
            "baseline_window": {
                "start": "2026-04-30T00:00:00Z",
                "end": "2026-05-01T00:00:00Z",
            },
        },
        "module_scorecards": [],
        "campaigns": [],
        "scraper_cases": [],
        "baseline_movement": {"metric_deltas": []},
        "impact_assessment": {
            "totals": {
                "current": {
                    "requests": 10000,
                    "bytes": 1000000000,
                    "hydrolix_log_ingest_bytes": 400000000,
                    "response_body_bytes": 1000000000,
                    "akamai_billed_bytes": 1600000000,
                },
                "baseline": {"requests": 10000, "bytes": 1000000000},
            },
            "hydrolix_log_ingest_metadata": {
                "availability": "available",
                "source": "hydro.logs usagemeter",
                "estimated": True,
                "metric": "billing_bytes_per_row",
            },
            "hunt": {
                "requests": 2500,
                "request_share": 0.25,
                "bytes": 200000000,
                "byte_share": 0.20,
                "hydrolix_log_ingest_bytes": 100000000,
                "hydrolix_log_ingest_byte_share": 0.25,
                "response_body_bytes": 200000000,
                "response_body_byte_share": 0.20,
                "akamai_billed_bytes": 500000000,
                "akamai_billed_byte_share": 0.3125,
            },
        },
        "fingerprints": [],
        "endpoints": [],
        "infrastructure": {},
        "classification_gap": {},
        "limitations": [],
    }
    ctx = threat_hunt.prepare(artifact)
    assert ctx["threat_hunt_ui"]["impact_rows"] == [
        {
            "label": "Hits",
            "value": "2.5K (25.0% of window)",
            "detail": "HTTP requests attributed to this hunt scope.",
        },
        {
            "label": "Hydrolix log ingest",
            "value": "100.0M (25.0% of customer log volume)",
            "detail": "Hydrolix bill driver",
        },
        {
            "label": "Response body",
            "value": "200.0M (20.0% of response bytes)",
            "detail": "response data copied to scrapers",
        },
        {
            "label": "Akamai-billed",
            "value": "500.0M (31.2% of CDN billed bandwidth)",
            "detail": "CDN bandwidth Akamai billed",
        },
    ]
    assert ctx["threat_hunt_ui"]["hunt_impact"] == {
        "eyebrow": "Hunt impact",
        "scope": "Local",
        "rows": [
            {
                "label": "Hits",
                "value": "2.5K",
                "share": "25.0%",
                "denom": "of window HTTP requests",
            },
            {
                "label": "Hydrolix log ingest",
                "value": "100.0 MB",
                "share": "25.0%",
                "denom": "of customer log volume - Hydrolix bill driver",
            },
            {
                "label": "Response body",
                "value": "200.0 MB",
                "share": "20.0%",
                "denom": "response data copied to scrapers",
            },
            {
                "label": "Akamai-billed",
                "value": "500.0 MB",
                "share": "31.2%",
                "denom": "of CDN billed bandwidth",
            },
        ],
        "footnote": "Hydrolix log ingest is estimated from Hydrolix usagemeter billing bytes per row for the Akamai logs table.",
        "pattern_note": None,
    }
    assert (
        ctx["impact_note"]
        == "Hydrolix log ingest is estimated from Hydrolix usagemeter billing bytes per row for the Akamai logs table."
    )
    assert ctx["threat_hunt_ui"]["impact_note"] == ctx["impact_note"]

def test_threat_hunt_pattern_notes_surface_light_payload_when_corroborated():
    from report_engine.contexts import threat_hunt

    artifact = {
        "schema_version": "bot_threat_hunt.v3",
        "scope": {
            "cluster": "local",
            "database": "akamai",
            "current_window": {"start": "2026-05-01T00:00:00Z", "end": "2026-05-02T00:00:00Z"},
            "baseline_window": {"start": "2026-04-30T00:00:00Z", "end": "2026-05-01T00:00:00Z"},
        },
        "module_scorecards": [],
        "campaigns": [],
        "scraper_cases": [
            {
                "user_agent": "CatalogScraper/1.0",
                "verdict": "lead",
                "requests": 1000,
                "endpoint_evidence": {"tier": "scoped", "counts_for_verdict": True},
                "endpoint_targets": [
                    {
                        "request_path": "/api/catalog",
                        "requests": 1000,
                        "share_pct": 100.0,
                        "markers": ["api", "catalog"],
                    }
                ],
            }
        ],
        "baseline_movement": {"metric_deltas": []},
        "impact_assessment": {
            "hunt": {
                "requests": 1000,
                "request_share": 0.10,
                "response_body_bytes": 500000000,
                "response_body_byte_share": 0.05,
            }
        },
        "fingerprints": [],
        "endpoints": [],
        "infrastructure": {},
        "classification_gap": {},
        "limitations": [],
    }
    note = threat_hunt.prepare(artifact)["threat_hunt_ui"]["hunt_impact"]["pattern_note"]
    assert note is not None
    assert note["title"] == "Light payload / high hits"
    assert "10.0% hits vs 5.0% response bytes" in note["text"]
    assert "supporting context, not a standalone scraper signature" in note["text"]
    assert "endpoint targeting" in note["evidence_basis"]
    assert "not classification evidence" in note["confidence_boundary"]
    assert [link["label"] for link in note["links"]] == [
        "OWASP OAT-011 Scraping",
        "OWASP Bot Management Cheat Sheet",
        "F5 scraper behavior patterns",
    ]
    assert note["links"][2]["url"] == "https://www.f5.com/labs/articles/how-to-identify-and-stop-scrapers"

def test_threat_hunt_light_payload_note_requires_corroboration_and_response_share():
    from report_engine.contexts import threat_hunt

    artifact = {
        "schema_version": "bot_threat_hunt.v3",
        "scope": {
            "cluster": "local",
            "database": "akamai",
            "current_window": {"start": "2026-05-01T00:00:00Z", "end": "2026-05-02T00:00:00Z"},
            "baseline_window": {"start": "2026-04-30T00:00:00Z", "end": "2026-05-01T00:00:00Z"},
        },
        "module_scorecards": [],
        "campaigns": [],
        "scraper_cases": [],
        "baseline_movement": {"metric_deltas": []},
        "impact_assessment": {
            "hunt": {
                "requests": 1000,
                "request_share": 0.10,
                "response_body_bytes": 500000000,
                "response_body_byte_share": 0.05,
            }
        },
        "fingerprints": [],
        "endpoints": [],
        "infrastructure": {},
        "classification_gap": {},
        "limitations": [],
    }
    ctx = threat_hunt.prepare(artifact)
    assert ctx["pattern_notes"] == []
    assert ctx["threat_hunt_ui"]["hunt_impact"]["pattern_note"] is None

    equal_shares = deepcopy(artifact)
    equal_shares["scraper_cases"] = [
        {
            "user_agent": "CatalogScraper/1.0",
            "endpoint_evidence": {"counts_for_verdict": True},
            "endpoint_targets": [{"request_path": "/api/catalog", "share_pct": 100.0}],
        }
    ]
    equal_shares["impact_assessment"]["hunt"]["response_body_byte_share"] = 0.09
    titles = [note["title"] for note in threat_hunt.prepare(equal_shares)["pattern_notes"]]
    assert "Light payload / high hits" not in titles

    missing_response_share = deepcopy(equal_shares)
    missing_response_share["impact_assessment"]["hunt"].pop("response_body_byte_share")
    titles = [note["title"] for note in threat_hunt.prepare(missing_response_share)["pattern_notes"]]
    assert "Light payload / high hits" not in titles

def test_threat_hunt_pattern_notes_cover_endpoint_timing_ua_and_fanout():
    from report_engine.contexts import threat_hunt

    artifact = {
        "schema_version": "bot_threat_hunt.v3",
        "scope": {
            "cluster": "local",
            "database": "akamai",
            "current_window": {"start": "2026-05-01T00:00:00Z", "end": "2026-05-02T00:00:00Z"},
            "baseline_window": {"start": "2026-04-30T00:00:00Z", "end": "2026-05-01T00:00:00Z"},
        },
        "module_scorecards": [],
        "campaigns": [
            {
                "campaign_id": "campaign-1",
                "verdict": "lead",
                "temporal_pattern": "interval",
                "total_requests": 1000,
                "leads": ["CatalogScraper/1.0"],
                "endpoint_evidence_summary": {"confirmed_member_count": 1, "counts_for_verdict": True},
                "endpoint_targets": [{"endpoint_prefix": "/api/listings", "requests": 1000, "share_pct": 90.0}],
                "ua_plausibility_summary": {"anomalous_member_count": 1, "forged_ua_candidate": True},
                "fanout_summary": {"unique_ips_lower_bound": 75, "source": "cooccurrence_lower_bound"},
            }
        ],
        "ua_families": [
            {
                "family_id": "ua-family-1",
                "template": "Chrome/{version}",
                "members": ["Chrome/147", "Chrome/148", "Chrome/149"],
                "member_count": 3,
                "version_count": 3,
                "structural_checks": ["version_rotation"],
            }
        ],
        "scraper_cases": [
            {
                "user_agent": "CatalogScraper/1.0",
                "verdict": "lead",
                "requests": 1000,
                "endpoint_evidence": {"counts_for_verdict": True},
                "endpoint_targets": [{"request_path": "/api/listings", "requests": 1000, "share_pct": 90.0}],
                "temporal_regularity": {
                    "resolution": "request_iat",
                    "archetype": "metronome",
                    "sample_size": 60,
                    "metrics": {"cv": 0.0},
                },
                "ua_plausibility": {"verdict": "confirmed"},
                "fanout_enrichment": {"source": "summary_hour", "unique_ips": 75, "threshold_class": "elevated"},
            }
        ],
        "baseline_movement": {"metric_deltas": []},
        "impact_assessment": {"hunt": {"requests": 1000, "request_share": 0.10}},
        "fingerprints": [],
        "endpoints": [],
        "infrastructure": {},
        "classification_gap": {},
        "limitations": [],
    }
    notes = threat_hunt.prepare(artifact)["pattern_notes"]
    titles = [note["title"] for note in notes]
    assert "Direct-to-data/API focus" in titles
    assert "Boxy or interval cadence" in titles
    assert "UA impersonation / rotation" in titles
    assert "Distributed fan-out" in titles
    fanout = next(note for note in notes if note["title"] == "Distributed fan-out")
    assert "at least 75 IPs" in fanout["text"]
    assert "IP-only blocking may be brittle" in fanout["text"]
    assert all("not classification evidence" in note["confidence_boundary"] for note in notes)

def test_threat_hunt_pattern_notes_do_not_render_from_endpoint_absence():
    from report_engine.contexts import threat_hunt

    artifact = {
        "schema_version": "bot_threat_hunt.v3",
        "scope": {"cluster": "local", "database": "akamai"},
        "module_scorecards": [],
        "campaigns": [],
        "scraper_cases": [{"user_agent": "Generic/1.0", "requests": 1000}],
        "baseline_movement": {"metric_deltas": []},
        "impact_assessment": {"hunt": {"requests": 1000, "request_share": 0.10}},
        "fingerprints": [],
        "endpoints": [],
        "infrastructure": {},
        "classification_gap": {},
        "limitations": [],
    }
    assert threat_hunt.prepare(artifact)["pattern_notes"] == []

def test_threat_hunt_legacy_bytes_do_not_populate_explicit_byte_lanes():
    from report_engine.contexts import threat_hunt

    artifact = {
        "schema_version": "bot_threat_hunt.v3",
        "scope": {
            "cluster": "local",
            "database": "akamai",
            "current_window": {"start": "2026-05-01T00:00:00Z", "end": "2026-05-02T00:00:00Z"},
            "baseline_window": {"start": "2026-04-30T00:00:00Z", "end": "2026-05-01T00:00:00Z"},
        },
        "module_scorecards": [],
        "campaigns": [],
        "scraper_cases": [],
        "baseline_movement": {"metric_deltas": []},
        "impact_assessment": {
            "hunt": {
                "requests": 100,
                "request_share": 0.1,
                "bytes": 123456,
                "byte_share": 0.2,
            }
        },
        "fingerprints": [],
        "endpoints": [],
        "infrastructure": {},
        "classification_gap": {},
        "limitations": [],
    }
    ui = threat_hunt.prepare(artifact)["threat_hunt_ui"]
    rows = ui["impact_rows"]
    assert rows[1]["value"] == "unavailable (unavailable of customer log volume)"
    assert rows[2]["value"] == "unavailable (unavailable of response bytes)"
    assert rows[3]["value"] == "unavailable (unavailable of CDN billed bandwidth)"
    hunt_impact = ui["hunt_impact"]
    assert hunt_impact["rows"][1]["value"] == "unavailable"
    assert hunt_impact["rows"][1]["share"] == "unavailable"
    assert hunt_impact["rows"][2]["value"] == "unavailable"
    assert hunt_impact["rows"][2]["share"] == "unavailable"
    assert hunt_impact["rows"][3]["value"] == "unavailable"
    assert hunt_impact["rows"][3]["share"] == "unavailable"
