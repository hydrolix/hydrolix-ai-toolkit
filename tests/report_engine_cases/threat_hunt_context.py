from __future__ import annotations

from tests.report_engine_helpers import *

def test_threat_hunt_context_derives_editorial_readouts():
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
        "module_scorecards": [
            {
                "module": "ua_fanout",
                "verdict": "lead",
                "rationale": "Fanout evidence present.",
            }
        ],
        "campaigns": [
            {
                "campaign_id": "campaign-strong",
                "verdict": "strong_lead",
                "sophistication": "moderate",
                "temporal_pattern": "synchronized",
                "leads": ["CatalogScraper/1.0", "CatalogScraper/2.0"],
                "linking_evidence": [{"shared_ip_count": 2}],
                "total_requests": 2400,
                "baseline_requests": 20,
                "bytes": 500000000,
                "baseline_bytes": 10000000,
                "impact_assessment": {
                    "requests": 2400,
                    "baseline_requests": 20,
                    "request_share": 0.24,
                    "baseline_request_share": 0.002,
                    "bytes": 500000000,
                    "baseline_bytes": 10000000,
                    "byte_share": 0.5,
                    "trend_severity": "accelerating",
                    "share_severity": "dominant",
                    "share_direction": "growing_share",
                    "interpretation": "Dominant traffic share that expanded sharply from baseline.",
                    "cost_estimate": {"low": 0.025, "high": 0.05, "basis_label": "configured CDN egress", "disclaimer": "estimate only"},
                },
                "unique_client_ips": 3,
                "unique_asns": 1,
                "unique_countries": 1,
                "endpoint_targets": [
                    {
                        "endpoint_prefix": "/api/catalog",
                        "requests": 2400,
                        "share_pct": 100.0,
                    }
                ],
            }
        ],
        "scraper_cases": [
            {
                "user_agent": "CatalogScraper/1.0",
                "verdict": "lead",
                "requests": 1200,
                "baseline_requests": 10,
                "bytes": 250000000,
                "baseline_bytes": 5000000,
                "impact_assessment": {
                    "requests": 1200,
                    "baseline_requests": 10,
                    "request_share": 0.12,
                    "baseline_request_share": 0.001,
                    "bytes": 250000000,
                    "baseline_bytes": 5000000,
                    "byte_share": 0.25,
                    "trend_severity": "accelerating",
                    "share_severity": "significant",
                    "share_direction": "growing_share",
                    "interpretation": "Significant traffic share with a sharp share increase versus baseline.",
                },
                "unique_client_ips": 12,
                "unique_asns": 2,
                "unique_countries": 2,
                "drilldown_coverage": {
                    "drilldown_requests": 1,
                    "total_requests": 1200,
                    "coverage_pct": 0.0833333333,
                    "status": "thin_slice",
                },
                "evidence_flags": ["ua_ip_fanout", "endpoint_targeting"],
                "case_for": ["Endpoint concentration."],
                "case_against": ["No operator attribution."],
                "endpoint_targets": [
                    {
                        "request_path": "/api/catalog",
                        "requests": 1200,
                        "share_pct": 100.0,
                        "markers": ["api"],
                    }
                ],
                "temporal_regularity": {
                    "resolution": "request_iat",
                    "archetype": "metronome",
                    "sample_size": 60,
                    "summary": "Fixed interval sample.",
                    "metrics": {"cv": 0.0, "log_bucket_entropy": 0.0},
                },
            }
        ],
        "baseline_movement": {"metric_deltas": []},
        "impact_assessment": {
            "totals": {
                "current": {"requests": 10000, "bytes": 1000000000},
                "baseline": {"requests": 10000, "bytes": 1000000000},
            },
            "hunt": {
                "requests": 2400,
                "baseline_requests": 20,
                "request_share": 0.24,
                "baseline_request_share": 0.002,
                "bytes": 500000000,
                "baseline_bytes": 10000000,
                "byte_share": 0.5,
                "trend_severity": "accelerating",
                "share_severity": "dominant",
                "share_direction": "growing_share",
            },
            "tiers": {
                "tier_3": {
                    "requests": 2400,
                    "baseline_requests": 20,
                    "request_share": 0.24,
                    "baseline_request_share": 0.002,
                    "bytes": 500000000,
                    "baseline_bytes": 10000000,
                    "byte_share": 0.5,
                    "trend_severity": "accelerating",
                    "share_severity": "dominant",
                    "share_direction": "growing_share",
                }
            },
            "cost_config": {
                "enabled": True,
                "basis_label": "configured CDN egress",
                "disclaimer": "estimate only",
                "egress_rate_low_per_gb": 0.05,
                "egress_rate_high_per_gb": 0.1,
            },
        },
        "fingerprints": [],
        "endpoints": [],
        "infrastructure": {},
        "classification_gap": {},
        "limitations": [],
    }
    ctx = threat_hunt.prepare(artifact)
    assert ctx["deterministic_summary"]["level_label"] == "Strong scraper lead"
    assert ctx["deterministic_summary"]["confidence_label"] == "Conservative confidence"
    assert len(ctx["threat_findings"]) == 3
    assert ctx["impact_tiles"][1]["value"] == "1"
    assert ctx["impact_tiles"][2]["value"] == "1"
    assert ctx["campaign_readouts"][0]["campaign_id"] == "campaign-strong"
    assert ctx["campaign_readouts"][0]["baseline_delta_display"] == "120.0x (+2.4K)"
    assert ctx["lead_cards"][0]["user_agent"] == "CatalogScraper/1.0"
    assert ctx["lead_cards"][0]["baseline_delta_display"] == "120.0x (+1.2K)"
    assert ctx["lead_cards"][0]["impact_assessment"]["request_share_display"] == "12.0%"
    assert ctx["impact_assessment"]["hunt"]["request_share_display"] == "24.0%"
    assert ctx["lead_cards"][0]["drilldown_coverage"]["status_label"] == "Thin Slice"
    assert any("multi-lead campaign" in item for item in ctx["evidence_boundaries"]["observed"])
    assert any("Operator identity" in item for item in ctx["evidence_boundaries"]["not_established"])
    assert any("Primary request surface characterized is not established" in item for item in ctx["evidence_boundaries"]["not_established"])
    print_ctx = deepcopy(ctx)
    print_ctx["profile"] = "print"
    threat_hunt.post_prepare(print_ctx)
    assert "(24.0% of window traffic)" in print_ctx["verdict"]["prose_html"]
    assert [row["label"] for row in print_ctx["attack_shape"]["impact_rows"][:4]] == [
        "Hits",
        "Hydrolix log ingest",
        "Response body",
        "Akamai-billed",
    ]
    assert print_ctx["story_primary_finding"]["impact"][1]["value"] == "24.0%"

    no_campaign = deepcopy(artifact)
    no_campaign["campaigns"] = []
    no_campaign["scraper_cases"][0].pop("temporal_regularity")
    no_campaign["scraper_cases"][0]["endpoint_targets"] = []
    ctx = threat_hunt.prepare(no_campaign)
    assert ctx["deterministic_summary"]["level_label"] == "Scraper lead"
    assert ctx["deterministic_summary"]["confidence_label"] == "Limited confidence"
    assert "No coordinated scraper campaign" in ctx["threat_findings"][0]["lead"]
    assert any("timing regularity is not established" in item for item in ctx["evidence_boundaries"]["not_established"])
    assert any("Primary request surface characterized is not established" in item for item in ctx["evidence_boundaries"]["not_established"])

    no_drilldown = deepcopy(artifact)
    no_drilldown["scraper_cases"][0]["endpoint_targets"] = []
    no_drilldown["scraper_cases"][0]["drilldown_coverage"] = {"status": "unavailable"}
    ctx = threat_hunt.prepare(no_drilldown)
    assert any("drilldown behavior is not established" in item for item in ctx["evidence_boundaries"]["not_established"])

    weak_first_party = deepcopy(artifact)
    weak_first_party["campaigns"] = []
    weak_first_party["scraper_cases"] = [
        {
            "user_agent": "Expedia/2026.19 CFNetwork/3826.400.120 Darwin/24.3.0",
            "verdict": "weak_lead",
            "requests": 5000,
            "baseline_requests": 4000,
            "evidence_flags": ["endpoint_targeting"],
            "ua_plausibility": {
                "parsed": {
                    "ua_class": "native_app",
                    "browser_family": "Unknown",
                    "platform": "iOS",
                },
                "verdict": "unavailable",
            },
            "confidence_assessment": {"qualifier": "partial"},
        }
    ]
    ctx = threat_hunt.prepare(weak_first_party)
    assert "lead scraper fingerprint" not in ctx["threat_findings"][1]["lead"]
    assert "evidence-bounded lead" in ctx["threat_findings"][1]["lead"]
