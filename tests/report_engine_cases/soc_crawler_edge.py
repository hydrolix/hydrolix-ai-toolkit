from __future__ import annotations

from tests.report_engine_helpers import *

def test_soc_triage_full_wrapper():
    """Full wrapper bundling a packet of two ranked ASNs. The top entity
    has a security_evidence primary domain and 5 triggered rules; the
    second entity has only one triggered SIEM rule (Watch). Caveat fires
    on missing-input ratio."""
    wrapper = FIXTURES / "soc_triage_full.json"
    snapshot = SNAPSHOTS / "soc_triage_full.html"
    actual = _normalize(_render(wrapper))
    _assert_snapshot(actual, snapshot)
    # Title and lead.
    assert "SOC Triage — www.example.com, ASN risk queue" in actual
    assert "ASN 64500" in actual
    assert "bad-bot share 65%" in actual
    assert "SIEM evidence present" in actual
    # Caveat fires on the example's high missing-input ratio.
    assert "Real risk may be higher than the score implies" in actual
    # Verdict strip mutes the zero-count pills.
    assert "pill-muted" in actual
    # Security evidence cards render for the Assign entity, with both
    # the security and supporting movement blocks populated.
    assert '<article class="sec-evidence-card' in actual
    assert ">Security signals<" in actual
    assert ">Supporting movement signals<" in actual
    # Domain score matrix renders both active domains.
    assert '<table class="data-table domain-matrix">' in actual
    # Full wrapper is NOT degraded.
    assert '<div class="degraded-banner"' not in actual

def test_soc_triage_index_only_degraded():
    """Wrapper carries the ranking index but no scorecards. Degraded
    banner fires; queue table renders rows from the index; no security
    cards or domain matrix."""
    wrapper = FIXTURES / "soc_triage_index_only.json"
    snapshot = SNAPSHOTS / "soc_triage_index_only.html"
    actual = _normalize(_render(wrapper))
    _assert_snapshot(actual, snapshot)
    assert '<div class="degraded-banner"' in actual
    assert "ASN 64500" in actual
    assert "ASN 64600" in actual
    # Domain matrix and security cards are absent in degraded mode.
    assert '<table class="data-table domain-matrix">' not in actual
    assert ">Security signals<" not in actual
    assert '<article class="sec-evidence-card' not in actual

def test_soc_triage_single_entity():
    """N=1 wrapper with full per-rule data plus entity_metrics. Triage
    strip reads as singular; traffic-share clause appears in the lead
    because every scorecard carries current_requests."""
    wrapper = FIXTURES / "soc_triage_single_entity.json"
    snapshot = SNAPSHOTS / "soc_triage_single_entity.html"
    actual = _normalize(_render(wrapper))
    _assert_snapshot(actual, snapshot)
    assert "1 of 1 ASN" in actual
    assert "covers 100% of fleet requests" in actual
    # Singular noun in the verdict-strip rationale ("1 ASN needs ...").
    assert "1 ASN needs analyst attention" in actual
    # Single-entity should still render the queue + cards + matrix.
    assert "ASN 64500" in actual

def test_crawler_governance_full_wrapper():
    """Full wrapper bundling a packet of three ranked AI categories. The
    top entity has a crawler_governance primary domain with all six
    crawler-governance rules triggered plus a movement supporting rule;
    the second entity has three crawler-governance triggers; the third
    only one. Verdict pills mute zero counts."""
    wrapper = FIXTURES / "crawler_governance_full.json"
    snapshot = SNAPSHOTS / "crawler_governance_full.html"
    actual = _normalize(_render(wrapper))
    _assert_snapshot(actual, snapshot)
    assert "Crawler Governance — www.example.com, AI category health queue" in actual
    assert "AI Training" in actual
    assert "80 governance-surface failures" in actual
    # Crawler evidence cards render for the Assign entities, with both
    # the crawler-governance and supporting blocks populated.
    assert '<article class="sec-evidence-card' in actual
    assert ">Crawler-governance signals<" in actual
    assert ">Supporting signals<" in actual
    # Domain score matrix renders both active domains (crawler + movement).
    assert '<table class="data-table domain-matrix">' in actual
    # Full wrapper is NOT degraded.
    assert '<div class="degraded-banner"' not in actual

def test_crawler_governance_index_only_degraded():
    """Wrapper carries the ranking index but no scorecards. Degraded
    banner fires; queue table renders rows from the index; no crawler
    cards or domain matrix."""
    wrapper = FIXTURES / "crawler_governance_index_only.json"
    snapshot = SNAPSHOTS / "crawler_governance_index_only.html"
    actual = _normalize(_render(wrapper))
    _assert_snapshot(actual, snapshot)
    assert '<div class="degraded-banner"' in actual
    assert "AI Training" in actual
    assert "Search Crawler" in actual
    # Domain matrix and crawler cards are absent in degraded mode.
    assert '<table class="data-table domain-matrix">' not in actual
    assert ">Crawler-governance signals<" not in actual
    assert '<article class="sec-evidence-card' not in actual

def test_crawler_governance_single_entity():
    """N=1 wrapper with full per-rule data plus entity_metrics. Triage
    strip reads as singular; traffic-share clause appears in the lead
    because every scorecard carries current_requests."""
    wrapper = FIXTURES / "crawler_governance_single_entity.json"
    snapshot = SNAPSHOTS / "crawler_governance_single_entity.html"
    actual = _normalize(_render(wrapper))
    _assert_snapshot(actual, snapshot)
    assert "1 of 1 AI category" in actual
    assert "covers 100% of fleet requests" in actual
    # Singular noun in the verdict-strip rationale.
    assert "1 AI category needs analyst attention" in actual
    # Single-entity should still render the queue + cards.
    assert "AI Training" in actual

def test_edge_ops_impact_full_wrapper():
    """Full wrapper bundling a packet of three ranked ASNs and a path-grain
    cache_origin_impact_report. Top two entities carry origin_cost_contribution_pct,
    so the cost-share headline fires; path candidates trigger the top-paths section."""
    wrapper = FIXTURES / "edge_ops_impact_full.json"
    snapshot = SNAPSHOTS / "edge_ops_impact_full.html"
    actual = _normalize(_render(wrapper))
    _assert_snapshot(actual, snapshot)
    # Cost-share headline assertions
    assert "concentrate" in actual
    assert "% of origin pressure" in actual
    # Top-paths section
    assert '<table class="data-table path-candidates-table">' in actual
    # Edge & origin block label (NOT "Crawler-governance signals")
    assert ">Edge &amp; origin signals<" in actual
    assert ">Crawler-governance signals<" not in actual
    # Evidence cards exist
    assert '<article class="sec-evidence-card' in actual
    # Domain matrix renders cache_busting + origin_impact at minimum
    assert '<table class="data-table domain-matrix">' in actual
    # Full wrapper is NOT degraded
    assert '<div class="degraded-banner"' not in actual
    assert "ASN 64500" in actual
    assert "/api/v1/pricing" in actual

def test_edge_ops_impact_index_only_degraded():
    """Wrapper carries the ranking index but no scorecards and no path
    artifact. Degraded banner fires; queue table renders rows from the
    index; no edge cards, no top-paths section, no domain matrix."""
    wrapper = FIXTURES / "edge_ops_impact_index_only.json"
    snapshot = SNAPSHOTS / "edge_ops_impact_index_only.html"
    actual = _normalize(_render(wrapper))
    _assert_snapshot(actual, snapshot)
    assert '<div class="degraded-banner"' in actual
    assert "ASN 64500" in actual
    assert "ASN 64600" in actual
    assert '<table class="data-table domain-matrix">' not in actual
    assert ">Edge &amp; origin signals<" not in actual
    assert '<article class="sec-evidence-card' not in actual
    # No path-candidates table when path artifact absent
    assert '<table class="data-table path-candidates-table">' not in actual

def test_edge_ops_impact_single_entity_no_paths():
    """N=1 wrapper with full per-rule data, entity_metrics, and no path
    artifact. Cost-share lens does NOT fire (origin_cost_contribution_pct
    omitted on the triggered rules), so the rule-based fallback headline
    fires; traffic-share clause appears."""
    wrapper = FIXTURES / "edge_ops_impact_single_entity_no_paths.json"
    snapshot = SNAPSHOTS / "edge_ops_impact_single_entity_no_paths.html"
    actual = _normalize(_render(wrapper))
    _assert_snapshot(actual, snapshot)
    # Cost-share clause should NOT appear (origin_cost_contribution_pct absent)
    assert "% of origin pressure" not in actual
    # Traffic-share clause should appear (entity_metrics carries current_requests)
    assert "covers 100% of fleet requests" in actual
    # Top-paths section absent
    assert '<table class="data-table path-candidates-table">' not in actual
