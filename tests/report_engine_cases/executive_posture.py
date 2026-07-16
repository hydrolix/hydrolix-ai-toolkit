from __future__ import annotations

from tests.report_engine_helpers import *

def test_executive_posture_full_wrapper():
    """Full wrapper with posture + mover + scorecards; mover concentration
    drives traffic-weighted lead and `requests` becomes top metric."""
    wrapper = FIXTURES / "executive_posture_full.json"
    snapshot = SNAPSHOTS / "executive_posture_full.html"
    actual = _normalize(_render(wrapper))
    _assert_snapshot(actual, snapshot)
    # Spot checks the snapshot doesn't enforce by itself.
    assert "Bot &amp; Edge Movement" in actual
    assert "Total requests up" in actual
    assert "covers 87" in actual  # mover share clause
    assert "Investigate" in actual
    assert "ASN 64500" in actual

def test_executive_posture_no_movers():
    """Mover artifact absent → headline falls back to direction + magnitude
    only, no contribution clause appended."""
    wrapper = FIXTURES / "executive_posture_no_movers.json"
    snapshot = SNAPSHOTS / "executive_posture_no_movers.html"
    actual = _normalize(_render(wrapper))
    _assert_snapshot(actual, snapshot)
    # No mover banner element (its CSS class still appears inside the
    # embedded stylesheet — check for the rendered <div> instead) and no
    # "covers N% of the increase" clause in prose.
    assert '<div class="shared-signal-banner"' not in actual
    assert "covers 87" not in actual
    # The actions section still surfaces the bot_share_pct and rate-related
    # actions when their thresholds trigger.
    assert "Bot share" in actual

def test_executive_posture_thin_coverage():
    """All metrics low confidence / one with unknown direction → caveat
    fires; metric rows carry confidence chips."""
    wrapper = FIXTURES / "executive_posture_thin_coverage.json"
    snapshot = SNAPSHOTS / "executive_posture_thin_coverage.html"
    actual = _normalize(_render(wrapper))
    _assert_snapshot(actual, snapshot)
    assert "Coverage is thin" in actual
    assert "Real movement may be larger than the visible delta" in actual
    assert "Low confidence" in actual
    # Insufficient data pill should be non-zero (one metric has unknown
    # direction).
    assert "Insufficient data" in actual
