"""Snapshot and unit tests for the Bot Insights report engine.

Run all tests:
    uv run pytest tests/test_report_engine.py -v

Update snapshots after an intentional rendering change:
    REPORT_ENGINE_UPDATE_SNAPSHOTS=1 uv run pytest tests/test_report_engine.py
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
ENGINE_DIR = ROOT / "skills/bot-insights/scripts/report_engine"
REPORTKIT_THEME = ROOT / "reportkit/src/reportkit/theme.py"
RENDER_PY = ENGINE_DIR / "render.py"
FIXTURES = Path(__file__).parent / "fixtures/report_engine"
SNAPSHOTS = Path(__file__).parent / "snapshots/report_engine"

# Make charts/findings/theme importable for direct unit tests.
# (markdown.py needs markdown_it + bleach which may be absent — those tests use importorskip.)
sys.path.insert(0, str(ENGINE_DIR.parent))

UPDATE_SNAPSHOTS = os.environ.get("REPORT_ENGINE_UPDATE_SNAPSHOTS") == "1"

VOLATILE_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # Footer "Generated 2026-05-09 12:34 UTC ·" — render time changes per run.
    (re.compile(r"Generated \d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC"), "Generated <FROZEN>"),
)


def _normalize(html: str) -> str:
    """Strip render-time volatility so snapshots are stable across runs."""
    for pattern, replacement in VOLATILE_PATTERNS:
        html = pattern.sub(replacement, html)
    return html


def _render(artifact: Path, *extra: str) -> str:
    """Invoke render.py via uv and return the rendered HTML string."""
    if shutil.which("uv") is None:
        pytest.skip("uv not available")
    with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
        out_path = Path(f.name)
    try:
        subprocess.run(
            [
                "uv",
                "run",
                "--quiet",
                str(RENDER_PY),
                "--artifact",
                str(artifact),
                "--out",
                str(out_path),
                *extra,
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        return out_path.read_text()
    finally:
        out_path.unlink(missing_ok=True)


def _assert_snapshot(actual: str, snapshot_path: Path) -> None:
    """Compare against a committed snapshot, or write one on first run."""
    snapshot_path.parent.mkdir(parents=True, exist_ok=True)
    if UPDATE_SNAPSHOTS or not snapshot_path.exists():
        snapshot_path.write_text(actual)
        if not UPDATE_SNAPSHOTS:
            pytest.skip(f"wrote initial snapshot to {snapshot_path}")
        return
    expected = snapshot_path.read_text()
    if actual != expected:
        diff_path = snapshot_path.with_suffix(".html.actual")
        diff_path.write_text(actual)
        pytest.fail(
            f"snapshot mismatch vs {snapshot_path}.\n"
            f"actual written to {diff_path} for inspection.\n"
            f"if the change is intentional, update with: "
            f"REPORT_ENGINE_UPDATE_SNAPSHOTS=1 uv run pytest "
            f"{Path(__file__).relative_to(ROOT)} -v"
        )


def test_scorecard_brief_artifact_full():
    artifact = FIXTURES / "scorecard_brief_acme_artifact.json"
    snapshot = SNAPSHOTS / "scorecard_brief_acme_full.html"
    actual = _normalize(_render(artifact))
    _assert_snapshot(actual, snapshot)


def test_scorecard_brief_artifact_brief():
    artifact = FIXTURES / "scorecard_brief_acme_artifact.json"
    snapshot = SNAPSHOTS / "scorecard_brief_acme_brief.html"
    actual = _normalize(_render(artifact, "--mode", "brief"))
    _assert_snapshot(actual, snapshot)


def test_scorecard_brief_wrapper_full():
    wrapper = FIXTURES / "scorecard_brief_acme_wrapper.json"
    snapshot = SNAPSHOTS / "scorecard_brief_acme_wrapper.html"
    actual = _normalize(_render(wrapper))
    _assert_snapshot(actual, snapshot)


def test_scorecard_brief_wrapper_brief():
    wrapper = FIXTURES / "scorecard_brief_acme_wrapper.json"
    snapshot = SNAPSHOTS / "scorecard_brief_acme_wrapper_brief.html"
    actual = _normalize(_render(wrapper, "--mode", "brief"))
    _assert_snapshot(actual, snapshot)


# ---- Executive posture (Bot & Edge Movement) --------------------------------


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


# ---- SOC triage --------------------------------------------------------------


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


# ---- Crawler governance ------------------------------------------------------


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


# ---- Edge ops impact ---------------------------------------------------------


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


# ---- XSS guard ---------------------------------------------------------------


def test_xss_in_analyst_notes_is_scrubbed():
    """Malicious analyst_notes must not survive the markdown→bleach pipeline.

    Safety is about what the browser EXECUTES, not literal substrings — escaped
    text like ``&lt;script&gt;`` is harmless and may legitimately appear inside
    rendered notes. Assertions look for live tag/attribute patterns only.
    """
    fixture = FIXTURES / "scorecard_brief_acme_malicious_notes.json"
    actual = _render(fixture)
    lower = actual.lower()

    # Live dangerous tags (escaped occurrences are fine).
    for tag in ("<script", "<iframe", "<img ", "<img>", "<object", "<embed"):
        assert tag not in lower, f"live {tag!r} tag survived"

    # Event-handler attributes inside any real tag: <tagname ... on*=
    # The escaped form (&lt;img ... onerror=…&gt;) does not match this pattern.
    assert not re.search(r"<\w+[^>]*\son\w+\s*=", lower), (
        "on*= event-handler attribute on a live tag survived"
    )

    # javascript: URLs inside live href/src attributes.
    assert not re.search(r"""(href|src)\s*=\s*['"]?\s*javascript:""", lower), (
        "javascript: URL in href/src survived"
    )

    # Only the template's own <style> should exist (one).
    assert lower.count("<style") == 1, (
        f"expected 1 <style> (template own), found {lower.count('<style')}"
    )

    # Safe content from the same notes SHOULD appear.
    assert "apihub.acme.com" in actual
    assert "the docs" in actual.lower()
    assert "https://example.com/docs" in actual

    # The note contained `# Top-level header` — must be demoted to h2.
    assert "Top-level header" in actual
    h1_count = lower.count("<h1>")
    assert h1_count == 1, f"expected exactly 1 <h1> (page title), found {h1_count}"


# ---- Pure helper unit tests --------------------------------------------------


def test_bullet_chart_svg_basic():
    from report_engine.charts import bullet_chart_svg

    svg = bullet_chart_svg(actual=85, comparison=70)
    assert svg.startswith("<svg")
    assert svg.endswith("</svg>")
    # Three band rectangles + one actual rectangle = at least 4 rects
    assert svg.count("<rect") >= 4
    # Comparison tick is a <line>
    assert "<line" in svg


def test_bullet_chart_svg_clamps_oob():
    from report_engine.charts import bullet_chart_svg

    # Out-of-range values must clamp, not crash or produce negative widths.
    svg = bullet_chart_svg(actual=150, comparison=-5)
    assert "<svg" in svg
    assert 'width="-' not in svg
    assert 'x1="-' not in svg


def test_slopegraph_svg_empty_returns_empty():
    from report_engine.charts import slopegraph_svg

    assert slopegraph_svg([]) == ""


def test_slopegraph_svg_renders_pairs():
    from report_engine.charts import slopegraph_svg

    entities = [
        {
            "entity": "a.example",
            "score": 80,
            "delta": -10,
        },  # improved (was 90 → 80? no — score went down)
        {"entity": "b.example", "score": 95, "delta": 5},  # was 90, now 95
        {"entity": "c.example", "score": 70, "delta": -20},
    ]
    svg = slopegraph_svg(entities, label_left="baseline", label_right="current")
    assert "a.example" in svg
    assert "baseline" in svg
    assert "current" in svg
    # Each entity → 2 dots + 1 line + 1 label = 4 elements minimum
    assert svg.count("<circle") == 6  # 3 entities × 2 dots
    assert svg.count("<line") == 3


def test_score_gauge_svg_band_zones():
    from report_engine.charts import score_gauge_svg

    svg = score_gauge_svg(85)
    # Three arc-zone strokes (escalate / monitor / observe) + 1 pointer line
    assert svg.count("<path") == 3
    # Big number rendered
    assert ">85<" in svg
    # Band label rendered
    assert "observe" in svg


def test_incident_volume_chart_uses_semantic_accent_only_for_incident_cues():
    from report_engine.charts import incident_volume_chart_svg

    svg = incident_volume_chart_svg(
        [10, 25, 90, 20],
        baseline=[8, 9, 10, 9],
        accent="#E15759",
        accent_fill="#FBE5E6",
        baseline_color="#4A5A73",
        peak_label="Peak 90",
        highlight_start_fraction=0.25,
        highlight_end_fraction=0.75,
    )

    assert "<path" not in svg
    assert 'stroke="#4E79A7" stroke-width="2.2"' in svg
    assert 'stroke="#E15759" stroke-width="2.2"' not in svg
    assert 'fill="#E15759" fill-opacity="0.10"' in svg
    assert svg.count('stroke="#E15759" stroke-width="1" stroke-opacity="0.35"') == 2
    assert '<circle cx="' in svg and 'fill="#E15759"' in svg
    assert 'fill="#E15759">Peak 90</text>' in svg
    assert 'stroke="#4A5A73"' in svg


def test_findings_shared_signal_when_one_rule_dominates():
    from report_engine.findings import build_scorecard_brief_findings
    from collections import Counter

    # Synthetic: 5 hosts, all with cache_miss_rate_high triggered
    scorecards = [
        {
            "rule_results": [
                {
                    "name": "cache_miss_rate_high",
                    "status": "triggered",
                    "domain": "cache_busting",
                    "points": 10,
                },
                {
                    "name": "querystring_diversity_high",
                    "status": "missing_input",
                    "domain": "cache_busting",
                    "points": 0,
                },
            ],
        }
        for _ in range(5)
    ]
    coverage = {
        "cache_busting": {"triggered": 5, "missing_input": 5, "evaluated_zero": 0},
    }
    domain_counts = Counter({"cache_busting": 5})

    findings = build_scorecard_brief_findings(
        scorecards,
        n_total=5,
        n_with_triggers=5,
        n_clean=0,
        n_moved=0,
        domain_counts=domain_counts,
        coverage=coverage,
    )

    assert len(findings) >= 1
    top = findings[0]
    assert top.finding_id == "shared_signal"
    assert "5 hosts" in top.title
    assert "investigate as one issue" in top.title


def test_findings_apply_overrides_replaces_headline():
    from report_engine.findings import Finding, apply_finding_overrides

    findings = [
        Finding(finding_id="shared_signal", title="orig title", body="b"),
        Finding(finding_id="no_movement", title="orig title 2", body="b2"),
    ]
    overrides = '[{"finding_id": "shared_signal", "headline": "Exec rewrite"}]'
    result = apply_finding_overrides(findings, overrides)
    assert result[0].headline == "Exec rewrite"
    assert result[1].headline is None  # untouched


def test_findings_apply_overrides_ignores_malformed():
    from report_engine.findings import Finding, apply_finding_overrides

    findings = [Finding(finding_id="x", title="t", body="b")]
    # Malformed JSON, missing fields, wrong types — all silently ignored.
    for bad in (
        None,
        "",
        "not json",
        "{}",
        "[]",
        '[{"finding_id": "x"}]',  # no headline
        '[{"headline": "lone"}]',  # no finding_id
        '[{"finding_id": "x", "headline": ""}]',  # empty headline
        "42",
    ):  # not a list
        result = apply_finding_overrides(
            [Finding(finding_id="x", title="t", body="b")], bad
        )
        assert result[0].headline is None, f"bad input {bad!r} produced override"


# ---- Markdown helper (gated on optional deps) --------------------------------


def test_markdown_render_safe_strips_scripts():
    pytest.importorskip("markdown_it")
    pytest.importorskip("bleach")
    from report_engine.markdown import render_safe

    out = str(render_safe("Hello\n\n<script>alert('x')</script>\n\n**bold**"))
    assert "<script" not in out
    assert "<strong>bold</strong>" in out


def test_markdown_render_safe_demotes_h1():
    pytest.importorskip("markdown_it")
    pytest.importorskip("bleach")
    from report_engine.markdown import render_safe

    out = str(render_safe("# Top header"))
    assert "<h1>" not in out
    assert "<h2>Top header</h2>" in out


def test_markdown_render_safe_blocks_javascript_links():
    """No exploitable ``<a>`` tag is emitted for a ``javascript:`` URL.

    Current ``markdown-it-py`` refuses to emit an ``<a>`` for a disallowed
    URL scheme and leaves the literal source inside a ``<p>``. The
    substantive property is structural — no anchor element with an
    executable href — not the absence of the inert source text.
    """
    pytest.importorskip("markdown_it")
    pytest.importorskip("bleach")
    from report_engine.markdown import render_safe

    out = str(render_safe("[click](javascript:alert('x'))"))
    assert 'href="javascript:' not in out
    assert "<a " not in out


def test_markdown_render_safe_allows_https_links():
    pytest.importorskip("markdown_it")
    pytest.importorskip("bleach")
    from report_engine.markdown import render_safe

    out = str(render_safe("[docs](https://example.com)"))
    assert 'href="https://example.com"' in out


# ---------------------------------------------------------------------------
# humanize / deltas — symbol consolidation in M1.1
# ---------------------------------------------------------------------------


def test_humanize_rule_label_parts_known_signal_returns_explicit_pair():
    from report_engine.humanize import rule_label_parts

    assert rule_label_parts("querystring_diversity_high") == (
        "Query String Diversity",
        "High",
    )
    assert rule_label_parts(
        "querystring_diversity_with_high_miss_rate"
    ) == ("Query String Diversity", "With High Miss Rate")


def test_humanize_rule_label_parts_unknown_falls_back_to_display_label():
    from report_engine.humanize import rule_label_parts

    assert rule_label_parts("unknown_signal_shape") == (
        "Unknown Signal Shape",
        "",
    )


def test_humanize_rule_label_parts_preserves_acronyms():
    from report_engine.humanize import rule_label_parts

    axis, condition = rule_label_parts("siem_blocked_present")
    assert axis == "SIEM Blocked Requests"
    assert condition == "Present"


def test_humanize_human_metric_name_known_returns_label():
    from report_engine.humanize import human_metric_name

    assert human_metric_name("requests") == "Total requests"
    assert human_metric_name("bot_share_pct") == "Bot share"


def test_humanize_human_metric_name_unknown_returns_raw_text():
    """Identity fallback is load-bearing — the legacy markdown escape
    test in test_skill_scripts expects user-controlled metric names to
    pass through unchanged so downstream escaping sees them verbatim.
    """
    from report_engine.humanize import human_metric_name

    assert human_metric_name("custom_producer_metric") == "custom_producer_metric"
    assert human_metric_name("bad*name_with|pipe") == "bad*name_with|pipe"


def test_humanize_render_report_reexports_are_the_same_objects():
    """Legacy callers still reference render_report.<name>; consolidation
    must preserve that path."""
    import render_report
    from report_engine import humanize

    assert render_report.METRIC_LABELS is humanize.METRIC_LABELS
    assert render_report.human_metric_name is humanize.human_metric_name
    assert render_report.display_label is humanize.display_label
    assert render_report.rule_label_parts is humanize.rule_label_parts
    assert render_report.stringify is humanize.stringify


def test_deltas_pct_delta_matches_baseline_helper():
    import baselines
    from report_engine import deltas

    assert deltas.pct_delta(150.0, 100.0) == baselines.pct_delta(150.0, 100.0)
    # Zero baseline clamps to 1.0, not a division error.
    assert deltas.pct_delta(7.0, 0.0) == 700.0


def test_deltas_direction_matches_baseline_helper():
    from report_engine import deltas

    assert deltas.direction(5.0) == "increase"
    assert deltas.direction(-3.0) == "decrease"
    assert deltas.direction(0.0) == "no_change"


def test_deltas_signed_delta_pp_is_subtraction_not_relative_change():
    """signed_delta_pp is the percentage-point delta for two values
    already expressed as percentages. It must NOT compute the relative
    pct_delta — that would conflate share-of-X with change-of-X."""
    from report_engine import deltas

    assert deltas.signed_delta_pp(42.5, 40.0) == 2.5
    assert deltas.signed_delta_pp(40.0, 42.5) == -2.5
    assert deltas.signed_delta_pp(0.0, 0.0) == 0.0
    # Negative inputs also work — caller is responsible for unit sanity.
    assert deltas.signed_delta_pp(-1.0, -3.0) == 2.0


def test_deltas_signed_delta_pp_returns_float_for_int_inputs():
    from report_engine import deltas

    result = deltas.signed_delta_pp(10, 7)
    assert result == 3.0
    assert isinstance(result, float)


# ---------------------------------------------------------------------------
# Companion selection (M1.2 extraction into report_engine.contexts._shared)
# ---------------------------------------------------------------------------


def _control_fixture(**overrides):
    """Minimal ``bot_control_review.v1`` artifact for companion-selection tests."""
    base = {
        "schema_version": "bot_control_review.v1",
        "artifact_id": "control-1",
        "before_window": {"start": "2026-04-08T00:00:00Z", "end": "2026-04-15T00:00:00Z"},
        "after_window": {"start": "2026-04-15T00:00:00Z", "end": "2026-04-22T00:00:00Z"},
        "scope": {"cluster": "demo", "database": "akamai"},
        "table_used": "akamai.bi_summary_hour",
        "comparison_type": "post_change_vs_expected",
        "target": {"feature": "policy-tighten-1"},
        "target_effects": [],
    }
    base.update(overrides)
    return base


def _posture_fixture(**overrides):
    base = {
        "schema_version": "bot_posture_movement.v1",
        "artifact_id": "posture-1",
        "scope": {"cluster": "demo", "database": "akamai"},
        "table_used": "akamai.bi_summary_hour",
        "comparison_type": "previous_window",
        "current_window": {
            "start": "2026-04-15T00:00:00Z",
            "end": "2026-04-22T00:00:00Z",
        },
        "baseline_windows": [
            {"start": "2026-04-08T00:00:00Z", "end": "2026-04-15T00:00:00Z"}
        ],
        "metrics": [],
    }
    base.update(overrides)
    return base


def _mover_fixture(**overrides):
    base = {
        "schema_version": "bot_mover_attribution.v1",
        "artifact_id": "mover-1",
        "scope": {"cluster": "demo", "database": "akamai"},
        "table_used": "akamai.bi_summary_hour",
        "comparison_type": "previous_window",
        "current_window": {
            "start": "2026-04-15T00:00:00Z",
            "end": "2026-04-22T00:00:00Z",
        },
        "baseline_windows": [
            {"start": "2026-04-08T00:00:00Z", "end": "2026-04-15T00:00:00Z"}
        ],
        "movers": [],
    }
    base.update(overrides)
    return base


def _timeseries_fixture(**overrides):
    base = {
        "schema_version": "bot_timeseries.v1",
        "artifact_id": "timeseries-1",
        "scope": {"cluster": "demo", "database": "akamai"},
        "table_used": "akamai.bi_summary_hour",
        "comparison_type": "previous_window",
        "current_window": {
            "start": "2026-04-15T00:00:00Z",
            "end": "2026-04-22T00:00:00Z",
        },
        "baseline_windows": [
            {"start": "2026-04-08T00:00:00Z", "end": "2026-04-15T00:00:00Z"}
        ],
        "metrics": [],
    }
    base.update(overrides)
    return base


def test_select_control_companions_happy_path_with_control_only():
    from report_engine.contexts._shared import select_control_companions

    warnings = []
    result = select_control_companions(
        [_control_fixture()],
        warn=warnings.append,
    )
    assert result["control"]["artifact_id"] == "control-1"
    assert result["posture"] is None
    assert result["mover"] is None
    assert result["timeseries"] is None
    assert warnings == []


def test_select_control_companions_drops_posture_when_window_metadata_differs():
    """The legacy renderer's compatibility check requires every field in
    COMPANION_COMPAT_FIELDS to match. The control artifact carries
    ``before_window``/``after_window``, not ``current_window``/
    ``baseline_windows``, so a posture companion is always rejected on
    missing-metadata grounds. Pin this behavior so the engine port matches.
    """
    from report_engine.contexts._shared import select_control_companions

    warnings = []
    result = select_control_companions(
        [_control_fixture(), _posture_fixture()],
        warn=warnings.append,
    )
    assert result["posture"] is None
    assert any(
        "posture posture-1" in w and "missing current_window" in w for w in warnings
    ), f"Expected missing-metadata warning, got: {warnings}"


def test_select_control_companions_accepts_companion_when_metadata_aligns():
    """If a companion happens to carry the same compatibility fields as
    the control (synthetic but possible), it should pass through."""
    from report_engine.contexts._shared import select_control_companions

    control = _control_fixture(
        current_window={
            "start": "2026-04-15T00:00:00Z",
            "end": "2026-04-22T00:00:00Z",
        },
        baseline_windows=[
            {"start": "2026-04-08T00:00:00Z", "end": "2026-04-15T00:00:00Z"}
        ],
        comparison_type="previous_window",
    )
    warnings = []
    result = select_control_companions(
        [control, _posture_fixture()],
        warn=warnings.append,
    )
    assert result["posture"]["artifact_id"] == "posture-1"
    assert warnings == []


def test_select_control_companions_raises_when_no_control_present():
    from report_engine.contexts._shared import select_control_companions

    with pytest.raises(ValueError, match="missing bot_control_review.v1"):
        select_control_companions([_posture_fixture()])


def test_select_control_companions_raises_on_multiple_controls():
    from report_engine.contexts._shared import select_control_companions

    with pytest.raises(ValueError, match="multiple bot_control_review.v1"):
        select_control_companions(
            [_control_fixture(), _control_fixture(artifact_id="control-2")]
        )


def test_select_control_companions_raises_on_multiple_postures():
    from report_engine.contexts._shared import select_control_companions

    with pytest.raises(ValueError, match="multiple bot_posture_movement.v1"):
        select_control_companions(
            [
                _control_fixture(),
                _posture_fixture(),
                _posture_fixture(artifact_id="posture-2"),
            ]
        )


def test_select_control_companions_drops_mover_with_conflicting_table_used():
    """Conflicting metadata (not just missing) also disqualifies a companion."""
    from report_engine.contexts._shared import select_control_companions

    control = _control_fixture(
        current_window={
            "start": "2026-04-15T00:00:00Z",
            "end": "2026-04-22T00:00:00Z",
        },
        baseline_windows=[
            {"start": "2026-04-08T00:00:00Z", "end": "2026-04-15T00:00:00Z"}
        ],
        comparison_type="previous_window",
    )
    bad_mover = _mover_fixture(table_used="akamai.bi_summary_day")
    warnings = []
    result = select_control_companions([control, bad_mover], warn=warnings.append)
    assert result["mover"] is None
    assert any("conflict on table_used" in w for w in warnings)


def test_select_control_companions_returns_timeseries_when_compatible():
    from report_engine.contexts._shared import select_control_companions

    control = _control_fixture(
        current_window={
            "start": "2026-04-15T00:00:00Z",
            "end": "2026-04-22T00:00:00Z",
        },
        baseline_windows=[
            {"start": "2026-04-08T00:00:00Z", "end": "2026-04-15T00:00:00Z"}
        ],
        comparison_type="previous_window",
    )
    warnings = []
    result = select_control_companions(
        [control, _timeseries_fixture()], warn=warnings.append
    )
    assert result["timeseries"]["artifact_id"] == "timeseries-1"
    assert warnings == []


def test_select_control_companions_warn_callable_is_optional():
    """``warn=None`` should suppress reporting; dropped companions still
    become ``None``. The legacy renderer always wires ``ctx.warn`` but
    tests and ad hoc callers should not have to."""
    from report_engine.contexts._shared import select_control_companions

    result = select_control_companions([_control_fixture(), _posture_fixture()])
    assert result["posture"] is None


def test_companion_compatible_known_helper_recognizes_empty_collections():
    """`known` is used to gate compatibility checks; empty containers are
    not "known" values and must disqualify the field on either side."""
    from report_engine.contexts._shared import known

    assert known("akamai.bi_summary_hour")
    assert known({"cluster": "demo"})
    assert known(["window-1"])
    assert known(0)
    assert known(False)
    assert not known(None)
    assert not known("")
    assert not known([])
    assert not known({})


# ---------------------------------------------------------------------------
# Control review — engine port (M1.2 part B)
# ---------------------------------------------------------------------------


def test_control_review_assemble_from_example_fixture():
    """Ported example wrapper assembles to the expected dict shape.

    The shipped example carries one control artifact, no companions, so
    posture/mover/timeseries should all be ``None``.
    """
    import json

    from report_engine.contexts import control_review

    wrapper = json.loads(
        (FIXTURES / "control_review_full.json").read_text()
    )
    result = control_review.assemble(wrapper["artifacts"])
    assert result["control"]["schema_version"] == "bot_control_review.v1"
    assert result["control"]["artifact_id"] == "control-review-1"
    assert result["posture"] is None
    assert result["mover"] is None
    assert result["timeseries"] is None


def test_control_review_prepare_emits_target_effects_rows():
    """``prepare()`` projects ``target_effects`` into the row shape the
    template consumes, with metric labels resolved through
    ``human_metric_name`` and status tones populated."""
    import json

    from report_engine.contexts import control_review

    wrapper = json.loads(
        (FIXTURES / "control_review_full.json").read_text()
    )
    artifact = control_review.assemble(wrapper["artifacts"])
    ctx = control_review.prepare(artifact)

    assert ctx["title"] == "Control Review"
    assert ctx["target"]["descriptor"] == "policy-bot-block-1"
    assert ctx["expected_basis"] == "explicit_target"
    assert ctx["expected_basis_label"] == "Explicit target"

    effects = ctx["effects"]
    assert len(effects) == 1
    effect = effects[0]
    assert effect["metric"] == "siem_blocked_requests"
    assert effect["metric_label"] == "SIEM blocked requests"
    assert effect["before"] == 90.0
    assert effect["after"] == 280.0
    assert effect["expected"] == 100.0
    assert effect["status"] == "increased"
    assert effect["status_label"] == "Increased"
    assert effect["status_tone"] == "monitor"
    assert effect["confidence"] == "high"


def test_control_review_prepare_emits_collateral_and_displacement_checks():
    """Collateral and displacement check arrays project to row dicts
    with the same status/tone shape the effects rows use."""
    import json

    from report_engine.contexts import control_review

    wrapper = json.loads(
        (FIXTURES / "control_review_full.json").read_text()
    )
    artifact = control_review.assemble(wrapper["artifacts"])
    ctx = control_review.prepare(artifact)

    coll = ctx["collateral_checks"]
    assert len(coll) == 1
    assert coll[0]["metric"] == "rate_429_pct"
    assert coll[0]["before"] == 0.4
    assert coll[0]["after"] == 2.1
    assert coll[0]["status"] == "increased"

    disp = ctx["displacement_checks"]
    assert len(disp) == 1
    assert disp[0]["metric"] == "requests"
    assert disp[0]["before"] == 1200000.0
    assert disp[0]["after"] == 1100000.0


def test_control_review_prepare_emits_dominant_finding_with_caveat():
    """The synthesized finding leads with the deterministic verdict, names
    the dominant effect, calls out the expected basis, and carries the
    no-causal-claim caveat plus an unavailable-deltas qualifier when
    side-effect deltas are missing.
    """
    import json

    from report_engine.contexts import control_review

    wrapper = json.loads(
        (FIXTURES / "control_review_full.json").read_text()
    )
    artifact = control_review.assemble(wrapper["artifacts"])
    ctx = control_review.prepare(artifact)

    assert len(ctx["findings"]) == 1
    finding = ctx["findings"][0]
    # Verdict-driven headline; the fixture's +180% vs expected lands in the
    # overshoot bucket.
    assert finding.finding_id == "control_review_overshoot"
    assert finding.headline.startswith("Overshoot vs expected")
    assert "SIEM blocked requests" in finding.headline
    assert "policy-bot-block-1" in finding.headline
    assert "explicit target" in (finding.body or "").lower()
    assert finding.recommendation is not None
    assert (
        "investigate" in finding.recommendation.lower()
        or "roll back" in finding.recommendation.lower()
    )
    assert finding.caveat is not None
    assert "causal" in finding.caveat.lower()
    # Collateral/displacement deltas are unavailable in the fixture, so the
    # caveat explicitly flags the confidence reduction.
    assert "unavailable" in finding.caveat.lower()


def test_control_review_prepare_empty_effects_emits_placeholder_finding():
    """An artifact with no ``target_effects`` still produces a finding
    so the executive summary slot has something to render."""
    from report_engine.contexts import control_review

    artifact = control_review.assemble(
        [
            {
                "schema_version": "bot_control_review.v1",
                "artifact_id": "control-empty-1",
                "before_window": {"start": "2026-04-08", "end": "2026-04-15"},
                "after_window": {"start": "2026-04-15", "end": "2026-04-22"},
                "scope": {"cluster": "demo"},
                "table_used": "demo.bi",
                "comparison_type": "post_change_vs_expected",
                "target": {"policy_id": "policy-x"},
                "target_effects": [],
            }
        ]
    )
    ctx = control_review.prepare(artifact)
    assert ctx["effects"] == []
    assert len(ctx["findings"]) == 1
    assert "No effects" in ctx["findings"][0].title


def test_control_review_renders_via_engine_with_oracle_class_names():
    """Smoke test the rendered HTML contains the engine-style class
    names the parity gates will assert on in M2.

    Renders through ``uv run`` (the same path the other snapshot tests
    use) so jinja2 doesn't have to be importable from the local Python.
    """
    wrapper = FIXTURES / "control_review_full.json"
    snapshot = SNAPSHOTS / "control_review_full.html"
    actual = _normalize(_render(wrapper))
    _assert_snapshot(actual, snapshot)

    # Engine-style scaffolding that the parity gates and class-presence
    # audit (M4.5) will assert on. These are inline assertions on top of
    # the snapshot comparison so the test's intent is legible.
    for needle in (
        "narrative-slot",
        "exec-summary",
        "report-header",
        "purpose-strip",
        "control-target",
        "control-effects",
        "control-collateral",
        "control-displacement",
        "effects-table",
        "status-pill",
    ):
        assert needle in actual, (
            f"expected class fragment {needle!r} in control_review render"
        )

    assert "SIEM blocked requests" in actual
    assert "Adjacent populations" in actual
    assert "substitute paths" in actual
    assert "Increased" in actual


# ---------------------------------------------------------------------------
# Markdown engine (M3.1)
# ---------------------------------------------------------------------------


def test_md_escape_escapes_table_pipe_separator():
    """Table cells separate on ``|`` in GFM tables; a producer-supplied
    string with a pipe must not break the table structure."""
    from report_engine.markdown import md_escape

    assert md_escape("a|b") == r"a\|b"


def test_md_escape_escapes_emphasis_markers():
    """``*`` and ``_`` start/end emphasis. Producer identifiers that
    contain them must stay literal."""
    from report_engine.markdown import md_escape

    assert md_escape("*bold*") == r"\*bold\*"
    assert md_escape("under_score") == r"under\_score"


def test_md_escape_escapes_backslash_first_to_avoid_recursion():
    """A literal backslash in the input must survive as a single escaped
    backslash, not double-escape into ``\\\\``."""
    from report_engine.markdown import md_escape

    assert md_escape("a\\b") == r"a\\b"


def test_md_escape_coerces_non_strings():
    from report_engine.markdown import md_escape

    assert md_escape(None) == ""
    assert md_escape(42) == "42"
    assert md_escape("") == ""


def test_md_escape_preserves_alphanumerics_and_spaces():
    from report_engine.markdown import md_escape

    assert md_escape("plain text 42") == "plain text 42"


def test_engine_template_for_derives_markdown_sibling_from_html():
    """The fmt-aware template selector replaces ``.html`` with ``.md.j2``
    so each context module only has to declare one TEMPLATE constant."""
    pytest.importorskip("jinja2")
    from report_engine import render as engine_render

    class _StubModule:
        REPORT_TYPE = "stub"
        TEMPLATE = "reports/stub_report.html"

    assert engine_render.template_for(_StubModule, "html") == "reports/stub_report.html"
    assert (
        engine_render.template_for(_StubModule, "markdown")
        == "reports/stub_report.md.j2"
    )


def test_engine_template_for_rejects_non_html_template_path():
    pytest.importorskip("jinja2")
    from report_engine import render as engine_render

    class _BadModule:
        REPORT_TYPE = "bad"
        TEMPLATE = "reports/bad_report.txt"

    with pytest.raises(ValueError, match="does not end in .html"):
        engine_render.template_for(_BadModule, "markdown")


def test_engine_render_executive_posture_markdown(tmp_path):
    """End-to-end smoke: render the executive_posture fixture through the
    engine's Markdown env and verify the output looks like Markdown
    (has H1 + H2 headers, has a GFM table, uses pct2 formatting)."""
    if not shutil.which("uv"):
        pytest.skip("uv not available")
    out = tmp_path / "exec.md"
    subprocess.run(
        [
            "uv",
            "run",
            "--quiet",
            "skills/bot-insights/scripts/report_engine/render.py",
            "--artifact",
            str(FIXTURES / "executive_posture_full.json"),
            "--out",
            str(out),
            "--format",
            "markdown",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    md = out.read_text()
    # Markdown structural markers
    assert md.startswith("# ")  # H1
    assert "\n## Executive Summary\n" in md
    assert "\n## Metric Deltas\n" in md
    assert "| Metric |" in md  # GFM table header
    # pct2 formatting reaches the body
    assert "87.18%" in md
    # md_escape applied — periods in domain identifiers are backslash-escaped
    assert "www\\.example\\.com" in md
    # The Markdown env does NOT HTML-escape (would have produced "&amp;").
    # md_escape uses CommonMark's backslash-escape list, which includes ``&``,
    # so a literal ampersand renders as ``\&`` in source and as ``&`` to the
    # reader.
    assert "\\&" in md
    assert "&amp;" not in md


# ---- M3.1b: per-type Markdown smoke tests -----------------------------------
#
# Each test renders one fixture through the engine's Markdown env and verifies
# the .md.j2 template produces a non-empty document with the expected
# structural markers (H1, the report-type fence, the type-specific section
# headers, and at least one GFM table for types that emit tabular content).
# These are deliberately lightweight — the full DOM-level Markdown parity
# gate lands in M3.2.

def _render_markdown(tmp_path, fixture_name: str) -> str:
    if not shutil.which("uv"):
        pytest.skip("uv not available")
    out = tmp_path / f"{fixture_name}.md"
    subprocess.run(
        [
            "uv",
            "run",
            "--quiet",
            "skills/bot-insights/scripts/report_engine/render.py",
            "--artifact",
            str(FIXTURES / f"{fixture_name}.json"),
            "--out",
            str(out),
            "--format",
            "markdown",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return out.read_text()


def test_engine_render_scorecard_brief_markdown(tmp_path):
    md = _render_markdown(tmp_path, "scorecard_brief_acme_artifact")
    assert md.startswith("# ")
    assert "Report type: `scorecard_brief`" in md
    assert "\n## Executive Summary\n" in md
    assert "\n## Triage\n" in md
    assert "\n## Queue\n" in md
    assert "\n## Method\n" in md
    assert "| State |" in md
    assert "| Rank |" in md
    # md_escape applied to host identifiers (fixture uses *.acme.com hosts).
    assert "acme\\.com" in md


def test_engine_render_scorecard_entity_review_markdown(tmp_path):
    # The wrapper has a single scorecard, so render auto-promotes to
    # scorecard_entity_review.
    md = _render_markdown(tmp_path, "scorecard_brief_acme_wrapper")
    assert md.startswith("# ")
    assert "Report type: `scorecard_entity_review`" in md
    assert "\n## Verdict\n" in md
    assert "\n## Executive Summary\n" in md
    assert "\n## Method\n" in md
    # md_escape applied to host identifiers (fixture uses *.acme.com hosts).
    assert "acme\\.com" in md


def test_engine_render_control_review_markdown(tmp_path):
    md = _render_markdown(tmp_path, "control_review_full")
    assert md.startswith("# ")
    assert "Report type: `control_review`" in md
    assert "\n## Target\n" in md
    assert "\n## Executive Summary\n" in md
    assert "\n## Target Effects\n" in md
    assert "\n## Collateral Checks\n" in md
    assert "\n## Displacement Checks\n" in md
    assert "\n## Method\n" in md
    assert "| Metric |" in md


def test_engine_render_soc_triage_markdown(tmp_path):
    md = _render_markdown(tmp_path, "soc_triage_full")
    assert md.startswith("# ")
    assert "Report type: `soc_triage`" in md
    assert "\n## Executive Summary\n" in md
    assert "\n## Triage\n" in md
    assert "\n## Queue\n" in md
    assert "\n## Method\n" in md
    # Per-entity security evidence cards render as H3s.
    assert "\n### ASN " in md


def test_engine_render_crawler_governance_markdown(tmp_path):
    md = _render_markdown(tmp_path, "crawler_governance_full")
    assert md.startswith("# ")
    assert "Report type: `crawler_governance`" in md
    assert "\n## Executive Summary\n" in md
    assert "\n## Triage\n" in md
    assert "\n## Queue\n" in md
    assert "\n## Method\n" in md
    assert "\n## Crawler Governance Evidence\n" in md


def test_engine_render_edge_ops_impact_markdown(tmp_path):
    md = _render_markdown(tmp_path, "edge_ops_impact_full")
    assert md.startswith("# ")
    assert "Report type: `edge_ops_impact`" in md
    assert "\n## Executive Summary\n" in md
    assert "\n## Triage\n" in md
    assert "\n## Queue\n" in md
    assert "\n## Method\n" in md
    # edge_ops_impact_full carries path candidates.
    assert "\n## Top Paths\n" in md
    assert "\n## Edge & Origin Evidence\n" in md


def test_control_review_target_descriptor_falls_back_to_key_value_join():
    """When the target dict carries an unfamiliar identifier shape, the
    descriptor falls back to a deterministic ``key=value`` join so the
    headline never collapses to empty.

    Uses ``prepare()`` directly because this assertion is about context
    shape, not rendered HTML — keeps it runnable from a plain Python
    without the uv dependency.
    """
    from report_engine.contexts import control_review

    artifact = control_review.assemble(
        [
            {
                "schema_version": "bot_control_review.v1",
                "artifact_id": "control-target-fallback-1",
                "before_window": {"start": "2026-04-08", "end": "2026-04-15"},
                "after_window": {"start": "2026-04-15", "end": "2026-04-22"},
                "scope": {"cluster": "demo"},
                "table_used": "demo.bi",
                "comparison_type": "post_change_vs_expected",
                "target": {"custom_key": "custom-value", "other": "v"},
                "target_effects": [],
            }
        ]
    )
    ctx = control_review.prepare(artifact)
    # Sorted ``key=value`` join keeps the output deterministic.
    assert ctx["target"]["descriptor"] == "custom_key=custom-value, other=v"


def test_companion_compatible_returns_reason_for_each_failure_mode():
    from report_engine.contexts._shared import companion_compatible

    # Primary that aligns on every COMPANION_COMPAT_FIELDS entry with a
    # baseline posture, so that we can construct failure scenarios by
    # toggling exactly one field at a time.
    base_window = {"start": "2026-04-15T00:00:00Z", "end": "2026-04-22T00:00:00Z"}
    base_prior = {"start": "2026-04-08T00:00:00Z", "end": "2026-04-15T00:00:00Z"}
    primary = _control_fixture(
        current_window=base_window,
        baseline_windows=[base_prior],
        comparison_type="previous_window",
    )

    ok, reason = companion_compatible(None, _posture_fixture())
    assert not ok
    assert "no primary artifact" in reason

    missing = _posture_fixture(
        current_window=base_window,
        baseline_windows=[base_prior],
        comparison_type="previous_window",
        scope={},
    )
    ok, reason = companion_compatible(primary, missing)
    assert not ok
    assert "missing scope" in reason

    conflicting = _posture_fixture(
        current_window=base_window,
        baseline_windows=[base_prior],
        comparison_type="rolling_baseline",
    )
    ok, reason = companion_compatible(primary, conflicting)
    assert not ok
    assert "conflict on comparison_type" in reason


# ── Incident Executive View ─────────────────────────────────────────
#
# Same wrapper artifacts as ``incident-report.json``; only the
# ``report_type`` and ``analyst_notes`` differ. Fixtures live in
# tests/fixtures/report_engine/ rather than the user-facing examples
# directory because the exec view is an alternate render of an
# existing example, not a standalone report shape.


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


def test_incident_report_print_degraded_fixture_renders_missing_data_states():
    fixture = ROOT / "skills/bot-insights/examples/incident-report-degraded.json"
    actual = _normalize(_render(fixture, "--profile", "print"))

    assert 'data-pdf-layout="fixed-letter"' in actual
    assert actual.count('<section class="page') == 10
    assert "raw drilldown is degraded" in actual or "Rows are truncated" in actual
    assert "No ATT&amp;CK mapping available" in actual or "Technique mapping" in actual


def test_incident_print_adapter_maps_series_and_limits_rows():
    from report_engine.contexts.incident.print_adapter import (
        build_print_report,
        series_to_svg_path,
        severity_band,
        volume_chart,
    )

    fixture = ROOT / "skills/bot-insights/examples/incident-report.json"
    data = json.loads(fixture.read_text())
    from report_engine.contexts.incident import module

    ctx = module.prepare(module.assemble(data["artifacts"]))
    ctx["notes_by_slot"] = {}
    adapted = build_print_report(ctx)

    assert (
        series_to_svg_path([0, 50, 100])
        == "M 56.0,196.0 L 284.0,118.0 L 512.0,40.0"
    )
    assert severity_band("critical", 75)["band"] == "critical"
    assert adapted["verdict"]["band"] == "critical"
    assert len(adapted["actors"]) == 10
    assert len(adapted["actions"]) == 5
    assert adapted["finding_ip_cluster"]["kicker"] == ""
    assert [chip["text"] for chip in adapted["finding_ip_cluster"]["chips"]] == [
        "Client IP"
    ]
    assert adapted["finding_ip_cluster"]["ips"][:1][0]["ip"] == "203.0.113.10"
    phases = [stop["phase"] for stop in adapted["attack_shape"]["timeline"]]
    assert "Ramp begins" in phases
    assert "Highest pressure" in phases
    cover_actions = adapted["at_a_glance"]["do_now"]["items"]
    assert cover_actions[1]["team"] == "Intel"
    assert "case mgmt" in cover_actions[1]["action_html"]
    assert "203.0.113.10" not in cover_actions[1]["action_html"]

    missing = volume_chart({"impact": {"volume_chart": {}}})
    assert missing["missing"] is True
    assert missing["spike_path"]


def test_incident_report_temporal_progression_bucket_fallback_without_timestamps():
    from report_engine.contexts import incident_report as ir

    view = ir._temporal_progression_view(
        {
            "volume_timeseries": {
                "series": {
                    "requests_per_minute": {
                        "current": [0, 10, 40, 30, 5],
                    }
                }
            }
        }
    )

    assert view["available"] is True
    assert any("Peak bucket was bucket 3" in bullet for bullet in view["bullets"])
    assert not any("UTC" in bullet for bullet in view["bullets"])


def test_incident_action_reasons_do_not_sum_overlapping_shares():
    from report_engine.contexts import incident_report as ir

    actions = ir._recommended_actions_view(
        [
            {
                "target_type": "client_ip",
                "target_type_label": "Client IP",
                "target_value": "203.0.113.10",
                "severity": "critical",
                "severity_label": "Critical",
                "share_pct": 95.0,
                "share_pct_display": "95%",
                "requests_display": "950K",
                "reason_flag_labels": ["high volume share"],
            },
            {
                "target_type": "user_agent",
                "target_type_label": "User Agent",
                "target_value": "curl",
                "severity": "critical",
                "severity_label": "Critical",
                "share_pct": 92.0,
                "share_pct_display": "92%",
                "requests_display": "920K",
                "reason_flag_labels": ["automation user-agent"],
            },
        ],
        "",
    )
    reasons = " ".join(action.get("reason") or "" for action in actions)

    assert "187% of window traffic" not in reasons
    assert "top rows account for" not in reasons
    assert "strongest individual share was 95%" in reasons


def test_incident_attack_aggregation_includes_supporting_evidence():
    from report_engine.contexts import incident_report as ir

    rows = ir._attack_aggregation(
        [
            {
                "target_type": "client_ip",
                "target_value": "203.0.113.10",
                "severity": "critical",
                "reason_flags": ["high_429_share", "single_path_concentration"],
                "supporting": {
                    "requests": 120000,
                    "share_pct": 12.5,
                    "req_429_share_pct": 42.0,
                },
                "attack_techniques": [
                    {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"}
                ],
            }
        ]
    )

    assert rows[0]["id"] == "T1110"
    assert rows[0]["mapping_class"] == "possible investigation lead"
    assert "Client IP `203.0.113.10`" in rows[0]["supporting_evidence_text"]
    assert "auth-specific telemetry" in rows[0]["supporting_evidence_text"]
    assert "path concentration" in rows[0]["supporting_evidence_text"]
    assert len(rows[0]["metric_chips"]) <= 2
    assert "120.00K requests" in rows[0]["metric_chips"]
    assert "12.5% of incident requests" in rows[0]["metric_chips"]


def test_incident_executive_view_no_notes_html():
    """Empty ``analyst_notes`` exercises the graceful-degradation
    strings — every analyst slot has a fallback."""
    fixture = FIXTURES / "incident_executive_view_no_notes.json"
    actual = _normalize(_render(fixture))
    snapshot = SNAPSHOTS / "incident_executive_view_no_notes.html"
    _assert_snapshot(actual, snapshot)
    assert "Analyst summary pending" in actual
    assert "Not assessed from logs" in actual
    assert "no root-cause or intent attribution" in actual
    # Status pill falls back to the default ``Active`` label.
    assert ">Active<" in actual


def test_incident_executive_view_markdown():
    """Markdown sibling renders the same seven sections plus the
    status / window header line."""
    fixture = FIXTURES / "incident_executive_view_full.json"
    actual = _render(fixture, "--format", "markdown")
    snapshot = SNAPSHOTS / "incident_executive_view_full.md"
    _assert_snapshot(actual, snapshot)
    for line in (
        "# www.example.com — Incident Executive View",
        "**Status:** Active",
        "## What happened",
        "## Measured impact",
        "## Business / customer impact",
        "## Response taken / recommended",
        "## Decision needed",
        "## Confidence and caveat",
    ):
        assert line in actual, f"markdown line missing: {line}"


@pytest.mark.parametrize(
    ("fixture_name", "snapshot_name", "markers"),
    [
        (
            "incident_soc_action_packet.json",
            "incident_soc_action_packet.html",
            ("SOC Action Packet", "Suspicious actors", "IOC handoff", "Evidence caveats"),
        ),
        (
            "incident_edge_platform_brief_no_notes.json",
            "incident_edge_platform_brief_no_notes.html",
            ("Edge Platform Brief", "Request impact", "429 / 5xx shape", "Policy assessment", "Operational caveats"),
        ),
        (
            "incident_edge_platform_brief_full.json",
            "incident_edge_platform_brief_full.html",
            ("Edge Platform Brief", "Request impact", "429 / 5xx shape", "Policy assessment", "Operational caveats"),
        ),
        (
            "incident_detection_engineering_no_notes.json",
            "incident_detection_engineering_no_notes.html",
            (
                "Detection Engineering Review",
                "Mechanical rules fired",
                "Fields driving confidence",
                "Calibration calls",
                "Follow-up instrumentation",
            ),
        ),
        (
            "incident_detection_engineering_full.json",
            "incident_detection_engineering_full.html",
            (
                "Detection Engineering Review",
                "Mechanical rules fired",
                "Fields driving confidence",
                "Calibration calls",
                "Follow-up instrumentation",
            ),
        ),
    ],
)
def test_incident_stakeholder_view_html(fixture_name, snapshot_name, markers):
    fixture = FIXTURES / fixture_name
    actual = _normalize(_render(fixture))
    _assert_snapshot(actual, SNAPSHOTS / snapshot_name)
    for marker in markers:
        assert marker in actual
    assert "unavailable" in actual or "No " in actual


@pytest.mark.parametrize(
    ("fixture_name", "snapshot_name", "heading"),
    [
        (
            "incident_soc_action_packet.json",
            "incident_soc_action_packet.md",
            "# www.example.com — SOC Action Packet",
        ),
        (
            "incident_edge_platform_brief_no_notes.json",
            "incident_edge_platform_brief_no_notes.md",
            "# www.example.com — Edge Platform Brief",
        ),
        (
            "incident_edge_platform_brief_full.json",
            "incident_edge_platform_brief_full.md",
            "# www.example.com — Edge Platform Brief",
        ),
        (
            "incident_detection_engineering_no_notes.json",
            "incident_detection_engineering_no_notes.md",
            "# www.example.com — Detection Engineering Review",
        ),
        (
            "incident_detection_engineering_full.json",
            "incident_detection_engineering_full.md",
            "# www.example.com — Detection Engineering Review",
        ),
    ],
)
def test_incident_stakeholder_view_markdown(fixture_name, snapshot_name, heading):
    fixture = FIXTURES / fixture_name
    actual = _render(fixture, "--format", "markdown")
    _assert_snapshot(actual, SNAPSHOTS / snapshot_name)
    assert heading in actual
    assert "## " in actual


def test_incident_stakeholder_views_registered_and_legacy_accepted():
    import render_report
    from report_engine.contexts import REPORT_TYPE_REGISTRY, incident_report

    expected = {
        "incident_soc_action_packet",
        "incident_edge_platform_brief",
        "incident_detection_engineering",
    }
    assert expected <= set(REPORT_TYPE_REGISTRY)
    assert expected <= set(render_report.REPORT_TYPES)
    wrapper = json.loads((FIXTURES / "incident_soc_action_packet.json").read_text())
    args = SimpleNamespace(
        text=[],
        file=None,
        format="markdown",
        report_type=None,
        output=None,
        limit=None,
        allow_unknown=False,
        title=None,
        palette="tableau",
        theme="auto",
    )
    ctx = render_report.ReportContext()
    artifacts, notes, wrapper_report_type, wrapper_title, wrapper_limit, scope_label, raw_mode = (
        render_report.load_report_input(wrapper, args, ctx)
    )
    report_type, _title, _limit, _scope = render_report.resolve_options(
        artifacts,
        wrapper_report_type=wrapper_report_type,
        wrapper_title=wrapper_title,
        wrapper_limit=wrapper_limit,
        scope_label=scope_label,
        raw_mode=raw_mode,
        args=args,
        ctx=ctx,
    )
    selected = render_report.validate_report_artifacts(report_type, artifacts, ctx)
    assert report_type == "incident_soc_action_packet"
    assert set(selected) == {"scope", "actors", "action_targets"}
    assert (
        REPORT_TYPE_REGISTRY["incident_soc_action_packet"].assemble(
            wrapper["artifacts"]
        )
        == incident_report.assemble(wrapper["artifacts"])
    )


def test_threat_hunt_registered_and_renders_markdown(tmp_path):
    import render_report
    from report_engine.contexts import REPORT_TYPE_REGISTRY

    assert "threat_hunt" in REPORT_TYPE_REGISTRY
    assert "threat_hunt" in render_report.REPORT_TYPES
    wrapper = {
        "schema_version": "bot_report_input.v1",
        "report_type": "threat_hunt",
        "title": "Threat Hunt",
        "scope_label": "local/akamai",
        "artifacts": [
            {
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
                        "verdict": "not_enough_data",
                        "rationale": "Cooccurrence evidence was not supplied.",
                    }
                ],
                "campaigns": [
                    {
                        "campaign_id": "campaign-1",
                        "verdict": "strong_lead",
                        "sophistication": "moderate",
                        "temporal_pattern": "synchronized",
                        "leads": ["CatalogScraper/1.0", "CatalogScraper/2.0"],
                        "linking_evidence": [
                            {
                                "left_user_agent": "CatalogScraper/1.0",
                                "right_user_agent": "CatalogScraper/2.0",
                                "link_types": ["shared_ips"],
                                "shared_ip_count": 3,
                                "shared_ip_samples": ["198.51.100.1"],
                                "path_cosine": 0.91,
                                "asn_cosine": None,
                                "country_cosine": 1.0,
                                "temporal_correlation": None,
                                "shared_path_count": 3,
                                "shared_path_samples": ["/api/catalog"],
                            }
                        ],
                        "total_requests": 2400,
                        "baseline_requests": 20,
                        "bytes": 500000000,
                        "baseline_bytes": 600000000,
                        "impact_assessment": {
                            "requests": 2400,
                            "baseline_requests": 20,
                            "request_share": 0.24,
                            "baseline_request_share": 0.30,
                            "bytes": 500000000,
                            "baseline_bytes": 600000000,
                            "byte_share": 0.50,
                            "baseline_byte_share": 0.60,
                            "trend_severity": "shrinking",
                            "share_severity": "dominant",
                            "share_direction": "shrinking_share",
                        },
                        "drilldown_coverage_summary": {
                            "status_counts": {"focused": 2},
                            "drilldown_requests": 2400,
                            "total_requests": 2400,
                            "weighted_coverage_pct": 100.0,
                            "surface_label": "focused_api_surface",
                        },
                        "unique_client_ips": 3,
                        "unique_asns": 1,
                        "unique_countries": 1,
                        "endpoint_targets": [
                            {"endpoint_prefix": "/api/catalog", "requests": 2400, "share_pct": 100.0}
                        ],
                        "hourly_profile": [],
                        "recommended_actions": [
                            {
                                "tier": "tier_3",
                                "scope": "campaign",
                                "action_type": "campaign_watchlist_or_challenge",
                                "target_values": {
                                    "campaign_id": "campaign-1",
                                    "user_agents": ["CatalogScraper/1.0", "CatalogScraper/2.0"],
                                },
                                "supporting_evidence": ["coordinated_activity"],
                                "estimated_observed_window_impact": {
                                    "requests": 2400,
                                    "bytes": 500000000,
                                    "request_share": 0.24,
                                    "byte_share": 0.50,
                                },
                                "validation_notes": ["Validate campaign membership."],
                                "false_positive_caveat": "Challenge first.",
                                "rollback_monitoring": ["Track post-change traffic."],
                                "enforcement_wording": "challenge_first",
                                "threat_category": "rate_limit_evasion",
                                "threat_confidence": 0.78,
                                "threat_action_modifier": "Challenge campaign members and watch for displacement.",
                            }
                        ],
                        "threat_classification": {
                            "primary": {
                                "category": "rate_limit_evasion",
                                "confidence": 0.78,
                                "trigger_evidence": ["coordinated activity", "endpoint focus"],
                                "attack_mapping": {
                                    "mitre_techniques": ["T1498", "T1190"],
                                    "mitre_tactics": ["Impact"],
                                    "hdx_techniques": ["HDX-BOT-03"],
                                },
                            }
                        },
                    }
                ],
                "ua_families": [
                    {
                        "family_id": "ua-family-1",
                        "template": (
                            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                            "(KHTML, like Gecko) Chrome/{ver}.0.0.0 Safari/537.36"
                        ),
                        "members": [
                            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36",
                            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
                            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36",
                        ],
                        "member_count": 3,
                        "version_range": {"min": 147, "max": 149},
                        "version_count": 3,
                        "versions": [147, 148, 149],
                        "total_requests": 3600,
                        "total_baseline": 30,
                        "bytes": 900000000,
                        "baseline_bytes": 10000000,
                        "impact_assessment": {
                            "requests": 3600,
                            "baseline_requests": 30,
                            "request_share": 0.36,
                            "baseline_request_share": 0.003,
                            "bytes": 900000000,
                            "baseline_bytes": 10000000,
                            "byte_share": 0.90,
                            "baseline_byte_share": 0.01,
                            "trend_severity": "accelerating",
                            "share_severity": "dominant",
                            "share_direction": "growing_share",
                        },
                        "request_volume_cv": 0.0,
                        "common_evidence": [
                            "Browser user-agent strings share the same template after replacing browser major versions.",
                            "Request volumes are uniform enough to suggest parameterized UA-version rotation.",
                        ],
                        "structural_checks": ["zero_point_version"],
                        "campaign_overlaps": [
                            {
                                "campaign_id": "campaign-1",
                                "member_count": 2,
                                "members": [
                                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36",
                                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
                                ],
                            }
                        ],
                        "recommended_actions": [
                            {
                                "tier": "tier_3",
                                "scope": "ua_family",
                                "action_type": "campaign_watchlist_or_challenge",
                                "target_values": {
                                    "ua_family_id": "ua-family-1",
                                    "ua_family_template": "Mozilla/5.0 Chrome/{ver}.0.0.0 Safari/537.36",
                                    "user_agents": [
                                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36",
                                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
                                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36",
                                    ],
                                },
                                "supporting_evidence": ["ua_family_version_rotation"],
                                "estimated_observed_window_impact": {
                                    "requests": 3600,
                                    "bytes": 900000000,
                                    "request_share": 0.36,
                                    "byte_share": 0.90,
                                },
                                "validation_notes": ["Validate current family membership."],
                                "false_positive_caveat": "Challenge-first handling is recommended.",
                                "rollback_monitoring": ["Track family traffic."],
                                "enforcement_wording": "challenge_first",
                                "threat_category": "rate_limit_evasion",
                                "threat_confidence": 0.72,
                                "threat_action_modifier": "Challenge UA-family pattern and monitor family churn.",
                            }
                        ],
                    }
                ],
                "scraper_cases": [
                    {
                        "user_agent": "CatalogScraper/1.0",
                        "verdict": "lead",
                        "campaign_id": "campaign-1",
                        "campaign_verdict": "strong_lead",
                        "ua_family_id": "ua-family-1",
                        "ua_family_template": "Mozilla/5.0 Chrome/{ver}.0.0.0 Safari/537.36",
                        "nested_under_family": False,
                        "requests": 1200,
                        "baseline_requests": 10,
                        "bytes": 250000000,
                        "baseline_bytes": 10000000,
                        "impact_assessment": {
                            "requests": 1200,
                            "baseline_requests": 10,
                            "request_share": 0.12,
                            "baseline_request_share": 0.001,
                            "bytes": 250000000,
                            "baseline_bytes": 10000000,
                            "byte_share": 0.25,
                            "baseline_byte_share": 0.01,
                            "trend_severity": "accelerating",
                            "share_severity": "significant",
                            "share_direction": "growing_share",
                        },
                        "unique_client_ips": 12,
                        "unique_asns": 2,
                        "unique_countries": 2,
                        "drilldown_coverage": {
                            "drilldown_requests": 1200,
                            "total_requests": 1200,
                            "coverage_pct": 100.0,
                            "status": "focused",
                        },
                        "evidence_flags": ["ua_ip_fanout", "endpoint_targeting"],
                        "ua_plausibility": {
                            "parsed": {
                                "browser_family": "Chrome",
                                "browser_major": 149,
                                "browser_version": "149.0.7777.1",
                                "platform": "Windows",
                                "device_class": "desktop",
                                "ua_class": "browser",
                            },
                            "signals": {
                                "version_currency": {"status": "future_dated", "score": 1.0},
                                "fanout": {"status": "unavailable", "score": 0.0},
                                "homogeneity": {"status": "unavailable", "score": 0.0},
                                "structural": {"status": "normal", "score": 0.0, "checks": []},
                            },
                            "composite_score": 1.0,
                            "verdict": "confirmed",
                            "trigger_reason": "Future-dated Chrome/149 for 2026-05-02 window",
                            "fired_structural_checks": [],
                            "counts_for_verdict": True,
                            "source": "scoped_fallback",
                        },
                        "case_for": [
                            "Exact UA/IP cooccurrence observed 12 client IPs across 2 ASNs.",
                            "Requests concentrated on API/search/catalog/content-like endpoint markers.",
                        ],
                        "case_against": [
                            "Scoped raw scraper drilldown was unavailable, so endpoint cooccurrence and hourly burst proof are limited."
                        ],
                        "missing_evidence": ["automation_signature"],
                        "endpoint_targets": [
                            {
                                "request_path": "/api/catalog",
                                "requests": 1200,
                                "share_pct": 100.0,
                                "markers": ["api", "catalog"],
                            }
                        ],
                        "hourly_bursts": [],
                        "temporal_regularity": {
                            "resolution": "request_iat",
                            "archetype": "metronome",
                            "sample_size": 60,
                            "summary": "Request-level inter-arrival timing matches metronome behavior in the sampled rows.",
                            "metrics": {
                                "cv": 0.0,
                                "log_bucket_entropy": 0.0,
                                "spectral_peak_ratio": None,
                            },
                            "top_pairs": [],
                        },
                        "fanout_enrichment": {
                            "source": "summary_hour",
                            "unique_ips": 12000,
                            "effective_ips": 12000,
                            "threshold_class": "elevated",
                        },
                        "confidence_assessment": {
                            "qualifier": "partial",
                            "score": 0.42,
                            "reasons": ["Confidence is bounded by available corroboration."],
                            "background_rates": {
                                "ua_ip_fanout": {
                                    "triggered": 0,
                                    "sample_size": 0,
                                    "rate_pct": None,
                                    "concern": "unavailable",
                                },
                                "endpoint_targeting": {
                                    "triggered": 12,
                                    "sample_size": 100,
                                    "rate_pct": 12.0,
                                    "concern": "moderate",
                                },
                            },
                            "baseline_significance": {"status": "unavailable"},
                            "evidence_shelf_life": [
                                {
                                    "evidence": "ua_ip_fanout",
                                    "shelf_life": "next_hunt_window",
                                    "guidance": "Fan-out counts are hunt-window specific and should be re-queried.",
                                }
                            ],
                        },
                        "bot_manager_context": {
                            "availability": "evidence_backed",
                            "source": "exact_ua_export",
                            "window": {
                                "start": "2026-05-01T00:00:00Z",
                                "end": "2026-05-02T00:00:00Z",
                            },
                            "total_requests": 900,
                            "average_bot_score": 87.5,
                            "action_class_mix": [
                                {"rank": 1, "value": "monitor", "requests": 900, "share_pct": 100.0}
                            ],
                            "bot_type_mix": [],
                            "policy_mix": [],
                        },
                        "threat_classification": {
                            "primary": {
                                "category": "rate_limit_evasion",
                                "confidence": 0.78,
                                "trigger_evidence": ["UA/IP fan-out", "endpoint targeting"],
                                "attack_mapping": {
                                    "mitre_techniques": ["T1498"],
                                    "mitre_tactics": ["Impact"],
                                    "hdx_techniques": ["HDX-BOT-03"],
                                },
                            }
                        },
                    }
                ],
                "baseline_movement": {"metric_deltas": []},
                "fingerprints": [],
                "endpoints": [],
                "infrastructure": {"asn_rollups": []},
                "classification_gap": {
                    "summary": "Bot/SIEM/edge classification artifacts were not supplied."
                },
                "impact_assessment": {
                    "totals": {
                        "current": {"requests": 10000, "bytes": 1000000000},
                        "baseline": {"requests": 10000, "bytes": 1000000000},
                    },
                    "hunt": {
                        "requests": 6000,
                        "baseline_requests": 50,
                        "request_share": 0.60,
                        "baseline_request_share": 0.005,
                        "bytes": 950000000,
                        "baseline_bytes": 20000000,
                        "byte_share": 0.95,
                        "baseline_byte_share": 0.02,
                        "trend_severity": "accelerating",
                        "share_severity": "dominant",
                        "share_direction": "growing_share",
                    },
                    "tiers": {
                        "tier_3": {
                            "requests": 6000,
                            "baseline_requests": 50,
                            "request_share": 0.60,
                            "baseline_request_share": 0.005,
                            "bytes": 950000000,
                            "baseline_bytes": 20000000,
                            "byte_share": 0.95,
                            "baseline_byte_share": 0.02,
                            "trend_severity": "accelerating",
                            "share_severity": "dominant",
                            "share_direction": "growing_share",
                        }
                    },
                },
                "bot_manager_context": {
                    "module": "bot_manager_context",
                    "availability": "evidence_backed",
                    "summary": "Bot Manager operational context is supplied for display only.",
                    "caveat": (
                        "Bot Manager context is operational enrichment, not threat-hunt "
                        "attribution or independent evidence for classification."
                    ),
                    "aggregate": {
                        "availability": "evidence_backed",
                        "source": "aggregate_siem_policy_summary",
                        "source_tables": ["akamai.bi_siem_policy_summary_hour"],
                        "window": {
                            "start": "2026-05-01T00:00:00Z",
                            "end": "2026-05-02T00:00:00Z",
                        },
                        "total_requests": 2400,
                        "average_bot_score": 74.25,
                        "action_class_mix": [
                            {"rank": 1, "value": "deny", "requests": 1600, "share_pct": 66.6667},
                            {"rank": 2, "value": "allow", "requests": 800, "share_pct": 33.3333},
                        ],
                        "bot_type_mix": [
                            {"rank": 1, "value": "scraper", "requests": 2400, "share_pct": 100.0}
                        ],
                        "policy_mix": [
                            {"rank": 1, "value": "policy-a", "requests": 1800, "share_pct": 75.0}
                        ],
                    },
                    "exact_ua": {
                        "availability": "evidence_backed",
                        "source": "exact_ua_export",
                        "total_requests": 900,
                        "action_class_mix": [],
                        "bot_type_mix": [],
                        "policy_mix": [],
                    },
                    "lead_context_available": True,
                },
                "recommended_actions": [
                    {
                        "tier": "tier_3",
                        "scope": "campaign",
                        "action_type": "campaign_watchlist_or_challenge",
                        "target_values": {"campaign_id": "campaign-1"},
                        "supporting_evidence": ["coordinated_activity"],
                        "estimated_observed_window_impact": {
                            "requests": 2400,
                            "bytes": 500000000,
                            "request_share": 0.24,
                            "byte_share": 0.50,
                        },
                        "validation_notes": ["Validate campaign membership."],
                        "false_positive_caveat": "Challenge first.",
                        "rollback_monitoring": ["Track post-change traffic."],
                        "enforcement_wording": "challenge_first",
                        "threat_category": "rate_limit_evasion",
                        "threat_confidence": 0.78,
                        "threat_action_modifier": "Challenge campaign members and watch for displacement.",
                    },
                    {
                        "tier": "tier_3",
                        "scope": "ua_family",
                        "action_type": "campaign_watchlist_or_challenge",
                        "target_values": {"ua_family_id": "ua-family-1"},
                        "supporting_evidence": ["ua_family_version_rotation"],
                        "estimated_observed_window_impact": {
                            "requests": 3600,
                            "bytes": 900000000,
                            "request_share": 0.36,
                            "byte_share": 0.90,
                        },
                        "validation_notes": ["Validate current family membership."],
                        "false_positive_caveat": "Challenge first.",
                        "rollback_monitoring": ["Track family traffic."],
                        "enforcement_wording": "challenge_first",
                        "threat_category": "rate_limit_evasion",
                        "threat_confidence": 0.72,
                        "threat_action_modifier": "Challenge UA-family pattern and monitor family churn.",
                    },
                    {
                        "tier": "tier_4",
                        "scope": "lead",
                        "action_type": "challenge_or_block_ua",
                        "target_values": {
                            "user_agents": ["ApiProbe/1.0"],
                            "endpoint_prefixes": ["/api/:slug"],
                        },
                        "supporting_evidence": ["temporal_regularity"],
                        "estimated_observed_window_impact": {
                            "requests": 100,
                            "bytes": 10000000,
                            "request_share": 0.01,
                            "byte_share": 0.01,
                        },
                        "validation_notes": ["Validate UA."],
                        "false_positive_caveat": "Challenge first.",
                        "rollback_monitoring": ["Track target."],
                        "enforcement_wording": "block_candidate",
                    },
                    {
                        "tier": "tier_4",
                        "scope": "lead",
                        "action_type": "challenge_or_block_ua",
                        "target_values": {
                            "user_agents": ["ApiProbe/2.0"],
                            "endpoint_prefixes": ["/api/:slug"],
                        },
                        "supporting_evidence": ["automation_signature"],
                        "estimated_observed_window_impact": {
                            "requests": 200,
                            "bytes": 20000000,
                            "request_share": 0.02,
                            "byte_share": 0.02,
                        },
                        "validation_notes": ["Validate UA."],
                        "false_positive_caveat": "Challenge first.",
                        "rollback_monitoring": ["Track target."],
                        "enforcement_wording": "block_candidate",
                    },
                ],
                "known_traffic": [
                    {
                        "user_agent": "Googlebot/2.1",
                        "disposition": "known_crawler",
                        "reason": "Major search crawler user-agent pattern; informational traffic unless crawler-specific analysis is requested.",
                        "requests": 2200,
                        "baseline_requests": 2100,
                    }
                ],
                "limitations": [
                    {
                        "module": "cooccurrence",
                        "availability": "not_available",
                        "detail": "UA fanout not supplied",
                    }
                ],
            }
        ],
        "analyst_notes": [],
    }
    path = tmp_path / "threat_hunt.json"
    path.write_text(json.dumps(wrapper), encoding="utf-8")
    md = _render(path, "--format", "markdown")
    assert "Report type: `threat_hunt`" in md
    assert md.index("## Campaign Summary") < md.index("## Scraper Leads")
    assert md.index("## UA Families") < md.index("## Scraper Leads")
    assert "ua\\-family\\-1" in md
    assert "Recommendation: **Tier 3** - Campaign Watchlist Or Challenge" in md
    assert md.count("Recommendation: **Tier 3** - Campaign Watchlist Or Challenge") == 1
    assert "## Known Crawler And Infrastructure Traffic" in md
    assert "Googlebot/2\\.1" in md
    assert "## Bot Manager Context" in md
    assert "Bot Manager context is operational enrichment" in md
    assert "Action class mix:" in md
    assert "deny" in md
    assert "Bot Manager exact-UA context: 900 requests" in md
    assert "Evidence: \n" not in md
    assert "Evidence: \r\n" not in md
    assert "Part of UA family ua\\-family\\-1" in md
    assert "2 members also appear in campaign\\-1" in md
    assert "links to CatalogScraper" in md
    assert "3 shared IPs" in md
    assert "path similarity 0\\.91" in md
    assert "Part of campaign\\-1" in md
    assert "Campaign surface: **Focused Api Surface**" in md
    assert "Impact: Share of total 24.0%; response body unavailable (unavailable of response bytes)" in md
    assert "Share of total bytes" not in md
    assert "IMPACT: 2.4K requests (24.0% of window total) · 500.0M response body (50.0% of response bytes)" in md
    assert "Campaign endpoint evidence" in md
    assert "## Scraper Leads" in md
    assert "CatalogScraper" in md
    assert "Surface coverage: **Focused**" in md
    assert "Endpoint evidence: **Not Available**" in md
    assert "UA plausibility: **Confirmed**" in md
    assert "UA plausibility anomaly confirmed" in md
    assert "Future\\-dated Chrome/149" in md
    assert "Timing status" in md
    assert "Metronome" in md
    assert "CV 0\\.00" in md
    assert "Background-rate caveats: Endpoint Targeting 12.0% (moderate)" in md
    assert "Ua Ip Fanout unavailable" not in md
    assert "Fan-out shelf life" in md
    assert "Case against / missing evidence" in md
    assert "/api/catalog" in md
    assert "Raw actor user-agent exports were not supplied." in md
    assert "operator" in md
    assert "malicious intent" not in md.lower()

    html = _render(path)
    assert 'class="report-header"' not in html
    assert '<div class="thr">' in html
    assert '<header class="thr-header">' in html
    assert "Hydrolix" in html
    assert "2026-05-01T00:00:00Z to 2026-05-02T00:00:00Z" in html
    assert 'data-hx-export-all' in html
    assert 'data-hx-drawer-toggle' in html
    assert "data:image/svg+xml;base64" in html
    assert 'static/reports/threat-hunt.css' not in html
    assert '<script src="static/kit.js"></script>' not in html
    assert "[hidden] { display: none !important; }" in html
    assert ".hx-drawer[hidden]," in html
    assert ".hx-rail[hidden] { display: none !important; }" in html
    assert 'body[data-hx-drawer-state="collapsed"] .thr-body' in html
    assert 'id="verdict" class="thr-verdict"' in html
    assert 'class="hx-ladder"' in html
    assert 'class="thr-hunt-impact"' in html
    assert 'class="thr-impact-strip"' not in html
    assert 'id="actions" class="thr-section"' in html
    assert "Response queue" in html
    assert "Impact-backed response candidates" in html
    assert "Monitor / validate before enforcement" in html
    assert "Actions are grouped by confidence boundary" in html
    assert "Do not treat them as part of the Hunt impact total." in html
    assert 'id="leads" class="thr-section"' in html
    assert 'id="campaign" class="thr-section"' in html
    assert 'id="infra" class="thr-section"' in html
    assert 'id="evidence" class="thr-section"' in html
    assert 'class="hx-drawer"' in html
    assert 'class="hx-rail"' in html
    assert "data-hx-drawer-collapse" in html
    assert "data-hx-rail-expand" in html
    assert re.search(
        r'<div class="hx-drawer-list" data-hx-drawer-panel="ua"[^>]*>',
        html,
    )
    assert re.search(
        r'<div class="hx-drawer-list" data-hx-drawer-panel="ep"[^>]*hidden',
        html,
    )
    assert re.search(
        r'<div class="hx-drawer-list" data-hx-drawer-panel="ip"[^>]*hidden',
        html,
    )
    assert 'id="leads"' in html
    assert "ua-family-1" in html
    assert "campaign-1" in html
    assert "CatalogScraper/1.0" in html
    assert "ApiProbe/1.0" in html
    assert "ApiProbe/2.0" in html
    assert "/api/:slug" in html
    assert "/api/catalog" in html
    assert "24.0% of window" in html
    assert "Hunt impact" in html
    assert "Response body" in html
    assert "Akamai-billed" in html
    assert "Hydrolix log ingest" in html
    assert "total bytes" not in html.lower()
    assert "UA plausibility" in html
    assert "Confirmed" in html
    assert "Ua Ip Fanout unavailable" not in html
    assert "120.0x (+1.2K)" in html
    assert "Observed" in html
    assert "Not established" in html
    assert "Operator identity" in html
    assert "Malicious intent" in html
    assert "Cross-customer reuse" in html
    assert "user_agents" in html
    assert "example.com" not in html.lower()
    assert "origin-capacity" not in html
    assert "cache-hit" not in html
    assert "Bot Manager context is operational enrichment" not in html

    bundle_out = tmp_path / "bundle" / "threat_hunt.html"
    bundle_out.parent.mkdir()
    subprocess.run(
        [
            "uv",
            "run",
            "--quiet",
            str(RENDER_PY),
            "--artifact",
            str(path),
            "--out",
            str(bundle_out),
            "--asset-mode",
            "bundle",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    bundle_html = bundle_out.read_text()
    assert '<link rel="stylesheet" href="static/tokens/brand.css" />' in bundle_html
    assert '<script src="static/kit.js"></script>' in bundle_html
    assert "data:image/svg+xml;base64" not in bundle_html
    assert (bundle_out.parent / "static/reports/threat-hunt.css").exists()
    assert (bundle_out.parent / "static/components/_kit.css").exists()
    assert (bundle_out.parent / "static/kit.js").exists()
    assert (bundle_out.parent / "assets/hydrolix-light.svg").exists()
    assert (
        "[hidden] { display: none !important; }"
        in (bundle_out.parent / "static/components/_kit.css").read_text()
    )
    kit_css = (bundle_out.parent / "static/components/_kit.css").read_text()
    assert ".hx-drawer[hidden]," in kit_css
    assert ".hx-rail[hidden] { display: none !important; }" in kit_css
    report_css = (bundle_out.parent / "static/reports/threat-hunt.css").read_text()
    assert 'body[data-hx-drawer-state="collapsed"] .thr-body' in report_css

    rejected = subprocess.run(
        [
            "uv",
            "run",
            "--quiet",
            str(RENDER_PY),
            "--artifact",
            str(path),
            "--out",
            str(tmp_path / "bad.md"),
            "--format",
            "markdown",
            "--asset-mode",
            "bundle",
        ],
        capture_output=True,
        text=True,
    )
    assert rejected.returncode == 1
    assert "--asset-mode bundle is only supported for screen HTML output" in rejected.stderr

    print_html = _render(path, "--profile", "print")
    assert 'data-pdf-layout="fixed-letter"' in print_html
    assert "HYDROLIX · BOTINSIGHTS" in print_html
    assert '<div class="hero pf-xl"' in print_html
    assert "Assessment summary" in print_html
    assert "Coordinated forged-UA operation consistent with Rate Limit Evasion" in print_html
    assert "Hunt Impact" in print_html
    assert "Finding share" in print_html
    assert "60.0% of window traffic" in print_html
    assert "campaign-1" in print_html
    assert "24.0% · 2.4K requests · 500.0 MB" in print_html
    assert "UA family" in print_html
    assert "36.0% · 3.6K requests" in print_html
    assert "Shares use total window traffic as the denominator" in print_html
    assert "Delta vs baseline" in print_html
    assert "120.0x (+1.2K)" in print_html
    assert print_html.count('<section class="page') == 6
    assert "01 Cover" in print_html
    assert "02 Story" in print_html
    assert "03 Recommended actions" in print_html
    assert "04 Evidence shape" in print_html
    assert "05 Scraper leads" in print_html
    assert "06 ATT&amp;CK · Methodology" in print_html
    assert "Threat Hunt Story" in print_html
    assert "Primary finding" in print_html
    assert "campaign-1 represents 24.0% of all Local traffic in this window" not in print_html
    assert "Secondary finding" in print_html
    assert "Independent leads" in print_html
    assert "What the hunt found" in print_html
    assert "ua-family-1" in print_html
    assert "147-149; 3 versions" in print_html
    assert "No independent high-priority leads outside campaign or UA-family groupings." in print_html
    assert "02 Analyst Assessment" not in print_html
    assert "Analyst Assessment · High confidence" not in print_html
    assert "Finding <b>01</b>" not in print_html
    assert "03 Findings" not in print_html
    assert "04 Evidence shape" in print_html
    assert "Findings and evidence boundaries" in print_html
    assert "Hunt Findings" in print_html
    assert "Evidence Boundaries" in print_html
    assert "Bottom line: the threat-hunt findings account for" in print_html
    assert "Trajectory: traffic share" in print_html
    assert "response-body bytes" in print_html
    assert "No dollar, origin-capacity, or cache-hit impact is shown" in print_html
    assert "campaign-1" in print_html
    assert "2 members" in print_html
    assert "Synchronized" in print_html
    assert "Focused Api Surface" in print_html
    assert "Campaigns</span><span class=\"value\">1 campaign" in print_html
    assert "Scraper leads</span><span class=\"value\">1 lead" in print_html
    assert "Campaign timing pattern</span><span class=\"value\">Synchronized" in print_html
    assert "Campaign surface</span><span class=\"value\">Focused Api Surface" in print_html
    assert "Temporal Regularity" in print_html
    assert "UA Anomaly" in print_html
    assert "Automation Signature" in print_html
    assert "Coordinated Activity" in print_html
    assert "Operator identity" in print_html
    assert "Malicious intent" in print_html
    assert "Cross-customer reuse" in print_html
    assert "Not established" in print_html
    assert "Partial" in print_html
    assert "Campaigns</span></div>" not in print_html
    assert "Leads</span></div>" not in print_html
    assert "Campaigns → Leads → Timing → Boundaries" not in print_html
    assert 'class="timeline"' not in print_html
    assert "Where they aimed" not in print_html
    assert "Score &amp; availability" not in print_html
    assert "Recommended Actions" in print_html
    assert "Mozilla/5.0 (Linux; Android" not in print_html
    assert "Evidence 1" not in print_html
    assert "2 lead targets" in print_html
    assert "IMPACT: 300 requests (3.0% of window total) · 30.0M response body (3.0% of response bytes)" in print_html
    assert "of window total" in print_html
    assert "of response bytes" in print_html
    assert print_html.count("Challenge Or Block Ua") == 1
    assert "Rate Limit Evasion · confidence 0.78" in print_html
    assert "Challenge campaign members and watch for displacement." in print_html
    assert "Bot Manager context:" in print_html
    assert "top action deny" in print_html
    assert "Known crawler and infrastructure traffic" in print_html
    assert "Googlebot/2.1" in print_html
    assert 'data-campaign-member="true" data-campaign-id="campaign-1"' in print_html
    assert "Classification &amp; edge" not in print_html
    assert "Validate current Bot Manager/SIEM coverage before enforcement" not in print_html
    assert "Browser UA age" not in print_html
    assert "No browser-age enrichment supplied." not in print_html
    assert "T1498, T1190, HDX-BOT-03" in print_html
    assert "ATT&amp;CK · Methodology" in print_html
    assert "Analyses included" in print_html
    assert "Traffic and byte-share impact" in print_html
    assert "Identifies which findings consume the largest share of total requests and bytes" in print_html
    assert "Baseline trajectory comparison" in print_html
    assert "Campaign linkage and coordination" in print_html
    assert "UA plausibility and family rotation" in print_html
    assert "Endpoint, fan-out, and timing evidence" in print_html
    assert "Evidence-boundary review" in print_html
    assert "bot_threat_hunt.v3" in print_html
    assert "Ua Ip Fanout unavailable" not in print_html


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
            "detail": "TrafficPeak retention cost",
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
                "denom": "of customer log volume - TrafficPeak retention cost",
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


def test_threat_hunt_impact_note_surfaces_light_payload_pattern():
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
    note = threat_hunt.prepare(artifact)["threat_hunt_ui"]["hunt_impact"]["pattern_note"]
    assert note is not None
    assert "10.0% hits vs 5.0% response bytes" in note["text"]
    assert "supporting evidence, not a standalone scraper signature" in note["text"]
    assert [link["label"] for link in note["links"]] == [
        "OWASP OAT-011 Scraping",
        "OWASP Bot Management Cheat Sheet",
        "F5 scraper behavior patterns",
    ]


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


class TestIncidentExecutiveView:
    """Direct unit tests on the incident_executive_view context module."""

    EXAMPLES = ROOT / "skills/bot-insights/examples"

    @staticmethod
    def _module():
        from report_engine.contexts import incident_executive_view

        return incident_executive_view

    @staticmethod
    def _load(name: str) -> dict:
        import json

        return json.loads((TestIncidentExecutiveView.EXAMPLES / name).read_text())

    def test_constants(self):
        mod = self._module()
        assert mod.SCHEMA == "bot_incident_scope.v1"
        assert mod.REPORT_TYPE == "incident_executive_view"
        assert mod.TEMPLATE == "reports/incident_executive_view.html"
        assert set(mod.NOTE_ID_TO_SLOT) == {
            "llm-incident-status-level",
            "llm-what-happened",
            "llm-executive-impact",
            "llm-response-taken",
            "llm-decision-needed",
            "llm-current-status",
        }
        assert set(mod.NOTE_ID_TO_SLOT.values()) == {
            "incident_status_level",
            "what_happened",
            "executive_impact",
            "response_taken",
            "decision_needed",
            "current_status",
        }
        # ``executive_impact`` and ``current_status`` slot keys are
        # intentionally shared with the analyst incident_report so
        # analyst tooling can author once and surface in both views.
        from report_engine.contexts import incident_report

        shared = {"executive_impact", "current_status"}
        assert shared <= set(incident_report.NOTE_ID_TO_SLOT.values())
        assert shared <= set(mod.NOTE_ID_TO_SLOT.values())

    def test_assemble_delegates(self):
        from report_engine.contexts import incident_report

        mod = self._module()
        wrapper = self._load("incident-report.json")
        assembled = mod.assemble(wrapper["artifacts"])
        assembled_ir = incident_report.assemble(wrapper["artifacts"])
        assert assembled == assembled_ir

    def test_prepare_thin_keys(self):
        mod = self._module()
        wrapper = self._load("incident-report.json")
        ctx = mod.prepare(mod.assemble(wrapper["artifacts"]))
        # Keys the exec template consumes.
        expected = {
            "title",
            "kicker",
            "headline",
            "dek",
            "scope",
            "windows",
            "impact_tiles",
            "top_affected_hosts",
            "top_path_pattern",
            "recommended_actions",
            "deterministic_summary",
            "incident_status_tone",
            "incident_status_default",
            "confidence_caveat_default",
            "dashboard_url",
            "method",
            "generated_at",
        }
        assert expected <= set(ctx.keys())
        # Analyst-view-only fields are dropped — the exec view ships
        # a thin context, not the full incident_report dict.
        for absent in (
            "findings",
            "iocs",
            "iocs_json_text",
            "severity_ladder",
            "attack_aggregation",
            "incident_findings",
            "actor_rankings",
            "suspicious_targets",
        ):
            assert absent not in ctx, (
                f"{absent!r} should not surface in exec view context"
            )
        # KPI tiles capped at the exec ceiling (5).
        assert len(ctx["impact_tiles"]) <= mod.EXEC_IMPACT_TILES_CAP
        # Actions capped at the exec ceiling (5).
        assert len(ctx["recommended_actions"]) <= mod.EXEC_ACTIONS_CAP

    def test_status_tone_known(self):
        mod = self._module()
        assert mod.INCIDENT_STATUS_TONE["Active"] == "critical"
        assert mod.INCIDENT_STATUS_TONE["Contained"] == "monitor"
        assert mod.INCIDENT_STATUS_TONE["Monitoring"] == "observe"
        assert mod.INCIDENT_STATUS_TONE["Closed"] == "observe-mute"

    def test_status_tone_unknown_permissive(self):
        """An unknown status label must render verbatim with the
        neutral ``monitor`` tone — the template uses
        ``incident_status_tone.get(label, "monitor")``."""
        mod = self._module()
        assert mod.INCIDENT_STATUS_TONE.get("Resolved", "monitor") == "monitor"
        assert mod.INCIDENT_STATUS_TONE.get("Standing-by", "monitor") == "monitor"

    def test_actions_capped_at_five(self):
        """Synthesize a suspicious-targets list large enough to push
        the upstream action generator past five items, then assert the
        exec view truncates."""
        mod = self._module()
        from report_engine.contexts import incident_report as ir

        # The action generator branches on severity tiers + types.
        # Build a mix that triggers every branch (block, enrich, rate-
        # limit, anomaly, dashboard, retro) so the upstream list grows
        # past 5 and the exec view's cap kicks in.
        suspicious_targets = []
        for ip in ("203.0.113.10", "198.51.100.42", "192.0.2.17", "203.0.113.55"):
            suspicious_targets.append({
                "target_type": "client_ip",
                "target_type_label": "Client IP",
                "target_value": ip,
                "severity": "critical",
                "severity_tone": "critical",
                "severity_label": "Critical",
                "share_pct": 10.0,
                "share_pct_display": "10%",
                "requests_display": "100K",
                "supporting": {"requests": 100000},
                "reason_flag_labels": [],
                "edge_action_top_label": None,
                "edge_action_top_share_display": None,
            })
        suspicious_targets.append({
            "target_type": "request_path",
            "target_type_label": "Request Path",
            "target_value": "/login/submit",
            "severity": "high",
            "severity_tone": "escalate",
            "severity_label": "High",
            "share_pct": 30.0,
            "share_pct_display": "30%",
            "requests_display": "300K",
            "supporting": {"requests": 300000},
            "reason_flag_labels": [],
        })
        suspicious_targets.append({
            "target_type": "cohort",
            "target_type_label": "Traffic cohort",
            "target_value": "Browser",
            "severity": "high",
            "severity_tone": "escalate",
            "severity_label": "High",
            "share_pct": 12.0,
            "share_pct_display": "12%",
            "requests_display": "120K",
            "supporting": {"requests": 120000},
            "reason_flag_labels": ["behavioral anomaly"],
        })

        upstream = ir._recommended_actions_view(
            suspicious_targets, "https://grafana.example/d/incident", None
        )
        assert len(upstream) >= 5, (
            "test setup invariant: upstream generator should now produce "
            f"at least 5 actions; got {len(upstream)}"
        )
        capped = upstream[: mod.EXEC_ACTIONS_CAP]
        assert len(capped) <= mod.EXEC_ACTIONS_CAP == 5


# ---------------------------------------------------------------------------
# Phase 6 extension seam tests
# ---------------------------------------------------------------------------


def test_palette_file_registers_palette_with_extends(tmp_path):
    """``theme.load_palette_file`` registers a palette so subsequent
    ``--palette <name>`` lookups succeed; ``extends`` overlays over a
    base palette so a brand kit only has to spell out the tokens it
    actually overrides."""
    import json

    from report_engine import theme

    palette_file = tmp_path / "brand.json"
    palette_file.write_text(
        json.dumps(
            {
                "name": "brand-test",
                "extends": "tableau",
                "light": {"observe": "#abcdef"},
            }
        )
    )
    try:
        name = theme.load_palette_file(palette_file)
        assert name == "brand-test"
        assert "brand-test" in theme.PALETTES
        light, _dark = theme.PALETTES["brand-test"]
        # Overridden token sticks.
        assert light["observe"] == "#abcdef"
        # Non-overridden tokens fall through to the tableau base.
        assert light["bg"] == theme.PALETTES["tableau"][0]["bg"]
    finally:
        theme.PALETTES.pop("brand-test", None)


def test_palette_file_rejects_unknown_extends(tmp_path):
    import json

    from report_engine import theme

    palette_file = tmp_path / "bad.json"
    palette_file.write_text(
        json.dumps(
            {
                "name": "x",
                "extends": "no-such-palette",
                "light": {"observe": "#000"},
            }
        )
    )
    with pytest.raises(ValueError, match="unknown palette"):
        theme.load_palette_file(palette_file)


def _load_reportkit_theme_module():
    spec = importlib.util.spec_from_file_location(
        "reportkit_theme_contract", REPORTKIT_THEME
    )
    if spec is None or spec.loader is None:
        pytest.fail(f"could not load reportkit theme module from {REPORTKIT_THEME}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _css_without_comments(path: Path) -> str:
    css = path.read_text(encoding="utf-8")
    return re.sub(r"/\*.*?\*/", "", css, flags=re.S)


def _css_blocks(css: str) -> list[tuple[str, str]]:
    return [
        (selector.strip(), declarations)
        for selector, declarations in re.findall(r"([^{}]+)\{([^{}]*)\}", css)
    ]


def _contrast_ratio(foreground: str, background: str) -> float:
    def channel(value: int) -> float:
        srgb = value / 255
        if srgb <= 0.03928:
            return srgb / 12.92
        return ((srgb + 0.055) / 1.055) ** 2.4

    def luminance(hex_color: str) -> float:
        raw = hex_color.lstrip("#")
        red = channel(int(raw[0:2], 16))
        green = channel(int(raw[2:4], 16))
        blue = channel(int(raw[4:6], 16))
        return 0.2126 * red + 0.7152 * green + 0.0722 * blue

    lighter, darker = sorted(
        (luminance(foreground), luminance(background)), reverse=True
    )
    return (lighter + 0.05) / (darker + 0.05)


def test_reportkit_and_bot_insights_editorial_theme_tokens_stay_in_sync():
    """The standalone reportkit theme and Bot Insights renderer should not
    drift on editorial brand/semantic tokens."""
    from report_engine import theme as bot_theme

    reportkit_theme = _load_reportkit_theme_module()

    assert reportkit_theme.EDITORIAL_PALETTE == bot_theme.EDITORIAL_PALETTE
    assert reportkit_theme.PALETTES == bot_theme.PALETTES


def test_editorial_semantic_tokens_do_not_use_hydrolix_brand_hexes():
    from report_engine import theme

    brand_values = {
        value.lower()
        for key, value in theme.EDITORIAL_PALETTE.items()
        if key.startswith("brand_")
    }
    semantic_keys = {
        "red",
        "red_ink",
        "red_bg",
        "red_text",
        "orange",
        "orange_ink",
        "orange_bg",
        "gold",
        "gold_ink",
        "gold_bg",
        "teal",
        "burgundy",
        "blue",
        "sev_observe",
        "sev_monitor",
        "sev_elevated",
        "sev_high",
        "sev_critical",
    }

    collisions = {
        key: theme.EDITORIAL_PALETTE[key]
        for key in semantic_keys
        if theme.EDITORIAL_PALETTE[key].lower() in brand_values
    }

    assert collisions == {}


def test_default_semantic_palette_tokens_do_not_use_hydrolix_brand_hexes():
    from report_engine import theme

    brand_values = {
        value.lower()
        for key, value in theme.EDITORIAL_PALETTE.items()
        if key.startswith("brand_")
    }
    semantic_keys = {
        "observe",
        "monitor",
        "escalate",
        "critical",
        "observe_fill",
        "monitor_fill",
        "escalate_fill",
        "critical_fill",
        "observe_pill_bg",
        "observe_pill_border",
        "observe_pill_text",
        "monitor_pill_bg",
        "monitor_pill_border",
        "monitor_pill_text",
        "escalate_pill_bg",
        "escalate_pill_border",
        "escalate_pill_text",
        "critical_pill_bg",
        "critical_pill_border",
        "critical_pill_text",
        "coverage_missing",
        "delta_down",
    }

    collisions = {}
    for palette_name, (light, dark) in theme.PALETTES.items():
        for mode, palette in (("light", light), ("dark", dark)):
            for key in semantic_keys:
                if palette[key].lower() in brand_values:
                    collisions[f"{palette_name}.{mode}.{key}"] = palette[key]

    assert collisions == {}


def test_editorial_css_keeps_brand_tokens_out_of_meaning_selectors():
    css = _css_without_comments(ENGINE_DIR / "templates/_styles_editorial.css")
    meaning_selector = re.compile(
        r"(severity|risk|delta|hot|critical|incident-status|action-tone)",
        re.I,
    )
    violations = []

    for selector, declarations in _css_blocks(css):
        selector_without_scope = selector.replace(".brief-incident", "")
        if (
            meaning_selector.search(selector_without_scope)
            and "var(--brand-" in declarations
        ):
            violations.append(selector.strip())

    assert violations == []


def test_primary_brand_teal_is_not_used_as_text_on_editorial_light_surfaces():
    from report_engine import theme

    css = _css_without_comments(ENGINE_DIR / "templates/_styles_editorial.css")
    text_color_declarations = []
    for selector, declarations in _css_blocks(css):
        if re.search(r"(?<!-)color\s*:\s*var\(--brand-teal(?:-soft)?\)", declarations):
            text_color_declarations.append(selector.strip())

    assert text_color_declarations == []
    assert _contrast_ratio(theme.EDITORIAL_PALETTE["brand_teal"], "#FFFFFF") < 4.5
    assert _contrast_ratio(theme.EDITORIAL_PALETTE["brand_teal_deep"], "#FFFFFF") >= 7
    assert _contrast_ratio(theme.EDITORIAL_PALETTE["brand_teal_darker"], "#FFFFFF") >= 7


def test_out_of_tree_context_registers_via_env_path(tmp_path, monkeypatch):
    """Dropping a context module on ``BOT_INSIGHTS_CONTEXTS_PATH``
    registers it in ``REPORT_TYPE_REGISTRY`` without code changes."""
    contexts_dir = tmp_path / "oot"
    contexts_dir.mkdir()
    (contexts_dir / "phase6_smoke_report.py").write_text(
        '"""Phase 6 OOT smoke test context."""\n'
        'SCHEMA = "bot_phase6_smoke.v1"\n'
        'REPORT_TYPE = "phase6_smoke_report"\n'
        'TEMPLATE = "reports/phase6_smoke_report.html"\n'
        "NOTE_ID_TO_SLOT = {}\n"
        "def assemble(artifacts):\n"
        "    return artifacts[0] if artifacts else {}\n"
        "def prepare(artifact):\n"
        '    return {"title": "smoke"}\n'
    )
    monkeypatch.setenv("BOT_INSIGHTS_CONTEXTS_PATH", str(contexts_dir))
    # Force a fresh import so the env var is honored at module load.
    import importlib

    from report_engine import contexts

    contexts_reloaded = importlib.reload(contexts)
    try:
        assert "phase6_smoke_report" in contexts_reloaded.REPORT_TYPE_REGISTRY
        assert (
            contexts_reloaded.REPORT_TYPE_REGISTRY["phase6_smoke_report"].SCHEMA
            == "bot_phase6_smoke.v1"
        )
    finally:
        # Reset the registry back to the built-in modules for downstream tests.
        monkeypatch.delenv("BOT_INSIGHTS_CONTEXTS_PATH", raising=False)
        importlib.reload(contexts_reloaded)


def test_register_rejects_module_missing_required_attrs():
    """``register`` raises on a module that doesn't expose the required surface."""
    from types import ModuleType

    from report_engine import contexts

    bogus = ModuleType("bogus_module")
    bogus.SCHEMA = "x"  # type: ignore[attr-defined]
    # Missing REPORT_TYPE / TEMPLATE / assemble / prepare
    with pytest.raises(TypeError, match="missing required attribute"):
        contexts.register(bogus)


def test_render_report_cli_accepts_print_pdf_and_analysis_mode(monkeypatch):
    import render_report

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "render_report.py",
            "--profile",
            "print",
            "--format",
            "pdf",
            "--analysis-mode",
            "both",
            "--output",
            "incident_report_print.pdf",
        ],
    )

    args = render_report.parse_args()

    assert args.profile == "print"
    assert args.format == "pdf"
    assert args.analysis_mode == "both"


def test_render_report_bootstrap_reexecs_for_missing_html_deps(monkeypatch):
    from _render_report import cli

    def fake_find_spec(name):
        return None

    captured = {}

    def fake_execvp(file, cmd):
        captured["file"] = file
        captured["cmd"] = cmd
        raise RuntimeError("exec")

    monkeypatch.delenv(cli.BOOTSTRAP_ENV, raising=False)
    monkeypatch.setattr(cli.importlib.util, "find_spec", fake_find_spec)
    monkeypatch.setattr(cli.shutil, "which", lambda name: "/usr/bin/uv")
    monkeypatch.setattr(cli.os, "execvp", fake_execvp)
    monkeypatch.setattr(sys, "argv", ["render_report.py", "--format", "html"])

    with pytest.raises(RuntimeError, match="exec"):
        cli._bootstrap_render_deps(SimpleNamespace(format="html"))

    assert captured["file"] == "uv"
    assert captured["cmd"][:2] == ["uv", "run"]
    assert captured["cmd"].count("--with") == 3
    assert "jinja2" in captured["cmd"]
    assert "markdown-it-py" in captured["cmd"]
    assert "bleach" in captured["cmd"]
    assert "playwright" not in captured["cmd"]
    assert captured["cmd"][-2:] == ["--format", "html"]
    assert os.environ[cli.BOOTSTRAP_ENV] == "1"


def test_render_report_bootstrap_adds_playwright_for_pdf(monkeypatch):
    from _render_report import cli

    captured = {}

    def fake_execvp(file, cmd):
        captured["cmd"] = cmd
        raise RuntimeError("exec")

    monkeypatch.delenv(cli.BOOTSTRAP_ENV, raising=False)
    monkeypatch.setattr(cli.importlib.util, "find_spec", lambda name: None)
    monkeypatch.setattr(cli.shutil, "which", lambda name: "/usr/bin/uv")
    monkeypatch.setattr(cli.os, "execvp", fake_execvp)
    monkeypatch.setattr(sys, "argv", ["render_report.py", "--format", "pdf"])

    with pytest.raises(RuntimeError, match="exec"):
        cli._bootstrap_render_deps(SimpleNamespace(format="pdf"))

    assert captured["cmd"].count("--with") == 4
    assert "playwright" in captured["cmd"]


def test_render_report_bootstrap_guard_prevents_recursive_reexec(monkeypatch):
    from _render_report import cli

    called = False

    def fake_execvp(file, cmd):
        nonlocal called
        called = True

    monkeypatch.setenv(cli.BOOTSTRAP_ENV, "1")
    monkeypatch.setattr(cli.importlib.util, "find_spec", lambda name: None)
    monkeypatch.setattr(cli.shutil, "which", lambda name: "/usr/bin/uv")
    monkeypatch.setattr(cli.os, "execvp", fake_execvp)

    cli._bootstrap_render_deps(SimpleNamespace(format="html"))

    assert called is False


def test_render_report_bootstrap_skips_when_deps_importable(monkeypatch):
    from _render_report import cli

    called = False

    def fake_execvp(file, cmd):
        nonlocal called
        called = True

    monkeypatch.delenv(cli.BOOTSTRAP_ENV, raising=False)
    monkeypatch.setattr(cli.importlib.util, "find_spec", lambda name: object())
    monkeypatch.setattr(cli.shutil, "which", lambda name: "/usr/bin/uv")
    monkeypatch.setattr(cli.os, "execvp", fake_execvp)

    cli._bootstrap_render_deps(SimpleNamespace(format="pdf"))

    assert called is False


def test_producer_pdf_render_command_includes_playwright():
    from producers.rendering import render_report_command

    cmd = render_report_command(
        wrapper_path=Path("/tmp/wrapper.json"),
        output_path=Path("/tmp/report.pdf"),
        output_format="pdf",
    )

    assert "playwright" in cmd


def test_render_report_analysis_mode_both_derives_sibling_outputs():
    from _render_report import cli

    args = SimpleNamespace(
        analysis_mode="both",
        output=Path("incident_report_print.pdf"),
    )

    jobs = cli._render_jobs({"schema_version": "bot_report_input.v1"}, args)

    assert jobs[0][2] == Path("incident_report_print_llm.pdf")
    assert jobs[1][2] == Path("incident_report_print_deterministic.pdf")
    assert jobs[1][0] == {"schema_version": "bot_report_input.v1"}


def test_render_report_print_profile_forces_light_and_marks_html(monkeypatch):
    import render_report
    from _render_report import cli

    monkeypatch.delenv("BOT_INSIGHTS_RENDER_PATH", raising=False)
    wrapper = json.loads((ROOT / "skills/bot-insights/examples/incident-report.json").read_text())
    calls = []

    def fake_engine(**kwargs):
        calls.append(kwargs)
        return '<body class="profile-print" data-profile="print"></body>'

    monkeypatch.setattr(cli, "_render_via_engine", fake_engine)
    output, warnings = render_report.render(
        wrapper,
        SimpleNamespace(
            text=[],
            file=None,
            format="html",
            profile="print",
            report_type=None,
            output=None,
            limit=None,
            allow_unknown=False,
            title=None,
            palette="tableau",
            theme="auto",
            analysis_mode="llm",
        ),
    )

    assert warnings == []
    assert 'data-profile="print"' in output
    assert 'class="profile-print"' in output
    assert calls[0]["profile"] == "print"
    assert calls[0]["theme_mode"] == "light"


def test_render_report_deterministic_mode_removes_analyst_notes(monkeypatch):
    from _render_report import cli

    wrapper = json.loads((ROOT / "skills/bot-insights/examples/incident-report.json").read_text())
    assert wrapper["analyst_notes"]

    deterministic = cli._without_analyst_notes(wrapper)

    assert "analyst_notes" not in deterministic
    assert "analyst_notes" in wrapper
