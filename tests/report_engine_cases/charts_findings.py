from __future__ import annotations

from tests.report_engine_helpers import *

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
