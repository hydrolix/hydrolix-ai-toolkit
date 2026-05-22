from __future__ import annotations

from tests.report_engine_helpers import *

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
