"""Focused tests for the extracted reportkit package."""

from __future__ import annotations

import sys
from types import SimpleNamespace
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
REPORTKIT_SRC = ROOT / "reportkit/src"
if str(REPORTKIT_SRC) not in sys.path:
    sys.path.insert(0, str(REPORTKIT_SRC))


class _FakePdfPage:
    def __init__(self, calls, *, with_title: bool = False):
        self.calls = calls
        self.with_title = with_title

    def set_content(self, html, wait_until):
        self.calls["content"] = (html, wait_until)

    def evaluate(self, script, title):
        if self.with_title:
            self.calls["title"] = (script, title)

    def pdf(self, **kwargs):
        self.calls["pdf"] = kwargs


class _FakePdfBrowser:
    def __init__(self, calls, *, with_title: bool = False):
        self.calls = calls
        self.with_title = with_title

    def new_page(self):
        return _FakePdfPage(self.calls, with_title=self.with_title)

    def close(self):
        self.calls["closed"] = True


class _FakePdfChromium:
    def __init__(self, calls, *, with_title: bool = False):
        self.calls = calls
        self.with_title = with_title

    def launch(self):
        return _FakePdfBrowser(self.calls, with_title=self.with_title)


class _FakePdfPlaywright:
    def __init__(self, calls, *, with_title: bool = False):
        self.chromium = _FakePdfChromium(calls, with_title=with_title)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


def _install_fake_playwright(monkeypatch, calls, *, with_title: bool = False):
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "playwright.sync_api":
            return SimpleNamespace(
                Error=RuntimeError,
                sync_playwright=lambda: _FakePdfPlaywright(
                    calls, with_title=with_title
                ),
            )
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)


def test_registry_lookup_by_report_type_and_schema():
    from reportkit.artifacts import ReportRegistry

    class Module:
        SCHEMA = "example_artifact.v1"
        REPORT_TYPE = "example_report"
        TEMPLATE = "reports/example.html"

        @staticmethod
        def assemble(artifacts):
            return artifacts[0]

        @staticmethod
        def prepare(artifact):
            return artifact

    registry = ReportRegistry([Module])

    assert registry.by_report_type("example_report") is Module
    assert registry.by_schema("example_artifact.v1") is Module


def test_note_slot_projection_first_write_wins():
    from reportkit.artifacts import project_notes_by_slot

    notes = [
        {"note_id": "lead", "text": "first"},
        {"note_id": "other", "text": "ignored"},
        {"note_id": "lead", "text": "second"},
    ]

    assert project_notes_by_slot(notes, {"lead": "executive_summary"}) == {
        "executive_summary": {"note_id": "lead", "text": "first"}
    }


def test_template_selection_html_and_markdown():
    from reportkit.artifacts import template_for

    class Module:
        REPORT_TYPE = "example"
        TEMPLATE = "reports/example.html"

    assert template_for(Module, "html") == "reports/example.html"
    assert template_for(Module, "markdown") == "reports/example.md.j2"


def test_template_selection_rejects_non_html_markdown_base():
    from reportkit.artifacts import template_for

    class Module:
        REPORT_TYPE = "example"
        TEMPLATE = "reports/example.txt"

    with pytest.raises(ValueError, match="does not end in .html"):
        template_for(Module, "markdown")


def test_safe_markdown_rendering_strips_html_and_demotes_h1():
    pytest.importorskip("bleach")
    pytest.importorskip("markdown_it")
    from reportkit.markdown import render_safe

    rendered = str(render_safe("# Title\n\n<script>alert(1)</script>\n\n[ok](javascript:bad)"))

    assert "<h2>Title</h2>" in rendered
    assert "<script>" not in rendered
    assert 'href="javascript:' not in rendered


def test_reportkit_incident_volume_chart_matches_incident_color_semantics():
    from reportkit.charts import incident_volume_chart_svg

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
    assert 'fill="#E15759">Peak 90</text>' in svg


def test_sql_validation_and_format_json_normalization():
    from reportkit.extract.hydrolix import ensure_format_json, reject_invalid_sql

    assert ensure_format_json("SELECT 1;") == "SELECT 1 FORMAT JSON"
    assert ensure_format_json("SELECT 1 FORMAT JSON") == "SELECT 1 FORMAT JSON"
    reject_invalid_sql(
        "SELECT 1 FROM table WHERE reqTimeSec >= now() - INTERVAL 1 HOUR FORMAT JSON",
        require_time_range=True,
    )
    with pytest.raises(SystemExit):
        reject_invalid_sql("DELETE FROM table WHERE reqTimeSec >= now()", require_time_range=True)


def test_hydrolix_response_shaping_and_handoff_packet():
    from reportkit.extract.hydrolix import (
        CredentialState,
        build_handoff_packet,
        response_row_count,
        shape_output,
    )

    response = {"data": [{"value": 1}], "rows": 1}
    shaped = shape_output(response, "rows")
    assert shaped == [{"value": 1}]
    assert response_row_count(response, shaped) == 1

    packet = build_handoff_packet(
        cluster="demo",
        database="akamai",
        sql="SELECT 1 FORMAT JSON",
        credentials=CredentialState(False, None, None, ("HYDROLIX_HOST/HDX_HOSTNAME",), (), None, "not_required"),
        output_path=Path("/tmp/raw.json"),
        shape="clickhouse",
    )

    assert packet["schema_version"] == "hydrolix_mcp_query_request.v1"
    assert packet["mcp"]["tool"] == "run_select_query"
    assert packet["validated_sql"] == "SELECT 1 FORMAT JSON"


def test_report_renderer_renders_wrapper_payload(tmp_path):
    pytest.importorskip("jinja2")
    from reportkit.artifacts import ReportRegistry
    from reportkit.render import ReportRenderer

    template_dir = tmp_path / "templates"
    (template_dir / "reports").mkdir(parents=True)
    (template_dir / "reports/example.html").write_text(
        "{{ title }}|{{ notes_by_slot.summary.text }}|{{ report_type }}|{{ mode }}",
        encoding="utf-8",
    )

    class Module:
        SCHEMA = "example_artifact.v1"
        REPORT_TYPE = "example_report"
        TEMPLATE = "reports/example.html"
        NOTE_ID_TO_SLOT = {"summary": "summary"}

        @staticmethod
        def assemble(artifacts):
            return artifacts[0]

        @staticmethod
        def prepare(artifact):
            return {"title": artifact["title"]}

    renderer = ReportRenderer(
        registry=ReportRegistry([Module]),
        template_paths=[template_dir],
        wrapper_schema="custom_wrapper.v1",
    )
    rendered = renderer.render_payload(
        {
            "schema_version": "custom_wrapper.v1",
            "report_type": "example_report",
            "artifacts": [{"schema_version": "example_artifact.v1", "title": "Hello"}],
            "analyst_notes": [{"note_id": "summary", "text": "Note"}],
        },
        mode="brief",
    )

    assert rendered == "Hello|Note|example_report|brief"


def test_report_renderer_adds_profile_to_context(tmp_path):
    pytest.importorskip("jinja2")
    from reportkit.artifacts import ReportRegistry
    from reportkit.render import ReportRenderer

    template_dir = tmp_path / "templates"
    (template_dir / "reports").mkdir(parents=True)
    (template_dir / "reports/example.html").write_text(
        "{{ report_type }}|{{ profile }}",
        encoding="utf-8",
    )

    class Module:
        SCHEMA = "example_artifact.v1"
        REPORT_TYPE = "example_report"
        TEMPLATE = "reports/example.html"

        @staticmethod
        def assemble(artifacts):
            return artifacts[0]

        @staticmethod
        def prepare(artifact):
            return artifact

    renderer = ReportRenderer(
        registry=ReportRegistry([Module]),
        template_paths=[template_dir],
        wrapper_schema="custom_wrapper.v1",
    )

    rendered = renderer.render_payload(
        {
            "schema_version": "custom_wrapper.v1",
            "report_type": "example_report",
            "artifacts": [{"schema_version": "example_artifact.v1"}],
        },
        profile="print",
    )

    assert rendered == "example_report|print"


def test_pdf_export_reports_missing_playwright(monkeypatch, tmp_path):
    import builtins
    from reportkit.print_export import PrintExportError, render_pdf_from_html

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "playwright.sync_api":
            raise ImportError("no playwright")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    with pytest.raises(PrintExportError, match="PDF export requires optional Playwright"):
        render_pdf_from_html("<html><body>ok</body></html>", tmp_path / "out.pdf")


def test_pdf_export_uses_css_page_size_and_footer(monkeypatch, tmp_path):
    from reportkit.print_export import render_pdf_from_html

    calls = {}
    _install_fake_playwright(monkeypatch, calls, with_title=True)

    render_pdf_from_html("<html><body>ok</body></html>", tmp_path / "out.pdf", title="Report")

    assert calls["content"] == ("<html><body>ok</body></html>", "networkidle")
    assert calls["title"][1] == "Report"
    assert calls["closed"] is True
    assert calls["pdf"]["prefer_css_page_size"] is True
    assert calls["pdf"]["display_header_footer"] is True
    assert "pageNumber" in calls["pdf"]["footer_template"]
    assert calls["pdf"]["margin"]["top"] == "0.48in"


def test_pdf_export_full_bleed_disables_footer_and_margins(monkeypatch, tmp_path):
    import builtins
    from reportkit.print_export import render_pdf_from_html

    calls = {}
    real_import = builtins.__import__

    class FakePage:
        def set_content(self, html, wait_until):
            calls["content"] = (html, wait_until)

        def pdf(self, **kwargs):
            calls["pdf"] = kwargs

    class FakeBrowser:
        def new_page(self):
            return FakePage()

        def close(self):
            calls["closed"] = True

    class FakeChromium:
        def launch(self):
            return FakeBrowser()

    class FakePlaywright:
        chromium = FakeChromium()

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    def fake_import(name, *args, **kwargs):
        if name == "playwright.sync_api":
            return SimpleNamespace(
                Error=RuntimeError,
                sync_playwright=lambda: FakePlaywright(),
            )
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    render_pdf_from_html(
        "<html><body>ok</body></html>",
        tmp_path / "out.pdf",
        full_bleed=True,
    )

    assert calls["closed"] is True
    assert calls["pdf"]["prefer_css_page_size"] is True
    assert calls["pdf"]["print_background"] is True
    assert calls["pdf"]["display_header_footer"] is False
    assert calls["pdf"]["margin"] == {
        "top": "0",
        "right": "0",
        "bottom": "0",
        "left": "0",
    }
    assert "footer_template" not in calls["pdf"]
