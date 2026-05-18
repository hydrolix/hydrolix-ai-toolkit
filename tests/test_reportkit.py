"""Focused tests for the extracted reportkit package."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
REPORTKIT_SRC = ROOT / "reportkit/src"
if str(REPORTKIT_SRC) not in sys.path:
    sys.path.insert(0, str(REPORTKIT_SRC))


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
