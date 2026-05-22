from __future__ import annotations

from tests.report_engine_helpers import *

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
