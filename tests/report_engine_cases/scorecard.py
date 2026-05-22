from __future__ import annotations

from tests.report_engine_helpers import *

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
