from __future__ import annotations

from tests.report_engine_helpers import *

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
