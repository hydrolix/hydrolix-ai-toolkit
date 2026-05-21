"""Tests for the Phase 6a threshold-config layer.

Pin every default value against the historic Python constants in
``heuristics.py`` so silent drift between the dataclass defaults and
the constants the rest of the codebase relies on gets caught at test
time. Also exercise the YAML / TOML / JSON loader paths and the
behavioral effect of an override applied through
``_compute_suspicious_targets``.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = ROOT / "skills/bot-insights/scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

import heuristics  # noqa: E402
from config import (  # noqa: E402
    AsReputationConfig,
    BrowserVersionHistoryConfig,
    DEFAULT_THRESHOLDS,
    RiskScoreThresholds,
    SuspiciousTargetsThresholds,
    Thresholds,
    load_thresholds,
    active_thresholds,
    set_active_thresholds,
)


# ---------------------------------------------------------------------------
# Defaults pin against the legacy constants.
# ---------------------------------------------------------------------------

def test_default_suspicious_targets_match_heuristics_constants() -> None:
    st = DEFAULT_THRESHOLDS.suspicious_targets
    assert st.volume_share_min == 0.05
    assert st.rate_429_share_min == 0.10
    assert st.rate_429_total_min == 100
    assert st.single_path_requests_min == 1000
    assert st.asn_cluster_min_ips == 3
    assert st.botnet_cluster_share_min == 0.005
    assert st.new_actor_volume_share_min == 0.001
    assert st.new_actor_requests_min == 1_000_000
    assert (
        st.volume_share_min == heuristics._SUSPICIOUS_VOLUME_SHARE_MIN
    )
    assert (
        st.rate_429_total_min == heuristics._SUSPICIOUS_RATE_429_TOTAL_MIN
    )
    assert (
        st.asn_cluster_min_ips == heuristics._SUSPICIOUS_ASN_CLUSTER_MIN_IPS
    )


def test_default_anomaly_matches_heuristics_constants() -> None:
    a = DEFAULT_THRESHOLDS.anomaly
    assert a.error_rate_ratio_min == heuristics._ANOMALY_ERROR_RATE_RATIO_MIN == 3.0
    assert (
        a.current_error_rate_min
        == heuristics._ANOMALY_CURRENT_ERROR_RATE_MIN
        == 0.05
    )
    assert a.min_requests == heuristics._ANOMALY_MIN_REQUESTS == 1000


def test_default_risk_weights_and_bands_match_legacy() -> None:
    from report_engine.contexts.incident import risk as risk_mod

    assert dict(DEFAULT_THRESHOLDS.risk_score.weights) == risk_mod._RISK_WEIGHTS
    assert dict(DEFAULT_THRESHOLDS.risk_score.bands) == risk_mod._RISK_BANDS
    assert DEFAULT_THRESHOLDS.risk_score.bands["critical"] == (75, 100)
    assert DEFAULT_THRESHOLDS.risk_score.weights["critical"] == 30


def test_default_display_caps() -> None:
    d = DEFAULT_THRESHOLDS.display
    assert d.suspicious_targets_cap == 10
    assert d.exec_actions_cap == 5
    assert d.exec_impact_tiles_cap == 5


def test_default_thresholds_disabled_rules_is_empty() -> None:
    assert DEFAULT_THRESHOLDS.disabled_rules == frozenset()


def test_default_as_reputation_config_is_opt_in() -> None:
    assert DEFAULT_THRESHOLDS.as_reputation == AsReputationConfig()
    assert DEFAULT_THRESHOLDS.as_reputation.enabled is True
    assert DEFAULT_THRESHOLDS.as_reputation.spamhaus_asndrop_path is None
    assert DEFAULT_THRESHOLDS.as_reputation.local_overrides_path is None


def test_default_browser_version_history_config_uses_packaged_snapshot() -> None:
    assert DEFAULT_THRESHOLDS.browser_version_history == BrowserVersionHistoryConfig()
    assert DEFAULT_THRESHOLDS.browser_version_history.enabled is True
    snapshot_path = DEFAULT_THRESHOLDS.browser_version_history.snapshot_path
    assert snapshot_path is not None
    assert snapshot_path.endswith("bot_insights/data/browser-version-history.json")
    assert Path(snapshot_path).exists()
    assert DEFAULT_THRESHOLDS.browser_version_history.stale_months == 18


# ---------------------------------------------------------------------------
# Loader.
# ---------------------------------------------------------------------------

def test_load_thresholds_with_no_path_returns_defaults() -> None:
    assert load_thresholds(None) is DEFAULT_THRESHOLDS


def test_load_thresholds_overlays_yaml_keys_over_defaults(tmp_path: Path) -> None:
    p = tmp_path / "tight.yaml"
    p.write_text(
        "heuristics:\n"
        "  suspicious_targets:\n"
        "    volume_share_min: 0.20\n"
    )
    t = load_thresholds(p)
    assert t.suspicious_targets.volume_share_min == 0.20
    # Every other field stays at the default.
    assert (
        t.suspicious_targets.rate_429_share_min
        == DEFAULT_THRESHOLDS.suspicious_targets.rate_429_share_min
    )
    assert t.anomaly == DEFAULT_THRESHOLDS.anomaly
    assert t.display == DEFAULT_THRESHOLDS.display
    assert dict(t.risk_score.weights) == dict(DEFAULT_THRESHOLDS.risk_score.weights)


def test_load_thresholds_supports_json(tmp_path: Path) -> None:
    p = tmp_path / "override.json"
    p.write_text(json.dumps({"display": {"suspicious_targets_cap": 25}}))
    t = load_thresholds(p)
    assert t.display.suspicious_targets_cap == 25


def test_load_thresholds_overlays_as_reputation_paths_relative_to_config(
    tmp_path: Path,
) -> None:
    p = tmp_path / "config.json"
    p.write_text(
        json.dumps(
            {
                "as_reputation": {
                    "spamhaus_asndrop_path": "fixtures/asndrop.json",
                    "local_overrides_path": "overrides/as-reputation.yaml",
                }
            }
        )
    )
    t = load_thresholds(p)
    assert (
        t.as_reputation.spamhaus_asndrop_path
        == str(tmp_path / "fixtures/asndrop.json")
    )
    assert (
        t.as_reputation.local_overrides_path
        == str(tmp_path / "overrides/as-reputation.yaml")
    )


def test_load_thresholds_overlays_browser_snapshot_path_relative_to_config(
    tmp_path: Path,
) -> None:
    p = tmp_path / "config.json"
    p.write_text(
        json.dumps(
            {
                "browser_version_history": {
                    "snapshot_path": "fixtures/browser-history.json",
                    "stale_months": 12,
                }
            }
        )
    )
    t = load_thresholds(p)
    assert (
        t.browser_version_history.snapshot_path
        == str(tmp_path / "fixtures/browser-history.json")
    )
    assert t.browser_version_history.stale_months == 12


def test_load_thresholds_supports_toml(tmp_path: Path) -> None:
    p = tmp_path / "override.toml"
    p.write_text(
        '[heuristics.anomaly]\n'
        'error_rate_ratio_min = 5.0\n'
    )
    t = load_thresholds(p)
    assert t.anomaly.error_rate_ratio_min == 5.0


def test_load_thresholds_overlays_disabled_rules(tmp_path: Path) -> None:
    p = tmp_path / "disabled.yaml"
    p.write_text(
        "heuristics:\n"
        "  disabled_rules: [high_rate_429_share, anomaly]\n"
    )
    t = load_thresholds(p)
    assert t.disabled_rules == frozenset({"high_rate_429_share", "anomaly"})


def test_load_thresholds_overlays_risk_score_bands(tmp_path: Path) -> None:
    p = tmp_path / "bands.yaml"
    p.write_text(
        "heuristics:\n"
        "  risk_score:\n"
        "    bands:\n"
        "      critical: [90, 100]\n"
    )
    t = load_thresholds(p)
    assert t.risk_score.bands["critical"] == (90, 100)
    # Other bands keep defaults.
    assert t.risk_score.bands["low"] == (0, 19)


def test_load_thresholds_validates_automation_ua_pattern(tmp_path: Path) -> None:
    p = tmp_path / "bad-regex.yaml"
    p.write_text(
        "heuristics:\n"
        "  suspicious_targets:\n"
        "    automation_ua_pattern: '['\n"  # invalid regex
    )
    with pytest.raises(re.error):
        load_thresholds(p)


def test_load_thresholds_rejects_unknown_extension(tmp_path: Path) -> None:
    p = tmp_path / "config.ini"
    p.write_text("not used")
    with pytest.raises(SystemExit):
        load_thresholds(p)


# ---------------------------------------------------------------------------
# Active-thresholds singleton.
# ---------------------------------------------------------------------------

def test_active_thresholds_round_trip() -> None:
    original = active_thresholds()
    try:
        custom = Thresholds(
            suspicious_targets=SuspiciousTargetsThresholds(volume_share_min=0.99),
        )
        set_active_thresholds(custom)
        assert active_thresholds().suspicious_targets.volume_share_min == 0.99
    finally:
        set_active_thresholds(original)


# ---------------------------------------------------------------------------
# Behavioral overrides flow through the heuristic ladder.
# ---------------------------------------------------------------------------

def _scope_artifact(total_requests: int = 1_000_000) -> dict:
    return {"window_confirmation": {"requests": total_requests, "rate_429_pct": 0.0}}


def _actors_artifact_one_ip(value: str, requests: int) -> dict:
    return {
        "actor_rankings": [
            {
                "field": "client_ip",
                "rows": [
                    {
                        "value": value,
                        "requests": requests,
                        "req_429": 0,
                        "req_5xx": 0,
                        "distinct_paths": 5,
                    }
                ],
            }
        ]
    }


def test_compute_suspicious_targets_honors_volume_share_min_override() -> None:
    from producers.suspicious_targets import _compute_suspicious_targets

    # 10% share — fires at default volume_share_min=0.05
    scope = _scope_artifact(total_requests=1_000_000)
    actors = _actors_artifact_one_ip("203.0.113.10", requests=100_000)
    baseline = {"client_ip": {"203.0.113.10": {"requests": 100_000, "req_429": 0, "req_5xx": 0}}}

    default_result = _compute_suspicious_targets(scope, actors, baseline)
    assert any(
        "high_volume_share" in (t["reason_flags"] or [])
        for t in default_result
    ), "default thresholds should flag high_volume_share at 10% share"

    # Tighten to 0.20 — 10% share now under floor.
    tight = Thresholds(
        suspicious_targets=SuspiciousTargetsThresholds(volume_share_min=0.20),
    )
    tight_result = _compute_suspicious_targets(
        scope, actors, baseline, thresholds=tight,
    )
    assert not any(
        "high_volume_share" in (t["reason_flags"] or [])
        for t in tight_result
    ), "tightened threshold should suppress high_volume_share at 10% share"


def test_risk_score_honors_band_override() -> None:
    from report_engine.contexts.incident.risk import _risk_score

    suspicious = [{"severity": "high"} for _ in range(3)]
    summary = {"level": "high"}

    # Default high band is (50, 74).
    default_score = _risk_score(summary, suspicious)
    assert 50 <= default_score["value"] <= 74

    # Override: pin the high band to (10, 20). Score must drop into it.
    override = Thresholds(
        risk_score=RiskScoreThresholds(
            weights=dict(DEFAULT_THRESHOLDS.risk_score.weights),
            bands={
                **dict(DEFAULT_THRESHOLDS.risk_score.bands),
                "high": (10, 20),
            },
        )
    )
    overridden_score = _risk_score(summary, suspicious, thresholds=override)
    assert 10 <= overridden_score["value"] <= 20
