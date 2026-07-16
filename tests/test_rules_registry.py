"""Tests for the Phase 6b suspicious-target rule registry.

Pin the builtin set against the legacy reason-flag vocabulary so a
silent rule deletion gets caught at test time. Exercise the disable +
register-rule extension paths and the cross-row pivot's handling of
``disabled_rules``.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = ROOT / "skills/bot-insights/scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

from config import (  # noqa: E402
    Thresholds,
)
from producers.suspicious_targets import _compute_suspicious_targets  # noqa: E402
from producers.suspicious_targets.rules import (  # noqa: E402
    BUILTIN_RULES,
    Rule,
    active_rules,
    register_rule,
    reset_to_builtins,
)


@pytest.fixture(autouse=True)
def _restore_registry():
    """Every test starts with a clean builtins-only registry."""
    yield
    reset_to_builtins()


def test_builtin_rules_cover_every_legacy_reason_flag() -> None:
    """Guards against accidental rule deletion."""
    builtin_names = {r.name for r in BUILTIN_RULES}
    assert builtin_names == {
        "high_volume_share",
        "high_rate_429_share",
        "single_path_concentration",
        "automation_user_agent",
        "new_in_window",
        "high_volume_new_actor",
        "anomaly",
    }


def test_active_rules_initially_match_builtins() -> None:
    assert {r.name for r in active_rules()} == {r.name for r in BUILTIN_RULES}


# ---------------------------------------------------------------------------
# Fixtures for the synthetic actor-ranking replay.
# ---------------------------------------------------------------------------

def _scope_artifact(
    total_requests: int = 1_000_000, rate_429_pct: float = 20.0
) -> dict:
    return {
        "window_confirmation": {
            "requests": total_requests,
            "rate_429_pct": rate_429_pct,
        }
    }


def _actors_one_ip_high_rate_429() -> dict:
    """One client_ip row with both high volume share AND high 429 share."""
    return {
        "actor_rankings": [
            {
                "field": "client_ip",
                "rows": [
                    {
                        "value": "203.0.113.10",
                        "requests": 100_000,    # 10% of 1M
                        "req_429": 60_000,      # 30% of 200k window 429s
                        "req_5xx": 0,
                        "distinct_paths": 5,
                    }
                ],
            }
        ]
    }


def test_disabled_rule_does_not_emit_flag() -> None:
    """Replay a row that would normally emit high_rate_429_share;
    disable the rule via thresholds and assert the flag is absent."""
    scope = _scope_artifact()
    actors = _actors_one_ip_high_rate_429()
    baseline = {"client_ip": {}}  # ensures new_in_window also fires but not contested

    default_targets = _compute_suspicious_targets(scope, actors, baseline)
    assert any(
        "high_rate_429_share" in t["reason_flags"] for t in default_targets
    )

    disabled_thresholds = Thresholds(disabled_rules=frozenset({"high_rate_429_share"}))
    disabled_targets = _compute_suspicious_targets(
        scope, actors, baseline, thresholds=disabled_thresholds,
    )
    assert all(
        "high_rate_429_share" not in t["reason_flags"] for t in disabled_targets
    )


def test_register_rule_appends_and_fires() -> None:
    fired_rows: list[str] = []

    def _custom_evaluator(ctx, thresholds):
        fired_rows.append(ctx.value)
        return ctx.field == "client_ip"

    register_rule(
        Rule(
            name="custom_smoke_flag",
            applies_to=frozenset({"client_ip"}),
            requires_baseline=False,
            evaluator=_custom_evaluator,
        )
    )
    # The default ladder routes share-tier rules through a name-allowlist;
    # this guards against silent breakage if the allowlist drops a name.
    assert "custom_smoke_flag" not in {r.name for r in BUILTIN_RULES}
    assert "custom_smoke_flag" in {r.name for r in active_rules()}


def test_register_rule_replaces_by_name() -> None:
    """A rule with the same name replaces the existing entry in place."""
    register_rule(
        Rule(
            name="high_volume_share",
            applies_to=frozenset({"client_ip"}),
            requires_baseline=False,
            evaluator=lambda ctx, t: False,
        )
    )
    matches = [r for r in active_rules() if r.name == "high_volume_share"]
    assert len(matches) == 1
    assert matches[0].evaluator(None, None) is False  # type: ignore[arg-type]


def test_cross_row_pivots_honor_disabled_rules() -> None:
    """Disable botnet_member; a ranking that would normally trigger
    the pivot leaves the flag off."""
    scope = _scope_artifact(total_requests=1_000_000)
    # 3 client_ip rows on the same ASN at 5% share each (combined 15%),
    # well above the botnet_cluster_share_min=0.005 floor.
    actors = {
        "actor_rankings": [
            {
                "field": "client_ip",
                "rows": [
                    {
                        "value": f"10.0.0.{n}",
                        "requests": 50_000,
                        "req_429": 0,
                        "req_5xx": 0,
                        "distinct_paths": 5,
                        "asn": 64500,
                        "asn_org": "Test-AS",
                    }
                    for n in range(3)
                ],
            }
        ]
    }
    baseline = {"client_ip": {}}

    default_targets = _compute_suspicious_targets(scope, actors, baseline)
    assert any(
        "botnet_member" in t["reason_flags"] for t in default_targets
    ), "default cluster pivot must emit botnet_member on 3+ IP same-ASN group"

    disabled_botnet = Thresholds(disabled_rules=frozenset({"botnet_member"}))
    disabled_targets = _compute_suspicious_targets(
        scope, actors, baseline, thresholds=disabled_botnet,
    )
    assert all(
        "botnet_member" not in t["reason_flags"] for t in disabled_targets
    )
    # single_asn_cluster still fires — only botnet_member was disabled.
    assert any(
        "single_asn_cluster" in t["reason_flags"] for t in disabled_targets
    )


def test_cross_row_pivots_disabled_single_asn_cluster() -> None:
    scope = _scope_artifact(total_requests=1_000_000)
    actors = {
        "actor_rankings": [
            {
                "field": "client_ip",
                "rows": [
                    {
                        "value": f"10.0.0.{n}",
                        "requests": 50_000,
                        "req_429": 0,
                        "req_5xx": 0,
                        "distinct_paths": 5,
                        "asn": 64500,
                        "asn_org": "Test-AS",
                    }
                    for n in range(3)
                ],
            }
        ]
    }
    baseline = {"client_ip": {}}

    disabled_asn = Thresholds(disabled_rules=frozenset({"single_asn_cluster"}))
    disabled_targets = _compute_suspicious_targets(
        scope, actors, baseline, thresholds=disabled_asn,
    )
    assert all(
        "single_asn_cluster" not in t["reason_flags"] for t in disabled_targets
    )


def test_share_based_rules_skip_aggregate_fields() -> None:
    """Aggregate fields (cohort, country) don't fire share-based primitives.
    Pinning this so registry rewiring keeps the legacy gating intact.
    """
    scope = _scope_artifact()
    actors = {
        "actor_rankings": [
            {
                "field": "country",
                "rows": [
                    {
                        "value": "US",
                        "requests": 800_000,
                        "req_429": 100_000,
                        "req_5xx": 0,
                        "distinct_paths": 1000,
                    }
                ],
            }
        ]
    }
    baseline = {"country": {"US": {"requests": 800_000, "req_429": 0, "req_5xx": 0}}}
    targets = _compute_suspicious_targets(scope, actors, baseline)
    flags = {f for t in targets for f in t["reason_flags"]}
    assert "high_volume_share" not in flags
    assert "single_path_concentration" not in flags


def test_automation_ua_rule_fires_on_user_agent_only() -> None:
    scope = _scope_artifact()
    actors = {
        "actor_rankings": [
            {
                "field": "user_agent",
                "rows": [
                    {
                        "value": "curl/7.81.0",
                        "requests": 1_000,
                        "req_429": 0,
                        "req_5xx": 0,
                        "distinct_paths": 1,
                    }
                ],
            }
        ]
    }
    baseline = {"user_agent": {"curl/7.81.0": {"requests": 1, "req_429": 0, "req_5xx": 0}}}
    targets = _compute_suspicious_targets(scope, actors, baseline)
    assert any("automation_user_agent" in t["reason_flags"] for t in targets)


def test_anomaly_rule_extras_populated() -> None:
    """The anomaly rule emits supporting_extras (baseline_error_rate_pct etc.)."""
    scope = _scope_artifact()
    actors = {
        "actor_rankings": [
            {
                "field": "trafficCohort",
                "rows": [
                    {
                        "value": "browser",
                        "requests": 100_000,
                        "req_429": 50_000,   # 50% error rate
                        "req_5xx": 0,
                        "distinct_paths": 50,
                    }
                ],
            }
        ]
    }
    # Baseline error rate ~0.5%; current 50% — 100× departure.
    baseline = {
        "trafficCohort": {
            "browser": {"requests": 1_000_000, "req_429": 5_000, "req_5xx": 0}
        }
    }
    targets = _compute_suspicious_targets(scope, actors, baseline)
    anomaly_target = next(
        (t for t in targets if "anomaly" in t["reason_flags"]), None
    )
    assert anomaly_target is not None
    extras = anomaly_target["supporting"]
    assert "baseline_error_rate_pct" in extras
    assert "current_error_rate_pct" in extras
    assert "error_rate_ratio" in extras
