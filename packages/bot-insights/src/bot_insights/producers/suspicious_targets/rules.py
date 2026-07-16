"""Per-row rule registry for the suspicious-target heuristic ladder.

The legacy ``_evaluate_share_flags`` / ``_evaluate_novelty_flags`` /
``_evaluate_anomaly`` triplet baked the rule definitions into Python
branch logic, so adding or disabling a rule for a single tenant
required a code fork. Phase 6b lifts each per-row primitive into a
``Rule`` instance held in a process-wide list, iterated at evaluation
time by the orchestrator.

Two extension paths:

  - Disable a rule for a tenant by listing its name in
    ``thresholds.disabled_rules`` (typically loaded from the ``--config``
    YAML's ``heuristics.disabled_rules:`` array). The slim evaluator
    skips any disabled rule before consulting it.
  - Register a custom rule from out-of-tree code via
    :func:`register_rule`. The rule's evaluator runs alongside the
    builtins; its name appears in the row's ``reason_flags`` exactly
    like a builtin.

Cross-row pivots (``single_asn_cluster``, ``botnet_member``) are not
registry-driven — they operate on a list, not a row. The orchestrator
still honors ``disabled_rules`` for them, but their evaluator code
stays in :mod:`producers.suspicious_targets.clusters` as post-pass
mutators.

The taxonomy mapping (reason_flag → ATT&CK technique, action class) in
:mod:`producers.suspicious_targets.taxonomy` joins on rule name. A new
rule registered at runtime that names an unknown reason_flag will
appear in ``reason_flags`` but won't carry an ATT&CK mapping until the
taxonomy is extended; this is intentional — taxonomy entries are a
contract surface and shouldn't be silently invented at import time.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from config import DEFAULT_THRESHOLDS, Thresholds


__all__ = [
    "RuleContext",
    "Rule",
    "BUILTIN_RULES",
    "register_rule",
    "active_rules",
    "disabled",
    "reset_to_builtins",
]


@dataclass(frozen=True)
class RuleContext:
    """Per-row inputs assembled once by the ladder orchestrator and
    handed to every rule evaluator that matches the row's ``field``.

    Bundling these here lets the orchestrator derive shares / 429
    totals / current-error rate exactly once per row, instead of every
    rule re-deriving the same arithmetic.
    """

    field: str
    value: str
    is_individual: bool
    requests: float
    share: float
    share_429: float
    total_429: float
    distinct_paths: int
    current_error_rate: float
    baseline_data: dict
    baseline_row: dict | None
    automation_ua_pattern: object  # re.Pattern — typing keeps the import surface small
    is_templated_catchall_path: Callable[[str], bool]


@dataclass(frozen=True)
class Rule:
    """A per-row primitive.

    Attributes:
      name: The emitted ``reason_flag`` for this rule. Must match the
        legacy vocabulary so the taxonomy (ATT&CK mapping, action
        class) joins by string identity. Avoid name collisions when
        registering custom rules.
      applies_to: Set of ranking fields the rule is allowed to fire on.
        Frozen so registration is hash-safe.
      requires_baseline: ``True`` when the evaluator needs the baseline
        row (anomaly). When ``True`` and the baseline lookup yields
        ``None``, the orchestrator short-circuits to ``False``.
      evaluator: ``(RuleContext, Thresholds) -> bool``. Returning
        ``True`` emits the rule's ``name`` as a reason_flag on the row.
    """

    name: str
    applies_to: frozenset[str]
    requires_baseline: bool
    evaluator: Callable[[RuleContext, Thresholds], bool]
    description: str = ""


# ---------------------------------------------------------------------------
# Builtin rule evaluators. Bodies are lifted verbatim from the original
# ``_evaluate_*`` branches in ladder.py:56-167 (pre-Phase-6b).
# ---------------------------------------------------------------------------

# Every "individual-entity" field on which share-based primitives apply.
# Aggregate fields (cohort, country) are excluded — share-based
# primitives fire by construction on them and produce noise.
_INDIVIDUAL_FIELDS = frozenset({"client_ip", "user_agent", "asn", "request_path"})


def _eval_high_volume_share(ctx: RuleContext, thresholds: Thresholds) -> bool:
    if not ctx.is_individual:
        return False
    return ctx.share >= thresholds.suspicious_targets.volume_share_min


def _eval_high_rate_429_share(ctx: RuleContext, thresholds: Thresholds) -> bool:
    if not ctx.is_individual:
        return False
    st = thresholds.suspicious_targets
    return (
        ctx.total_429 >= st.rate_429_total_min
        and ctx.share_429 >= st.rate_429_share_min
    )


def _eval_single_path_concentration(ctx: RuleContext, thresholds: Thresholds) -> bool:
    if not ctx.is_individual:
        return False
    st = thresholds.suspicious_targets
    if ctx.distinct_paths != 1:
        return False
    if ctx.requests < st.single_path_requests_min:
        return False
    if ctx.field == "request_path" and ctx.is_templated_catchall_path(ctx.value):
        return False
    return True


def _eval_automation_user_agent(ctx: RuleContext, thresholds: Thresholds) -> bool:  # noqa: ARG001
    # Pattern lives on the context (built once per row from the active
    # thresholds) so individual rules don't recompile per row.
    if ctx.field != "user_agent":
        return False
    return bool(ctx.automation_ua_pattern.search(ctx.value))


def _eval_new_in_window(ctx: RuleContext, thresholds: Thresholds) -> bool:  # noqa: ARG001
    if not ctx.value:
        return False
    return ctx.value not in ctx.baseline_data


def _eval_high_volume_new_actor(ctx: RuleContext, thresholds: Thresholds) -> bool:
    if ctx.field != "client_ip":
        return False
    if not ctx.value or ctx.value in ctx.baseline_data:
        return False
    st = thresholds.suspicious_targets
    return (
        ctx.share >= st.new_actor_volume_share_min
        and ctx.requests >= st.new_actor_requests_min
    )


def _eval_anomaly(ctx: RuleContext, thresholds: Thresholds) -> bool:
    if ctx.baseline_row is None:
        return False
    a = thresholds.anomaly
    baseline_requests = ctx.baseline_row.get("requests") or 0
    baseline_errors = (ctx.baseline_row.get("req_429") or 0) + (
        ctx.baseline_row.get("req_5xx") or 0
    )
    baseline_error_rate = (
        baseline_errors / baseline_requests if baseline_requests > 0 else 0.0
    )
    if baseline_error_rate <= 0:
        return False
    if ctx.current_error_rate < a.current_error_rate_min:
        return False
    if ctx.requests < a.min_requests:
        return False
    return ctx.current_error_rate / baseline_error_rate >= a.error_rate_ratio_min


BUILTIN_RULES: tuple[Rule, ...] = (
    Rule(
        name="high_volume_share",
        applies_to=_INDIVIDUAL_FIELDS,
        requires_baseline=False,
        evaluator=_eval_high_volume_share,
        description="Row's request share >= volume_share_min of in-window total.",
    ),
    Rule(
        name="high_rate_429_share",
        applies_to=_INDIVIDUAL_FIELDS,
        requires_baseline=False,
        evaluator=_eval_high_rate_429_share,
        description="Row's 429 share clears both absolute and proportional floors.",
    ),
    Rule(
        name="single_path_concentration",
        applies_to=_INDIVIDUAL_FIELDS,
        requires_baseline=False,
        evaluator=_eval_single_path_concentration,
        description="Row hit one distinct path with significant volume; CMS catch-alls suppressed.",
    ),
    Rule(
        name="automation_user_agent",
        applies_to=frozenset({"user_agent"}),
        requires_baseline=False,
        evaluator=_eval_automation_user_agent,
        description="UA string matches the automation_ua_pattern regex.",
    ),
    Rule(
        name="new_in_window",
        applies_to=frozenset({"client_ip", "user_agent", "asn", "request_path"}),
        requires_baseline=False,
        evaluator=_eval_new_in_window,
        description="Value absent from baseline-window actor data.",
    ),
    Rule(
        name="high_volume_new_actor",
        applies_to=frozenset({"client_ip"}),
        requires_baseline=False,
        evaluator=_eval_high_volume_new_actor,
        description="Lone new-in-window IP carries significant absolute volume.",
    ),
    Rule(
        name="anomaly",
        applies_to=frozenset(
            {"client_ip", "user_agent", "asn", "request_path", "cohort", "country"}
        ),
        requires_baseline=True,
        evaluator=_eval_anomaly,
        description="Current-window error rate >= N× baseline rate; absolute floors clear.",
    ),
)


# ---------------------------------------------------------------------------
# Registry. Mirrors the ``contexts.register`` pattern from Phase 6d:
# builtins seed the list, ``register_rule`` appends / replaces by name.
# ---------------------------------------------------------------------------

_RULES: list[Rule] = list(BUILTIN_RULES)


def register_rule(rule: Rule) -> None:
    """Append or replace ``rule`` in the active registry. A rule with
    the same name replaces the existing entry in-place so the iteration
    order stays predictable for tests.
    """
    for idx, existing in enumerate(_RULES):
        if existing.name == rule.name:
            _RULES[idx] = rule
            return
    _RULES.append(rule)


def active_rules() -> tuple[Rule, ...]:
    return tuple(_RULES)


def reset_to_builtins() -> None:
    """Reset the registry to ``BUILTIN_RULES``. Test-only helper."""
    _RULES[:] = list(BUILTIN_RULES)


def disabled(rule_name: str, thresholds: Thresholds | None = None) -> bool:
    """Return ``True`` when ``rule_name`` is in
    ``thresholds.disabled_rules``. ``thresholds`` falls through to
    :data:`config.DEFAULT_THRESHOLDS` when ``None`` (matches the
    fallback contract elsewhere in this package)."""
    t = thresholds if thresholds is not None else DEFAULT_THRESHOLDS
    return rule_name in t.disabled_rules
