"""Deterministic risk-band scoring and severity-ladder rendering."""

from __future__ import annotations

import sys
from pathlib import Path

# Make ``config`` (under scripts/) importable when this module is loaded
# from report_engine.contexts.incident.
_SCRIPTS_DIR = Path(__file__).resolve().parents[4]
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

from config import DEFAULT_THRESHOLDS, Thresholds, active_thresholds  # noqa: E402

from .labels import (  # noqa: E402
    CRITICALITY_TONE,
    SPIKE_FLAG_LABELS,
)

__all__ = [
    '_SEVERITY_ORDER',
    '_RISK_WEIGHTS',
    '_RISK_BANDS',
    '_SEVERITY_LADDER_STEPS',
    '_SEVERITY_LADDER_LABELS',
    '_SEVERITY_LADDER_CSS_VARS',
    '_deterministic_summary',
    '_risk_score',
    '_severity_ladder',
]


_SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "review": 2,  # v1 vocabulary, sorts with medium
    "low": 3,
}


# Backwards-compatibility imports: external callers that read
# ``_RISK_WEIGHTS`` / ``_RISK_BANDS`` directly continue to see the
# default values. Operator overrides take effect when the caller
# threads a :class:`Thresholds` instance through ``_risk_score``.
_RISK_WEIGHTS = dict(DEFAULT_THRESHOLDS.risk_score.weights)
_RISK_BANDS = dict(DEFAULT_THRESHOLDS.risk_score.bands)


_SEVERITY_LADDER_STEPS = ("low", "medium", "elevated", "high", "critical")


_SEVERITY_LADDER_LABELS = {
    "low": "Observe",
    "medium": "Monitor",
    "elevated": "Elevated",
    "high": "High",
    "critical": "Critical",
}


_SEVERITY_LADDER_CSS_VARS = {
    "low": "var(--sev-observe)",
    "medium": "var(--sev-monitor)",
    "elevated": "var(--sev-elevated)",
    "high": "var(--sev-high)",
    "critical": "var(--sev-critical)",
}


_HEADLINE_MAP = {
    "critical": "this window shows a high-severity traffic anomaly with suspicious automation indicators and warrants escalation.",
    "high": "this window shows a traffic anomaly with suspicious automation indicators.",
    "elevated": "this window shows critical-tier targets without full corroborating signal — investigate before standing down.",
    "medium": "this window shows movement worth investigating; the evidence is not yet decisive.",
    "low": "this window does not present evidence of an active incident.",
}


def _classify_severity_buckets(
    suspicious_targets: list[dict],
) -> tuple[list[dict], list[dict], list[dict], list[dict]]:
    """Return ``(critical, high, medium_or_review, low)`` partition."""
    critical = [t for t in suspicious_targets if t.get("severity") == "critical"]
    high = [t for t in suspicious_targets if t.get("severity") == "high"]
    medium = [
        t for t in suspicious_targets if t.get("severity") in ("medium", "review")
    ]
    low = [t for t in suspicious_targets if t.get("severity") == "low"]
    return critical, high, medium, low


def _critical_signal_fires(
    critical_targets: list[dict],
    spike_flags: list[str],
    raw_drilldown_available: bool,
    raw_volume_signal: bool = False,
) -> bool:
    return bool(
        critical_targets
        and ("volume_up" in spike_flags or raw_volume_signal)
        and raw_drilldown_available
    )


def _high_signal_fires(
    critical_targets: list[dict],
    high_targets: list[dict],
    spike_flags: list[str],
    raw_drilldown_available: bool,
    raw_volume_signal: bool = False,
) -> bool:
    if not (critical_targets or high_targets):
        return False
    if not raw_drilldown_available:
        return False
    return bool({"volume_up", "rate_429_up"} & set(spike_flags)) or raw_volume_signal


def _determine_incident_level(
    spike_flags: list[str],
    raw_drilldown_available: bool,
    critical_targets: list[dict],
    high_targets: list[dict],
    any_flagged: bool,
    raw_volume_signal: bool = False,
) -> str:
    """5-tier level rule. See ``_deterministic_summary`` docstring.

    `elevated` fires when critical/high targets exist but the strict
    high rule did not — typically because the required spike flag is
    absent or raw drilldown is unavailable. This is the "partial
    signal" tier the editorial ladder needs so a 4→5 promotion does
    not have to overstate the verdict.
    """
    if _critical_signal_fires(
        critical_targets, spike_flags, raw_drilldown_available, raw_volume_signal
    ):
        return "critical"
    if _high_signal_fires(
        critical_targets, high_targets, spike_flags, raw_drilldown_available,
        raw_volume_signal
    ):
        return "high"
    if critical_targets or high_targets:
        return "elevated"
    if spike_flags or any_flagged:
        return "medium"
    return "low"


def _determine_confidence(
    raw_drilldown_available: bool, edge_response_available: bool
) -> str:
    if raw_drilldown_available and edge_response_available:
        return "high"
    if raw_drilldown_available or edge_response_available:
        return "medium"
    return "low"


def _raw_fallback_volume_signal(scope_art: dict, critical_targets: list[dict]) -> bool:
    """Raw fallback can produce decisive target evidence without spike flags.

    Expedia-style captures use raw ``akamai.logs`` fallback when summary
    spike fields are unavailable. In that mode ``spike_flags`` may be
    empty even though the artifact has a large raw current window and
    many critical action targets. Treat that as corroborating volume
    evidence for the incident-level ladder only when critical targets
    already exist.
    """
    scope_meta = scope_art.get("scope") or {}
    window = scope_art.get("window_confirmation") or {}
    return bool(
        critical_targets
        and (scope_meta.get("raw_fallback_used") or window.get("source") == "raw")
        and float(window.get("requests") or 0) > 0
    )


def _named_targets(targets: list[dict]) -> str:
    return ", ".join(
        f"{t.get('target_type_label')} `{t.get('target_value')}`"
        for t in targets[:3]
    )


def _spike_flag_reason(spike_flags: list[str]) -> str | None:
    if not spike_flags:
        return None
    labelled = [SPIKE_FLAG_LABELS.get(f, f.replace("_", " ")) for f in spike_flags]
    return "spike flags fired (" + ", ".join(labelled) + ")"


def _severity_tier_reason(targets: list[dict], tier: str) -> str | None:
    if not targets:
        return None
    return f"{len(targets)} target(s) at severity:{tier} — {_named_targets(targets)}"


def _fallback_severity_reason(
    critical_targets: list[dict],
    high_targets: list[dict],
    medium_targets: list[dict],
    low_targets: list[dict],
) -> str | None:
    """When no critical/high targets fired, surface medium-or-low context."""
    if critical_targets or high_targets:
        return None
    if medium_targets:
        return (
            f"{len(medium_targets)} target(s) at severity:medium "
            "(single-dimension concentration only)"
        )
    if low_targets:
        return (
            f"{len(low_targets)} target(s) at severity:low "
            "(single weak signal, no concurrence)"
        )
    return None


def _availability_caveats(
    raw_drilldown_available: bool, edge_response_available: bool
) -> list[str]:
    caveats: list[str] = []
    if not raw_drilldown_available:
        caveats.append(
            "raw-log drilldown unavailable on this cluster, so target naming is out of reach"
        )
    if not edge_response_available:
        caveats.append(
            "no edge-response signal available (neither SIEM action class "
            "nor raw action_applied), so block coverage cannot be cross-checked"
        )
    return caveats


def _build_summary_reasons(
    spike_flags: list[str],
    critical_targets: list[dict],
    high_targets: list[dict],
    medium_targets: list[dict],
    low_targets: list[dict],
    raw_drilldown_available: bool,
    edge_response_available: bool,
) -> list[str]:
    """Name the specific signals driving the call, not a generic narration."""
    candidates: list[str | None] = [
        _spike_flag_reason(spike_flags),
        _severity_tier_reason(critical_targets, "critical"),
        _severity_tier_reason(high_targets, "high"),
        _fallback_severity_reason(
            critical_targets, high_targets, medium_targets, low_targets
        ),
    ]
    reasons: list[str] = [r for r in candidates if r]
    reasons.extend(_availability_caveats(raw_drilldown_available, edge_response_available))
    if not reasons:
        reasons.append(
            "no spike flags fired and no targets crossed the heuristic ladder"
        )
    return reasons


def _deterministic_summary(
    scope_art: dict,
    actors_art: dict,
    action_targets_art: dict,  # noqa: ARG001 (kept in signature for API stability)
    suspicious_targets: list[dict],
) -> dict:
    """Build a mechanical criticality call + reasoning sentence.

    Renders at the top of the report when no LLM-authored
    ``executive_summary`` note is supplied. The level and the text are
    derived only from the artifact data — no LLM, no opinion beyond the
    deterministic rule. The shape mirrors what the LLM contract asks
    for ("criticality, why, confidence") so a reader gets the same
    decision-relevant frame either way.

    Level rule (5 tiers — `elevated` is the v2 addition between
    `medium` and `high`):
      - ``critical`` — at least one ``severity: critical`` target AND
        ``volume_up`` fired AND raw drilldown is available. The
        critical-tier target already required multi-signal concurrence
        in the orchestrator's heuristic ladder; pairing it with a
        confirmed volume spike means the evidence is decisive.
      - ``high`` — at least one ``severity: critical`` or
        ``severity: high`` target AND one of ``volume_up`` /
        ``rate_429_up`` fired AND raw drilldown is available.
      - ``elevated`` — at least one ``severity: critical`` or
        ``severity: high`` target IS present, but the strict ``high``
        rule did not fire (e.g. the required spike flag did not fire,
        OR raw drilldown is unavailable so target naming is partial).
        Reads to operators as "the heuristic flagged dangerous
        targets, but the corroborating signal isn't quite there."
      - ``medium`` — any spike flag fired OR any flagged target (even
        if only ``severity: medium`` or ``severity: low``).
      - ``low`` — none of the above.

    Confidence rule: ``high`` when raw drilldown is available AND
    edge-response data is available; ``medium`` when one is missing;
    ``low`` when both are missing.

    "Edge-response data" means we know how the WAF/edge decided per
    request — either via the SIEM policy summary table (``actionClass``)
    OR via ``akamai.logs.action_applied`` on a canonical-schema
    cluster. The producer surfaces both paths as the same artifact
    field (``window_confirmation.blocked_share_pct``), so the
    confidence rule tracks the evidence presence, not the source
    table. Tying confidence to ``siem_available`` instead would
    artificially under-count confidence on canonical clusters where
    the edge response is carried inline on the raw log.
    """
    window = scope_art.get("window_confirmation") or {}
    spike_flags = list(window.get("spike_flags") or [])
    raw_drilldown_available = bool(actors_art.get("raw_drilldown_available"))
    edge_response_available = window.get("blocked_share_pct") is not None

    critical_targets, high_targets, medium_targets, low_targets = (
        _classify_severity_buckets(suspicious_targets)
    )
    raw_volume_signal = _raw_fallback_volume_signal(scope_art, critical_targets)

    level = _determine_incident_level(
        spike_flags, raw_drilldown_available,
        critical_targets, high_targets, bool(suspicious_targets),
        raw_volume_signal,
    )
    confidence = _determine_confidence(
        raw_drilldown_available, edge_response_available
    )
    reasons = _build_summary_reasons(
        spike_flags, critical_targets, high_targets, medium_targets, low_targets,
        raw_drilldown_available, edge_response_available,
    )

    return {
        "level": level,
        "level_label": level.title(),
        "level_tone": CRITICALITY_TONE.get(level, "observe"),
        "confidence": confidence,
        "confidence_label": confidence.title(),
        # Headlines flow after a CISA-cadence "Assessed with
        # [confidence] confidence:" prefix added in the template —
        # lowercase first letter, no leading "This window".
        "headline": _HEADLINE_MAP[level],
        "reasons": reasons,
    }


def _risk_score(
    deterministic_summary: dict,
    suspicious_targets: list[dict],
    *,
    thresholds: Thresholds | None = None,
) -> dict:
    """Compute the editorial Risk Score (0–100, **higher is worse**).

    Two-step calculation, deliberately simple so a reader can audit it
    by hand:

      1. ``raw = 100 * penalty / (50 + penalty)``, where
         ``penalty = sum(weight[sev] * count[sev])``. Weights live in
         :data:`_RISK_WEIGHTS`. A hyperbolic curve (rather than a hard
         linear sum) so genuinely catastrophic incidents still
         differentiate within the critical band instead of all
         pinning at 100:

            penalty   raw_score
                  0          0
                 30         38
                 50         50
                100         67
                200         80
                500         91
               1000         95

         The denominator (50) is calibrated so a single
         severity:critical target alone lands the raw score in the
         high band (38) before clamping; the band-clamping step then
         lifts the displayed score into agreement with the verdict
         pill.

      2. The raw score is clamped into the band for the verdict level
         (:data:`_RISK_BANDS`). This guarantees the score and the
         verdict pill point the same direction — a reader scanning
         left-to-right sees the severity ladder rise toward
         "Critical" *and* the score rise toward 100; no cognitive
         dissonance between the two visual anchors.

    Returns ``{"value": int, "value_display": "<int>/100"}``. v1
    intentionally omits a ``delta`` field — the artifact carries no
    baseline-window actor data, so a "vs prior window" comparison
    cannot be honestly computed. Adding it is deferred to Phase 3.
    """
    # Renderer-side consumers read from the active-thresholds singleton
    # (the renderer's main() primes it from --config before render()
    # runs). Producer-side callers can still pass an explicit
    # thresholds= override for unit testing or direct invocation.
    t = thresholds if thresholds is not None else active_thresholds()
    weights = t.risk_score.weights
    bands = t.risk_score.bands
    level = deterministic_summary.get("level") or "low"
    counts: dict[str, int] = {}
    for target in suspicious_targets or []:
        sev = target.get("severity") or "review"
        counts[sev] = counts.get(sev, 0) + 1
    penalty = sum(weights.get(sev, 0) * count for sev, count in counts.items())
    raw_score = 100.0 * penalty / (50.0 + penalty)
    band_min, band_max = bands.get(level, (0, 100))
    clamped = max(band_min, min(band_max, raw_score))
    return {
        "value": int(round(clamped)),
        "value_display": f"{int(round(clamped))}/100",
    }


def _severity_ladder(level: str) -> list[dict]:
    """Return the 5-step ladder descriptor for `level`.

    Each step carries:
      - ``key`` — the underlying tier name
      - ``label`` — display text (e.g. "Critical")
      - ``bar_color`` — CSS-var reference for the lit bar
      - ``on`` — True for every step at-or-below the current level
      - ``current`` — True only for the rightmost lit step

    A `level` outside the 5-tier vocabulary falls back to lighting the
    leftmost step.
    """
    try:
        cutoff = _SEVERITY_LADDER_STEPS.index(level)
    except ValueError:
        cutoff = 0
    steps: list[dict] = []
    for idx, key in enumerate(_SEVERITY_LADDER_STEPS):
        steps.append(
            {
                "key": key,
                "label": _SEVERITY_LADDER_LABELS[key],
                "bar_color": _SEVERITY_LADDER_CSS_VARS[key],
                "on": idx <= cutoff,
                "current": idx == cutoff,
            }
        )
    return steps
