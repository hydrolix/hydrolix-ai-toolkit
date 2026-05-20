"""Threshold configuration layer for the Bot Insights heuristics + renderer caps.

Provides a typed :class:`Thresholds` aggregate that bundles every operator-
tunable knob the heuristic ladder, the risk-band scorer, and the renderer's
display caps read. The producer-side consumers thread an explicit
``thresholds`` argument through their evaluator signatures
(see ``producers/suspicious_targets/ladder.py``); the renderer-side
display caps fall through a process-wide singleton (``active_thresholds()``)
so the existing ``prepare(artifact: dict) -> dict`` shape stays unchanged.

Default behaviour matches the heuristic constants that landed in Phase 1 of
the refactor (`10ebf42`), with additive report enrichments enabled where a
packaged local data snapshot is available.

The loader auto-detects file format by suffix:
  - ``.yaml`` / ``.yml`` — soft dep on ``pyyaml`` (raises a clear
    SystemExit if invoked without it installed; the default path is
    zero-dep).
  - ``.toml`` — uses the stdlib :mod:`tomllib` (Python 3.11+).
  - ``.json`` — uses the stdlib :mod:`json`.

YAML / TOML / JSON keys overlay onto the default :class:`Thresholds`
shape; any key omitted from the config falls through to its default.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, fields, replace
from pathlib import Path
from typing import Any, Mapping


__all__ = [
    "SuspiciousTargetsThresholds",
    "AnomalyThresholds",
    "RiskScoreThresholds",
    "DisplayCaps",
    "AsReputationConfig",
    "BrowserVersionHistoryConfig",
    "Thresholds",
    "DEFAULT_THRESHOLDS",
    "load_thresholds",
    "active_thresholds",
    "set_active_thresholds",
]


# Mirrors heuristics.py:66 — kept here so the dataclass can carry the
# canonical default UA pattern without circular imports.
_DEFAULT_AUTOMATION_UA_PATTERN = (
    r"\b(curl|python-requests|Go-http-client|wget|libwww|httpx|aiohttp)\b"
)
_DEFAULT_BROWSER_VERSION_HISTORY_PATH = (
    Path(__file__).resolve().parents[1] / "data" / "browser-version-history.json"
)


@dataclass(frozen=True)
class SuspiciousTargetsThresholds:
    """Share / volume / cluster floors for the suspicious-target ladder.

    Field defaults match the ``_SUSPICIOUS_*`` constants in
    ``heuristics.py`` exactly; calibration narrative for each value lives
    in that module's docstring.
    """

    volume_share_min: float = 0.05
    rate_429_share_min: float = 0.10
    rate_429_total_min: float = 100
    single_path_requests_min: float = 1000
    asn_cluster_min_ips: int = 3
    botnet_cluster_share_min: float = 0.005
    new_actor_volume_share_min: float = 0.001
    new_actor_requests_min: float = 1_000_000
    automation_ua_pattern: str = _DEFAULT_AUTOMATION_UA_PATTERN


@dataclass(frozen=True)
class AnomalyThresholds:
    """Baseline-rate departure thresholds for the ``anomaly`` flag.

    Field defaults match ``_ANOMALY_*`` constants in ``heuristics.py``.
    """

    error_rate_ratio_min: float = 3.0
    current_error_rate_min: float = 0.05
    min_requests: float = 1000


@dataclass(frozen=True)
class RiskScoreThresholds:
    """Risk-score weights + bands for ``contexts/incident/risk.py``.

    Field defaults match ``_RISK_WEIGHTS`` / ``_RISK_BANDS``.
    """

    weights: Mapping[str, int] = field(
        default_factory=lambda: {
            "critical": 30,
            "high": 15,
            "elevated": 8,
            "medium": 4,
            "review": 4,  # v1 vocabulary, weighted with medium
            "low": 1,
        }
    )
    bands: Mapping[str, tuple[int, int]] = field(
        default_factory=lambda: {
            "critical": (75, 100),
            "high": (50, 74),
            "elevated": (35, 49),
            "medium": (20, 34),
            "low": (0, 19),
        }
    )


@dataclass(frozen=True)
class DisplayCaps:
    """Renderer-side row caps. Read through ``active_thresholds()``."""

    suspicious_targets_cap: int = 10
    exec_actions_cap: int = 5
    exec_impact_tiles_cap: int = 5


@dataclass(frozen=True)
class AsReputationConfig:
    """Optional AS reputation enrichment sources for incident reports."""

    enabled: bool = True
    spamhaus_asndrop_path: str | None = None
    local_overrides_path: str | None = None


@dataclass(frozen=True)
class BrowserVersionHistoryConfig:
    """Optional local browser release-history snapshot for incident reports."""

    enabled: bool = True
    snapshot_path: str | None = str(_DEFAULT_BROWSER_VERSION_HISTORY_PATH)
    stale_months: int = 18


@dataclass(frozen=True)
class Thresholds:
    """Top-level aggregate. Single value plumbed through producers + renderers."""

    suspicious_targets: SuspiciousTargetsThresholds = field(
        default_factory=SuspiciousTargetsThresholds
    )
    anomaly: AnomalyThresholds = field(default_factory=AnomalyThresholds)
    risk_score: RiskScoreThresholds = field(default_factory=RiskScoreThresholds)
    display: DisplayCaps = field(default_factory=DisplayCaps)
    as_reputation: AsReputationConfig = field(default_factory=AsReputationConfig)
    browser_version_history: BrowserVersionHistoryConfig = field(
        default_factory=BrowserVersionHistoryConfig
    )
    disabled_rules: frozenset[str] = frozenset()


DEFAULT_THRESHOLDS = Thresholds()


# ---------------------------------------------------------------------------
# Process-wide singleton — feeds the renderer's display-cap consumers
# without forcing every ``prepare()`` to grow a thresholds kwarg.
# ---------------------------------------------------------------------------

_ACTIVE_THRESHOLDS: Thresholds = DEFAULT_THRESHOLDS


def active_thresholds() -> Thresholds:
    return _ACTIVE_THRESHOLDS


def set_active_thresholds(thresholds: Thresholds) -> None:
    global _ACTIVE_THRESHOLDS
    _ACTIVE_THRESHOLDS = thresholds


# ---------------------------------------------------------------------------
# Loader.
# ---------------------------------------------------------------------------


def load_thresholds(path: Path | None = None) -> Thresholds:
    """Load thresholds from ``path``; return :data:`DEFAULT_THRESHOLDS` when
    ``path`` is ``None``.

    The file's top-level keys overlay onto the dataclass shape. Any key
    omitted falls through to its dataclass default.
    """
    if path is None:
        return DEFAULT_THRESHOLDS
    config_path = Path(path)
    raw = _read_config_file(config_path)
    return _resolve_config_relative_paths(
        _overlay(DEFAULT_THRESHOLDS, raw),
        config_path.parent,
    )


def _read_config_file(path: Path) -> Mapping[str, Any]:
    suffix = path.suffix.lower()
    if suffix in (".yaml", ".yml"):
        return _read_yaml(path)
    if suffix == ".toml":
        return _read_toml(path)
    if suffix == ".json":
        return json.loads(path.read_text())
    raise SystemExit(
        f"Unsupported --config file extension {suffix!r}; "
        "use .yaml, .yml, .toml, or .json."
    )


def _read_yaml(path: Path) -> Mapping[str, Any]:
    try:
        import yaml  # type: ignore[import-not-found]
    except (
        ImportError
    ) as exc:  # pragma: no cover - exercised in CI environments without pyyaml
        raise SystemExit(
            f"--config {path} requires pyyaml. Install it (`uv pip install pyyaml`) "
            "or supply the override as JSON / TOML instead."
        ) from exc
    return yaml.safe_load(path.read_text()) or {}


def _read_toml(path: Path) -> Mapping[str, Any]:
    import tomllib

    with path.open("rb") as handle:
        return tomllib.load(handle)


# ---------------------------------------------------------------------------
# Overlay merge — turn a nested-dict config into a Thresholds replace().
# ---------------------------------------------------------------------------


def _overlay(base: Thresholds, raw: Mapping[str, Any]) -> Thresholds:
    """Overlay nested-dict overrides onto ``base``.

    Keys are flexible — the loader accepts both the canonical layout
    (``heuristics.suspicious_targets.volume_share_min``) and the flat
    field names so analyst-authored YAML can stay terse.
    """
    heuristics = (raw.get("heuristics") or {}) if isinstance(raw, dict) else {}
    display = (raw.get("display") or {}) if isinstance(raw, dict) else {}
    return replace(
        base,
        suspicious_targets=_overlay_dc(
            base.suspicious_targets,
            heuristics.get("suspicious_targets") or {},
        ),
        anomaly=_overlay_dc(base.anomaly, heuristics.get("anomaly") or {}),
        risk_score=_overlay_risk(base.risk_score, heuristics.get("risk_score") or {}),
        display=_overlay_dc(base.display, display),
        as_reputation=_overlay_dc(
            base.as_reputation,
            raw.get("as_reputation") or {},
        ),
        browser_version_history=_overlay_dc(
            base.browser_version_history,
            raw.get("browser_version_history") or {},
        ),
        disabled_rules=frozenset(heuristics.get("disabled_rules") or []),
    )


def _resolve_config_relative_paths(
    thresholds: Thresholds,
    config_dir: Path,
) -> Thresholds:
    as_rep = thresholds.as_reputation
    updates = {}
    for field_name in ("spamhaus_asndrop_path", "local_overrides_path"):
        value = getattr(as_rep, field_name)
        if not value:
            continue
        p = Path(value)
        updates[field_name] = str(p if p.is_absolute() else config_dir / p)
    if not updates:
        resolved = thresholds
    else:
        resolved = replace(thresholds, as_reputation=replace(as_rep, **updates))

    browser_history = resolved.browser_version_history
    snapshot_path = browser_history.snapshot_path
    if not snapshot_path:
        return resolved
    p = Path(snapshot_path)
    return replace(
        resolved,
        browser_version_history=replace(
            browser_history,
            snapshot_path=str(p if p.is_absolute() else config_dir / p),
        ),
    )


def _overlay_dc(instance, overrides: Mapping[str, Any]):
    if not overrides:
        return instance
    known = {f.name for f in fields(instance)}
    payload = {k: v for k, v in overrides.items() if k in known}
    if not payload:
        return instance
    if "automation_ua_pattern" in payload:
        # Compile-test now so loader-time mistakes surface here, not
        # mid-evaluation when the pattern is first applied.
        re.compile(str(payload["automation_ua_pattern"]))
    return replace(instance, **payload)


def _overlay_risk(
    instance: RiskScoreThresholds, overrides: Mapping[str, Any]
) -> RiskScoreThresholds:
    if not overrides:
        return instance
    weights = dict(instance.weights)
    if overrides.get("weights"):
        weights.update(overrides["weights"])
    bands = dict(instance.bands)
    if overrides.get("bands"):
        for level, span in overrides["bands"].items():
            bands[level] = tuple(span)  # JSON / YAML may yield list
    return RiskScoreThresholds(weights=weights, bands=bands)
