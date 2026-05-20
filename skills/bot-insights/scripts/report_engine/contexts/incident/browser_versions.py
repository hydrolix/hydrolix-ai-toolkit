"""Browser user-agent age context for incident reports.

The renderer consumes only a configured local snapshot. Snapshot rows use:
``family``, ``major_version``, ``release_date``, ``channel``,
``source_name``, and ``source_url``.

Suggested refresh sources:
  - Chrome VersionHistory API: https://versionhistory.googleapis.com/v1
  - Firefox Product Details release data:
    https://docs.telemetry.mozilla.org/datasets/releases
  - Microsoft Edge release schedule:
    https://learn.microsoft.com/en-us/deployedge/microsoft-edge-release-schedule
  - Safari Release Notes:
    https://developer.apple.com/documentation/safari-release-notes
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

_SCRIPTS_DIR = Path(__file__).resolve().parents[4]
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

from config import active_thresholds  # noqa: E402

from .formatters import _format_count, _format_pct, _safe_number

__all__ = [
    "build_browser_version_context",
    "load_browser_version_snapshot",
    "parse_browser_user_agent",
]


_TOKEN_PATTERNS = (
    ("Edge", re.compile(r"\bEdg(?:e|A|iOS)?/(\d+)", re.I)),
    ("Firefox", re.compile(r"\bFirefox/(\d+)", re.I)),
    ("Chrome", re.compile(r"\b(?:Chrome|CriOS)/(\d+)", re.I)),
    ("Safari", re.compile(r"\bVersion/(\d+)(?:\.\d+)*\s+Safari/", re.I)),
)


@dataclass(frozen=True)
class BrowserToken:
    family: str
    major_version: int | None
    label: str
    caveat: str | None = None


def parse_browser_user_agent(user_agent: str) -> dict[str, Any]:
    """Parse browser family/version with deterministic precedence."""
    ua = str(user_agent or "")
    for family, pattern in _TOKEN_PATTERNS:
        match = pattern.search(ua)
        if not match:
            continue
        caveat = None
        label = family
        if family == "Chrome":
            label = "Chrome/Chromium token"
            caveat = (
                "Chromium-compatible clients can expose a Chrome token; "
                "age uses Chrome milestone release history."
            )
        return {
            "family": family,
            "major_version": int(match.group(1)),
            "label": label,
            "caveat": caveat,
        }
    return {
        "family": "Unknown",
        "major_version": None,
        "label": "Unknown browser family",
        "caveat": "No supported browser version token was found.",
    }


def load_browser_version_snapshot(path: str | Path | None) -> list[dict[str, Any]]:
    """Read a local browser-version snapshot.

    JSON may be either a list of rows or ``{"rows": [...]}``. YAML/TOML
    support is best-effort to match the threshold config loader.
    """
    if not path:
        return []
    p = Path(path)
    if not p.exists():
        return []
    suffix = p.suffix.lower()
    if suffix == ".json":
        payload = json.loads(p.read_text())
    elif suffix in {".yaml", ".yml"}:
        try:
            import yaml  # type: ignore[import-not-found]
        except ImportError:
            return []
        payload = yaml.safe_load(p.read_text()) or {}
    elif suffix == ".toml":
        import tomllib

        with p.open("rb") as handle:
            payload = tomllib.load(handle)
    else:
        return []
    if isinstance(payload, list):
        rows = payload
    else:
        rows = payload.get("rows") or []
    return [row for row in rows if isinstance(row, dict)]


def _parse_date(value: Any) -> date | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).date()
    except ValueError:
        try:
            return date.fromisoformat(str(value)[:10])
        except ValueError:
            return None


def _as_of_date(scope_meta: dict[str, Any]) -> date:
    end = _parse_date(scope_meta.get("end"))
    if end:
        return end
    return datetime.now(timezone.utc).date()


def _snapshot_index(rows: list[dict[str, Any]]) -> dict[tuple[str, int], dict[str, Any]]:
    indexed: dict[tuple[str, int], dict[str, Any]] = {}
    for row in rows:
        family = str(row.get("family") or "").strip().lower()
        major = _safe_number(row.get("major_version"))
        release_date = _parse_date(row.get("release_date"))
        if not family or major is None or release_date is None:
            continue
        channel = str(row.get("channel") or "stable").strip().lower()
        key = (family, int(major))
        current = indexed.get(key)
        # Prefer stable rows; otherwise keep the earliest known release date.
        if current is None or (
            channel == "stable"
            and str(current.get("channel") or "").lower() != "stable"
        ) or release_date < current["_release_date"]:
            indexed[key] = {**row, "_release_date": release_date}
    return indexed


def _age_phrase(age_days: int) -> str:
    if age_days < 45:
        return f"{age_days} days old"
    months = round(age_days / 30.4375)
    if months < 24:
        return f"{months} months old"
    years = age_days / 365.25
    return f"{years:.1f} years old"


def _lookup_age(
    parsed: dict[str, Any],
    snapshot: dict[tuple[str, int], dict[str, Any]],
    as_of: date,
    stale_days: int,
) -> dict[str, Any]:
    family = str(parsed.get("family") or "")
    major = parsed.get("major_version")
    if family == "Unknown" or major is None:
        return {
            "status": "unknown",
            "status_label": "Age unknown",
            "age_days": None,
            "age_display": "age unknown",
            "stale": False,
            "source_name": "",
            "source_url": "",
            "release_date": "",
        }
    snap = snapshot.get((family.lower(), int(major)))
    if not snap:
        return {
            "status": "unknown",
            "status_label": "Age unknown",
            "age_days": None,
            "age_display": "age unknown",
            "stale": False,
            "source_name": "",
            "source_url": "",
            "release_date": "",
        }
    release_date = snap["_release_date"]
    age_days = max(0, (as_of - release_date).days)
    stale = age_days >= stale_days
    return {
        "status": "stale" if stale else "recent",
        "status_label": "Stale" if stale else "Recent",
        "age_days": age_days,
        "age_display": _age_phrase(age_days),
        "stale": stale,
        "source_name": snap.get("source_name") or "",
        "source_url": snap.get("source_url") or "",
        "release_date": release_date.isoformat(),
    }


def _ranking_rows(actors_art: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for ranking in actors_art.get("actor_rankings") or []:
        if ranking.get("field") == "user_agent":
            rows.extend(ranking.get("rows") or [])
    return rows


def _row_requests(row: dict[str, Any]) -> float:
    return max(float(_safe_number(row.get("requests")) or 0), 0.0)


def _target_requests(target: dict[str, Any]) -> float:
    supporting = target.get("supporting") or {}
    return max(float(_safe_number(supporting.get("requests")) or 0), 0.0)


def _target_share(target: dict[str, Any], total_requests: float) -> float | None:
    supporting = target.get("supporting") or {}
    share = _safe_number(supporting.get("share_pct"))
    if share is not None:
        return float(share)
    requests = _target_requests(target)
    if total_requests > 0:
        return 100.0 * requests / total_requests
    return None


def _comparison_share(row: dict[str, Any], total_requests: float) -> float | None:
    share = _safe_number(row.get("share_pct"))
    if share is not None:
        return float(share)
    requests = _row_requests(row)
    if total_requests > 0:
        return 100.0 * requests / total_requests
    return None


def _decorate_ua_row(
    user_agent: str,
    *,
    requests: float,
    share_pct: float | None,
    baseline_delta_pct: Any,
    snapshot: dict[tuple[str, int], dict[str, Any]],
    as_of: date,
    stale_days: int,
) -> dict[str, Any]:
    parsed = parse_browser_user_agent(user_agent)
    age = _lookup_age(parsed, snapshot, as_of, stale_days)
    return {
        "user_agent": user_agent,
        "browser_family": parsed["family"],
        "browser_label": parsed["label"],
        "major_version": parsed["major_version"],
        "version_display": (
            str(parsed["major_version"]) if parsed["major_version"] is not None else "unknown"
        ),
        "token_caveat": parsed["caveat"],
        "requests": requests,
        "requests_display": _format_count(requests),
        "share_pct": share_pct,
        "share_pct_display": _format_pct(share_pct) if share_pct is not None else "—",
        "baseline_delta_display": (
            _format_pct(baseline_delta_pct)
            if _safe_number(baseline_delta_pct) is not None
            else "—"
        ),
        **age,
    }


def build_browser_version_context(
    actors_art: dict[str, Any],
    suspicious_targets: list[dict[str, Any]],
    scope_meta: dict[str, Any],
) -> dict[str, Any]:
    cfg = active_thresholds().browser_version_history
    if not cfg.enabled:
        return {"available": False, "rows": [], "comparison_rows": []}

    snapshot_rows = load_browser_version_snapshot(cfg.snapshot_path)
    snapshot = _snapshot_index(snapshot_rows)
    as_of = _as_of_date(scope_meta)
    stale_days = int(round(max(cfg.stale_months, 1) * 30.4375))
    total_requests = float(
        _safe_number((actors_art.get("scope") or {}).get("requests")) or 0
    )
    ranking_rows = _ranking_rows(actors_art)
    if total_requests <= 0:
        total_requests = sum(_row_requests(row) for row in ranking_rows)

    flagged: list[dict[str, Any]] = []
    flagged_values: set[str] = set()
    for target in suspicious_targets or []:
        if target.get("target_type") != "user_agent":
            continue
        ua = str(target.get("target_value") or "")
        if not ua:
            continue
        flagged_values.add(ua)
        flagged.append(
            _decorate_ua_row(
                ua,
                requests=_target_requests(target),
                share_pct=_target_share(target, total_requests),
                baseline_delta_pct=(target.get("supporting") or {}).get(
                    "delta_vs_baseline_pct"
                ),
                snapshot=snapshot,
                as_of=as_of,
                stale_days=stale_days,
            )
        )

    comparison: list[dict[str, Any]] = []
    for row in sorted(ranking_rows, key=lambda r: (-_row_requests(r), str(r.get("value") or ""))):
        ua = str(row.get("value") or "")
        if not ua or ua in flagged_values:
            continue
        comparison.append(
            _decorate_ua_row(
                ua,
                requests=_row_requests(row),
                share_pct=_comparison_share(row, total_requests),
                baseline_delta_pct=row.get("delta_vs_baseline_pct"),
                snapshot=snapshot,
                as_of=as_of,
                stale_days=stale_days,
            )
        )
        if len(comparison) >= 3:
            break

    return {
        "available": bool(flagged),
        "rows": flagged,
        "comparison_rows": comparison,
        "stale_rows": [row for row in flagged if row["stale"]],
        "unknown_rows": [row for row in flagged if row["status"] == "unknown"],
        "as_of": as_of.isoformat(),
        "stale_threshold_months": cfg.stale_months,
        "snapshot_configured": bool(cfg.snapshot_path),
        "snapshot_row_count": len(snapshot_rows),
        "boundary": (
            "Browser age is context only. Older UA tokens are consistent with "
            "intentionally configured, pinned, spoofed, or non-updating clients; "
            "they are not proof of operator intent or classification bypass."
        ),
    }
