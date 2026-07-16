"""User-agent plausibility scoring for ``bot_threat_hunt.v3`` leads."""

from __future__ import annotations

import json
import math
import re
from collections import Counter
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

from config import active_thresholds


_TOKEN_PATTERNS = (
    ("Edge", re.compile(r"\bEdg(?:e|A|iOS)?/(\d+(?:\.\d+){0,3})", re.I)),
    ("Firefox", re.compile(r"\bFirefox/(\d+(?:\.\d+){0,3})", re.I)),
    ("Chrome", re.compile(r"\b(?:Chrome|CriOS|Chromium)/(\d+(?:\.\d+){0,3})", re.I)),
    ("Safari", re.compile(r"\bVersion/(\d+(?:\.\d+){0,3})\s+Safari/", re.I)),
)


def _num(value: Any, default: float = 0.0) -> float:
    if value is None or value == "":
        return default
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    if math.isnan(number) or math.isinf(number):
        return default
    return number


def _parse_date(value: Any) -> date | None:
    if not value:
        return None
    raw = str(value).strip().replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(raw).date()
    except ValueError:
        try:
            return date.fromisoformat(raw[:10])
        except ValueError:
            return None


def _load_snapshot_rows() -> list[dict[str, Any]]:
    cfg = active_thresholds().browser_version_history
    if not cfg.enabled or not cfg.snapshot_path:
        return []
    path = Path(cfg.snapshot_path)
    if not path.exists():
        return []
    payload = json.loads(path.read_text(encoding="utf-8"))
    rows = payload.get("rows") if isinstance(payload, dict) else payload
    return [row for row in rows or [] if isinstance(row, dict)]


def _stable_major_as_of(
    rows: list[dict[str, Any]], family: str, as_of: date
) -> dict[str, Any] | None:
    candidates = []
    for row in rows:
        if str(row.get("family") or "").lower() != family.lower():
            continue
        if str(row.get("channel") or "stable").lower() != "stable":
            continue
        released = _parse_date(row.get("release_date"))
        if released is None or released > as_of:
            continue
        try:
            major = int(row.get("major_version"))
        except (TypeError, ValueError):
            continue
        candidates.append((major, released, row))
    if not candidates:
        return None
    major, released, row = max(candidates, key=lambda item: (item[0], item[1]))
    return {**row, "major_version": major, "_release_date": released}


def parse_user_agent(user_agent: str) -> dict[str, Any]:
    ua = str(user_agent or "")
    ua_lower = ua.lower()
    browser_family = "Unknown"
    browser_version = None
    browser_major = None
    for family, pattern in _TOKEN_PATTERNS:
        match = pattern.search(ua)
        if not match:
            continue
        browser_family = family
        browser_version = match.group(1)
        try:
            browser_major = int(browser_version.split(".", 1)[0])
        except ValueError:
            browser_major = None
        break

    platform = "unknown"
    if "Android" in ua:
        platform = "Android"
    elif "iPhone" in ua or "iPad" in ua:
        platform = "iOS"
    elif "Mac OS X" in ua or "Macintosh" in ua:
        platform = "macOS"
    elif "Windows" in ua:
        platform = "Windows"
    elif "Linux" in ua or "X11" in ua:
        platform = "Linux"

    device_class = "mobile" if re.search(r"\b(Mobile|Android|iPhone|iPad)\b", ua) else "desktop"
    if "iPad" in ua or "Tablet" in ua:
        device_class = "tablet"
    client_family = browser_family
    ua_class = "browser" if browser_family != "Unknown" else "unknown"
    if ua_class == "unknown":
        first_party_match = re.match(r"\s*(Expedia|Vrbo|Hotels\.com)/", ua, re.I)
        if first_party_match and "cfnetwork" in ua_lower:
            ua_class = "first_party_native_app"
            client_family = first_party_match.group(1)
            if platform == "unknown":
                platform = "iOS"
            device_class = "mobile"
        elif re.search(r"\bokhttp/", ua, re.I) or re.search(r"\bDalvik/", ua, re.I):
            ua_class = "http_client_library"
            client_family = "okhttp" if re.search(r"\bokhttp/", ua, re.I) else "Dalvik"
            if platform == "unknown" and ("Dalvik/" in ua or "Android" in ua):
                platform = "Android"
            device_class = "mobile" if platform == "Android" else "unknown"
        elif "cfnetwork" in ua_lower:
            ua_class = "native_sdk"
            client_family = "CFNetwork"
            if platform == "unknown":
                platform = "iOS"
            device_class = "mobile"

    return {
        "browser_family": browser_family,
        "browser_major": browser_major,
        "browser_version": browser_version,
        "platform": platform,
        "device_class": device_class,
        "ua_class": ua_class,
        "client_family": client_family,
    }


def _signal(status: str, score: float, **fields: Any) -> dict[str, Any]:
    return {"status": status, "score": round(score, 3), **fields}


def _version_currency(
    parsed: dict[str, Any], *, as_of: date, snapshot_rows: list[dict[str, Any]]
) -> dict[str, Any]:
    family = str(parsed.get("browser_family") or "Unknown")
    major = parsed.get("browser_major")
    if family == "Unknown" or major is None:
        return _signal("unavailable", 0.0, reason="unsupported_browser_token")
    stable = _stable_major_as_of(snapshot_rows, family, as_of)
    if stable is None:
        return _signal("unavailable", 0.0, reason="no_stable_history", browser_family=family)
    stable_major = int(stable["major_version"])
    delta = int(major) - stable_major
    if delta > 1:
        return _signal(
            "future_dated",
            1.0,
            browser_family=family,
            claimed_major=major,
            stable_major_as_of=stable_major,
            release_date_as_of=str(stable.get("release_date") or ""),
        )
    if delta >= -2:
        return _signal("current_or_recent", 0.0, claimed_major=major, stable_major_as_of=stable_major)
    if delta >= -8:
        return _signal("older_but_plausible", 0.15, claimed_major=major, stable_major_as_of=stable_major)
    return _signal("stale", 0.25, claimed_major=major, stable_major_as_of=stable_major)


def _structural(user_agent: str, parsed: dict[str, Any]) -> dict[str, Any]:
    ua = str(user_agent or "")
    checks: list[str] = []
    version = str(parsed.get("browser_version") or "")
    family = str(parsed.get("browser_family") or "")
    platform = str(parsed.get("platform") or "")
    device = str(parsed.get("device_class") or "")

    if re.search(r"Android 10;\s*K[;\)]", ua):
        checks.append("android_10_k_anachronism")
    if version and re.fullmatch(r"\d+\.0\.0\.0", version):
        checks.append("zero_point_version")
    if family == "Edge" and platform == "macOS" and parsed.get("browser_major"):
        checks.append("edge_on_mac_with_future_version")
    if family in {"Chrome", "Edge"} and "Safari/" not in ua:
        checks.append("missing_chrome_compatible_safari_token")
    if platform == "Android" and device == "desktop":
        checks.append("android_mobile_desktop_token_mismatch")
    if platform in {"Windows", "macOS", "Linux"} and "Mobile Safari" in ua and "iPhone" not in ua and "Android" not in ua:
        checks.append("desktop_platform_mobile_safari_mismatch")

    if not checks:
        return _signal("normal", 0.0, checks=[])
    score = 0.25
    if "android_10_k_anachronism" in checks:
        score = max(score, 0.35)
    if "missing_chrome_compatible_safari_token" in checks:
        score = max(score, 0.5)
    if "edge_on_mac_with_future_version" in checks:
        score = max(score, 0.6)
    if any("mismatch" in check for check in checks):
        score = max(score, 0.4)
    return _signal("anomalous", score, checks=checks)


def _fanout(
    parsed: dict[str, Any],
    *,
    user_agent: str,
    fanout_by_ua: dict[str, dict[str, Any]],
    fallback_unique_ips: Any,
) -> dict[str, Any]:
    row = fanout_by_ua.get(user_agent)
    source = "summary_hour"
    if row:
        source = str(row.get("source") or source)
        unique_ips = _num(row.get("unique_ips") if row.get("unique_ips") is not None else row.get("unique_client_ips"))
        requests = _num(row.get("hits") if row.get("hits") is not None else row.get("requests"))
        probe_window_hours = _num(row.get("probe_window_hours"), 0.0) or None
    else:
        source = "cooccurrence_lower_bound" if fallback_unique_ips is not None else "unavailable"
        unique_ips = _num(fallback_unique_ips)
        requests = 0.0
        probe_window_hours = None
    if source == "unavailable" or unique_ips <= 0:
        return _signal(
            "unavailable",
            0.0,
            source=source,
            unique_ips=None,
            unique_client_ips=None,
            effective_ips=None,
            requests=None,
            threshold_class="unavailable",
            caveat="Fan-out enrichment was not available.",
        )

    family = str(parsed.get("browser_family") or "")
    device = str(parsed.get("device_class") or "")
    ua_class = str(parsed.get("ua_class") or "unknown")
    if ua_class == "browser":
        strong_threshold = 100_000 if device in {"mobile", "tablet"} or family == "Safari" else 50_000
        elevated_threshold = strong_threshold / 5
    elif ua_class == "first_party_native_app":
        strong_threshold = 5_000_000
        elevated_threshold = 250_000
    elif ua_class == "http_client_library":
        strong_threshold = 1_000_000
        elevated_threshold = 100_000
    elif ua_class == "native_sdk":
        strong_threshold = 2_500_000
        elevated_threshold = 250_000
    else:
        strong_threshold = 100_000
        elevated_threshold = 20_000
    if source == "logs_probe":
        effective_ips = unique_ips * min((probe_window_hours or 1.0) * 3.0, 24.0)
        caveat = (
            f"Peak-hour raw-log probe observed {int(unique_ips):,} IPs; "
            f"effective IPs use a conservative bounded lower-bound estimate over {probe_window_hours or 1:g} hour(s)."
        )
    elif source == "cooccurrence_lower_bound":
        effective_ips = unique_ips
        caveat = (
            f"Existing cooccurrence evidence observed at least {int(unique_ips):,} IPs; "
            "true full-window fan-out is unknown and no extrapolation is applied."
        )
    else:
        effective_ips = unique_ips
        caveat = f"Full-window summary-hour fan-out observed {int(unique_ips):,} unique IPs for this byte-identical UA."
    if effective_ips >= strong_threshold:
        status = "strong_shared_exact_ua" if ua_class == "browser" else f"strong_{ua_class}_fanout"
        score = 1.0 if ua_class == "browser" else 0.6 if ua_class == "first_party_native_app" else 0.45
        threshold_class = "strong"
    elif effective_ips >= elevated_threshold:
        status = "elevated_shared_exact_ua" if ua_class == "browser" else f"normal_{ua_class}_scale_distribution"
        score = 0.45 if ua_class == "browser" else 0.15 if ua_class == "first_party_native_app" else 0.25
        threshold_class = "elevated"
    else:
        status = "normal"
        score = 0.0
        threshold_class = "normal"
    return _signal(
        status,
        score,
        source=source,
        unique_ips=int(unique_ips),
        unique_client_ips=int(unique_ips),
        effective_ips=int(effective_ips),
        requests=int(requests) if requests else None,
        hits=int(requests) if requests else None,
        probe_window_hours=probe_window_hours,
        threshold_class=threshold_class,
        caveat=caveat,
        strong_threshold=strong_threshold,
        elevated_threshold=elevated_threshold,
        ua_class=ua_class,
    )


def _homogeneity(
    parsed: dict[str, Any],
    *,
    family_request_totals: Counter[str],
    total_requests: float,
    browser_fingerprint_count: int,
) -> dict[str, Any]:
    family = str(parsed.get("browser_family") or "Unknown")
    if family == "Unknown" or total_requests <= 0 or browser_fingerprint_count < 3:
        return _signal("unavailable", 0.0, browser_family=family)
    share = family_request_totals.get(family, 0.0) / total_requests
    if share > 0.9:
        status, score = "monoculture", 0.35
    elif share > 0.6:
        status, score = "homogeneous", 0.25
    else:
        status, score = "diverse", 0.0
    return _signal(status, score, browser_family=family, family_share=round(share, 4))


def _trigger_reason(
    user_agent: str,
    parsed: dict[str, Any],
    signals: dict[str, dict[str, Any]],
    as_of: date,
) -> str:
    version = signals["version_currency"]
    fanout = signals["fanout"]
    structural = signals["structural"]
    if version["status"] == "future_dated":
        return (
            f"Future-dated {parsed.get('browser_family')}/{parsed.get('browser_major')} "
            f"for {as_of.isoformat()} window"
        )
    if fanout["status"] == "strong_shared_exact_ua":
        ips = int(_num(fanout.get("effective_ips") or fanout.get("unique_client_ips")))
        platform = str(parsed.get("device_class") or parsed.get("ua_class") or "browser")
        family = str(parsed.get("browser_family") or "browser")
        return f"{ips:,}+ IPs shared one byte-identical {platform} {family} UA"
    if str(fanout.get("status") or "").startswith("strong_"):
        ips = int(_num(fanout.get("effective_ips") or fanout.get("unique_client_ips")))
        ua_class = str(parsed.get("ua_class") or "non_browser").replace("_", " ")
        family = str(parsed.get("client_family") or ua_class)
        return f"{ips:,}+ IPs shared one byte-identical {ua_class} {family} UA"
    checks = structural.get("checks") or []
    if checks:
        return "Structural UA anomaly: " + ", ".join(str(check) for check in checks[:3])
    return f"UA plausibility elevated for {user_agent[:80]}"


def score_ua_plausibility(
    *,
    user_agent: str,
    window_end: datetime,
    fanout_by_ua: dict[str, dict[str, Any]],
    fallback_unique_ips: Any,
    family_request_totals: Counter[str],
    total_family_requests: float,
    browser_fingerprint_count: int,
    source: str,
) -> dict[str, Any]:
    as_of = window_end.astimezone(timezone.utc).date()
    parsed = parse_user_agent(user_agent)
    snapshot_rows = _load_snapshot_rows()
    signals = {
        "version_currency": _version_currency(parsed, as_of=as_of, snapshot_rows=snapshot_rows),
        "fanout": _fanout(
            parsed,
            user_agent=user_agent,
            fanout_by_ua=fanout_by_ua,
            fallback_unique_ips=fallback_unique_ips,
        ),
        "homogeneity": _homogeneity(
            parsed,
            family_request_totals=family_request_totals,
            total_requests=total_family_requests,
            browser_fingerprint_count=browser_fingerprint_count,
        ),
        "structural": _structural(user_agent, parsed),
    }
    composite = min(1.0, sum(_num(signal.get("score")) for signal in signals.values()))
    strong_single = any(
        signals[name]["score"] >= 1.0
        or signals[name]["status"] in {"future_dated", "strong_shared_exact_ua"}
        for name in ("version_currency", "fanout", "structural")
    )
    counts_for_verdict = bool(composite >= 0.6 or strong_single)
    weak = bool(0.3 <= composite < 0.6)
    if counts_for_verdict:
        verdict = "confirmed"
    elif weak:
        verdict = "elevated"
    elif any(signal["status"] != "unavailable" for signal in signals.values()):
        verdict = "inconclusive"
    else:
        verdict = "unavailable"
    trigger = _trigger_reason(user_agent, parsed, signals, as_of) if counts_for_verdict or weak else None
    return {
        "parsed": parsed,
        "signals": signals,
        "composite_score": round(composite, 3),
        "verdict": verdict,
        "trigger_reason": trigger,
        "fired_structural_checks": signals["structural"].get("checks") or [],
        "counts_for_verdict": counts_for_verdict,
        "source": source,
    }
