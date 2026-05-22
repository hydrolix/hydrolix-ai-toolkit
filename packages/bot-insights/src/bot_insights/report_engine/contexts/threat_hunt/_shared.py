"""Context preparer for ``bot_threat_hunt.v3``."""
from __future__ import annotations
import json
from datetime import datetime, timezone
from typing import Any
SCHEMA = "bot_threat_hunt.v3"
REPORT_TYPE = "threat_hunt"
TEMPLATE = "reports/threat_hunt.html"
PRINT_TEMPLATE = "reports/incident_report_print.html"
NOTE_ID_TO_SLOT = {
    "llm-interpretation": "executive_summary",
}
SCRAPER_PATTERN_LINKS = {
    "owasp_oat_011": {
        "label": "OWASP OAT-011 Scraping",
        "url": "https://owasp.org/www-project-automated-threats-to-web-applications/assets/oats/EN/OAT-011_Scraping",
    },
    "owasp_bot_management": {
        "label": "OWASP Bot Management Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Bot_Management_and_Anti-Automation_Cheat_Sheet.html",
    },
    "f5_scraper_patterns": {
        "label": "F5 scraper behavior patterns",
        "url": "https://www.f5.com/labs/articles/how-to-identify-and-stop-scrapers",
    },
    "cloudflare_bot_detection": {
        "label": "Cloudflare bot detection concepts",
        "url": "https://developers.cloudflare.com/bots/concepts/bot-detection-engines/",
    },
}
def _artifact(artifacts: list[dict[str, Any]]) -> dict[str, Any]:
    for artifact in artifacts:
        if artifact.get("schema_version") == SCHEMA:
            return artifact
    raise ValueError(f"threat_hunt requires {SCHEMA}")
def assemble(artifacts: list[dict[str, Any]]) -> dict[str, Any]:
    return _artifact(artifacts)
def _label(value: str) -> str:
    return value.replace("_", " ").title()
def _subject_label(scope: dict[str, Any]) -> str:
    value = str(scope.get("customer") or scope.get("tenant") or scope.get("cluster") or "").strip()
    if not value:
        return "Threat Hunt"
    return value.replace("_", " ").replace("-", " ").title()
def _tone(verdict: str) -> str:
    return {
        "confirmed": "escalate",
        "likely": "monitor",
        "possible": "observe",
        "strong_lead": "escalate",
        "lead": "monitor",
        "weak_lead": "observe",
        "not_enough_data": "neutral",
    }.get(verdict, "neutral")
def _fmt_num(value: Any) -> str:
    try:
        n = float(value)
    except (TypeError, ValueError):
        return "unavailable"
    if abs(n) >= 1_000_000:
        return f"{n / 1_000_000:,.1f}M"
    if abs(n) >= 1_000:
        return f"{n / 1_000:,.1f}K"
    return f"{n:.0f}"
def _to_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
def _fmt_signed_num(value: Any) -> str:
    number = _to_float(value)
    if number is None:
        return "unavailable"
    sign = "+" if number >= 0 else "-"
    return f"{sign}{_fmt_num(abs(number))}"
def _baseline_comparison(row: dict[str, Any]) -> dict[str, Any]:
    current = _to_float(row.get("requests") if row.get("requests") is not None else row.get("total_requests"))
    baseline = _to_float(row.get("baseline_requests"))
    delta = _to_float(row.get("request_delta"))
    if delta is None and current is not None and baseline is not None:
        delta = current - baseline
    if baseline is None:
        return {
            "baseline": baseline,
            "delta": delta,
            "ratio": None,
            "display": "no baseline",
            "delta_display": _fmt_signed_num(delta) if delta is not None else "unavailable",
            "class": "ink-3",
        }
    if baseline == 0:
        if current and current > 0:
            return {
                "baseline": baseline,
                "delta": delta,
                "ratio": None,
                "display": f"new ({_fmt_signed_num(delta if delta is not None else current)})",
                "delta_display": _fmt_signed_num(delta if delta is not None else current),
                "class": "critical",
            }
        return {
            "baseline": baseline,
            "delta": delta,
            "ratio": 0.0,
            "display": "no change",
            "delta_display": _fmt_signed_num(delta or 0),
            "class": "ink-3",
        }
    if current is None:
        return {
            "baseline": baseline,
            "delta": delta,
            "ratio": None,
            "display": "unavailable",
            "delta_display": _fmt_signed_num(delta),
            "class": "ink-3",
        }
    ratio = current / baseline
    css_class = "critical" if ratio >= 2.0 else "high" if ratio >= 1.25 else "ink-3"
    return {
        "baseline": baseline,
        "delta": delta,
        "ratio": ratio,
        "display": f"{ratio:.1f}x ({_fmt_signed_num(delta if delta is not None else current - baseline)})",
        "delta_display": _fmt_signed_num(delta if delta is not None else current - baseline),
        "class": css_class,
    }
def _fmt_pct(value: Any) -> str:
    if value is None:
        return "unavailable"
    try:
        return f"{float(value):.1f}%"
    except (TypeError, ValueError):
        return "unavailable"
def _fmt_tiny_pct(value: Any) -> str:
    number = _to_float(value)
    if number is None:
        return "unavailable"
    if 0 < number < 0.01:
        return "<0.01%"
    if number < 1.0:
        return f"{number:.2f}%"
    return f"{number:.1f}%"
def _fmt_share(value: Any) -> str:
    number = _to_float(value)
    if number is None:
        return "unavailable"
    return _fmt_tiny_pct(number * 100.0)
def _fmt_money(value: Any) -> str:
    number = _to_float(value)
    if number is None:
        return "unavailable"
    if abs(number) >= 1000:
        return f"${number:,.0f}"
    return f"${number:,.2f}"
def _fmt_bytes(value: Any) -> str:
    number = _to_float(value)
    if number is None:
        return "unavailable"
    magnitude = abs(number)
    units = [
        (1_000_000_000_000_000, "P"),
        (1_000_000_000_000, "T"),
        (1_000_000_000, "B"),
        (1_000_000, "M"),
        (1_000, "K"),
    ]
    for divisor, suffix in units:
        if magnitude >= divisor:
            return f"{number / divisor:.1f}{suffix}"
    return f"{number:.0f}"
def _fmt_bytes_long(value: Any) -> str:
    number = _to_float(value)
    if number is None:
        return "unavailable"
    magnitude = abs(number)
    units = [
        (1_000_000_000_000_000, "PB"),
        (1_000_000_000_000, "TB"),
        (1_000_000_000, "GB"),
        (1_000_000, "MB"),
        (1_000, "KB"),
    ]
    for divisor, suffix in units:
        if magnitude >= divisor:
            return f"{number / divisor:.1f} {suffix}"
    return f"{number:.0f} bytes"
def _impact_action_text(impact: dict[str, Any]) -> str:
    response_bytes = impact.get("response_body_bytes")
    response_share = impact.get("response_body_byte_share")
    if response_bytes is None:
        response_bytes = impact.get("bytes")
        response_share = impact.get("byte_share")
    return (
        f"IMPACT: {_fmt_num(impact.get('requests'))} requests"
        f" ({_fmt_share(impact.get('request_share'))} of window total)"
        f" · {_fmt_bytes(response_bytes)} response body"
        f" ({_fmt_share(response_share)} of response bytes)"
    )

__all__ = [name for name in globals() if not name.startswith("__")]
