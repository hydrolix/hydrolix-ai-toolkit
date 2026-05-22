"""Actor row and recommended-action helpers for incident print reports."""

from __future__ import annotations

from typing import Any

from .shared import _compact, _html, _text

def _first_actor_rows(ctx: dict[str, Any], limit: int = 10) -> list[dict[str, str]]:
    soc_rows = ctx.get("raw_actor_rows") or []
    if soc_rows:
        return [
            {
                "rank": _text(row.get("rank")),
                "ip": _text(row.get("value")),
                "asn_meta": _text(row.get("asn") or "raw actor"),
                "requests": _text(row.get("requests_display")),
                "share": _text(row.get("share_display")),
                "rate_429": _text(row.get("req_429_rate_display")),
                "severity": _text(row.get("severity_label") or "raw").lower().replace(" ", "-"),
                "severity_label": _text(row.get("severity_label") or "Raw"),
                "edge_action_html": _html(row.get("edge_action")),
                "attck": "target table" if row.get("severity_label") != "Raw volume only" else "raw volume",
            }
            for row in soc_rows[:limit]
        ]
    ranking = next(
        (r for r in ctx.get("actor_rankings") or [] if r.get("field") == "client_ip"),
        None,
    )
    rows = (ranking or {}).get("rows") or []
    out = []
    for idx, row in enumerate(rows[:limit], start=1):
        out.append(
            {
                "rank": str(idx),
                "ip": _text(row.get("value")),
                "asn_meta": _text(row.get("asn") or "raw actor"),
                "requests": _text(row.get("requests_display") or _compact(row.get("requests"))),
                "share": _text(row.get("share_pct_display") or ""),
                "rate_429": _text(row.get("req_429_share_display") or ""),
                "severity": "critical" if idx <= 3 else "high",
                "severity_label": "Critical" if idx <= 3 else "High",
                "edge_action_html": "Observed",
                "attck": "T1498 / T1110",
            }
        )
    return out

def _actions(ctx: dict[str, Any], limit: int = 5) -> list[dict[str, str]]:
    out = []
    for idx, action in enumerate((ctx.get("recommended_actions") or [])[:limit], start=1):
        out.append(
            {
                "n": f"{idx:02d}",
                "severity": _text(action.get("urgency_tone") or "monitor"),
                "chip_text": _text(action.get("urgency") or "next"),
                "team": _text(action.get("role") or "Owner"),
                "action_html": _html(action.get("step")),
                "title_html": _html(action.get("step")),
                "why_html": _html(action.get("reason") or action.get("effect") or ""),
                "meta_html": _html(
                    " · ".join(
                        part
                        for part in (
                            f"Target: {action.get('target')}" if action.get("target") else "",
                            f"Duration: {action.get('duration')}" if action.get("duration") else "",
                            f"Rollback: {action.get('rollback')}" if action.get("rollback") else "",
                        )
                        if part
                    )
                ),
            }
        )
    return out

def _team_short(value: Any) -> str:
    team = _text(value or "Owner").strip()
    return {
        "Security Operations": "SOC",
        "Threat Intel": "Intel",
        "Threat Intelligence": "Intel",
        "Platform": "Edge",
    }.get(team, team[:10])

def _compact_cover_action(value: Any) -> str:
    text = _text(value).replace("`", "")
    if text.startswith("Time-boxed edge control candidate: Client IP "):
        target = text.removeprefix("Time-boxed edge control candidate: Client IP ").split(" ", 1)[0]
        return f"Time-box {target}; monitor 429s"
    if text.startswith("Enrich the "):
        count = text.removeprefix("Enrich the ").split(" ", 1)[0]
        return f"Enrich {count} critical targets in case mgmt"
    if text.startswith("Validate route normalization and owner telemetry for "):
        target = text.removeprefix("Validate route normalization and owner telemetry for ").split(" ", 1)[0]
        return f"Validate {target} route evidence"
    return text[:82].rstrip() + ("..." if len(text) > 82 else "")

def _cover_actions(ctx: dict[str, Any], limit: int = 3) -> list[dict[str, str]]:
    return [
        {
            "severity": action["severity"],
            "team": _team_short(action["team"]),
            "action_html": _html(_compact_cover_action(action["action_html"])),
        }
        for action in _actions(ctx, limit)
    ]
