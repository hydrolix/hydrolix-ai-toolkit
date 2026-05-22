"""Finding card helpers for incident print reports."""

from __future__ import annotations

from typing import Any

from ..browser_versions import parse_browser_user_agent
from .shared import _first_sentence, _html, _join_phrase, _text

def _finding_kicker(finding: dict[str, Any], idx: int) -> str:
    label = _text(finding.get("label"))
    return "" if label == f"Finding {idx:02d}" else label

def _finding_chips(entities: list[dict[str, Any]]) -> list[dict[str, str]]:
    chips = []
    seen = set()
    for entity in entities:
        text = _text(entity.get("target_type_label") or "Signal")
        key = text.casefold()
        if key in seen:
            continue
        seen.add(key)
        chips.append({"text": text, "class": "ghost"})
        if len(chips) == 2:
            break
    return chips

def _compact_as_meta(meta: Any) -> str:
    parts = [_text(part).strip() for part in _text(meta).split("·")]
    parts = [part for part in parts if part]
    if not parts:
        return ""
    asn = next((part for part in parts if part.upper().startswith("AS")), parts[0])
    share = next((part for part in reversed(parts) if "%" in part), "")
    if share:
        share = share.replace(" of window", " window")
        return f"{asn} · {share}"
    return asn

def _browser_family_label(row: dict[str, Any]) -> str:
    family = _text(row.get("browser_family"))
    if family and family != "Unknown":
        return family
    label = _text(row.get("browser_label"))
    if "Chrome" in label or "Chromium" in label:
        return "Chrome"
    return label.split()[0] if label else "Browser"

def _ua_platform_label(user_agent: str) -> str:
    ua = _text(user_agent)
    if "Windows" in ua:
        return "Windows"
    if "Macintosh" in ua or "Mac OS X" in ua:
        return "macOS"
    if "Android" in ua:
        return "Android"
    if "iPhone" in ua or "iPad" in ua:
        return "iOS"
    if "Linux" in ua:
        return "Linux"
    return "Unknown"

def _compact_ua_label(user_agent: Any, ctx: dict[str, Any]) -> str:
    ua = _text(user_agent)
    rows = (ctx.get("browser_version_context") or {}).get("rows") or []
    for row in rows:
        if _text(row.get("user_agent")) != ua:
            continue
        browser = _browser_family_label(row)
        version = _text(row.get("version_display"))
        platform = _ua_platform_label(ua)
        token = f"{browser} {version}".strip()
        return f"{token} / {platform}" if platform != "Unknown" else token
    parsed = parse_browser_user_agent(ua)
    browser = _browser_family_label(
        {
            "browser_family": parsed.get("family"),
            "browser_label": parsed.get("label"),
        }
    )
    version = _text(parsed.get("major_version"))
    platform = _ua_platform_label(ua)
    token = f"{browser} {version}".strip()
    return f"{token} / {platform}" if token and platform != "Unknown" else (token or ua)

def _compact_browser_age(row: dict[str, Any]) -> str:
    age = _text(row.get("age_display"))
    age = age.replace(" years old", "y").replace(" year old", "y")
    age = age.replace(" months old", "mo").replace(" month old", "mo")
    age = age.replace(" days old", "d").replace(" day old", "d")
    return age

def _finding_as_reputation_callout(
    finding: dict[str, Any],
    ctx: dict[str, Any],
) -> dict[str, str] | None:
    entities = finding.get("entities") or []
    source = ctx.get("as_reputation_context") or {}
    if not source.get("available"):
        return None
    entity_text = " ".join(
        _text(entity.get("meta")) for entity in entities
    )
    for row in source.get("rows") or []:
        asn = _text(row.get("asn_display"))
        if not asn or asn not in entity_text:
            continue
        name = _text(row.get("name"))
        requests = _text(row.get("requests_display"))
        flagged = int(float(row.get("flagged_target_count") or 0))
        flagged_text = (
            f"{flagged} flagged target{'' if flagged == 1 else 's'}"
            if flagged > 0
            else "flagged actor overlap"
        )
        inclusion_reason = (
            f"Included because {asn} matched the AS reputation corpus and "
            "overlapped this finding's flagged client-IP cluster"
        )
        public_reason = _first_sentence(row.get("external_reputation_point"))
        public_reason = f" {public_reason}" if public_reason else ""
        return {
            "title": "Why AS context is included",
            "summary_html": _html(
                f"{inclusion_reason}: {requests} requests; {flagged_text}."
                f"{public_reason}"
            ),
            "boundary_html": _html(
                "Corroborating context only; not attribution."
            ),
        }
    return None

def _finding_ua_age_callout(
    finding: dict[str, Any],
    ctx: dict[str, Any],
) -> dict[str, str] | None:
    entities = [
        entity
        for entity in (finding.get("entities") or [])
        if entity.get("target_type") == "user_agent"
    ]
    if not entities:
        return None
    source = ctx.get("browser_version_context") or {}
    if not source.get("available"):
        return None
    ua_values = {_text(entity.get("value")) for entity in entities}
    stale_rows = [
        row
        for row in (source.get("rows") or [])
        if bool(row.get("stale")) and _text(row.get("user_agent")) in ua_values
    ]
    if not stale_rows:
        return None
    stale_rows = stale_rows[:2]
    tokens = [
        f"{_browser_family_label(row)} {_text(row.get('version_display'))}"
        f" ({_compact_browser_age(row)})"
        for row in stale_rows
    ]
    subject = _join_phrase(tokens)
    predicate = "is a stale UA token" if len(tokens) == 1 else "are stale UA tokens"
    return {
        "title": "Browser age context",
        "summary_html": _html(
            f"{subject} {predicate}."
        ),
        "boundary_html": _html(
            "Stale tokens can be pinned, spoofed, or non-updating clients; "
            "not identity or intent evidence."
        ),
    }

def _findings(ctx: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for idx, finding in enumerate((ctx.get("incident_findings") or [])[:3], start=1):
        entities = finding.get("entities") or []
        out.append(
            {
                "n": f"{idx:02d}",
                "kicker": _finding_kicker(finding, idx),
                "severity": "critical" if idx == 1 else "high",
                "severity_label": "Critical" if idx == 1 else "High",
                "chips": _finding_chips(entities),
                "as_callout": _finding_as_reputation_callout(finding, ctx),
                "ua_age_callout": _finding_ua_age_callout(finding, ctx),
                "headline": _text(finding.get("lead")),
                "prose_html": _html(finding.get("body")),
                "ips": [
                    {
                        "ip": _text(entity.get("value")),
                        "tag": _text(entity.get("severity_label") or entity.get("severity")),
                        "asn_label": _text(entity.get("target_type_label")),
                        "volume": _text(entity.get("requests_display") or ""),
                        "share": _compact_as_meta(entity.get("meta")),
                    }
                    for entity in entities[:4]
                ],
                "uas": [
                    {
                        "label_html": _html(_compact_ua_label(entity.get("value"), ctx)),
                        "share": _text(entity.get("meta") or ""),
                        "full": _text(entity.get("target_type_label")),
                    }
                    for entity in entities[:4]
                ],
            }
        )
    while len(out) < 2:
        out.append(
            {
                "n": f"{len(out)+1:02d}",
                "kicker": "Data availability",
                "severity": "monitor",
                "severity_label": "Monitor",
                "chips": [],
                "headline": "No additional deterministic finding was available.",
                "prose_html": "The report rendered with the evidence present in the artifact.",
                "ips": [],
                "uas": [],
            }
        )
    return out
