"""Findings list + triggered-row + coverage-detail + actions builders."""

from __future__ import annotations

from dataclasses import asdict
from ...findings import Finding
from ...humanize import display_label
from ...theme import DOMAIN_LABELS

__all__ = [
    '_build_findings',
    '_triggered_row',
    '_coverage_detail',
    '_actions',
]


def _build_findings(
    score: int,
    delta: int,
    triggered: list[dict],
    missing: list[dict],
    below_threshold: list[dict],
    primary_domain: str,
) -> list[dict]:
    """Synthesize a Finding-shaped list for the executive summary macro.

    The macro is shared with scorecard_brief and renders ``findings[0]`` as
    the deterministic top-finding paragraph. We surface a one-finding list
    keyed to the host's situation.
    """
    if triggered:
        domain_label = DOMAIN_LABELS.get(primary_domain, primary_domain)
        rule_word = "rule" if len(triggered) == 1 else "rules"
        rule_names = ", ".join(r["name_label"] for r in triggered[:3])
        if len(triggered) > 3:
            rule_names += f", and {len(triggered) - 3} more"
        headline = (
            f"Score {score} — {len(triggered)} {rule_word} triggered in {domain_label}"
        )
        body_parts = [f"Triggered: {rule_names}."]
        if missing:
            body_parts.append(
                f"{len(missing)} additional rule{'s' if len(missing) != 1 else ''} "
                "could not be scored due to missing inputs — treat the score as a "
                "floor on risk, not a complete picture."
            )
        finding = Finding(
            finding_id="entity_review.triggered",
            title=headline,
            headline=headline,
            body=" ".join(body_parts),
            priority=10,
        )
    else:
        headline = f"Score {score} — no rules triggered"
        body = (
            "No mechanical signals crossed threshold for this host in the "
            "current window."
        )
        if missing:
            body += (
                f" {len(missing)} rule{'s' if len(missing) != 1 else ''} "
                "could not be scored due to missing inputs."
            )
        finding = Finding(
            finding_id="entity_review.clean",
            title=headline,
            headline=headline,
            body=body,
            priority=10,
        )
    return [asdict(finding)]


def _triggered_row(rule: dict) -> dict:
    """Project a triggered rule_result into a render-ready dict."""
    domain = rule.get("domain") or ""
    return {
        "name": rule.get("name") or "",
        "name_label": display_label(rule.get("name") or ""),
        "domain": domain,
        "domain_label": DOMAIN_LABELS.get(domain, domain),
        "threshold": rule.get("threshold"),
        "current": rule.get("current"),
        "baseline": rule.get("baseline"),
        "points": rule.get("points"),
        "evidence": rule.get("evidence") or "",
        "supporting_metrics": rule.get("supporting_metrics") or {},
    }


def _coverage_detail(missing: list[dict]) -> dict | None:
    """Group missing-input rules by domain for the coverage disclosure."""
    if not missing:
        return None
    grouped: dict[str, list[dict]] = {}
    for rule in missing:
        domain = rule.get("domain") or "other"
        grouped.setdefault(domain, []).append(
            {
                "name": rule.get("name") or "",
                "missing_inputs": rule.get("missing_inputs") or [],
            }
        )
    return {
        "total": len(missing),
        "groups": [
            {
                "domain": d,
                "domain_label": DOMAIN_LABELS.get(d, d),
                "rules": sorted(rules, key=lambda r: r["name"]),
            }
            for d, rules in sorted(grouped.items())
        ],
    }


def _actions(sc: dict) -> list[dict]:
    """Project this host's recommended_next_steps into the actions shape.

    Accepts both the structured ``{"summary", "detail"}`` shape that current
    producers emit and the legacy plain-string shape from older artifacts.
    """
    out: list[dict] = []
    for step in sc.get("recommended_next_steps") or []:
        if isinstance(step, dict):
            summary = step.get("summary") or step.get("detail") or ""
            detail = step.get("detail") or step.get("summary") or ""
        else:
            text = str(step)
            summary = text.split(".")[0] + ("." if "." in text else "")
            detail = text
        out.append(
            {
                "summary": summary,
                "detail": detail,
                "step": detail,
                "host_count": 1,
                "preview": sc["entity"],
                "extra": 0,
            }
        )
    return out
