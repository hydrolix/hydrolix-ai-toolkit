"""Audience-specific incident views built from the shared incident bundle."""

from __future__ import annotations

from datetime import datetime, timezone

from . import incident_report as _ir
from .incident import module as _irm
from .incident.targets import _scope_views_for_indicator


SCHEMA = "bot_incident_scope.v1"

# Display-form labels that signal an edge denied or otherwise actively
# challenged the request. These match the capitalized values produced by
# ``_humanize_edge_action_rows`` (the raw artifact lowercase keys live in
# ``ACTION_CLASS_LABELS`` at incident/labels.py:57-63).
_DENY_CODED_ACTIONS = {"Block", "Deny", "Challenge", "Tarpit"}

# Threshold for the "Tune down" calibration call — a rule that fires on
# more than this many targets, and on >50% of them, is treated as likely
# catching baseline traffic rather than only suspicious actors.
_HIGH_VOLUME_RULE_TARGET_CAP = 10


def assemble(artifacts: list[dict]) -> dict:
    """Every stakeholder variant consumes the incident analyst artifacts."""
    return _ir.assemble(artifacts)


def _method(actors_art: dict, actor_rankings: list[dict]) -> dict:
    return {
        "schema_version": SCHEMA,
        "comparison_type": "previous_window",
        "producer_limit": actors_art.get("top_n"),
        "result_row_count": sum(len(r.get("rows") or []) for r in actor_rankings),
        "result_truncated": False,
        "interpretation_constraints": [
            "mechanical_features_only",
            "no_causal_claim",
            "no_malicious_intent_claim",
        ],
    }


def _common_context(artifact: dict, *, title: str, kicker: str, dek: str) -> dict:
    scope_art = artifact["scope"]
    actors_art = artifact["actors"]
    action_targets_art = artifact.get("action_targets") or {}
    scope_meta = scope_art.get("scope") or {}
    cluster = scope_meta.get("cluster") or ""
    raw_drilldown_available = bool(actors_art.get("raw_drilldown_available"))
    actor_rankings = (
        _ir._actor_rankings_view(actors_art) if raw_drilldown_available else []
    )
    suspicious_targets = _ir._suspicious_targets_view(
        action_targets_art, actors_artifact=actors_art
    )
    deterministic_summary = _ir._deterministic_summary(
        scope_art, actors_art, action_targets_art, suspicious_targets
    )
    scope_rows = _irm._build_scope_view_rows(scope_art, actors_art)
    siem_rows = _irm._build_siem_view_rows(
        scope_art, bool(scope_meta.get("siem_available"))
    )
    editorial = _irm._build_editorial_extensions(
        scope_art,
        actors_art,
        action_targets_art,
        scope_meta,
        suspicious_targets,
        deterministic_summary,
    )
    return {
        "title": title,
        "kicker": kicker,
        "headline": _irm._build_headline(scope_meta),
        "dek": dek,
        "purpose": None,
        "scope": _irm._build_scope_block(scope_meta, cluster),
        "windows": _irm._build_windows_block(scope_meta),
        "window_confirmation": _ir._window_confirmation_view(
            scope_art.get("window_confirmation") or {}
        ),
        "impact": _ir._impact_view(scope_art),
        "suspicious_targets": suspicious_targets,
        "suspicious_targets_visible": suspicious_targets[:10],
        "deterministic_summary": deterministic_summary,
        "actor_rankings": actor_rankings,
        "raw_drilldown_available": raw_drilldown_available,
        "raw_table": actors_art.get("raw_table") or "",
        "fields_resolved": actors_art.get("fields_resolved") or [],
        "fields_unresolved": actors_art.get("fields_unresolved") or [],
        "dashboard_url": scope_art.get("dashboard_url") or "",
        "limitations": _irm._collect_limitations(
            scope_art, actors_art, action_targets_art
        ),
        "method": _method(actors_art, actor_rankings),
        "confidence": {"reasons": []},
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        **scope_rows,
        **siem_rows,
        **editorial,
    }


def _limited(rows: list[dict], limit: int = 5) -> list[dict]:
    return rows[:limit]


def _enrich_targets_with_cooccurrence(
    targets: list[dict], actors_artifact: dict
) -> list[dict]:
    """Attach ``seen_at`` (top paths the IP hit) and ``seen_with`` (top
    UAs paired with the IP) to each target row, plus the per-IP
    ``edge_action`` block already used by the analyst view. Lets the
    SOC analyst pivot an indicator into a focused WAF/SIEM query —
    "block IP 203.0.113.10 on /api/auth/login when UA contains
    'python-requests'" — without leaving the packet.
    """
    out: list[dict] = []
    for target in targets:
        scope_views = _scope_views_for_indicator(target, actors_artifact)
        enriched = dict(target)
        for key in ("seen_at", "seen_with", "edge_action"):
            if scope_views.get(key) and key not in enriched:
                enriched[key] = scope_views[key]
        out.append(enriched)
    return out


def _incident_window_shape(window_confirmation: dict, scope_art: dict) -> str:
    """One-line summary of the window shape — volume, 429/5xx rates,
    bot share, and any spike flags that fired. Reads from the raw
    ``window_confirmation`` payload (not the tiles view) so the values
    keep their numeric precision."""
    wc = (scope_art.get("window_confirmation") or {}) if scope_art else {}
    requests = wc.get("requests")
    rate_429 = wc.get("rate_429_pct")
    rate_5xx = wc.get("rate_5xx_pct")
    bot_share = wc.get("bot_share_pct")
    blocked = wc.get("blocked_share_pct")
    parts: list[str] = []
    if requests:
        parts.append(f"{int(requests):,} requests")
    if rate_429 is not None:
        parts.append(f"429 rate {rate_429:g}%")
    if rate_5xx is not None:
        parts.append(f"5xx rate {rate_5xx:g}%")
    if bot_share is not None:
        parts.append(f"bot share {bot_share:g}%")
    if blocked is not None:
        parts.append(f"edge-blocked share {blocked:g}%")
    spike_flags = (window_confirmation or {}).get("spike_flags") or []
    flag_labels = [
        flag.get("label") if isinstance(flag, dict) else str(flag)
        for flag in spike_flags
    ]
    body = "; ".join(parts) if parts else "No window evidence captured"
    if flag_labels:
        body += ". Spike flags: " + ", ".join(flag_labels)
    return body + "."


def _edge_policy_assessment(
    edge_action_mix_rows: list[dict],
    deny_rule_mix_rows: list[dict],
    suspicious_targets: list[dict],  # noqa: ARG001  (reserved for future pass-through cross-checks)
) -> dict:
    """Mechanical edge-posture summary for the Policy assessment block.

    Returns ``{headline, evidence, gap}``. The headline is a single
    sentence; evidence is a (possibly empty) bullet list; gap is a
    single sentence or empty string.
    """
    if not edge_action_mix_rows:
        return {
            "headline": (
                "Edge action mix was not present in the incident artifact; "
                "policy posture cannot be assessed mechanically."
            ),
            "evidence": [],
            "gap": "",
        }

    top_action = max(
        edge_action_mix_rows,
        key=lambda r: r.get("share_pct") or 0,
    )
    top_value = top_action.get("value") or ""
    top_share_display = top_action.get("share_pct_display") or ""
    top_requests_display = top_action.get("requests_display") or ""
    top_value_label = top_action.get("value_label") or "Action"

    if top_value in _DENY_CODED_ACTIONS:
        headline = "Edge is actively blocking the dominant traffic share."
    elif top_value == "No Action":
        headline = "Edge is passing the dominant traffic share without action."
    else:
        headline = f"Edge is applying {top_value} to the dominant traffic share."

    evidence: list[str] = [
        f"{top_value_label} '{top_value}' applied to {top_share_display} of window "
        f"({top_requests_display} requests)."
    ]

    if deny_rule_mix_rows:
        top_rule = deny_rule_mix_rows[0]
        evidence.append(
            f"Deny rule '{top_rule.get('value') or ''}' dominates at "
            f"{top_rule.get('share_pct_display') or ''} of window."
        )

    has_deny_coded = any(
        (row.get("value") in _DENY_CODED_ACTIONS) and (row.get("share_pct") or 0) > 0
        for row in edge_action_mix_rows
    )
    no_action_row = next(
        (row for row in edge_action_mix_rows if row.get("value") == "No Action"),
        None,
    )
    if has_deny_coded and no_action_row is not None:
        evidence.append(
            f"{no_action_row.get('share_pct_display') or ''} of window still "
            "passes with no edge action applied."
        )

    if not deny_rule_mix_rows and has_deny_coded:
        gap = (
            "Deny-rule mix is unavailable — cannot tie blocked traffic back "
            "to a specific rule."
        )
    else:
        gap = ""

    return {"headline": headline, "evidence": evidence, "gap": gap}


def _de_calibration_calls(
    rule_summary: list[dict],
    field_rankings: list[dict],  # noqa: ARG001  (reserved for future tie-in)
    fields_resolved: list[str],  # noqa: ARG001  (reserved for future tie-in)
    fields_unresolved: list[str],
    suspicious_targets: list[dict],
) -> dict:
    """Mechanical detector-posture summary for the Calibration calls block.

    Returns ``{headline, calls}``. Each call is a dict with
    ``verb``, ``subject``, ``rationale``. Calls cap at 4 entries.
    """
    if not rule_summary:
        return {
            "headline": (
                "No mechanical rule flags fired; detector posture cannot be "
                "assessed from this artifact."
            ),
            "calls": [],
        }

    top_rule = rule_summary[0]
    headline = (
        f"{top_rule.get('rule')} dominated detector firing; "
        f"{len(rule_summary)} distinct rules fired this window."
    )

    calls: list[dict] = []
    used_subjects: set[str] = set()

    top_count = int(top_rule.get("count") or 0)
    top_name = str(top_rule.get("rule") or "")
    if top_name and top_count >= 3:
        calls.append({
            "verb": "Keep",
            "subject": top_name,
            "rationale": (
                f"fired {top_count} times this window without producing pad findings"
            ),
        })
        used_subjects.add(top_name)

    watch_target = next(
        (row for row in rule_summary
         if int(row.get("count") or 0) == 1
         and str(row.get("rule") or "") not in used_subjects),
        None,
    )
    if watch_target is not None:
        name = str(watch_target.get("rule") or "")
        calls.append({
            "verb": "Watch",
            "subject": name,
            "rationale": "fired on a single target; insufficient evidence to tune",
        })
        used_subjects.add(name)

    n_targets = len(suspicious_targets)
    if n_targets > _HIGH_VOLUME_RULE_TARGET_CAP:
        for row in rule_summary:
            name = str(row.get("rule") or "")
            if name in used_subjects:
                continue
            count = int(row.get("count") or 0)
            pct = (count / n_targets) * 100 if n_targets else 0
            if pct > 50:
                calls.append({
                    "verb": "Tune down",
                    "subject": name,
                    "rationale": (
                        f"fires on {pct:.0f}% of targets — likely catching "
                        "baseline traffic, not just suspicious"
                    ),
                })
                used_subjects.add(name)
                break

    if fields_unresolved and len(calls) < 4:
        subject = "raw-log fields " + ", ".join(fields_unresolved[:3])
        calls.append({
            "verb": "Add coverage",
            "subject": subject,
            "rationale": (
                "unresolved this window; confidence is bounded by missing "
                "field instrumentation"
            ),
        })

    return {"headline": headline, "calls": calls[:4]}


def prepare_soc_action_packet(artifact: dict) -> dict:
    ctx = _common_context(
        artifact,
        title="Incident SOC Action Packet",
        kicker="Bot Insights - SOC action packet",
        dek="IR handoff from the incident evidence bundle: suspicious actors, IOCs, edge actions, and caveats.",
    )
    primary_targets = _enrich_targets_with_cooccurrence(
        _limited(ctx["suspicious_targets"], 12),
        artifact["actors"],
    )
    ctx.update(
        {
            "primary_targets": primary_targets,
            "ioc_indicators": _limited((ctx.get("iocs") or {}).get("indicators") or [], 20),
            "edge_controls": _limited(ctx.get("edge_action_mix_rows") or []),
            "deny_rules": _limited(ctx.get("deny_rule_mix_rows") or []),
            "cooccurrence": artifact["actors"].get("actor_cooccurrence") or {},
            "recommended_actions": _limited(ctx.get("recommended_actions") or [], 8),
            "coverage_limitations": _coverage_limitations(ctx),
            "incident_window_shape": _incident_window_shape(
                ctx.get("window_confirmation") or {}, artifact["scope"],
            ),
        }
    )
    return ctx


def prepare_edge_platform_brief(artifact: dict) -> dict:
    ctx = _common_context(
        artifact,
        title="Incident Edge Platform Brief",
        kicker="Bot Insights - edge platform brief",
        dek="CDN and edge-operations view of request impact, response mix, affected surfaces, and rule/action evidence.",
    )
    ctx.update(
        {
            "top_hosts": _limited(ctx.get("targeted_hosts_rows") or []),
            "top_paths": _limited(
                ctx.get("top_raw_paths_rows") or ctx.get("path_pattern_rows") or []
            ),
            "status_rows": _limited(ctx.get("status_mix_rows") or []),
            "edge_actions": _limited(ctx.get("edge_action_mix_rows") or []),
            "deny_rules": _limited(ctx.get("deny_rule_mix_rows") or []),
            "operational_actions": _limited(ctx.get("recommended_actions") or [], 6),
            "coverage_limitations": _coverage_limitations(ctx),
            "policy_assessment": _edge_policy_assessment(
                ctx.get("edge_action_mix_rows") or [],
                ctx.get("deny_rule_mix_rows") or [],
                ctx.get("suspicious_targets") or [],
            ),
        }
    )
    return ctx


def prepare_detection_engineering(artifact: dict) -> dict:
    ctx = _common_context(
        artifact,
        title="Incident Detection Engineering Review",
        kicker="Bot Insights - detection engineering",
        dek="Detector review of the mechanical rules, fields, confidence drivers, missing coverage, and follow-up instrumentation.",
    )
    rule_counts: dict[str, int] = {}
    for target in ctx.get("suspicious_targets") or []:
        for flag in target.get("reason_flag_labels") or target.get("reason_flags") or []:
            rule_counts[str(flag)] = rule_counts.get(str(flag), 0) + 1
    ctx.update(
        {
            "rule_summary": [
                {"rule": rule, "count": count}
                for rule, count in sorted(
                    rule_counts.items(), key=lambda item: (-item[1], item[0])
                )
            ],
            "field_rankings": _limited(ctx.get("actor_rankings") or [], 8),
            "missing_coverage": _coverage_limitations(ctx),
            "follow_up_instrumentation": _instrumentation_followups(ctx),
        }
    )
    ctx["calibration_calls"] = _de_calibration_calls(
        ctx.get("rule_summary") or [],
        ctx.get("field_rankings") or [],
        ctx.get("fields_resolved") or [],
        ctx.get("fields_unresolved") or [],
        ctx.get("suspicious_targets") or [],
    )
    return ctx


def _coverage_limitations(ctx: dict) -> list[str]:
    limitations = list(ctx.get("limitations") or [])
    if not ctx.get("raw_drilldown_available"):
        limitations.append(
            "Raw actor drilldown was unavailable; actor-level rows are summary-limited."
        )
    if not ctx.get("edge_action_mix_rows"):
        limitations.append(
            "Edge action mix was not present in the incident artifact."
        )
    if not ctx.get("deny_rule_mix_rows"):
        limitations.append(
            "Deny-rule mix was not present in the incident artifact."
        )
    if not ctx.get("siem_action_rows"):
        limitations.append(
            "SIEM action evidence was unavailable or not emitted for this window."
        )
    return list(dict.fromkeys(limitations))


def _instrumentation_followups(ctx: dict) -> list[str]:
    followups: list[str] = []
    if ctx.get("fields_unresolved"):
        followups.append(
            "Resolve missing raw-log fields: " + ", ".join(ctx["fields_unresolved"])
        )
    if not ctx.get("edge_action_mix_rows"):
        followups.append("Emit edge action mix for future incident action review.")
    if not ctx.get("deny_rule_mix_rows"):
        followups.append("Emit deny-rule mix to connect detector output to policy controls.")
    if not ctx.get("actor_rankings"):
        followups.append("Restore raw actor rankings or record the raw-drilldown limitation.")
    if not followups:
        followups.append("No instrumentation gaps were mechanically flagged by this artifact.")
    return followups
