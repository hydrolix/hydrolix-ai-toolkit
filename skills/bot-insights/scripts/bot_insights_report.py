from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

# report_engine.humanize and report_engine.theme are pure-Python
# (no jinja2 / bleach / markdown-it-py imports). Importing them here
# lets the orchestrator surface human-readable labels alongside the
# raw snake_case identifiers in evidence packets so the LLM
# interpretation step doesn't have to copy ``cache_miss_rate_high`` /
# ``feature_input_missing`` / ``request_host`` into prose.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from report_engine import humanize as _humanize  # noqa: E402
from report_engine.theme import DOMAIN_LABELS as _DOMAIN_LABELS  # noqa: E402

# Heuristic-ladder calibration constants (suspicious-target thresholds,
# anomaly rate floors, automation-UA pattern, severity-rank table, and
# the quant/concentration flag partitions). Lifted to ``heuristics`` so
# tuning against real incidents is one focused file change. Imported
# under their original names so every call site in this module keeps
# working without touching the heuristic body.
from heuristics import (  # noqa: E402
    _ANOMALY_CURRENT_ERROR_RATE_MIN,
    _ANOMALY_ERROR_RATE_RATIO_MIN,
    _ANOMALY_MIN_REQUESTS,
    _AUTOMATION_UA_PATTERN,
    _SEVERITY_RANK,
    _SUSPICIOUS_ASN_CLUSTER_MIN_IPS,
    _SUSPICIOUS_BOTNET_CLUSTER_SHARE_MIN,
    _SUSPICIOUS_CONCENTRATION_FLAGS,
    _SUSPICIOUS_NEW_ACTOR_REQUESTS_MIN,
    _SUSPICIOUS_NEW_ACTOR_VOLUME_SHARE_MIN,
    _SUSPICIOUS_QUANT_FLAGS,
    _SUSPICIOUS_RATE_429_SHARE_MIN,
    _SUSPICIOUS_RATE_429_TOTAL_MIN,
    _SUSPICIOUS_SINGLE_PATH_REQUESTS_MIN,
    _SUSPICIOUS_VOLUME_SHARE_MIN,
    _is_templated_catchall_path,
)


# Root of the hydrolix-ai-toolkit checkout that hosts this script.
# Derived from __file__ so the orchestrator continues to work from a
# git worktree under .worktrees/<feature> — the previous hardcoded
# path made worktree-based development silently route the render
# subprocess through the main checkout's render_report.py, which is
# the wrong version when changes only exist on the worktree branch.
PUBLIC_SKILLS = Path(__file__).resolve().parents[3]
CAPTURE = Path(__file__).resolve().with_name("bot_insights_capture.py")
DEFAULT_SAMPLE_ROOT = Path("/Users/turtlebender/src/sample-data/bot-insights/1.1")
NEEDS_MCP_EXIT = 42
HANDOFF_SCHEMA = "bot_hydrolix_mcp_query_request.v1"


# Stateless formatters (number / time / SQL literal) live in
# ``producers.formatting``. Re-imported under the original module-level
# names so every existing call site in this file — and every test that
# reaches in via ``bot_insights_report.<name>`` — continues to work.
from producers.formatting import (  # noqa: E402
    as_number,
    bucket_expr,
    choose_granularity,
    human_number,
    label_change,
    parse_time,
    pct,
    pct_change,
    sql_literal,
    sql_ts,
)

# Per-report SQL builders live under ``producers.sql.*``. Re-imported
# under their original module-level names so main() and tests keep
# resolving them via ``bot_insights_report.<name>``.
from producers.sql.executive_posture import executive_posture_sql  # noqa: E402
from producers.sql.control_review import (  # noqa: E402
    control_review_sql,
    control_review_timeseries_sql,
)
from producers.sql.scorecard import (  # noqa: E402
    CRAWLER_ENTITY_SQL,
    CRAWLER_POPULATION_BY_ENTITY,
    EDGE_OPS_ENTITY_SQL,
    SCORECARD_ENTITY_SQL,
    SOC_ENTITY_SQL,
    cache_origin_path_sql,
    scorecard_crawler_sql,
    scorecard_edge_ops_sql,
    scorecard_soc_sql,
    scorecard_sql,
)
from producers.sql.incident import (  # noqa: E402
    _incident_actor_cooccurrence_sql,
    _incident_actor_scoped_metrics_baseline_sql,
    _incident_actor_scoped_metrics_sql,
    _incident_actor_topk_baseline_sql,
    _incident_actor_topk_sql,
    _incident_columns_query,
    _incident_deny_rule_mix_sql,
    _incident_dimension_sql,
    _incident_edge_action_mix_sql,
    _incident_in_list,
    _incident_raw_scope_predicate,
    _incident_scope_predicate,
    _incident_siem_dimension_sql,
    _incident_status_mix_sql,
    _incident_time_predicate,
    _incident_volume_timeseries_sql,
    _incident_window_confirmation_sql,
)

METRIC_LABELS = {
    "ai_requests": "AI requests",
    "bot_like_requests": "Bot-like requests",
    "cache_misses": "Cache misses",
    "error_5xx_requests": "5xx errors",
    "rate_limited_requests": "429 rate-limited requests",
    "requests": "Total requests",
    "avg_bot_score": "Average bot score",
    "siem_auth_fail_requests": "SIEM auth failures",
    "siem_blocked_requests": "SIEM blocked requests",
    "unique_client_ips": "Unique client IPs",
}


# --- Label enrichment for evidence packets ------------------------------
#
# The deterministic capture path produces packets with raw snake_case
# identifiers in every field that names a producer concept: entity_type,
# rule names (cache_miss_rate_high), domain keys (origin_impact),
# confidence reason codes (feature_input_missing), band keys
# (low_review). When the LLM writes interpretation prose against the
# packet it tends to copy those identifiers verbatim, which leaks
# internal naming into reader-facing text. The fix is to pair every
# identifier with a human-readable label in the packet itself; the
# interpretation_contract then directs the LLM to prefer the label
# fields. Tables (``bi_summary_*``, ``bot_agg_path_*``) are not user
# concepts and should not appear in prose at all — see SKILL.md.


def _humanize_feature_name(name: object) -> str:
    """Human label for a scorecard rule name. Wraps
    ``humanize_identifier`` so the orchestrator doesn't have to repeat
    the snake_case → Sentence-case rule.
    """
    if not name:
        return ""
    return _humanize.humanize_identifier(str(name))


def _humanize_input_list(inputs: object) -> list[str]:
    if not isinstance(inputs, list):
        return []
    return [_humanize.humanize_identifier(str(x)) for x in inputs if x]


def _enrich_feature_card(card: dict) -> dict:
    """Add human label fields to a single feature/rule entry.

    Mirrors the same enrichment the engine's render-time filters apply,
    so the LLM sees ready-to-paste labels (``Cache miss rate high``,
    ``Origin impact``) instead of the producer-side identifier
    (``cache_miss_rate_high``, ``origin_impact``).
    """
    if not isinstance(card, dict):
        return card
    out = dict(card)
    name = card.get("name")
    if name and "name_label" not in out:
        out["name_label"] = _humanize_feature_name(name)
    domain = card.get("domain")
    if domain and "domain_label" not in out:
        out["domain_label"] = _DOMAIN_LABELS.get(domain, _humanize.humanize_identifier(domain))
    missing_inputs = card.get("missing_inputs")
    if isinstance(missing_inputs, list) and "missing_inputs_labels" not in out:
        out["missing_inputs_labels"] = _humanize_input_list(missing_inputs)
    return out


def humanize_evidence_packet(packet: dict) -> dict:
    """Return a copy of ``packet`` with ``*_label`` fields added next
    to each producer-identifier field. Pure transformation — does not
    rename or remove existing keys. Safe to call on any
    ``bot_report_evidence.v1`` packet shape; missing sections are
    no-ops.
    """
    if not isinstance(packet, dict):
        return packet
    out = dict(packet)

    selected = out.get("selected_entity")
    if isinstance(selected, dict):
        s = dict(selected)
        if s.get("entity_type") and "entity_type_label" not in s:
            s["entity_type_label"] = _humanize.humanize_entity_type(s["entity_type"])
        if s.get("band") and "band_label" not in s:
            s["band_label"] = _humanize.humanize_band(s["band"])
        if s.get("confidence") and "confidence_label" not in s:
            s["confidence_label"] = _humanize.humanize_confidence(s["confidence"])
        if s.get("primary_domain") and "primary_domain_label" not in s:
            s["primary_domain_label"] = _DOMAIN_LABELS.get(
                s["primary_domain"],
                _humanize.humanize_identifier(s["primary_domain"]),
            )
        reasons = s.get("confidence_reasons")
        if isinstance(reasons, list) and "confidence_reasons_labels" not in s:
            s["confidence_reasons_labels"] = [
                _humanize.humanize_confidence_reason(str(r)) for r in reasons
            ]
        out["selected_entity"] = s

    features = out.get("evaluated_feature_evidence")
    if isinstance(features, list):
        out["evaluated_feature_evidence"] = [_enrich_feature_card(c) for c in features]

    not_evaluated = out.get("not_evaluated_features")
    if isinstance(not_evaluated, list):
        out["not_evaluated_features"] = [_enrich_feature_card(c) for c in not_evaluated]

    missing_inputs = out.get("missing_inputs")
    if isinstance(missing_inputs, list) and "missing_inputs_labels" not in out:
        out["missing_inputs_labels"] = _humanize_input_list(missing_inputs)

    rule_results = out.get("rule_results")
    if isinstance(rule_results, list):
        out["rule_results"] = [_enrich_feature_card(c) for c in rule_results]

    domain_scores = out.get("domain_scores")
    if isinstance(domain_scores, dict) and "domain_scores_labeled" not in out:
        out["domain_scores_labeled"] = {
            _DOMAIN_LABELS.get(k, _humanize.humanize_identifier(k)): v
            for k, v in domain_scores.items()
        }

    # --- Fleet-shaped packet enrichment ---------------------------------
    # The scorecard_brief --fleet packet has a different top-level
    # shape: fleet_summary / top_entities / lowest_entities /
    # rule_triggers_across_fleet, none of which existed when the
    # original enrichment was wired. Without the labels here, the
    # fleet packet still hands the LLM raw identifiers
    # (band="low_review", primary_domain="cache_busting",
    # rule_triggers[*].name="volume_delta_high"), defeating the
    # interpretation-step label-preference rule.
    fleet_summary = out.get("fleet_summary")
    if isinstance(fleet_summary, dict):
        fs = dict(fleet_summary)
        band_dist = fs.get("band_distribution")
        if isinstance(band_dist, dict) and "band_distribution_labeled" not in fs:
            fs["band_distribution_labeled"] = {
                _humanize.humanize_band(k): v for k, v in band_dist.items()
            }
        conf_dist = fs.get("confidence_distribution")
        if isinstance(conf_dist, dict) and "confidence_distribution_labeled" not in fs:
            fs["confidence_distribution_labeled"] = {
                _humanize.humanize_confidence(k): v for k, v in conf_dist.items()
            }
        pd_dist = fs.get("primary_domain_distribution")
        if isinstance(pd_dist, dict) and "primary_domain_distribution_labeled" not in fs:
            fs["primary_domain_distribution_labeled"] = {
                _DOMAIN_LABELS.get(k, _humanize.humanize_identifier(k)): v
                for k, v in pd_dist.items()
            }
        mid = fs.get("missing_input_domains")
        if isinstance(mid, dict) and "missing_input_domains_labeled" not in fs:
            fs["missing_input_domains_labeled"] = {
                _DOMAIN_LABELS.get(k, _humanize.humanize_identifier(k)): v
                for k, v in mid.items()
            }
        out["fleet_summary"] = fs

    def _enrich_entity_summary(card: object) -> object:
        if not isinstance(card, dict):
            return card
        e = dict(card)
        if e.get("entity_type") and "entity_type_label" not in e:
            e["entity_type_label"] = _humanize.humanize_entity_type(e["entity_type"])
        if e.get("band") and "band_label" not in e:
            e["band_label"] = _humanize.humanize_band(e["band"])
        if e.get("confidence") and "confidence_label" not in e:
            e["confidence_label"] = _humanize.humanize_confidence(e["confidence"])
        if e.get("primary_domain") and "primary_domain_label" not in e:
            e["primary_domain_label"] = _DOMAIN_LABELS.get(
                e["primary_domain"],
                _humanize.humanize_identifier(e["primary_domain"]),
            )
        return e

    top_entities = out.get("top_entities")
    if isinstance(top_entities, list):
        out["top_entities"] = [_enrich_entity_summary(c) for c in top_entities]

    lowest_entities = out.get("lowest_entities")
    if isinstance(lowest_entities, list):
        out["lowest_entities"] = [_enrich_entity_summary(c) for c in lowest_entities]

    rule_triggers = out.get("rule_triggers_across_fleet")
    if isinstance(rule_triggers, list):
        labelled = []
        for entry in rule_triggers:
            if not isinstance(entry, dict):
                labelled.append(entry)
                continue
            e = dict(entry)
            name = e.get("name")
            if name and "name_label" not in e:
                e["name_label"] = _humanize_feature_name(name)
            labelled.append(e)
        out["rule_triggers_across_fleet"] = labelled

    contract = out.get("interpretation_contract")
    if isinstance(contract, dict):
        out["interpretation_contract"] = _with_label_preference(contract)

    return out


# Common interpretation-contract addendum: instructs the LLM to prefer
# the ``*_label`` fields for prose. Appended to every per-report
# ``allowed`` list. Keeping the rest of the contract untouched
# preserves the existing forbidden constraints.
_LABEL_PREFERENCE_RULE = (
    "Prefer human-readable label fields (entity_type_label, band_label, "
    "confidence_label, primary_domain_label, confidence_reasons_labels, "
    "name_label, domain_label, missing_inputs_labels, "
    "domain_scores_labeled) over the paired raw snake_case identifier "
    "when writing prose. Do not name internal tables (bi_summary_*, "
    "bot_agg_path_*, bi_siem_policy_summary_*) in prose; describe the "
    "data source as 'this report's evidence' or refer to it by the "
    "report type."
)


def _with_label_preference(contract: dict) -> dict:
    """Append ``_LABEL_PREFERENCE_RULE`` to ``allowed`` once."""
    if not isinstance(contract, dict):
        return contract
    out = dict(contract)
    allowed = list(out.get("allowed") or [])
    if _LABEL_PREFERENCE_RULE not in allowed:
        allowed.append(_LABEL_PREFERENCE_RULE)
    out["allowed"] = allowed
    return out


# Formatters live in ``producers.formatting``; see the import block at
# the top of this module.


def run(
    cmd: list[str],
    *,
    stdout_path: Path | None = None,
    cwd: Path | None = None,
    allowed_returncodes: tuple[int, ...] = (),
) -> str:
    ok_codes = (0, *allowed_returncodes)
    if stdout_path is None:
        result = subprocess.run(
            cmd, cwd=cwd, text=True, capture_output=True, check=False
        )
        if result.returncode not in ok_codes:
            detail = result.stderr.strip() or result.stdout.strip()
            raise SystemExit(detail)
        return result.stdout
    with stdout_path.open("w", encoding="utf-8") as handle:
        result = subprocess.run(
            cmd,
            cwd=cwd,
            text=True,
            stdout=handle,
            stderr=subprocess.PIPE,
            check=False,
        )
    if result.returncode not in ok_codes:
        raise SystemExit(result.stderr.strip())
    return ""




def metric_by_name(artifact: dict) -> dict[str, dict]:
    return {
        str(metric.get("name")): metric
        for metric in artifact.get("metrics", [])
        if isinstance(metric, dict) and metric.get("name")
    }


def rate_row(
    name: str, label: str, numerator: str, denominator: str, metrics: dict[str, dict]
) -> dict:
    num = metrics.get(numerator, {})
    den = metrics.get(denominator, {})
    current = pct(num.get("current"), den.get("current"))
    baseline = pct(num.get("baseline"), den.get("baseline"))
    delta_points = None if current is None or baseline is None else current - baseline
    return {
        "name": name,
        "label": label,
        "current_pct": current,
        "baseline_pct": baseline,
        "delta_points": delta_points,
        "current_display": human_number(current, percent=True)
        if current is not None
        else "unavailable",
        "baseline_display": human_number(baseline, percent=True)
        if baseline is not None
        else "unavailable",
        "delta_points_display": human_number(delta_points, percent=True, signed=True)
        if delta_points is not None
        else "unavailable",
        "change_label": label_change(delta_points),
    }


def metric_card_from_metric(metric: dict) -> dict:
    name = str(metric.get("name", ""))
    return {
        "name": name,
        "label": METRIC_LABELS.get(name, name),
        "current": metric.get("current"),
        "baseline": metric.get("baseline"),
        "absolute_delta": metric.get("absolute_delta"),
        "pct_change": metric.get("pct_change"),
        "current_display": human_number(metric.get("current")),
        "baseline_display": human_number(metric.get("baseline")),
        "absolute_delta_display": human_number(
            metric.get("absolute_delta"), signed=True
        ),
        "pct_change_display": human_number(
            metric.get("pct_change"), percent=True, signed=True
        ),
        "direction": metric.get("direction"),
        "confidence": metric.get("confidence"),
        "change_label": label_change(metric.get("pct_change")),
    }


def metric_map_from_control_effects(artifact: dict) -> dict[str, dict]:
    metrics: dict[str, dict] = {}
    for effect in artifact.get("target_effects", []):
        if not isinstance(effect, dict) or not effect.get("metric"):
            continue
        name = str(effect["metric"])
        metrics[name] = {
            "name": name,
            "current": effect.get("after"),
            "baseline": effect.get("expected"),
            "absolute_delta": effect.get("absolute_delta_vs_expected"),
            "pct_change": effect.get("pct_change_vs_expected"),
            "direction": effect.get("direction"),
            "confidence": effect.get("confidence"),
        }
    return metrics


def standard_derived_rates(metrics: dict[str, dict]) -> list[dict]:
    return [
        rate_row(
            "bot_like_share_pct",
            "Bot-like share",
            "bot_like_requests",
            "requests",
            metrics,
        ),
        rate_row("ai_share_pct", "AI share", "ai_requests", "requests", metrics),
        rate_row(
            "cache_miss_rate_pct",
            "Cache miss rate",
            "cache_misses",
            "requests",
            metrics,
        ),
        rate_row(
            "rate_limited_rate_pct",
            "429 rate-limit rate",
            "rate_limited_requests",
            "requests",
            metrics,
        ),
        rate_row(
            "error_5xx_rate_pct",
            "5xx error rate",
            "error_5xx_requests",
            "requests",
            metrics,
        ),
    ]


def control_followups(args: argparse.Namespace) -> list[dict]:
    if args.control_source == "posture":
        return [
            {
                "question": "Which ASNs drove the bot-like request movement?",
                "capture_preset": "posture-by-asn",
            },
            {
                "question": "Which paths drove the cache-miss or 429 movement?",
                "capture_preset": "posture-by-path",
            },
            {
                "question": "If SIEM summaries are available for another scope, do policy outcomes line up with this posture movement?",
                "capture_preset": "siem-policy",
            },
        ]
    return [
        {
            "question": "Which policy, action, or bot type drove the after-window movement?",
            "capture_preset": "siem-policy",
        },
        {
            "question": "Did protected crawler or verified bot populations see collateral rate-limit or deny changes?",
            "capture_preset": "siem-policy",
        },
        {
            "question": "Did traffic shift to other ASNs, paths, hosts, or bot categories after the control changed?",
            "capture_preset": "posture-by-asn",
        },
    ]


def build_evidence_packet(
    *,
    args: argparse.Namespace,
    artifact: dict,
    raw_path: Path,
    artifact_path: Path,
    granularity: str,
    table_used: str,
    baseline_start: datetime,
) -> dict:
    metrics = metric_by_name(artifact)
    metric_cards = []
    for metric in artifact.get("metrics", []):
        if not isinstance(metric, dict):
            continue
        metric_cards.append(metric_card_from_metric(metric))

    derived_rates = standard_derived_rates(metrics)

    total = metrics.get("requests", {})
    bot_like = metrics.get("bot_like_requests", {})
    ai = metrics.get("ai_requests", {})
    cache = metrics.get("cache_misses", {})
    findings = []
    for source, title in (
        (total, "Total request volume changed"),
        (bot_like, "Bot-like request volume changed"),
        (ai, "AI request volume changed"),
        (cache, "Cache-miss volume changed"),
    ):
        if not source:
            continue
        findings.append(
            {
                "title": title,
                "change_label": label_change(source.get("pct_change")),
                "evidence": (
                    f"{human_number(source.get('current'))} current vs "
                    f"{human_number(source.get('baseline'))} baseline "
                    f"({human_number(source.get('pct_change'), percent=True, signed=True)})."
                ),
            }
        )

    return {
        "schema_version": "bot_report_evidence.v1",
        "report_type": args.report,
        "title": args.title or "Bot & Edge Movement",
        "scope": {"cluster": args.cluster, "database": args.database},
        "query_context": {
            "cluster": args.cluster,
            "database": args.database,
            "table_used": table_used,
            "granularity": granularity,
            "raw_artifact_path": str(raw_path),
            "deterministic_artifact_path": str(artifact_path),
        },
        "current_window": artifact.get("current_window"),
        "baseline_windows": artifact.get("baseline_windows"),
        "metric_cards": metric_cards,
        "derived_rates": derived_rates,
        "headline_findings": findings,
        "suggested_followups": [
            {
                "question": "Which ASNs drove the bot-like request movement?",
                "capture_preset": "posture-by-asn",
            },
            {
                "question": "Which paths drove the cache-miss movement?",
                "capture_preset": "posture-by-path",
            },
            {
                "question": "Do SIEM policy outcomes line up with the bot-like movement?",
                "capture_preset": "siem-policy",
            },
        ],
        "interpretation_contract": {
            "allowed": [
                "Summarize only the fields in this packet.",
                "Compare metric changes and derived rates.",
                "Recommend follow-up queries from suggested_followups.",
            ],
            "forbidden": [
                "Do not claim root cause.",
                "Do not call traffic malicious without additional evidence.",
                "Do not introduce values not present in this packet.",
                "Do not query Hydrolix from the interpretation step.",
            ],
        },
        "template": {
            "sections": [
                "Executive Summary",
                "Key Changes",
                "Operational Interpretation",
                "Recommended Follow-ups",
                "Method and Caveats",
            ]
        },
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "baseline_start": baseline_start.isoformat().replace("+00:00", "Z"),
    }


def build_control_evidence_packet(
    *,
    args: argparse.Namespace,
    artifact: dict,
    raw_path: Path,
    artifact_path: Path,
    granularity: str,
    table_used: str,
    baseline_start: datetime,
) -> dict:
    metrics = metric_map_from_control_effects(artifact)
    metric_cards = [metric_card_from_metric(metric) for metric in metrics.values()]
    derived_rates = standard_derived_rates(metrics)
    effect_cards = []
    findings = []
    for effect in artifact.get("target_effects", []):
        if not isinstance(effect, dict):
            continue
        metric = str(effect.get("metric", ""))
        card = {
            "metric": metric,
            "label": METRIC_LABELS.get(metric, metric),
            "before": effect.get("before"),
            "after": effect.get("after"),
            "expected": effect.get("expected"),
            "absolute_delta_vs_expected": effect.get("absolute_delta_vs_expected"),
            "pct_change_vs_expected": effect.get("pct_change_vs_expected"),
            "before_display": human_number(effect.get("before")),
            "after_display": human_number(effect.get("after")),
            "expected_display": human_number(effect.get("expected")),
            "absolute_delta_vs_expected_display": human_number(
                effect.get("absolute_delta_vs_expected"),
                signed=True,
            ),
            "pct_change_vs_expected_display": human_number(
                effect.get("pct_change_vs_expected"),
                percent=True,
                signed=True,
            ),
            "direction": effect.get("direction"),
            "status": effect.get("status"),
            "confidence": effect.get("confidence"),
        }
        effect_cards.append(card)
        findings.append(
            {
                "title": f"{card['label']} vs expected",
                "change_label": str(effect.get("status") or "not evaluated"),
                "evidence": (
                    f"{card['after_display']} after vs {card['expected_display']} expected "
                    f"({card['pct_change_vs_expected_display']})."
                ),
            }
        )

    return {
        "schema_version": "bot_report_evidence.v1",
        "report_type": args.report,
        "title": args.title or "Bot Insights Control Review",
        "scope": {"cluster": args.cluster, "database": args.database},
        "query_context": {
            "cluster": args.cluster,
            "database": args.database,
            "table_used": table_used,
            "granularity": granularity,
            "raw_artifact_path": str(raw_path),
            "deterministic_artifact_path": str(artifact_path),
        },
        "change_time": artifact.get("change_time"),
        "target": artifact.get("target"),
        "before_window": artifact.get("before_window"),
        "after_window": artifact.get("after_window"),
        "expected_window": artifact.get("expected_window"),
        "expected_basis": artifact.get("expected_basis"),
        "target_effects": effect_cards,
        "metric_cards": metric_cards,
        "derived_rates": derived_rates,
        "collateral_checks": artifact.get("collateral_checks", []),
        "displacement_checks": artifact.get("displacement_checks", []),
        "headline_findings": findings,
        "suggested_followups": control_followups(args),
        "interpretation_contract": {
            "allowed": [
                "Summarize only the fields in this packet.",
                "Compare after-window metrics, derived rates, and expected values.",
                "Describe control-review caveats and recommend follow-up checks.",
            ],
            "forbidden": [
                "Do not claim the control caused the movement without external change evidence.",
                "Do not call traffic malicious without additional artifacts.",
                "Do not introduce values not present in this packet.",
                "Do not query Hydrolix from the interpretation step.",
                "Do not emit final HTML or Markdown layout.",
            ],
        },
        "template": {
            "sections": [
                "Control Review Summary",
                "Target Effects",
                "Collateral and Displacement Checks",
                "Operational Interpretation",
                "Recommended Follow-ups",
                "Method and Caveats",
            ]
        },
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "baseline_start": baseline_start.isoformat().replace("+00:00", "Z"),
    }


def selected_rank(index: dict, card: dict) -> int | None:
    for row in index.get("ranked_entities", []):
        if (
            isinstance(row, dict)
            and row.get("entity_type") == card.get("entity_type")
            and row.get("entity") == card.get("entity")
        ):
            rank = row.get("rank")
            return (
                int(rank)
                if isinstance(rank, int) and not isinstance(rank, bool)
                else None
            )
    return None


def select_scorecard(
    artifacts: dict,
    *,
    entity_type: str | None = None,
    entity_value: str | None = None,
) -> dict:
    scorecards = artifacts.get("scorecards")
    if not isinstance(scorecards, list) or not scorecards:
        raise SystemExit("Scorecard artifacts did not contain any emitted scorecards.")

    if entity_type or entity_value:
        if not entity_type or entity_value is None:
            raise SystemExit(
                "--entity-type and --entity-value must be supplied together."
            )
        for card in scorecards:
            if (
                isinstance(card, dict)
                and card.get("entity_type") == entity_type
                and str(card.get("entity")) == entity_value
            ):
                return card
        raise SystemExit(f"No scorecard found for {entity_type}={entity_value}.")

    index = artifacts.get("index")
    ranked = index.get("ranked_entities") if isinstance(index, dict) else None
    if isinstance(ranked, list) and ranked:
        top = ranked[0]
        if isinstance(top, dict):
            for card in scorecards:
                if (
                    isinstance(card, dict)
                    and card.get("entity_type") == top.get("entity_type")
                    and card.get("entity") == top.get("entity")
                ):
                    return card
    return scorecards[0]


SOC_INTERPRETATION_CONTRACT: dict[str, list[str]] = {
    "allowed": [
        "Summarize the SIEM-active SOC scorecard rows and emitted security_evidence features.",
        "Use score, band, confidence, blocked-request and auth-failure volumes, and recommended next steps.",
        "Describe SOC rowset limits and missing security inputs explicitly.",
    ],
    "forbidden": [
        "Do not call traffic malicious without additional artifacts.",
        "Do not invent SIEM metrics or other security evidence inputs.",
        "Do not query Hydrolix from the interpretation step.",
        "Do not emit final HTML or Markdown layout.",
    ],
}

SOC_TEMPLATE_SECTIONS = [
    "SOC Triage Summary",
    "Top Risky Entities",
    "Selected Entity",
    "Domain Scores",
    "Evaluated Security Evidence",
    "Missing Security Inputs",
    "Recommended Next Steps",
    "Method and Caveats",
]


CRAWLER_INTERPRETATION_CONTRACT: dict[str, list[str]] = {
    "allowed": [
        "Summarize the emitted crawler_governance scorecard features and rowset population.",
        "Use score, band, confidence, missing inputs, and recommended next steps.",
        "Describe rowset-limit caveats and missing crawler inputs explicitly.",
    ],
    "forbidden": [
        "Do not claim malicious crawler intent without additional artifacts.",
        "Do not invent missing feature inputs.",
        "Do not query Hydrolix from the interpretation step.",
        "Do not emit final HTML or Markdown layout.",
    ],
}

CRAWLER_TEMPLATE_SECTIONS = [
    "Crawler Governance Summary",
    "Top Crawler Entities",
    "Selected Entity",
    "Domain Scores",
    "Evaluated Crawler Evidence",
    "Missing Crawler Inputs",
    "Recommended Next Steps",
    "Method and Caveats",
]


EDGE_OPS_INTERPRETATION_CONTRACT: dict[str, list[str]] = {
    "allowed": [
        "Summarize the emitted edge_ops_impact scorecard features and entity population.",
        "Use score, band, confidence, missing inputs, and recommended next steps.",
        "Describe origin cost contribution and cache miss movement using only the emitted evidence.",
        "Describe rowset-limit caveats and missing edge/ops inputs explicitly.",
    ],
    "forbidden": [
        "Do not claim origin billing cost without real byte-level evidence.",
        "Do not invent missing feature inputs.",
        "Do not query Hydrolix from the interpretation step.",
        "Do not emit final HTML or Markdown layout.",
    ],
}

EDGE_OPS_TEMPLATE_SECTIONS = [
    "Edge & Origin Cost Summary",
    "Top Entities by Origin Pressure",
    "Selected Entity",
    "Domain Scores",
    "Evaluated Edge/Ops Evidence",
    "Top Cache-Impacting Paths",
    "Missing Edge/Ops Inputs",
    "Recommended Next Steps",
    "Method and Caveats",
]


def build_scorecard_fleet_evidence_packet(
    *,
    args: argparse.Namespace,
    artifacts: dict,
    raw_path: Path,
    artifact_path: Path,
    granularity: str,
    table_used: str,
    baseline_start: datetime,
) -> dict:
    """Fleet-shaped evidence packet for ``--fleet scorecard_brief``.

    The single-entity packet shape (``selected_entity`` +
    ``evaluated_feature_evidence``) anchors the LLM on one host's
    rules, which is exactly the wrong framing when the render is
    going to be a multi-entity ``scorecard_brief``. This builder
    swaps that section for fleet aggregates: band distribution, rule
    trigger counts across hosts, top-N entities by score, aggregate
    missing-input domains. The shape stays under the same
    ``bot_report_evidence.v1`` schema_version because the additions
    are additive — consumers that read only the universal fields
    (scope, query_context, interpretation_contract, rowset_context)
    keep working.
    """
    from collections import Counter

    index = artifacts.get("index") if isinstance(artifacts.get("index"), dict) else {}
    scorecards = [
        sc for sc in (artifacts.get("scorecards") or []) if isinstance(sc, dict)
    ]
    # Fail closed here too, not just in the render path. The
    # documented two-pass skill flow starts with ``--mode evidence``;
    # an empty-fleet packet would silently feed the LLM an aggregate
    # block full of zeros and an empty rule-trigger list, which would
    # encourage prose like "no rules triggered across the fleet" when
    # the real condition is "this cluster has nothing to render". Make
    # the failure mode the same as the render path's.
    if not scorecards:
        raise SystemExit(
            "Scorecard artifacts did not contain any emitted "
            "scorecards; --fleet has nothing to summarize."
        )
    n_total = len(scorecards)

    band_distribution: dict[str, int] = {}
    confidence_distribution: dict[str, int] = {}
    primary_domain_distribution: dict[str, int] = {}
    rule_trigger_counts: Counter[str] = Counter()
    missing_input_domains: Counter[str] = Counter()
    aggregate_recommended: dict[str, dict] = {}
    for sc in scorecards:
        band = sc.get("band")
        if band:
            band_distribution[band] = band_distribution.get(band, 0) + 1
        confidence = sc.get("confidence")
        if confidence:
            confidence_distribution[confidence] = (
                confidence_distribution.get(confidence, 0) + 1
            )
        primary = sc.get("primary_domain")
        if primary:
            primary_domain_distribution[primary] = (
                primary_domain_distribution.get(primary, 0) + 1
            )
        for rule in sc.get("rule_results") or []:
            if isinstance(rule, dict) and rule.get("status") == "triggered":
                name = rule.get("name")
                if name:
                    rule_trigger_counts[name] += 1
        for feature in sc.get("not_evaluated_features") or []:
            if isinstance(feature, dict):
                domain = feature.get("domain")
                if domain:
                    missing_input_domains[domain] += 1
        for step in sc.get("recommended_next_steps") or []:
            if isinstance(step, dict):
                detail = step.get("detail") or step.get("summary") or ""
            else:
                detail = str(step)
            detail = detail.strip()
            if not detail:
                continue
            entry = aggregate_recommended.setdefault(
                detail,
                {"detail": detail, "host_count": 0, "hosts": []},
            )
            entry["host_count"] += 1
            entity = sc.get("entity")
            if entity and entity not in entry["hosts"]:
                entry["hosts"].append(str(entity))

    scored = [sc for sc in scorecards if isinstance(sc.get("score"), (int, float))]
    top_entities = [
        {
            "entity_type": sc.get("entity_type"),
            "entity": sc.get("entity"),
            "score": sc.get("score"),
            "band": sc.get("band"),
            "primary_domain": sc.get("primary_domain"),
            "confidence": sc.get("confidence"),
        }
        for sc in sorted(scored, key=lambda s: -float(s.get("score") or 0))[:5]
    ]
    lowest_entities = [
        {
            "entity_type": sc.get("entity_type"),
            "entity": sc.get("entity"),
            "score": sc.get("score"),
            "band": sc.get("band"),
            "primary_domain": sc.get("primary_domain"),
            "confidence": sc.get("confidence"),
        }
        for sc in sorted(scored, key=lambda s: float(s.get("score") or 0))[:5]
    ]

    rule_triggers = [
        {"name": name, "host_count": count}
        for name, count in rule_trigger_counts.most_common()
    ]

    recommended_next_steps = sorted(
        ({
            "detail": entry["detail"],
            "host_count": entry["host_count"],
            "hosts": entry["hosts"][:5],
        } for entry in aggregate_recommended.values()),
        key=lambda e: (-e["host_count"], e["detail"]),
    )

    current_window = None
    baseline_windows = None
    if scorecards:
        current_window = scorecards[0].get("current_window")
        baseline_windows = scorecards[0].get("baseline_windows")

    interpretation_contract = {
        "allowed": [
            "Summarize fleet aggregates: band distribution, rule trigger counts, top and lowest scoring entities.",
            "Use the rule_triggers_across_fleet counts and the top_entities / lowest_entities lists to describe the shape of the fleet's risk.",
            "Describe rowset_context.total_ranked_entities, result_truncated, and producer_limit as caveats when relevant.",
        ],
        "forbidden": [
            "Do not single out an individual entity's evidence as if it were the whole fleet.",
            "Do not invent rule names, band labels, or hosts not present in this packet.",
            "Do not query Hydrolix from the interpretation step.",
            "Do not claim root cause or malicious intent from scorecard rules alone.",
            "Do not emit final HTML or Markdown layout.",
        ],
    }
    template_sections = [
        "Scorecard Interpretation",
        "Fleet Summary",
        "Rule Triggers Across Fleet",
        "Top and Lowest Entities",
        "Recommended Next Steps",
        "Method and Caveats",
    ]

    return {
        "schema_version": "bot_report_evidence.v1",
        "report_type": args.report,
        "title": args.title or "Bot Insights Scorecard Brief — Fleet",
        "scope": {"cluster": args.cluster, "database": args.database},
        "query_context": {
            "cluster": args.cluster,
            "database": args.database,
            "table_used": table_used,
            "granularity": granularity,
            "raw_artifact_path": str(raw_path),
            "deterministic_artifact_path": str(artifact_path),
            "producer_limit": args.scorecard_limit,
            "entity_selection": "fleet",
        },
        "fleet_summary": {
            "n_ranked_entities": n_total,
            "band_distribution": band_distribution,
            "confidence_distribution": confidence_distribution,
            "primary_domain_distribution": primary_domain_distribution,
            "missing_input_domains": dict(missing_input_domains),
        },
        "top_entities": top_entities,
        "lowest_entities": lowest_entities,
        "rule_triggers_across_fleet": rule_triggers,
        "recommended_next_steps": recommended_next_steps,
        "rowset_context": {
            "producer_limit": artifacts.get("producer_limit")
            or index.get("producer_limit"),
            "result_row_count": artifacts.get("result_row_count")
            or index.get("result_row_count"),
            "result_truncated": artifacts.get("result_truncated")
            or index.get("result_truncated"),
            "total_ranked_entities": artifacts.get("total_ranked_entities")
            or index.get("total_ranked_entities"),
        },
        "current_window": current_window,
        "baseline_windows": baseline_windows,
        "analysis_domains": (
            (scorecards[0].get("analysis_domains") if scorecards else None)
            or index.get("analysis_domains")
        ),
        "interpretation_contract": interpretation_contract,
        "template": {"sections": template_sections},
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "baseline_start": baseline_start.isoformat().replace("+00:00", "Z"),
    }


def build_scorecard_evidence_packet(
    *,
    args: argparse.Namespace,
    artifacts: dict,
    selected_card: dict,
    raw_path: Path,
    artifact_path: Path,
    granularity: str,
    table_used: str,
    baseline_start: datetime,
) -> dict:
    index = artifacts.get("index") if isinstance(artifacts.get("index"), dict) else {}
    if args.report == "soc_triage":
        default_title = "Bot Insights SOC Triage"
        interpretation_contract = SOC_INTERPRETATION_CONTRACT
        template_sections = SOC_TEMPLATE_SECTIONS
    elif args.report == "crawler_governance":
        default_title = "Bot Insights Crawler Governance"
        interpretation_contract = CRAWLER_INTERPRETATION_CONTRACT
        template_sections = CRAWLER_TEMPLATE_SECTIONS
    elif args.report == "edge_ops_impact":
        default_title = "Bot Insights Edge & Origin Cost"
        interpretation_contract = EDGE_OPS_INTERPRETATION_CONTRACT
        template_sections = EDGE_OPS_TEMPLATE_SECTIONS
    else:
        default_title = "Bot Insights Scorecard Brief"
        interpretation_contract = {
            "allowed": [
                "Summarize only the selected scorecard entity and emitted feature evidence.",
                "Use score, band, confidence, domain scores, missing inputs, and recommended next steps.",
                "Describe rowset limits and provenance caveats when present.",
            ],
            "forbidden": [
                "Do not invent metrics or missing scorecard inputs.",
                "Do not query Hydrolix from the interpretation step.",
                "Do not claim root cause or malicious intent from scorecard rules alone.",
                "Do not emit final HTML or Markdown layout.",
            ],
        }
        template_sections = [
            "Scorecard Interpretation",
            "Selected Entity",
            "Domain Scores",
            "Evaluated Feature Evidence",
            "Missing Scorecard Inputs",
            "Recommended Next Steps",
            "Method and Caveats",
        ]
    return {
        "schema_version": "bot_report_evidence.v1",
        "report_type": args.report,
        "title": args.title or default_title,
        "scope": {"cluster": args.cluster, "database": args.database},
        "query_context": {
            "cluster": args.cluster,
            "database": args.database,
            "table_used": table_used,
            "granularity": granularity,
            "raw_artifact_path": str(raw_path),
            "deterministic_artifact_path": str(artifact_path),
            "producer_limit": args.scorecard_limit,
            "entity_selection": "explicit" if args.entity_value else "top_ranked",
        },
        "selected_entity": {
            "entity_type": selected_card.get("entity_type"),
            "entity": selected_card.get("entity"),
            "rank": selected_rank(index, selected_card),
            "score": selected_card.get("score"),
            "band": selected_card.get("band"),
            "primary_domain": selected_card.get("primary_domain"),
            "confidence": selected_card.get("confidence"),
            "confidence_reasons": selected_card.get("confidence_reasons", []),
        },
        "domain_scores": selected_card.get("domain_scores", {}),
        "rule_results": selected_card.get("rule_results", []),
        "evaluated_feature_evidence": selected_card.get("features", []),
        "not_evaluated_features": selected_card.get("not_evaluated_features", []),
        "missing_inputs": sorted(
            {
                str(missing_input)
                for feature in selected_card.get("not_evaluated_features", [])
                if isinstance(feature, dict)
                for missing_input in feature.get("missing_inputs", [])
            }
        ),
        "recommended_next_steps": selected_card.get("recommended_next_steps", []),
        "evidence_summary": selected_card.get("evidence_summary", []),
        "rowset_context": {
            "rowset_scope": selected_card.get("rowset_scope"),
            "feature_provenance": selected_card.get("feature_provenance"),
            "producer_limit": artifacts.get("producer_limit")
            or index.get("producer_limit"),
            "result_row_count": artifacts.get("result_row_count")
            or index.get("result_row_count"),
            "result_truncated": artifacts.get("result_truncated")
            or index.get("result_truncated"),
            "total_ranked_entities": artifacts.get("total_ranked_entities")
            or index.get("total_ranked_entities"),
        },
        "current_window": selected_card.get("current_window"),
        "baseline_windows": selected_card.get("baseline_windows"),
        "analysis_domains": selected_card.get("analysis_domains")
        or index.get("analysis_domains"),
        "interpretation_contract": interpretation_contract,
        "template": {"sections": template_sections},
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "baseline_start": baseline_start.isoformat().replace("+00:00", "Z"),
    }


def load_raw_query_result(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(value, dict):
        return value
    if isinstance(value, list):
        return {"data": value, "rows": len(value)}
    raise SystemExit(
        f"Expected {path} to contain a Hydrolix MCP or ClickHouse JSON object."
    )


def result_rows(value: dict) -> list[dict]:
    rows = value.get("data")
    if isinstance(rows, list):
        return [row for row in rows if isinstance(row, dict)]
    rows = value.get("rows")
    if isinstance(rows, list):
        return [row for row in rows if isinstance(row, dict)]
    return []


def build_timeseries_artifact(
    *,
    args: argparse.Namespace,
    raw_value: dict,
    control_artifact: dict,
    table_used: str,
    granularity: str,
) -> dict:
    metrics = metric_map_from_control_effects(control_artifact)
    before_by_metric: dict[str, list[dict]] = {name: [] for name in metrics}
    after_by_metric: dict[str, list[dict]] = {name: [] for name in metrics}
    for row in result_rows(raw_value):
        period = str(row.get("period", "")).lower()
        bucket = row.get("bucket")
        if period not in {"before", "after"} or bucket is None:
            continue
        for name in metrics:
            value = row.get(name)
            point = {"timestamp": bucket, "value": value}
            if period == "before":
                before_by_metric[name].append(point)
            else:
                after_by_metric[name].append(point)

    series = []
    for name, metric in metrics.items():
        before_values = sorted(
            before_by_metric[name], key=lambda item: str(item.get("timestamp"))
        )
        after_values = sorted(
            after_by_metric[name], key=lambda item: str(item.get("timestamp"))
        )
        length = max(len(before_values), len(after_values))
        points = []
        for index in range(length):
            before_point = before_values[index] if index < len(before_values) else {}
            after_point = after_values[index] if index < len(after_values) else {}
            points.append(
                {
                    "baseline_timestamp": before_point.get("timestamp"),
                    "current_timestamp": after_point.get("timestamp"),
                    "baseline": before_point.get("value"),
                    "current": after_point.get("value"),
                }
            )
        if points:
            series.append(
                {
                    "name": name,
                    "label": METRIC_LABELS.get(name, name),
                    "current": metric.get("current"),
                    "baseline": metric.get("baseline"),
                    "absolute_delta": metric.get("absolute_delta"),
                    "pct_change": metric.get("pct_change"),
                    "points": points,
                }
            )

    return {
        "schema_version": "bot_timeseries.v1",
        "artifact_id": f"{args.report}-timeseries",
        "title": "Control Review Trends",
        "report_type": "control_review",
        "scope": control_artifact.get("scope", {}),
        "table_used": table_used,
        "granularity": granularity,
        "current_window": control_artifact.get("after_window", {}),
        "baseline_windows": [control_artifact.get("before_window", {})],
        "metrics": series,
        "interpretation_constraints": [
            "trend_shape_only",
            "no_causal_claim",
            "llm_may_summarize_structured_evidence_only",
        ],
    }


def add_report_metadata(
    *,
    raw_value: dict,
    args: argparse.Namespace,
    granularity: str,
    table_used: str,
    baseline_start: datetime,
) -> dict:
    enriched = dict(raw_value)
    enriched.update(
        {
            "comparison_type": "previous_window",
            "granularity": granularity,
            "table_used": table_used,
            "scope": {
                "cluster": args.cluster,
                "database": args.database,
            },
            "current_window": {
                "start": args.start,
                "end": args.end,
            },
            "baseline_windows": [
                {
                    "start": baseline_start.isoformat().replace("+00:00", "Z"),
                    "end": args.start,
                }
            ],
        }
    )
    return enriched


def add_control_metadata(
    *,
    raw_value: dict,
    args: argparse.Namespace,
    granularity: str,
    table_used: str,
    baseline_start: datetime,
) -> dict:
    enriched = dict(raw_value)
    if args.control_source == "posture":
        target = {"control_scope": "posture_summary"}
        target_metrics = [
            "requests",
            "bot_like_requests",
            "ai_requests",
            "cache_misses",
            "rate_limited_requests",
            "error_5xx_requests",
        ]
    else:
        target = (
            {"policy_id": args.policy_id}
            if args.policy_id
            else {"policy_scope": "all_policies"}
        )
        target_metrics = [
            "siem_blocked_requests",
            "siem_auth_fail_requests",
            "requests",
            "avg_bot_score",
            "unique_client_ips",
        ]
    enriched.update(
        {
            "comparison_type": "post_change_vs_expected",
            "granularity": granularity,
            "table_used": table_used,
            "change_time": args.change_time or args.start,
            "target": target,
            "scope": {
                "cluster": args.cluster,
                "database": args.database,
            },
            "before_window": {
                "start": baseline_start.isoformat().replace("+00:00", "Z"),
                "end": args.start,
            },
            "after_window": {
                "start": args.start,
                "end": args.end,
            },
            "expected_window": {
                "start": baseline_start.isoformat().replace("+00:00", "Z"),
                "end": args.start,
            },
            "expected_basis": "before_window",
            "target_metrics": target_metrics,
        }
    )
    return enriched


def add_scorecard_metadata(
    *,
    raw_value: dict,
    args: argparse.Namespace,
    granularity: str,
    table_used: str,
    baseline_start: datetime,
) -> dict:
    enriched = dict(raw_value)
    enriched.update(
        {
            "comparison_type": "previous_window",
            "granularity": granularity,
            "table_used": table_used,
            "scope": {
                "cluster": args.cluster,
                "database": args.database,
                "entity_type": args.entity_type,
            },
            "current_window": {
                "start": args.start,
                "end": args.end,
            },
            "baseline_windows": [
                {
                    "start": baseline_start.isoformat().replace("+00:00", "Z"),
                    "end": args.start,
                }
            ],
            "summary_table_used": True,
            "rowset_complete": False,
            "source_row_count": enriched.get("rows"),
            "producer_limit": args.scorecard_limit,
        }
    )
    if args.domains:
        enriched["analysis_domains"] = [
            item.strip() for item in args.domains.split(",") if item.strip()
        ]
    if args.report == "crawler_governance":
        population = CRAWLER_POPULATION_BY_ENTITY.get(args.entity_type)
        if population is not None:
            enriched["rowset_scope"] = {"population": population}
    return enriched


def analyst_note_from_args(args: argparse.Namespace) -> dict | None:
    text = args.analyst_notes
    if args.analyst_notes_file:
        text = Path(args.analyst_notes_file).expanduser().read_text(encoding="utf-8")
    if not text:
        return None
    return {
        "note_id": "llm-interpretation",
        "author_type": "llm",
        "title": {
            "executive_posture": "Executive Interpretation",
            "control_review": "Control Review Interpretation",
            "scorecard_brief": "Scorecard Interpretation",
            "soc_triage": "SOC Triage Interpretation",
            "crawler_governance": "Crawler Governance Interpretation",
            "edge_ops_impact": "Edge & Origin Cost Interpretation",
        }.get(args.report, "Analyst Interpretation"),
        "text": text.strip(),
        "show_data_sources": False,
        "data_sources": [],
    }


def build_report_wrapper(
    *,
    args: argparse.Namespace,
    artifacts: list[dict],
    analyst_note: dict | None = None,
) -> dict:
    wrapper = {
        "schema_version": "bot_report_input.v1",
        "report_type": args.report,
        "title": args.title
        or {
            "executive_posture": "Bot & Edge Movement",
            "control_review": "Bot Insights Control Review",
            "scorecard_brief": "Bot Insights Scorecard Brief",
            # The auto-generated form lowercases the SOC acronym ("Soc
            # Triage") which reads wrong; spell it explicitly.
            "soc_triage": "SOC Triage",
            "crawler_governance": "Crawler Governance",
            "edge_ops_impact": "Edge & Origin Cost",
        }.get(args.report, f"Bot Insights {args.report.replace('_', ' ').title()}"),
        "scope_label": f"{args.cluster}/{args.database}",
        "artifacts": artifacts,
        "analyst_notes": [analyst_note] if analyst_note else [],
    }
    return wrapper


def render_template_packet(packet: dict) -> str:
    findings = "\n".join(
        f"- {item['title']}: {item['evidence']}"
        for item in packet.get("headline_findings", [])
    )
    rates = "\n".join(
        "- "
        + f"{rate['label']}: {rate['current_display']} current vs "
        + f"{rate['baseline_display']} baseline "
        + f"({rate['delta_points_display']} percentage points)."
        for rate in packet.get("derived_rates", [])
    )
    metrics = "\n".join(
        "- "
        + f"{metric['label']}: {metric['current_display']} current vs "
        + f"{metric['baseline_display']} baseline; "
        + f"{metric['pct_change_display']} change."
        for metric in packet.get("metric_cards", [])
    )
    effects = "\n".join(
        "- "
        + f"{effect['label']}: {effect['after_display']} after vs "
        + f"{effect['expected_display']} expected; "
        + f"{effect['pct_change_vs_expected_display']} vs expected."
        for effect in packet.get("target_effects", [])
    )
    selected_entity = packet.get("selected_entity") or {}
    # Prefer the labelled domain_scores_labeled when present (added by
    # humanize_evidence_packet). Falls back to the raw domain_scores so
    # this renderer continues to work on packets that haven't been
    # enriched.
    domain_scores_source = packet.get("domain_scores_labeled") or packet.get("domain_scores") or {}
    domain_scores = "\n".join(
        f"- {domain}: {score}"
        for domain, score in domain_scores_source.items()
    )
    feature_evidence = "\n".join(
        "- "
        + f"{feature.get('domain_label') or feature.get('domain')} / "
        + f"{feature.get('name_label') or feature.get('name')}: "
        + f"{feature.get('evidence')}"
        for feature in packet.get("evaluated_feature_evidence", [])
        if isinstance(feature, dict)
    )
    followups = (
        "\n".join(
            f"- {item['question']} (`{item['capture_preset']}`)"
            for item in packet["suggested_followups"]
        )
        if "suggested_followups" in packet
        else "\n".join(
            f"- {item['detail'] if isinstance(item, dict) else item}"
            for item in packet.get("recommended_next_steps", [])
        )
    )
    context = packet["query_context"]
    return f"""# {packet["title"]}

## Executive Summary

LLM: Write 2-4 concise sentences using only the evidence below. Do not infer root cause.

## Key Changes

{findings or "- No headline findings available."}

## Rates

{rates or "- No derived rates available."}

## Metrics

{metrics or "- No metrics available."}

## Control Effects

{effects or "- No control effects available."}

## Selected Scorecard Entity

- Entity: {selected_entity.get("entity_type_label") or selected_entity.get("entity_type", "unavailable")}={selected_entity.get("entity", "unavailable")}
- Rank: {selected_entity.get("rank", "unavailable")}
- Score: {selected_entity.get("score", "unavailable")}
- Band: {selected_entity.get("band_label") or selected_entity.get("band", "unavailable")}
- Confidence: {selected_entity.get("confidence_label") or selected_entity.get("confidence", "unavailable")}

## Domain Scores

{domain_scores or "- No domain scores available."}

## Evaluated Feature Evidence

{feature_evidence or "- No evaluated feature evidence available."}

## Operational Interpretation

LLM: Explain what the changes may mean operationally. Keep this as hypotheses or checks, not causal claims.

## Recommended Follow-ups

{followups}

## Method and Caveats

- Data source: `{context["table_used"]}`
- Cluster: `{context["cluster"]}`
- Database: `{context["database"]}`
- Granularity: `{context["granularity"]}`
- Current/after window: `{json.dumps(packet.get("current_window") or packet.get("after_window"), sort_keys=True)}`
- Baseline/before windows: `{json.dumps(packet.get("baseline_windows") or packet.get("before_window"), sort_keys=True)}`
- This report is based on deterministic summary-table evidence. It does not identify root cause by itself.
"""


# ---- incident_report orchestrator ------------------------------------------
#
# The incident_report flow is materially different from the other report
# types: it produces two artifacts (``bot_incident_scope.v1`` and
# ``bot_incident_actors.v1``) via vetted SQL templates against the
# cluster's summary tables AND raw ``akamai.logs``, then ships the
# bundle through render_report.py. It does not pass through
# compare_posture.py or scorecard.py — the artifacts are assembled
# mechanically inside this script. The LLM emits prose only, into
# the three slots ``contexts/incident_report.NOTE_ID_TO_SLOT`` defines.
#
# Capture is reused as a generic SQL runner (``capture --sql ...``)
# for each phase. DESCRIBE-style introspection runs through
# ``system.columns`` (capture rejects non-SELECT statements, so a true
# DESCRIBE TABLE would be blocked).


INCIDENT_INTERPRETATION_CONTRACT: dict[str, list[str]] = {
    "allowed": [
        "Lead the executive_summary slot with a CISA-style assessment "
        "opening: 'Assessed with [high|medium|low] confidence: <criticality "
        "call>.' (Or an equivalent decisive first sentence that carries "
        "the same authority.) The slot renders above the Impact tiles, "
        "so a reader who only reads the opening should know whether to "
        "escalate and how solid the call is.",
        "Explain *why* the evidence reads that way - which combination of "
        "spike flags, suspicious-target reason flags, and SIEM signals "
        "is driving the call. State this as an opinion grounded in the "
        "named evidence, not a generic narration.",
        "Format the executive_summary as a hybrid when there are 3+ "
        "distinct parallel signals (different evidence sources concurring): "
        "a 1-sentence prose lead naming the pattern, a bulleted reasoning "
        "trail with one bullet per signal, then an optional 1-sentence "
        "closing interpretation. With 1-2 tightly-coupled signals or when "
        "reasoning interweaves with limitations, prefer integrated prose. "
        "Do not pad prose with inline (1)(2)(3) numbered reasons - use "
        "Markdown bullets instead. The colored criticality + confidence "
        "pills render above the slot already; do not restate them inside "
        "the prose.",
        "Summarize the incident's shape from the scope-confirmation evidence: "
        "request volume, 429 rate, 5xx rate, bot share, SIEM-blocked share.",
        "Describe actor concentration using the top rows in the actors section.",
        "Reference evidence with human-readable labels (Client IP, Client ASN, "
        "Request Path, User Agent, Country, Request host, Status code).",
        "State limitations explicitly when the actors section is empty or SIEM "
        "evidence is missing - including how that affects confidence in the "
        "criticality call.",
        "Name the top 1-3 suspicious targets explicitly using their "
        "human-readable label (Client IP `203.0.113.10`, Client ASN 64500, "
        "User Agent `python-requests/2.31`).",
        "Cite the reason flags that promoted each target - for example "
        "'flagged for high volume share and single-path concentration'.",
        "When the `anomaly` primitive fires on a target, name the "
        "baseline-relative magnitude explicitly (e.g. 'Browser cohort "
        "error rate climbed to X% vs ~Y% baseline, an N× departure'). "
        "The anomaly flag carries baseline corroboration the share-based "
        "primitives don't, so it warrants a sentence in the lede when "
        "present.",
        "Reference at least one target from the action-targets artifact in "
        "the next-steps slot.",
    ],
    "forbidden": [
        "Do not name internal tables (akamai.logs, bi_summary_*, "
        "bi_siem_policy_summary_*) — refer to 'this report's evidence' or to "
        "the report type by name.",
        "Do not claim malicious intent, abuse, attack causality, or root cause.",
        "Do not invent metrics, rankings, share percentages, deltas, severity "
        "labels, or dashboard URLs.",
        "Do not query Hydrolix from the interpretation step.",
        "Do not emit final HTML or Markdown layout.",
        "Do not write an executive_summary that only restates the Impact "
        "tiles - the slot must carry a criticality call and reasoning the "
        "tiles do not already convey.",
        "Do not summarize actor concentration in generic terms ('a small "
        "number of actors covered most traffic') without naming the specific "
        "top targets and their reason flags.",
        "Do not propose a specific mitigation action (block, rate-limit, "
        "challenge) - `suggested_action_hint` is mechanical and the LLM's "
        "job is to describe evidence, not propose enforcement.",
        "Do not modify the action-targets list or invent targets, reason "
        "flags, severities, or confidence labels.",
    ],
}


# Heuristic-ladder thresholds, the automation-UA pattern, and the
# templated-catchall path helper live in ``heuristics``; imported at
# the top of this module under their original names. The taxonomy
# tables below (field-to-target-type, ATT&CK mapping, individual vs.
# aggregate fields, target kind) stay here because they're not
# calibration knobs — changing them is a schema or contract change,
# not a tuning change.
_SUSPICIOUS_TARGET_TYPE_BY_FIELD = {
    "client_ip": "client_ip",
    "asn": "asn",
    "user_agent": "user_agent",
    "request_path": "request_path",
    "country": "country",
    "trafficCohort": "cohort",
}

# MITRE ATT&CK technique mapping per primitive.
#
# Each heuristic primitive maps to one or more techniques *consistent with*
# its signal. This is deliberately not "evidence of" — a single primitive
# alone is rarely conclusive, and the LLM contract forbids causal claims.
# The framing carried through to the rendered report is "techniques
# consistent with this signal," not "techniques used by this actor."
#
# Mapping rationale per primitive:
#   - `high_volume_share`: volume concentration alone is consistent with
#     volumetric attack patterns (DoS family). Specific technique
#     depends on path; we keep the mapping generic.
#   - `high_rate_429_share`: 429 spike indicates rate-limit pressure, the
#     hallmark of credential-stuffing / brute-force families.
#   - `single_path_concentration`: single-path focus paired with rate
#     pressure is the textbook credential-stuffing pattern.
#   - `single_asn_cluster`: multiple flagged IPs sharing one ASN is
#     consistent with VPS/proxy fleet acquisition.
#   - `botnet_member`: a cluster of flagged IPs whose combined volume
#     crosses the fleet-level share floor — the magnitude signal that
#     individual share% misses when fan-out splits the load across
#     thousands of nodes. Consistent with volumetric (DoS) patterns.
#   - `high_volume_new_actor`: a brand-new client IP whose absolute
#     volume crosses the share floor — captures lone high-volume IPs
#     across distinct ASNs that the cluster pivots miss. Consistent
#     with VPS-sourced volumetric / probing patterns.
#   - `automation_user_agent`: direct evidence of scripted, non-browser
#     HTTP clients.
#   - `anomaly`: behavioral departure in a normally-trusted cohort is
#     consistent with traffic passing classification by mimicking the
#     cohort it joined.
#   - `new_in_window`: novelty alone is pre-attack signal, not a technique
#     itself — no mapping.
#
# Update with care: the technique IDs ship in the artifact and are
# consumed by downstream WAF / SOC tooling. Changing an ID is a
# breaking change for those consumers.
_PRIMITIVE_ATTACK_TECHNIQUES: dict[str, list[dict]] = {
    "high_volume_share": [
        {"id": "T1498", "name": "Network Denial of Service", "tactic": "Impact"},
    ],
    "high_rate_429_share": [
        {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
    ],
    "single_path_concentration": [
        {
            "id": "T1110.004",
            "name": "Credential Stuffing",
            "tactic": "Credential Access",
        },
    ],
    "single_asn_cluster": [
        {
            "id": "T1583.003",
            "name": "Acquire Infrastructure: Virtual Private Server",
            "tactic": "Resource Development",
        },
    ],
    "botnet_member": [
        {"id": "T1498", "name": "Network Denial of Service", "tactic": "Impact"},
    ],
    "high_volume_new_actor": [
        {"id": "T1498", "name": "Network Denial of Service", "tactic": "Impact"},
        {
            "id": "T1583.003",
            "name": "Acquire Infrastructure: Virtual Private Server",
            "tactic": "Resource Development",
        },
    ],
    "automation_user_agent": [
        {
            "id": "T1071.001",
            "name": "Application Layer Protocol: Web Protocols",
            "tactic": "Command and Control",
        },
    ],
    "anomaly": [
        {"id": "T1036", "name": "Masquerading", "tactic": "Defense Evasion"},
    ],
    # `new_in_window` intentionally has no mapping — novelty isn't a technique.
}


def _attack_techniques_for_flags(flags: list[str]) -> list[dict]:
    """Union of ATT&CK techniques from a target's reason_flags, deduped by id.

    Order preserved from flag order so the rendered output reflects the
    investigative narrative (volume → rate → concentration → infra → UA).
    """
    out: list[dict] = []
    seen_ids: set[str] = set()
    for flag in flags:
        for tech in _PRIMITIVE_ATTACK_TECHNIQUES.get(flag, []):
            tech_id = tech["id"]
            if tech_id not in seen_ids:
                seen_ids.add(tech_id)
                out.append(dict(tech))
    return out


# Field-type taxonomy.
#
# Individual-entity fields (client_ip, asn, user_agent, request_path)
# enumerate many distinct values, most of which are a small share of
# the window. Share-based primitives (high_volume_share,
# high_rate_429_share, single_path_concentration, etc.) are meaningful
# here because a 5% share IS an outlier.
#
# Aggregate fields (cohort, country, status_code) enumerate a small
# fixed set of values, most of which are large shares of the window by
# construction (the Bot cohort, the US country). Share-based primitives
# would fire on every major value and produce noise. Only baseline-
# relative primitives — anomaly, new_in_window — fire on these fields,
# because those compare an entity against its own normal behavior.
#
# This split keeps the Suspicious Targets table actionable: a row with
# severity:high on an aggregate field means "this aggregate is behaving
# differently from how it normally does," not "this aggregate happens
# to be large."
_INDIVIDUAL_ENTITY_FIELDS = frozenset(
    {"client_ip", "asn", "user_agent", "request_path"}
)


# Role taxonomy for flagged signals. An ``actor`` is the WHO of the
# attack — the entity originating traffic. A ``target`` is the WHAT —
# the resource being hit. Same heuristic ladder catches both; the
# distinction matters for downstream SOC action because the action
# class (block / challenge / rate-limit / watch / monitor) differs
# fundamentally by role even at the same severity tier.
_TARGET_KIND_BY_TYPE = {
    "client_ip":    "actor",
    "asn":          "actor",
    "user_agent":   "actor",
    "cohort":       "actor",
    "country":      "actor",   # source country = who hit you
    "request_path": "target",
}


def _suspicious_action_class(
    target_type: str,
    severity: str,
    reason_flags: list[str] | set[str],
) -> str:
    """Descriptive (not prescriptive) action class for an indicator.

    Names the *kind* of mitigation the signal is typically actioned
    with at a WAF / SIEM consumer — so a downstream SOAR playbook can
    bucket indicators by mitigation pathway without each consumer
    re-deriving the same logic. **Not** a directive: the report still
    sets ``suggested_action_hint = "review"`` on every indicator. A
    consumer is expected to read this as "this indicator belongs in
    the block-list workflow if you have one" rather than "block this".

    Action classes:
      - ``block``: hard-deny at the edge. Used only when the entity is
        narrowly attributed (a verified-cluster IP, an automation UA
        like curl / python-requests). Low false-positive risk.
      - ``challenge``: graceful friction (JS / CAPTCHA / fingerprint).
        Right for high-confidence-but-not-conclusive actor signals —
        a singleton high-volume new IP, a UA caught by volume alone.
      - ``rate-limit``: path-scoped throttle. The natural mitigation
        for a target (endpoint) finding — protects the resource
        without per-actor identification.
      - ``watch``: surface in analyst review, no automatic edge
        action. Right for real-browser UA strings, ASN-level findings
        (too broad to block), low-severity actors with weak signals.
      - ``monitor``: track over time, no immediate action expected.
        Right for cohort-level findings and low-severity tail.
    """
    flags = set(reason_flags or [])
    if target_type == "client_ip":
        if severity == "critical":
            return "block"
        if severity == "high":
            # Volume / cluster signals are confidence-grade enough for
            # challenge friction. Anomaly-only highs are weaker — watch.
            if flags & {
                "high_volume_share", "high_rate_429_share",
                "botnet_member", "high_volume_new_actor",
            }:
                return "challenge"
            return "watch"
        return "monitor"
    if target_type == "user_agent":
        # Automation UAs (curl, python-requests, etc.) are narrowly
        # attributed to scripted clients — blockable.
        if "automation_user_agent" in flags:
            return "block" if severity in ("critical", "high") else "challenge"
        # Real-browser strings caught by volume / share alone — never
        # block UA-only, that drops genuine users. Watch and pair with
        # other signals before acting.
        return "watch"
    if target_type == "request_path":
        if severity in ("critical", "high"):
            return "rate-limit"
        return "monitor"
    if target_type == "asn":
        # ASN-level block is too broad — would drop legitimate
        # self-hosting customers, scrapers, etc. Watch only.
        return "watch"
    if target_type == "country":
        # Geo-rate-limit or watch — default watch.
        return "watch"
    if target_type == "cohort":
        # Behavioral grouping, not directly actionable.
        return "monitor"
    return "monitor"


_INCIDENT_DEFAULT_FIELDS = (
    "client_ip,asn,request_path,user_agent,country,status_code,request_method,trafficCohort"
)


_INCIDENT_FIELD_LABELS = {
    "client_ip": "Client IP",
    "asn": "Client ASN",
    "request_path": "Request Path",
    "user_agent": "User Agent",
    "country": "Country",
    "status_code": "Status Code",
    "request_method": "Request Method",
    "trafficCohort": "Traffic cohort",
}



def _capture_sql_to_rows(
    args: argparse.Namespace,
    sql: str,
    output_path: Path,
    *,
    label: str,
) -> tuple[list[dict], dict | None]:
    """Run a single ``capture --sql`` invocation and return parsed rows.

    Returns ``(rows, handoff_packet)``. ``handoff_packet`` is non-None
    when capture exited ``NEEDS_MCP_EXIT`` with a
    ``bot_hydrolix_mcp_query_request.v1`` packet. The orchestrator
    re-emits that packet upstream so the existing MCP handoff
    contract carries over unchanged.
    """
    capture_text = run(
        [
            sys.executable,
            str(CAPTURE),
            "--cluster",
            args.cluster,
            "--database",
            args.database,
            "--sql",
            sql,
            "--output",
            str(output_path),
        ],
        allowed_returncodes=(NEEDS_MCP_EXIT,),
    )
    try:
        summary = json.loads(capture_text) if capture_text else {}
    except json.JSONDecodeError as exc:
        raise SystemExit(
            f"{label}: capture did not return machine-readable JSON ({exc})."
        ) from exc
    if (
        isinstance(summary, dict)
        and summary.get("schema_version") == HANDOFF_SCHEMA
    ):
        return [], summary
    raw_value = load_raw_query_result(output_path)
    return result_rows(raw_value), None


def _incident_split_period_rows(rows: list[dict], *, source: str) -> dict:
    """Bucket UNION-ALL rows by ``period`` for a given ``source`` tag."""
    out: dict[str, dict] = {"current": {}, "baseline": {}}
    for row in rows:
        if row.get("source") != source:
            continue
        period = row.get("period")
        if period in out:
            out[period] = row
    return out


def _incident_compute_window_confirmation(
    rows: list[dict], siem_available: bool
) -> tuple[dict, dict]:
    """Return ``(window_confirmation, baseline_stats)`` from the phase-1 rows."""
    import baselines as baselines_mod

    summary = _incident_split_period_rows(rows, source="summary")
    current = summary.get("current") or {}
    baseline = summary.get("baseline") or {}

    def _num(row: dict, key: str) -> float:
        n = baselines_mod.to_number(row.get(key))
        return float(n) if n is not None else 0.0

    requests_current = _num(current, "requests")
    requests_baseline = _num(baseline, "requests")
    bot_current = _num(current, "bot_like_requests")
    bot_baseline = _num(baseline, "bot_like_requests")
    req_429_current = _num(current, "req_429")
    req_429_baseline = _num(baseline, "req_429")
    req_5xx_current = _num(current, "req_5xx")
    req_5xx_baseline = _num(baseline, "req_5xx")

    def _share(num: float, denom: float) -> float:
        return 100.0 * num / denom if denom > 0 else 0.0

    bot_share = _share(bot_current, requests_current)
    rate_429 = _share(req_429_current, requests_current)
    rate_5xx = _share(req_5xx_current, requests_current)
    blocked_share: float | None = None
    if siem_available:
        # Prefer the SIEM-table value when both sources exist — it carries
        # the authoritative ``actionClass`` semantics from the policy
        # summary.
        siem = _incident_split_period_rows(rows, source="siem")
        siem_current = siem.get("current") or {}
        siem_requests = _num(siem_current, "requests")
        siem_blocked = _num(siem_current, "blocked")
        if siem_requests > 0:
            blocked_share = _share(siem_blocked, siem_requests)
        else:
            blocked_share = 0.0
    else:
        # Fall back to raw ``akamai.logs`` action_applied counts. For
        # canonical-schema clusters (no separate SIEM summary table) the
        # Akamai DS2 stream carries the edge response inline so the deny
        # + monitor decision is visible directly from the access log.
        raw = _incident_split_period_rows(rows, source="raw")
        raw_current = raw.get("current") or {}
        raw_requests = _num(raw_current, "requests")
        denied = _num(raw_current, "denied_requests")
        monitored = _num(raw_current, "monitored_requests")
        if raw_requests > 0:
            blocked_share = _share(denied + monitored, raw_requests)

    # Spike flags fire on +25% volume/share moves vs the trailing window.
    spike_flags: list[str] = []
    if baselines_mod.pct_delta(requests_current, requests_baseline) >= 25:
        spike_flags.append("volume_up")
    if baselines_mod.pct_delta(bot_current, bot_baseline) >= 25:
        spike_flags.append("bot_share_up")
    if baselines_mod.pct_delta(req_429_current, req_429_baseline) >= 25:
        spike_flags.append("rate_429_up")
    if baselines_mod.pct_delta(req_5xx_current, req_5xx_baseline) >= 25:
        spike_flags.append("rate_5xx_up")

    window_confirmation = {
        "requests": int(requests_current),
        "bot_share_pct": baselines_mod.clean_number(round(bot_share, 2)),
        "rate_429_pct": baselines_mod.clean_number(round(rate_429, 2)),
        "rate_5xx_pct": baselines_mod.clean_number(round(rate_5xx, 2)),
        "blocked_share_pct": (
            baselines_mod.clean_number(round(blocked_share, 2))
            if blocked_share is not None
            else None
        ),
        "spike_flags": spike_flags,
    }
    baseline_stats = {
        "requests": int(requests_baseline),
        "bot_like_requests": int(bot_baseline),
        "req_429": int(req_429_baseline),
        "req_5xx": int(req_5xx_baseline),
    }
    return window_confirmation, baseline_stats


_INCIDENT_GRANULARITY_DELTA = {
    "minute": timedelta(minutes=1),
    "hour": timedelta(hours=1),
    "day": timedelta(days=1),
}


def _incident_compute_timeseries(
    rows: list[dict],
    *,
    granularity: str,
    current_start: datetime,
    current_end: datetime,
    baseline_start: datetime,
    baseline_end: datetime,
) -> dict | None:
    """Reshape per-bucket timeseries rows into the artifact's volume_timeseries field.

    Fills missing buckets with 0 so the chart's polyline does not get
    short-circuited by holes (a quiet baseline minute is still a
    legitimate data point). Returns ``None`` if no rows came back; the
    renderer then omits the chart instead of rendering an empty box.

    Series keys are stable identifiers (``requests_per_minute`` etc.)
    regardless of actual granularity — the chart-series selection rule
    in ``contexts/incident_report.py`` switches on these names. The
    bucket size is carried separately in the ``granularity`` field and
    used to humanize the chart labels.
    """
    import baselines as baselines_mod

    if not rows:
        return None

    bucket_delta = _INCIDENT_GRANULARITY_DELTA.get(
        granularity, timedelta(minutes=1)
    )

    def _to_dt(value: object) -> datetime | None:
        if isinstance(value, datetime):
            return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        if isinstance(value, str):
            try:
                return datetime.fromisoformat(
                    value.replace("Z", "+00:00")
                ).astimezone(timezone.utc)
            except ValueError:
                return None
        return None

    indexed: dict[tuple[str, datetime], dict] = {}
    for r in rows:
        period = r.get("period")
        bucket = _to_dt(r.get("bucket"))
        if period in ("current", "baseline") and bucket is not None:
            indexed[(period, bucket)] = r

    def _bucketize(start: datetime, end: datetime) -> list[datetime]:
        out: list[datetime] = []
        t = start
        while t < end:
            out.append(t)
            t += bucket_delta
        return out

    def _series_for(
        period: str, start: datetime, end: datetime, key: str
    ) -> list[int]:
        out: list[int] = []
        for b in _bucketize(start, end):
            row = indexed.get((period, b))
            if row is None:
                out.append(0)
            else:
                v = baselines_mod.to_number(row.get(key)) or 0
                out.append(int(v))
        return out

    granularity_label = granularity if granularity in ("minute", "hour", "day") else "minute"

    return {
        "granularity": granularity_label,
        "start": current_start.isoformat().replace("+00:00", "Z"),
        "end": current_end.isoformat().replace("+00:00", "Z"),
        "baseline_start": baseline_start.isoformat().replace("+00:00", "Z"),
        "baseline_end": baseline_end.isoformat().replace("+00:00", "Z"),
        "series": {
            "requests_per_minute": {
                "label": f"Requests per {granularity_label}",
                "spike_flag": "volume_up",
                "current": _series_for(
                    "current", current_start, current_end, "requests"
                ),
                "baseline": _series_for(
                    "baseline", baseline_start, baseline_end, "requests"
                ),
            },
            "req_429_per_minute": {
                "label": f"429s per {granularity_label}",
                "spike_flag": "rate_429_up",
                "current": _series_for(
                    "current", current_start, current_end, "req_429"
                ),
                "baseline": _series_for(
                    "baseline", baseline_start, baseline_end, "req_429"
                ),
            },
            "bot_like_requests_per_minute": {
                "label": f"Bot-classified requests per {granularity_label}",
                "spike_flag": "bot_share_up",
                "current": _series_for(
                    "current", current_start, current_end, "bot_like_requests"
                ),
                "baseline": _series_for(
                    "baseline", baseline_start, baseline_end, "bot_like_requests"
                ),
            },
        },
    }


def _incident_dimension_rows(
    rows: list[dict], *, total_current: float, include_delta: bool = True
) -> list[dict]:
    import baselines as baselines_mod

    out: list[dict] = []
    for row in rows:
        current = baselines_mod.to_number(row.get("current_requests")) or 0.0
        baseline = baselines_mod.to_number(row.get("baseline_requests")) or 0.0
        share = 100.0 * current / total_current if total_current > 0 else 0.0
        entry: dict = {
            "value": str(row.get("value") if row.get("value") is not None else ""),
            "requests": int(current),
            "share_pct": baselines_mod.clean_number(round(share, 2)),
        }
        if include_delta:
            entry["delta_vs_baseline_pct"] = baselines_mod.clean_number(
                round(baselines_mod.pct_delta(current, baseline), 2)
            )
        out.append(entry)
    return out


def _incident_status_rows(
    rows: list[dict], *, total_current: float
) -> list[dict]:
    import baselines as baselines_mod

    out: list[dict] = []
    for row in rows:
        requests = baselines_mod.to_number(row.get("requests")) or 0.0
        share = 100.0 * requests / total_current if total_current > 0 else 0.0
        status_code_val = baselines_mod.to_number(row.get("status_code"))
        out.append(
            {
                "status_code": int(status_code_val) if status_code_val is not None else None,
                "requests": int(requests),
                "share_pct": baselines_mod.clean_number(round(share, 2)),
            }
        )
    return out


def _incident_actor_rows(
    rows: list[dict],
) -> list[dict]:
    import baselines as baselines_mod

    out: list[dict] = []
    for row in rows:
        requests = baselines_mod.to_number(row.get("requests")) or 0.0
        req_429 = baselines_mod.to_number(row.get("req_429")) or 0.0
        req_5xx = baselines_mod.to_number(row.get("req_5xx")) or 0.0
        share_429 = 100.0 * req_429 / requests if requests > 0 else 0.0
        share_5xx = 100.0 * req_5xx / requests if requests > 0 else 0.0
        projected = {
            "value": str(row.get("value") if row.get("value") is not None else ""),
            "requests": int(requests),
            "bytes": int(baselines_mod.to_number(row.get("bytes")) or 0),
            "distinct_paths": int(
                baselines_mod.to_number(row.get("distinct_paths")) or 0
            ),
            "req_429": int(req_429),
            "req_5xx": int(req_5xx),
            "req_429_share_pct": baselines_mod.clean_number(round(share_429, 2)),
            "req_5xx_share_pct": baselines_mod.clean_number(round(share_5xx, 2)),
        }
        # Per-row ASN attribution (projected by the scoped-metrics query
        # for the ``client_ip`` field — ``any(asn) AS asn``). Feeds the
        # heuristic's verified per-ASN ``single_asn_cluster`` /
        # ``botnet_member`` pivots.
        raw_asn = row.get("asn")
        if raw_asn not in (None, "", 0):
            asn_num = baselines_mod.to_number(raw_asn)
            if asn_num is not None:
                projected["asn"] = int(asn_num)
        out.append(projected)
    return out


def _evaluate_share_flags(
    *,
    field: str,
    value: str,
    is_individual: bool,
    requests: float,
    share: float,
    share_429: float,
    total_429: float,
    distinct_paths: int,
) -> list[str]:
    """Share-based primitives. Apply only to individual-entity fields —
    on aggregate fields (cohort, country) they would fire on every
    major value by construction and produce noise. The
    ``single_path_concentration`` flag is suppressed for CMS-bucket
    templated patterns (``/:slug``, ``/:locale/...``) on the
    ``request_path`` field, where distinct_paths == 1 is tautological.
    """
    if not is_individual:
        return []
    flags: list[str] = []
    if share >= _SUSPICIOUS_VOLUME_SHARE_MIN:
        flags.append("high_volume_share")
    if (
        total_429 >= _SUSPICIOUS_RATE_429_TOTAL_MIN
        and share_429 >= _SUSPICIOUS_RATE_429_SHARE_MIN
    ):
        flags.append("high_rate_429_share")
    if (
        distinct_paths == 1
        and requests >= _SUSPICIOUS_SINGLE_PATH_REQUESTS_MIN
        and not (
            field == "request_path"
            and _is_templated_catchall_path(value)
        )
    ):
        flags.append("single_path_concentration")
    if field == "user_agent" and _AUTOMATION_UA_PATTERN.search(value):
        flags.append("automation_user_agent")
    return flags


def _evaluate_novelty_flags(
    *,
    field: str,
    value: str,
    baseline_data: dict[str, dict],
    share: float,
    requests: float,
) -> list[str]:
    """Absence-based primitives. ``new_in_window`` fires when ``value``
    is missing from the baseline. ``high_volume_new_actor`` is the
    magnitude-aware companion: a lone new IP doing high absolute
    volume carries real signal even without a peer cluster, capping
    the asymmetry where ``new_in_window`` alone treats a 100-req new
    IP the same as a 30M-req one. Scoped to ``client_ip`` because
    that's where the gap matters operationally — lone high-volume
    new UAs / paths are surfaced through other primitives.
    """
    if not value or value in baseline_data:
        return []
    flags = ["new_in_window"]
    if (
        field == "client_ip"
        and share >= _SUSPICIOUS_NEW_ACTOR_VOLUME_SHARE_MIN
        and requests >= _SUSPICIOUS_NEW_ACTOR_REQUESTS_MIN
    ):
        flags.append("high_volume_new_actor")
    return flags


def _evaluate_anomaly(
    baseline_row: dict | None,
    *,
    requests: float,
    current_error_rate: float,
    clean_number,
) -> tuple[list[str], dict]:
    """Baseline-rate departure check. Returns ``(["anomaly"], extras)``
    when the actor's current error rate is at least N× its own
    baseline (with absolute floors); otherwise ``([], {})``. Extras
    carry the rendered baseline rate + current rate + ratio so the
    renderer can show "Browser cohort error rate 11.4% vs ~0.5%
    baseline (22× departure)" instead of just naming the flag.
    """
    if baseline_row is None:
        return [], {}
    baseline_requests = baseline_row.get("requests") or 0
    baseline_errors = (
        (baseline_row.get("req_429") or 0)
        + (baseline_row.get("req_5xx") or 0)
    )
    baseline_error_rate = (
        baseline_errors / baseline_requests if baseline_requests > 0 else 0.0
    )
    if not (
        baseline_error_rate > 0
        and current_error_rate >= _ANOMALY_CURRENT_ERROR_RATE_MIN
        and requests >= _ANOMALY_MIN_REQUESTS
        and current_error_rate / baseline_error_rate >= _ANOMALY_ERROR_RATE_RATIO_MIN
    ):
        return [], {}
    return (
        ["anomaly"],
        {
            "baseline_error_rate_pct": clean_number(round(100.0 * baseline_error_rate, 2)),
            "current_error_rate_pct": clean_number(round(100.0 * current_error_rate, 2)),
            "error_rate_ratio": clean_number(
                round(current_error_rate / baseline_error_rate, 2)
            ),
        },
    )


def _evaluate_ranking_row(
    *,
    row: dict,
    row_idx: int,
    ranking_idx: int,
    field: str,
    target_type: str,
    is_individual: bool,
    baseline_data: dict[str, dict],
    total_current: float,
    total_429: float,
    baselines_mod,
) -> dict | None:
    """Run every per-row primitive against one actor-ranking row.

    Returns an ``intermediate`` entry (the unflagged-clean dict that
    feeds cross-row pivots + final tier assignment), or ``None`` if
    no flags fire. ``intermediate`` carries pre-computed share %s
    and the captured ASN attribution so the cross-row pivots don't
    re-derive them.
    """
    value = str(row.get("value") or "")
    requests = float(baselines_mod.to_number(row.get("requests")) or 0)
    req_429 = float(baselines_mod.to_number(row.get("req_429")) or 0)
    req_5xx = float(baselines_mod.to_number(row.get("req_5xx")) or 0)
    distinct_paths = int(baselines_mod.to_number(row.get("distinct_paths")) or 0)

    share = requests / total_current if total_current > 0 else 0.0
    share_429 = req_429 / total_429 if total_429 > 0 else 0.0
    current_error_rate = (
        (req_429 + req_5xx) / requests if requests > 0 else 0.0
    )

    flags: list[str] = _evaluate_share_flags(
        field=field,
        value=value,
        is_individual=is_individual,
        requests=requests,
        share=share,
        share_429=share_429,
        total_429=total_429,
        distinct_paths=distinct_paths,
    )
    flags.extend(
        _evaluate_novelty_flags(
            field=field,
            value=value,
            baseline_data=baseline_data,
            share=share,
            requests=requests,
        )
    )
    anomaly_flags, supporting_extras = _evaluate_anomaly(
        baseline_data.get(value),
        requests=requests,
        current_error_rate=current_error_rate,
        clean_number=baselines_mod.clean_number,
    )
    flags.extend(anomaly_flags)

    if not flags:
        return None

    # Per-row ASN attribution feeds the single_asn_cluster +
    # botnet_member pivots. Absence triggers the coarse-count fallback
    # so the heuristic stays backward-compatible with legacy producers
    # that don't carry IP -> ASN attribution.
    row_asn = row.get("asn")
    row_asn_org = row.get("asn_org") or row.get("asn_name") or ""
    return {
        "field": field,
        "ranking_idx": ranking_idx,
        "row_idx": row_idx,
        "target_type": target_type,
        "value": value,
        "flags": flags,
        "requests": requests,
        "share_pct": baselines_mod.clean_number(round(100.0 * share, 2)),
        "req_429": req_429,
        "req_429_share_pct": baselines_mod.clean_number(round(100.0 * share_429, 2)),
        "distinct_paths": distinct_paths,
        "supporting_extras": supporting_extras,
        "asn": row_asn if row_asn not in ("", None) else None,
        "asn_org": str(row_asn_org) if row_asn_org else "",
    }


def _apply_asn_grouped_pivots(
    flagged_client_ips: list[dict],
    total_current: float,
    *,
    clean_number,
) -> None:
    """Per-ASN grouping path. Rows without an ASN are excluded from
    clustering entirely — they're attribution-unknown and shouldn't
    claim membership in any specific cluster. Mutates rows in place.
    """
    groups: dict[object, list[dict]] = {}
    for row in flagged_client_ips:
        asn = row.get("asn")
        if asn in (None, "", 0):
            continue
        groups.setdefault(asn, []).append(row)
    for asn, members in groups.items():
        if len(members) < _SUSPICIOUS_ASN_CLUSTER_MIN_IPS:
            continue
        asn_org = next(
            (m.get("asn_org") for m in members if m.get("asn_org")), ""
        )
        for row in members:
            if "single_asn_cluster" not in row["flags"]:
                row["flags"].append("single_asn_cluster")
            extras = row.setdefault("supporting_extras", {})
            extras["asn_cluster_id"] = asn
            if asn_org:
                extras["asn_cluster_org"] = asn_org
            extras["asn_cluster_size"] = len(members)
        if total_current <= 0:
            continue
        cluster_requests = sum(m["requests"] for m in members)
        cluster_share = cluster_requests / total_current
        if cluster_share < _SUSPICIOUS_BOTNET_CLUSTER_SHARE_MIN:
            continue
        cluster_share_pct = clean_number(round(100.0 * cluster_share, 2))
        for row in members:
            if "botnet_member" not in row["flags"]:
                row["flags"].append("botnet_member")
            extras = row.setdefault("supporting_extras", {})
            extras["botnet_cluster_requests"] = int(cluster_requests)
            extras["botnet_cluster_share_pct"] = cluster_share_pct
            extras["botnet_cluster_size"] = len(members)


def _apply_unverified_cluster_pivots(
    flagged_client_ips: list[dict],
    total_current: float,
    *,
    clean_number,
) -> None:
    """Legacy fallback for producers without per-row ASN attribution.
    Uses the coarse count + total-share rule and marks the
    supporting_extras so downstream consumers can tell this is an
    approximation, not a verified same-ASN cluster. Mutates rows in
    place.
    """
    for row in flagged_client_ips:
        if "single_asn_cluster" not in row["flags"]:
            row["flags"].append("single_asn_cluster")
        extras = row.setdefault("supporting_extras", {})
        extras["asn_cluster_attribution"] = "unverified"
        extras["asn_cluster_size"] = len(flagged_client_ips)
    if total_current <= 0:
        return
    cluster_requests = sum(r["requests"] for r in flagged_client_ips)
    cluster_share = cluster_requests / total_current
    if cluster_share < _SUSPICIOUS_BOTNET_CLUSTER_SHARE_MIN:
        return
    cluster_share_pct = clean_number(round(100.0 * cluster_share, 2))
    for row in flagged_client_ips:
        if "botnet_member" not in row["flags"]:
            row["flags"].append("botnet_member")
        extras = row.setdefault("supporting_extras", {})
        extras["botnet_cluster_requests"] = int(cluster_requests)
        extras["botnet_cluster_share_pct"] = cluster_share_pct
        extras["botnet_cluster_size"] = len(flagged_client_ips)


def _apply_cluster_pivots(
    intermediate: list[dict],
    total_current: float,
    *,
    clean_number,
) -> None:
    """Cross-row pivots that add ``single_asn_cluster`` (shape) and
    ``botnet_member`` (magnitude) flags to flagged client_ip rows.
    Routes through per-ASN grouping when the producer carries ASN
    attribution, falling back to the coarse count + total-share rule
    when no row carries an ``asn`` field.
    """
    flagged_client_ips = [r for r in intermediate if r["field"] == "client_ip"]
    have_asn_attribution = any(
        r.get("asn") not in (None, "", 0) for r in flagged_client_ips
    )
    if have_asn_attribution:
        _apply_asn_grouped_pivots(
            flagged_client_ips, total_current, clean_number=clean_number,
        )
    elif len(flagged_client_ips) >= _SUSPICIOUS_ASN_CLUSTER_MIN_IPS:
        _apply_unverified_cluster_pivots(
            flagged_client_ips, total_current, clean_number=clean_number,
        )


def _assign_severity(
    flag_set: set[str],
    *,
    cross_field_corroboration: bool,
) -> tuple[str, str]:
    """Tier mapping → ``(severity, confidence)``. Anomaly is a
    baseline-corroborated signal so it counts as 2 toward the
    effective flag count: an anomaly-alone finding reaches
    ``severity: high``, share-based singles stay at ``medium``.
    ``critical`` additionally requires one flag from each of
    (quantitative) AND (concentration in shape) so a single-dimension
    actor never reaches the top tier.
    """
    flag_count = len(flag_set)
    effective_flag_count = flag_count + (1 if "anomaly" in flag_set else 0)
    if (
        effective_flag_count >= 3
        and bool(flag_set & _SUSPICIOUS_QUANT_FLAGS)
        and bool(flag_set & _SUSPICIOUS_CONCENTRATION_FLAGS)
    ):
        return "critical", "high" if cross_field_corroboration else "medium"
    if effective_flag_count >= 2:
        return "high", "high" if cross_field_corroboration else "medium"
    if flag_set & _SUSPICIOUS_QUANT_FLAGS:
        return "medium", "low"
    return "low", "low"


def _build_target_entry(row: dict, field_appearance: dict[str, int]) -> dict:
    """Project an ``intermediate`` row into a final
    ``bot_incident_action_targets.v1`` ``targets`` entry — tier
    assignment, supporting payload, evidence_refs, and the
    descriptive (not prescriptive) action_class.
    """
    flag_set = set(row["flags"])
    cross_field_corroboration = field_appearance.get(row["value"], 0) >= 2
    severity, confidence = _assign_severity(
        flag_set, cross_field_corroboration=cross_field_corroboration,
    )
    supporting = {
        "requests": int(row["requests"]),
        "share_pct": row["share_pct"],
        "req_429": int(row["req_429"]),
        "req_429_share_pct": row["req_429_share_pct"],
        "distinct_paths": row["distinct_paths"],
    }
    supporting.update(row.get("supporting_extras") or {})
    return {
        "target_type": row["target_type"],
        "target_value": row["value"],
        "kind": _TARGET_KIND_BY_TYPE.get(row["target_type"], "actor"),
        "action_class": _suspicious_action_class(
            row["target_type"], severity, row["flags"],
        ),
        "reason_flags": list(row["flags"]),
        "attack_techniques": _attack_techniques_for_flags(row["flags"]),
        "severity": severity,
        "supporting": supporting,
        "suggested_action_hint": "review",
        "confidence": confidence,
        "evidence_refs": [
            {
                "artifact": "bot_incident_actors.v1",
                "json_pointer": (
                    f"/actor_rankings/{row['ranking_idx']}/rows/"
                    f"{row['row_idx']}"
                ),
            }
        ],
    }


def _evaluate_all_rankings(
    rankings: list[dict],
    baseline_actor_rows_by_field: dict[str, dict[str, dict]],
    *,
    total_current: float,
    total_429: float,
    baselines_mod,
) -> tuple[list[dict], dict[str, int]]:
    """Walk every actor ranking, evaluate each row's heuristic flags,
    and return (intermediate flagged rows, value→appearance count).
    Rankings whose field isn't in the target-type taxonomy are
    skipped silently — that's the contract for unknown producers.
    """
    field_appearance: dict[str, int] = {}
    intermediate: list[dict] = []
    for ranking_idx, ranking in enumerate(rankings):
        field = ranking.get("field") or ""
        target_type = _SUSPICIOUS_TARGET_TYPE_BY_FIELD.get(field)
        if target_type is None:
            continue
        baseline_data = baseline_actor_rows_by_field.get(field, {})
        is_individual = field in _INDIVIDUAL_ENTITY_FIELDS
        for row_idx, row in enumerate(ranking.get("rows") or []):
            entry = _evaluate_ranking_row(
                row=row,
                row_idx=row_idx,
                ranking_idx=ranking_idx,
                field=field,
                target_type=target_type,
                is_individual=is_individual,
                baseline_data=baseline_data,
                total_current=total_current,
                total_429=total_429,
                baselines_mod=baselines_mod,
            )
            if entry is None:
                continue
            field_appearance[entry["value"]] = (
                field_appearance.get(entry["value"], 0) + 1
            )
            intermediate.append(entry)
    return intermediate, field_appearance


def _compute_suspicious_targets(
    scope_artifact: dict,
    actors_artifact: dict,
    baseline_actor_rows_by_field: dict[str, dict[str, dict]],
) -> list[dict]:
    """Run the heuristic ladder mechanically against the actor rankings.

    Returns rows in canonical order: severity desc, then requests desc.
    Each row matches the ``bot_incident_action_targets.v1`` ``targets``
    shape — including ``supporting``, ``severity``, ``confidence``,
    ``reason_flags``, ``suggested_action_hint`` (always ``review``),
    and ``evidence_refs``.

    ``scope_artifact`` supplies the in-window totals used for
    share-of-window checks. ``baseline_actor_rows_by_field`` maps each
    resolved field to a dict of ``value`` -> ``{requests, req_429,
    req_5xx}`` for actors observed during the baseline window —
    absence still satisfies the ``new_in_window`` contract; presence
    feeds the ``anomaly`` primitive's baseline-rate comparison.

    Field-type taxonomy:
      - Individual-entity fields (client_ip, asn, user_agent,
        request_path) — share-based primitives apply.
      - Aggregate fields (cohort, country) — only baseline-relative
        primitives (anomaly, new_in_window) apply, because share-based
        primitives produce noise when every major value is a big share
        by construction.
    """
    import baselines as baselines_mod

    window = scope_artifact.get("window_confirmation") or {}
    total_current = float(baselines_mod.to_number(window.get("requests")) or 0)
    rate_429_pct = float(baselines_mod.to_number(window.get("rate_429_pct")) or 0)
    total_429 = total_current * rate_429_pct / 100.0

    intermediate, field_appearance = _evaluate_all_rankings(
        actors_artifact.get("actor_rankings") or [],
        baseline_actor_rows_by_field,
        total_current=total_current,
        total_429=total_429,
        baselines_mod=baselines_mod,
    )
    _apply_cluster_pivots(
        intermediate, total_current, clean_number=baselines_mod.clean_number,
    )

    targets = [_build_target_entry(row, field_appearance) for row in intermediate]
    targets.sort(
        key=lambda t: (
            _SEVERITY_RANK.get(t["severity"], 99),
            -int(t["supporting"]["requests"]),
        )
    )
    return targets


def _build_action_targets_artifact(
    scope_meta: dict,
    suspicious_targets: list[dict],
    *,
    heuristic_version: str = "v2",
    limitations: list[str] | None = None,
) -> dict:
    """Wrap a list of suspicious-target rows in the canonical artifact shape."""
    return {
        "artifact_id": "incident-action-targets-1",
        "schema_version": "bot_incident_action_targets.v1",
        "scope": scope_meta,
        "targets": suspicious_targets,
        "heuristic_version": heuristic_version,
        "limitations": list(limitations or []),
    }


def _resolve_dashboard_url(args: argparse.Namespace) -> str:
    """Look up ``BI_INCIDENT_DASHBOARD_URL`` from the cluster env, then
    substitute scope placeholders mechanically. Returns ``""`` when
    unset — the renderer omits the handoff block in that case.
    """
    import os
    import shutil

    env_path = Path(
        f"~/.config/hydrolix/clusters/{args.cluster}.env"
    ).expanduser()
    template = ""
    if env_path.exists():
        for line in env_path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if stripped.startswith("BI_INCIDENT_DASHBOARD_URL="):
                template = stripped.split("=", 1)[1].strip().strip("'\"")
                break
    if not template:
        template = os.environ.get("BI_INCIDENT_DASHBOARD_URL", "")
    if not template:
        return ""
    return (
        template.replace("{start}", args.start)
        .replace("{end}", args.end)
        .replace("{host}", args.host or "")
        .replace("{asn}", str(args.asn) if args.asn else "")
        .replace("{path_pattern}", args.path_pattern or "")
    )


def _emit_handoff_packet(
    packet: dict,
    args: argparse.Namespace,
    granularity: str,
    baseline_start: datetime,
    artifact: str,
) -> int:
    report_context = packet.get("report_context")
    if not isinstance(report_context, dict):
        report_context = {}
    report_context.update(
        {
            "report": args.report,
            "mode": args.mode,
            "artifact": artifact,
            "start": args.start,
            "end": args.end,
            "baseline_start": baseline_start.isoformat().replace("+00:00", "Z"),
            "granularity": granularity,
        }
    )
    packet["report_context"] = report_context
    print(json.dumps(packet, sort_keys=True))
    return NEEDS_MCP_EXIT


def _run_incident_report(
    args: argparse.Namespace,
    start: datetime,
    end: datetime,
    baseline_start: datetime,
    sample_dir: Path,
    output_path: Path,
) -> int:
    """End-to-end orchestrator for ``--report incident_report``.

    Flow:
      1. Run ``system.columns`` queries to detect ``akamai.logs`` and the
         SIEM policy summary table. Validate ``--fields`` mechanically.
      2. Run a single phase-1 SQL query (summary + optional SIEM blocked
         share) plus dimension/status/country queries.
      3. If raw drilldown is available, run one actor query per resolved
         field against ``akamai.logs``.
      4. Assemble ``bot_incident_scope.v1`` and ``bot_incident_actors.v1``,
         build an evidence packet, then either emit ``--mode evidence``
         or render via ``render_report.py``.

    MCP-handoff: any capture call that exits ``NEEDS_MCP_EXIT`` is
    re-emitted upstream with the report-context metadata appended.
    """
    granularity = choose_granularity(start, end)
    summary_table = f"{args.database}.bi_summary_{granularity}"
    siem_table_candidate = f"{args.database}.bi_siem_policy_summary_{granularity}"

    requested_fields = [
        name.strip()
        for name in (args.fields or _INCIDENT_DEFAULT_FIELDS).split(",")
        if name.strip()
    ]
    top_n = max(1, int(args.top_n or 10))

    # --- Step 1: introspect column availability ----------------------------
    columns_logs_path = sample_dir / f"{args.report}-columns-logs.json"
    logs_rows, handoff = _capture_sql_to_rows(
        args,
        _incident_columns_query(args.database, "logs"),
        columns_logs_path,
        label="akamai.logs columns",
    )
    if handoff is not None:
        return _emit_handoff_packet(
            handoff, args, granularity, baseline_start, artifact="columns_logs"
        )
    logs_columns = {row.get("name") for row in logs_rows if row.get("name")}
    raw_drilldown_available = bool(logs_columns)

    columns_siem_path = sample_dir / f"{args.report}-columns-siem.json"
    siem_rows, handoff = _capture_sql_to_rows(
        args,
        _incident_columns_query(
            args.database, f"bi_siem_policy_summary_{granularity}"
        ),
        columns_siem_path,
        label="SIEM columns",
    )
    if handoff is not None:
        return _emit_handoff_packet(
            handoff, args, granularity, baseline_start, artifact="columns_siem"
        )
    siem_available = bool({row.get("name") for row in siem_rows if row.get("name")})
    siem_table = siem_table_candidate if siem_available else None

    # --- Step 2: validate --fields against the column list ----------------
    fields_resolved: list[str] = []
    fields_unresolved: list[str] = []
    if raw_drilldown_available:
        for field in requested_fields:
            if field in logs_columns:
                fields_resolved.append(field)
            else:
                fields_unresolved.append(field)
        if fields_unresolved:
            print(
                "ERROR: --fields contains names not present on this cluster's "
                f"raw access log: {', '.join(fields_unresolved)}. "
                "Resolve the column names before re-running.",
                file=sys.stderr,
            )
            return 2

    limitations_scope: list[str] = []
    limitations_actors: list[str] = []
    if not siem_available:
        limitations_scope.append(
            "SIEM policy summary table not present on this cluster; SIEM "
            "mixes are not available."
        )
    if not raw_drilldown_available:
        limitations_actors.append(
            "akamai.logs is not present on this cluster; per-actor "
            "drilldown is not available."
        )

    # --- Step 3: phase-1 captures (summary + optional SIEM blocked share) -
    wc_path = sample_dir / f"{args.report}-phase1-window.json"
    wc_rows, handoff = _capture_sql_to_rows(
        args,
        _incident_window_confirmation_sql(
            summary_table,
            siem_table,
            start,
            end,
            baseline_start,
            args.host,
            args.asn,
            args.path_pattern,
            raw_drilldown_available=raw_drilldown_available,
        ),
        wc_path,
        label="window confirmation",
    )
    if handoff is not None:
        return _emit_handoff_packet(
            handoff, args, granularity, baseline_start, artifact="phase1_window"
        )
    window_confirmation, _baseline_stats = (
        _incident_compute_window_confirmation(wc_rows, siem_available)
    )

    # --- Step 3b: per-bucket volume timeseries (drives the Impact chart) ---
    # One extra grouped scan of the same summary table the window-
    # confirmation query already touched. Same time bounds, same scope
    # predicate. Returns per-bucket (period, requests, req_429,
    # bot_like_requests) which the compute helper reshapes into three
    # series consumed by the renderer's mechanical chart-selection rule.
    ts_path = sample_dir / f"{args.report}-phase1-timeseries.json"
    ts_rows, handoff = _capture_sql_to_rows(
        args,
        _incident_volume_timeseries_sql(
            summary_table,
            granularity,
            start,
            end,
            baseline_start,
            args.host,
            args.asn,
            args.path_pattern,
        ),
        ts_path,
        label="volume timeseries",
    )
    if handoff is not None:
        return _emit_handoff_packet(
            handoff, args, granularity, baseline_start, artifact="phase1_timeseries"
        )
    volume_timeseries = _incident_compute_timeseries(
        ts_rows,
        granularity=granularity,
        current_start=start,
        current_end=end,
        baseline_start=baseline_start,
        baseline_end=start,
    )

    def _run_dimension(table: str, dimension: str, label: str) -> list[dict]:
        out_path = sample_dir / f"{args.report}-phase1-{label}.json"
        rows, hop = _capture_sql_to_rows(
            args,
            _incident_dimension_sql(
                table,
                dimension,
                start,
                end,
                baseline_start,
                args.host,
                args.asn,
                args.path_pattern,
                top_n,
            ),
            out_path,
            label=label,
        )
        if hop is not None:
            raise _IncidentHandoff(hop, label)
        return rows

    def _run_siem_dimension(dimension: str, label: str) -> list[dict]:
        assert siem_table is not None
        out_path = sample_dir / f"{args.report}-phase1-{label}.json"
        rows, hop = _capture_sql_to_rows(
            args,
            _incident_siem_dimension_sql(
                siem_table,
                dimension,
                start,
                end,
                baseline_start,
                args.host,
                args.asn,
                args.path_pattern,
                top_n,
            ),
            out_path,
            label=label,
        )
        if hop is not None:
            raise _IncidentHandoff(hop, label)
        return rows

    try:
        hosts_rows = _run_dimension(summary_table, "reqHost", "top_hosts")
        path_rows = _run_dimension(
            summary_table, "requestPathPattern", "top_path_patterns"
        )
        country_rows = _run_dimension(summary_table, "country", "country_mix")
        status_rows, hop = _capture_sql_to_rows(
            args,
            _incident_status_mix_sql(
                summary_table,
                start,
                end,
                args.host,
                args.asn,
                args.path_pattern,
                top_n,
            ),
            sample_dir / f"{args.report}-phase1-status_mix.json",
            label="status mix",
        )
        if hop is not None:
            return _emit_handoff_packet(
                hop, args, granularity, baseline_start, artifact="status_mix"
            )
        siem_action_rows: list[dict] = []
        siem_policy_rows: list[dict] = []
        siem_bot_type_rows: list[dict] = []
        if siem_available:
            siem_action_rows = _run_siem_dimension("actionClass", "siem_action")
            siem_policy_rows = _run_siem_dimension("policyId", "siem_policy")
            siem_bot_type_rows = _run_siem_dimension("botType", "siem_bot_type")
        edge_action_mix_rows: list[dict] = []
        deny_rule_mix_rows: list[dict] = []
        if raw_drilldown_available:
            edge_action_rows_raw, hop = _capture_sql_to_rows(
                args,
                _incident_edge_action_mix_sql(
                    start,
                    end,
                    baseline_start,
                    args.host,
                    args.asn,
                    args.path_pattern,
                    top_n,
                ),
                sample_dir / f"{args.report}-phase1-edge_action_mix.json",
                label="edge action mix",
            )
            if hop is not None:
                raise _IncidentHandoff(hop, "edge_action_mix")
            edge_action_mix_rows = edge_action_rows_raw
            deny_rule_rows_raw, hop = _capture_sql_to_rows(
                args,
                _incident_deny_rule_mix_sql(
                    start,
                    end,
                    baseline_start,
                    args.host,
                    args.asn,
                    args.path_pattern,
                    top_n,
                ),
                sample_dir / f"{args.report}-phase1-deny_rule_mix.json",
                label="deny rule mix",
            )
            if hop is not None:
                raise _IncidentHandoff(hop, "deny_rule_mix")
            deny_rule_mix_rows = deny_rule_rows_raw
    except _IncidentHandoff as exc:
        return _emit_handoff_packet(
            exc.packet, args, granularity, baseline_start, artifact=exc.label
        )

    total_current = float(window_confirmation.get("requests") or 0)

    scope_meta = {
        "cluster": args.cluster,
        "database": args.database,
        "start": args.start,
        "end": args.end,
        "baseline_start": baseline_start.isoformat().replace("+00:00", "Z"),
        "baseline_end": args.start,
        "granularity": granularity,
        "host": args.host,
        "asn": args.asn,
        "path_pattern": args.path_pattern,
        "siem_available": siem_available,
    }

    scope_artifact = {
        "artifact_id": "incident-scope-1",
        "schema_version": "bot_incident_scope.v1",
        "scope": scope_meta,
        "window_confirmation": window_confirmation,
        "volume_timeseries": volume_timeseries,
        "top_targeted_hosts": _incident_dimension_rows(
            hosts_rows, total_current=total_current
        ),
        "top_targeted_path_patterns": _incident_dimension_rows(
            path_rows, total_current=total_current
        ),
        "status_mix": _incident_status_rows(
            status_rows, total_current=total_current
        ),
        "country_mix": _incident_dimension_rows(
            country_rows, total_current=total_current
        ),
        "siem_action_mix": (
            _incident_dimension_rows(siem_action_rows, total_current=total_current)
            if siem_available
            else None
        ),
        "siem_policy_mix": (
            _incident_dimension_rows(siem_policy_rows, total_current=total_current)
            if siem_available
            else None
        ),
        "siem_bot_type_mix": (
            _incident_dimension_rows(
                siem_bot_type_rows, total_current=total_current
            )
            if siem_available
            else None
        ),
        "edge_action_mix": (
            _incident_dimension_rows(
                edge_action_mix_rows, total_current=total_current
            )
            if raw_drilldown_available
            else None
        ),
        "deny_rule_mix": (
            _incident_dimension_rows(
                deny_rule_mix_rows, total_current=total_current
            )
            if raw_drilldown_available
            else None
        ),
        "dashboard_url": _resolve_dashboard_url(args),
        "limitations": limitations_scope,
    }

    # --- Step 4: phase-2 actor queries ------------------------------------
    # Two-step pattern per field: ``topK(N)`` (Filtered Space-Saving,
    # O(K) memory) yields the candidate list, then a scoped metrics
    # GROUP BY computes per-actor stats bounded to that list. Replaces
    # the v1 single-shot ``GROUP BY field ORDER BY count() DESC LIMIT N``
    # that OOM'd at scale on high-cardinality fields like ``client_ip``.
    actor_rankings: list[dict] = []
    current_candidates_by_field: dict[str, list[str]] = {}
    if raw_drilldown_available and fields_resolved:
        for field in fields_resolved:
            topk_path = sample_dir / f"{args.report}-phase2-{field}-topk.json"
            topk_rows, hop = _capture_sql_to_rows(
                args,
                _incident_actor_topk_sql(
                    field, start, end, args.host, args.asn, args.path_pattern, top_n,
                ),
                topk_path,
                label=f"actors_topk:{field}",
            )
            if hop is not None:
                return _emit_handoff_packet(
                    hop, args, granularity, baseline_start,
                    artifact=f"actors_topk_{field}",
                )
            candidates = (
                [str(v) for v in (topk_rows[0].get("candidates") or []) if v]
                if topk_rows else []
            )
            current_candidates_by_field[field] = candidates
            if not candidates:
                actor_rankings.append(
                    {
                        "field": field,
                        "field_label": _INCIDENT_FIELD_LABELS.get(
                            field, field.replace("_", " ").title()
                        ),
                        "rows": [],
                    }
                )
                continue

            metrics_path = sample_dir / f"{args.report}-phase2-{field}.json"
            rows, hop = _capture_sql_to_rows(
                args,
                _incident_actor_scoped_metrics_sql(
                    field, candidates, start, end,
                    args.host, args.asn, args.path_pattern,
                    full_metrics=True,
                ),
                metrics_path,
                label=f"actors:{field}",
            )
            if hop is not None:
                return _emit_handoff_packet(
                    hop, args, granularity, baseline_start,
                    artifact=f"actors_{field}",
                )
            actor_rankings.append(
                {
                    "field": field,
                    "field_label": _INCIDENT_FIELD_LABELS.get(
                        field, field.replace("_", " ").title()
                    ),
                    "rows": _incident_actor_rows(rows),
                }
            )

    actors_artifact = {
        "artifact_id": "incident-actors-1",
        "schema_version": "bot_incident_actors.v1",
        "scope": scope_meta,
        "raw_drilldown_available": raw_drilldown_available,
        "raw_table": "akamai.logs",
        "fields_resolved": fields_resolved,
        "fields_unresolved": fields_unresolved,
        "top_n": top_n,
        "actor_rankings": actor_rankings,
        "limitations": limitations_actors,
    }

    # --- Step 4b: baseline-actor queries + suspicious-target heuristics ----
    # Same two-step pattern over the baseline window. The baseline
    # topK is its own candidate set (matches the v1 baseline GROUP BY
    # LIMIT N semantics — the heuristic's ``new_in_window`` primitive
    # interprets "value not in baseline_actor_rows_by_field" as
    # "value not in baseline's top-N", which the existing tests pin).
    baseline_actor_rows_by_field: dict[str, dict[str, dict]] = {}
    action_targets_limitations: list[str] = []
    if raw_drilldown_available and fields_resolved:
        for field in fields_resolved:
            baseline_topk_path = (
                sample_dir / f"{args.report}-phase2-{field}-baseline-topk.json"
            )
            topk_rows, hop = _capture_sql_to_rows(
                args,
                _incident_actor_topk_baseline_sql(
                    field, baseline_start, start,
                    args.host, args.asn, args.path_pattern, top_n,
                ),
                baseline_topk_path,
                label=f"actors_baseline_topk:{field}",
            )
            if hop is not None:
                return _emit_handoff_packet(
                    hop, args, granularity, baseline_start,
                    artifact=f"actors_baseline_topk_{field}",
                )
            baseline_candidates = (
                [str(v) for v in (topk_rows[0].get("candidates") or []) if v]
                if topk_rows else []
            )
            if not baseline_candidates:
                baseline_actor_rows_by_field[field] = {}
                continue

            baseline_path = (
                sample_dir / f"{args.report}-phase2-{field}-baseline.json"
            )
            rows, hop = _capture_sql_to_rows(
                args,
                _incident_actor_scoped_metrics_baseline_sql(
                    field, baseline_candidates, baseline_start, start,
                    args.host, args.asn, args.path_pattern,
                ),
                baseline_path,
                label=f"actors_baseline:{field}",
            )
            if hop is not None:
                return _emit_handoff_packet(
                    hop, args, granularity, baseline_start,
                    artifact=f"actors_baseline_{field}",
                )
            baseline_actor_rows_by_field[field] = {
                str(row["value"]): {
                    "requests": float(row.get("requests") or 0),
                    "req_429": float(row.get("req_429") or 0),
                    "req_5xx": float(row.get("req_5xx") or 0),
                }
                for row in rows
                if row.get("value") is not None
            }

        # --- Step 4c: joint cooccurrence queries ---------------------------
        # When the relevant marginal rankings exist, fire bounded joint
        # GROUP BYs scoped to current-window top-K candidate sets:
        #   - client_ip × user_agent: feeds the disjoint-cohort finding
        #     (Finding 03) and the cohort_topology block in the IOC export.
        #   - client_ip × request_path: feeds per-indicator scope qualifiers
        #     (``seen_at`` on actor indicators, ``seen_with`` on target
        #     indicators) in the IOC export — a SOAR consumer reads them
        #     to compose path-scoped blocks instead of site-wide ones.
        # Each query is bounded to top_n × top_n cells.
        cooccurrence: dict[str, list[dict]] = {}
        ip_candidates = current_candidates_by_field.get("client_ip") or []
        ua_candidates = current_candidates_by_field.get("user_agent") or []
        path_candidates = current_candidates_by_field.get("request_path") or []

        for (
            pair_label,
            field_a,
            field_b,
            candidates_a,
            candidates_b,
            key_a,
            key_b,
            b_required,
        ) in (
            (
                "client_ip__user_agent",
                "client_ip", "user_agent",
                ip_candidates, ua_candidates,
                "ip", "ua",
                True,
            ),
            (
                "client_ip__request_path",
                "client_ip", "request_path",
                ip_candidates, path_candidates,
                "ip", "path",
                True,
            ),
            (
                # ``action_applied`` is small-cardinality (Allow / Deny
                # / Monitor / Tarpit) so no topK candidate set is needed
                # — the joint GROUP BY stays bounded by len(ip_candidates)
                # × ~5 actions. ``b_required=False`` lets the SQL skip
                # the second IN clause when the candidate list is empty.
                "client_ip__action_applied",
                "client_ip", "action_applied",
                ip_candidates, [],
                "ip", "action",
                False,
            ),
        ):
            if not candidates_a:
                continue
            if b_required and not candidates_b:
                continue
            cooccur_path = (
                sample_dir
                / f"{args.report}-phase2-{pair_label}-cooccurrence.json"
            )
            rows, hop = _capture_sql_to_rows(
                args,
                _incident_actor_cooccurrence_sql(
                    field_a, field_b,
                    candidates_a, candidates_b,
                    start, end,
                    args.host, args.asn, args.path_pattern,
                ),
                cooccur_path,
                label=f"actors_cooccurrence:{pair_label}",
            )
            if hop is not None:
                return _emit_handoff_packet(
                    hop, args, granularity, baseline_start,
                    artifact=f"actors_cooccurrence_{pair_label}",
                )
            cooccurrence[pair_label] = [
                {
                    key_a: str(row.get("value_a") or ""),
                    key_b: str(row.get("value_b") or ""),
                    "requests": int(float(row.get("requests") or 0)),
                }
                for row in rows
                if row.get("value_a") and row.get("value_b")
            ]
        if cooccurrence:
            actors_artifact["actor_cooccurrence"] = cooccurrence

        suspicious_targets = _compute_suspicious_targets(
            scope_artifact,
            actors_artifact,
            baseline_actor_rows_by_field,
        )
    else:
        suspicious_targets = []
        action_targets_limitations.append(
            "Suspicious-target heuristics produced no flagged rows because "
            "the cluster has no raw access log; only summary-level scope "
            "evidence is available."
        )

    action_targets_artifact = _build_action_targets_artifact(
        scope_meta,
        suspicious_targets,
        heuristic_version="v2",
        limitations=action_targets_limitations,
    )

    # --- Step 5: evidence packet ------------------------------------------
    evidence_packet = {
        "schema_version": "bot_report_evidence.v1",
        "report_type": args.report,
        "cluster": args.cluster,
        "database": args.database,
        "granularity": granularity,
        "current_window": {"start": args.start, "end": args.end},
        "baseline_windows": [
            {
                "start": baseline_start.isoformat().replace("+00:00", "Z"),
                "end": args.start,
            }
        ],
        "scope": {
            "host": args.host,
            "asn": args.asn,
            "path_pattern": args.path_pattern,
        },
        "window_confirmation": window_confirmation,
        "top_targeted_hosts": scope_artifact["top_targeted_hosts"],
        "top_targeted_path_patterns": scope_artifact["top_targeted_path_patterns"],
        "status_mix": scope_artifact["status_mix"],
        "country_mix": scope_artifact["country_mix"],
        "siem_action_mix": scope_artifact["siem_action_mix"],
        "siem_policy_mix": scope_artifact["siem_policy_mix"],
        "siem_bot_type_mix": scope_artifact["siem_bot_type_mix"],
        "actor_rankings": actor_rankings,
        "raw_drilldown_available": raw_drilldown_available,
        "siem_available": siem_available,
        "suspicious_targets": suspicious_targets,
        "heuristic_version": "v2",
        "limitations": (
            limitations_scope + limitations_actors + action_targets_limitations
        ),
        "interpretation_contract": INCIDENT_INTERPRETATION_CONTRACT,
    }
    evidence_packet = humanize_evidence_packet(evidence_packet)

    if args.mode == "evidence":
        output_path.write_text(
            json.dumps(evidence_packet, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(
            json.dumps(
                {
                    "cluster": args.cluster,
                    "database": args.database,
                    "granularity": granularity,
                    "mode": args.mode,
                    "output": str(output_path),
                    "siem_available": siem_available,
                    "raw_drilldown_available": raw_drilldown_available,
                },
                sort_keys=True,
            )
        )
        return 0

    # --- Step 6: build wrapper + render -----------------------------------
    wrapper = build_report_wrapper(
        args=args,
        artifacts=[scope_artifact, actors_artifact, action_targets_artifact],
        analyst_note=analyst_note_from_args(args),
    )
    wrapper_path = sample_dir / f"{args.report}-wrapper.json"
    wrapper_path.write_text(
        json.dumps(wrapper, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    render_cmd = [
        "uv",
        "run",
        "python",
        "skills/bot-insights/scripts/render_report.py",
        "--file",
        str(wrapper_path),
        "--format",
        args.format,
        "--output",
        str(output_path),
    ]
    if args.title:
        render_cmd.extend(["--title", args.title])
    run(render_cmd, cwd=PUBLIC_SKILLS)

    print(
        json.dumps(
            {
                "cluster": args.cluster,
                "database": args.database,
                "granularity": granularity,
                "mode": args.mode,
                "output": str(output_path),
                "siem_available": siem_available,
                "raw_drilldown_available": raw_drilldown_available,
            },
            sort_keys=True,
        )
    )
    return 0


class _IncidentHandoff(Exception):
    """Propagate a capture MCP handoff packet out of nested helpers."""

    def __init__(self, packet: dict, label: str) -> None:
        super().__init__(label)
        self.packet = packet
        self.label = label


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="bot-insights-report",
        description="Generate Bot Insights reports from Hydrolix summary data via local artifacts.",
    )
    parser.add_argument(
        "--cluster", required=True, help="Hydrolix cluster alias or .env file path."
    )
    parser.add_argument(
        "--database", default="akamai", help="Hydrolix database/project."
    )
    parser.add_argument(
        "--report",
        choices=(
            "executive_posture",
            "control_review",
            "scorecard_brief",
            "soc_triage",
            "crawler_governance",
            "edge_ops_impact",
            "incident_report",
        ),
        default="executive_posture",
        help="Report type to generate.",
    )
    parser.add_argument(
        "--mode",
        choices=("report", "evidence", "template"),
        default="report",
        help="Output a deterministic report, an LLM evidence packet, or a Markdown template scaffold.",
    )
    parser.add_argument(
        "--start", required=True, help="Inclusive ISO-8601 current-window start."
    )
    parser.add_argument(
        "--end", required=True, help="Exclusive ISO-8601 current-window end."
    )
    parser.add_argument(
        "--baseline-start",
        help="Inclusive ISO-8601 baseline start. Defaults to the equal-length previous window.",
    )
    parser.add_argument(
        "--sample-dir",
        help="Directory for intermediate local JSON. Defaults to ~/src/sample-data/bot-insights/1.1/<cluster>.",
    )
    parser.add_argument(
        "--output", required=True, help="Output path for the selected mode."
    )
    parser.add_argument(
        "--raw-input",
        help="Resume from a saved Hydrolix MCP or ClickHouse JSON result instead of running capture.",
    )
    parser.add_argument(
        "--raw-path-input",
        type=str,
        default=None,
        help="Resume edge_ops_impact from a saved path-grain JSON result alongside --raw-input.",
    )
    parser.add_argument(
        "--format",
        choices=("markdown", "html"),
        default="html",
        help="Rendered report format.",
    )
    parser.add_argument("--title", help="Optional rendered report title.")
    parser.add_argument(
        "--policy-id", help="Optional SIEM policyId filter for control_review."
    )
    parser.add_argument(
        "--control-source",
        choices=("siem-policy", "posture"),
        default="siem-policy",
        help="Summary surface for control_review evidence.",
    )
    parser.add_argument(
        "--change-time",
        help="Optional control change timestamp. Defaults to --start for control_review.",
    )
    parser.add_argument(
        "--entity-type",
        choices=tuple(SCORECARD_ENTITY_SQL),
        default="request_host",
        help="Entity type to score for scorecard_brief.",
    )
    parser.add_argument(
        "--entity-value",
        help="Optional explicit entity value to render for scorecard_brief. Defaults to top-ranked scorecard entity.",
    )
    parser.add_argument(
        "--fleet",
        action="store_true",
        default=False,
        help=(
            "Render scorecard_brief as a fleet (multi-entity) view "
            "instead of collapsing to a single entity. The default "
            "(no flag, no --entity-value) selects the top-ranked "
            "entity and the engine auto-promotes to "
            "scorecard_entity_review for that one host. --fleet "
            "keeps every ranked scorecard in the wrapper so the "
            "report renders as scorecard_brief with the queue table, "
            "triage strip, and coverage detail; --mode evidence with "
            "--fleet also emits a fleet-shaped packet (band "
            "distribution, rule trigger counts across hosts, top "
            "entities) instead of the single-entity packet shape, so "
            "the LLM's interpretation prose matches the rendered "
            "framing. Only valid for --report scorecard_brief."
        ),
    )
    parser.add_argument(
        "--scorecard-limit",
        type=int,
        default=20,
        help="Maximum aggregate rows/scorecards to keep for scorecard_brief.",
    )
    parser.add_argument(
        "--host",
        type=str,
        default=None,
        help="Optional hostname filter for edge_ops_impact path-grain query (scopes path candidates to a single request_host).",
    )
    parser.add_argument(
        "--include-paths",
        action="store_true",
        default=False,
        help=(
            "Opt in to the edge_ops_impact path-grain capture against "
            "bot_agg_path_<granularity>. This table is not currently "
            "deployed on any production cluster, so the path-grain query "
            "is off by default; enabling it falls back gracefully when "
            "the table is missing."
        ),
    )
    parser.add_argument(
        "--domains",
        help="Optional comma-separated scorecard domains to evaluate.",
    )
    parser.add_argument(
        "--asn",
        default=None,
        help="Optional client ASN scope filter for incident_report.",
    )
    parser.add_argument(
        "--path-pattern",
        default=None,
        help=(
            "Optional path-pattern scope filter for incident_report "
            "(requestPathPattern bucket for summary queries; SQL LIKE for "
            "raw drilldown)."
        ),
    )
    parser.add_argument(
        "--fields",
        default=None,
        help=(
            "Comma-separated akamai.logs column names to rank in the "
            "incident_report actors section. Default: "
            f"{_INCIDENT_DEFAULT_FIELDS}."
        ),
    )
    parser.add_argument(
        "--top-n",
        type=int,
        default=10,
        help="Top-N row cap for incident_report dimension and actor queries.",
    )
    parser.add_argument(
        "--analyst-notes",
        help="LLM interpretation prose to include in the final report wrapper.",
    )
    parser.add_argument(
        "--analyst-notes-file",
        help="Read LLM interpretation prose from a file for the final report wrapper.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    start = parse_time(args.start, "start")
    end = parse_time(args.end, "end")
    window = end - start
    if args.baseline_start:
        baseline_start = parse_time(args.baseline_start, "baseline-start")
    else:
        baseline_start = start - window
    if baseline_start >= start:
        raise SystemExit("--baseline-start must be earlier than --start")
    if args.scorecard_limit < 0:
        raise SystemExit("--scorecard-limit must be zero or a positive integer.")
    scorecard_reports = {
        "scorecard_brief",
        "soc_triage",
        "crawler_governance",
        "edge_ops_impact",
    }
    if args.report not in scorecard_reports and args.entity_value:
        raise SystemExit(
            "--entity-value is only supported with --report scorecard_brief, --report soc_triage, "
            "--report crawler_governance, or --report edge_ops_impact."
        )
    if args.fleet and args.report != "scorecard_brief":
        raise SystemExit(
            "--fleet is only supported with --report scorecard_brief; "
            "soc_triage, crawler_governance, and edge_ops_impact "
            "already render multi-entity views by default."
        )
    if args.fleet and args.entity_value:
        raise SystemExit(
            "--fleet and --entity-value are mutually exclusive: "
            "--fleet renders every emitted scorecard, while "
            "--entity-value pins to one specific entity."
        )
    if args.report == "soc_triage" and args.entity_type not in SOC_ENTITY_SQL:
        raise SystemExit(
            "--entity-type "
            + args.entity_type
            + " is not supported for soc_triage; use one of "
            + ", ".join(sorted(SOC_ENTITY_SQL))
        )
    if (
        args.report == "crawler_governance"
        and args.entity_type not in CRAWLER_ENTITY_SQL
    ):
        raise SystemExit(
            "--entity-type "
            + args.entity_type
            + " is not supported for crawler_governance; use one of "
            + ", ".join(sorted(CRAWLER_ENTITY_SQL))
        )
    if args.report == "edge_ops_impact" and args.entity_type not in EDGE_OPS_ENTITY_SQL:
        raise SystemExit(
            "--entity-type "
            + args.entity_type
            + " is not supported for edge_ops_impact; use one of "
            + ", ".join(sorted(EDGE_OPS_ENTITY_SQL))
        )
    if args.raw_path_input and not args.raw_input:
        raise SystemExit(
            "--raw-path-input requires --raw-input to also be supplied "
            "(both raw inputs must be provided to resume an edge_ops_impact run)."
        )
    if args.raw_path_input and args.report != "edge_ops_impact":
        raise SystemExit(
            "--raw-path-input is only valid with --report edge_ops_impact."
        )
    if args.report == "soc_triage" and not args.domains:
        # SOC scorecards must evaluate only the security_evidence domain so
        # crawler/Edge/Ops features do not surface as missing SOC evidence.
        args.domains = "security_evidence"
    if args.report == "crawler_governance" and not args.domains:
        # Crawler governance scorecards must evaluate only the
        # crawler_governance domain so SOC/Edge features do not surface as
        # missing crawler evidence.
        args.domains = "crawler_governance"
    if args.report == "edge_ops_impact" and not args.domains:
        # Edge/Ops scorecards evaluate cache_busting and origin_impact domains
        # so SOC/crawler features do not surface as missing edge evidence.
        args.domains = "cache_busting,origin_impact"

    sample_dir = (
        Path(args.sample_dir).expanduser().resolve()
        if args.sample_dir
        else DEFAULT_SAMPLE_ROOT / args.cluster
    )
    sample_dir.mkdir(parents=True, exist_ok=True)

    if args.report == "incident_report":
        output_path = Path(args.output).expanduser().resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        return _run_incident_report(
            args,
            start,
            end,
            baseline_start,
            sample_dir,
            output_path,
        )

    raw_path = sample_dir / f"{args.report}-raw.json"
    artifact_path = sample_dir / f"{args.report}-artifact.json"
    timeseries_raw_path = sample_dir / f"{args.report}-timeseries-raw.json"
    timeseries_artifact_path = sample_dir / f"{args.report}-timeseries.json"
    path_raw_path = sample_dir / f"{args.report}-path-raw.json"
    path_artifact_path = sample_dir / f"{args.report}-path-artifact.json"
    wrapper_path = sample_dir / f"{args.report}-wrapper.json"
    output_path = Path(args.output).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if args.report == "executive_posture":
        sql = executive_posture_sql(args.database, start, end, baseline_start)
        granularity = choose_granularity(start, end)
        table_used = f"{args.database}.bi_summary_{granularity}"
        compare_schema = "posture"
    elif args.report == "control_review":
        sql = control_review_sql(
            args.database,
            start,
            end,
            baseline_start,
            args.policy_id,
            args.control_source,
        )
        granularity = choose_granularity(start, end)
        if args.control_source == "posture":
            table_used = f"{args.database}.bi_summary_{granularity}"
        else:
            table_used = f"{args.database}.bi_siem_policy_summary_{granularity}"
        compare_schema = "control"
    elif args.report == "scorecard_brief":
        sql = scorecard_sql(
            args.database,
            start,
            end,
            baseline_start,
            args.entity_type,
            args.scorecard_limit,
        )
        granularity = choose_granularity(start, end)
        table_used = f"{args.database}.bi_summary_{granularity}"
        compare_schema = None
    elif args.report == "soc_triage":
        sql = scorecard_soc_sql(
            args.database,
            start,
            end,
            baseline_start,
            args.entity_type,
            args.scorecard_limit,
        )
        granularity = choose_granularity(start, end)
        table_used = f"{args.database}.bi_siem_policy_summary_{granularity}"
        compare_schema = None
    elif args.report == "crawler_governance":
        sql = scorecard_crawler_sql(
            args.database,
            start,
            end,
            baseline_start,
            args.entity_type,
            args.scorecard_limit,
        )
        granularity = choose_granularity(start, end)
        table_used = f"{args.database}.bi_summary_{granularity}"
        compare_schema = None
    elif args.report == "edge_ops_impact":
        sql = scorecard_edge_ops_sql(
            args.database,
            start,
            end,
            baseline_start,
            args.entity_type,
            args.scorecard_limit,
        )
        granularity = choose_granularity(start, end)
        table_used = f"{args.database}.bi_summary_{granularity}"
        compare_schema = None
    else:
        raise AssertionError(args.report)

    capture_summary: dict[str, object] = {"rows": None}
    raw_timeseries_value: dict | None = None
    raw_path_value: dict | None = None
    if args.raw_input:
        raw_value = load_raw_query_result(Path(args.raw_input).expanduser().resolve())
        if args.report == "control_review" and timeseries_raw_path.exists():
            raw_timeseries_value = load_raw_query_result(timeseries_raw_path)
        if args.report == "edge_ops_impact":
            if args.raw_path_input:
                raw_path_value = load_raw_query_result(
                    Path(args.raw_path_input).expanduser().resolve()
                )
            elif args.include_paths:
                print(
                    "WARNING: --raw-path-input not supplied for edge_ops_impact; "
                    "path-grain artifact will be omitted.",
                    file=sys.stderr,
                )
    else:
        try:
            capture_summary_text = run(
                [
                    sys.executable,
                    str(CAPTURE),
                    "--cluster",
                    args.cluster,
                    "--database",
                    args.database,
                    "--sql",
                    sql,
                    "--output",
                    str(raw_path),
                ],
                allowed_returncodes=(NEEDS_MCP_EXIT,),
            )
        except SystemExit as exc:
            # SOC triage depends on bi_siem_policy_summary_<granularity>,
            # which is not deployed on every cluster. Without SIEM data the
            # script cannot produce a SOC report, so warn clearly and exit
            # cleanly rather than crash with a raw capture traceback.
            if args.report == "soc_triage":
                print(
                    "WARNING: SOC capture failed; "
                    f"{table_used} may not be deployed on this cluster ({exc}). "
                    "soc_triage requires SIEM policy summary data; skipping report.",
                    file=sys.stderr,
                )
                return 0
            raise
        try:
            capture_summary = json.loads(capture_summary_text)
        except json.JSONDecodeError as exc:
            raise SystemExit("Capture did not return machine-readable JSON.") from exc
        if (
            isinstance(capture_summary, dict)
            and capture_summary.get("schema_version") == HANDOFF_SCHEMA
        ):
            report_context = capture_summary.get("report_context")
            if not isinstance(report_context, dict):
                report_context = {}
            report_context.update(
                {
                    "report": args.report,
                    "mode": args.mode,
                    "start": args.start,
                    "end": args.end,
                    "baseline_start": baseline_start.isoformat().replace("+00:00", "Z"),
                    "table_used": table_used,
                    "granularity": granularity,
                }
            )
            if args.report in {
                "scorecard_brief",
                "soc_triage",
                "crawler_governance",
                "edge_ops_impact",
            }:
                report_context.update(
                    {
                        "entity_type": args.entity_type,
                        "entity_value": args.entity_value,
                        "producer_limit": args.scorecard_limit,
                        "analysis_domains": args.domains,
                    }
                )
            if args.report == "edge_ops_impact":
                report_context["artifact"] = "scorecard"
            capture_summary["report_context"] = report_context
            print(json.dumps(capture_summary, sort_keys=True))
            return NEEDS_MCP_EXIT
        raw_value = load_raw_query_result(raw_path)
        if args.report == "control_review":
            timeseries_sql = control_review_timeseries_sql(
                args.database,
                start,
                end,
                baseline_start,
                args.policy_id,
                args.control_source,
            )
            timeseries_summary_text = run(
                [
                    sys.executable,
                    str(CAPTURE),
                    "--cluster",
                    args.cluster,
                    "--database",
                    args.database,
                    "--sql",
                    timeseries_sql,
                    "--output",
                    str(timeseries_raw_path),
                ],
                allowed_returncodes=(NEEDS_MCP_EXIT,),
            )
            try:
                timeseries_summary = json.loads(timeseries_summary_text)
            except json.JSONDecodeError as exc:
                raise SystemExit(
                    "Timeseries capture did not return machine-readable JSON."
                ) from exc
            if (
                isinstance(timeseries_summary, dict)
                and timeseries_summary.get("schema_version") == HANDOFF_SCHEMA
            ):
                report_context = timeseries_summary.get("report_context")
                if not isinstance(report_context, dict):
                    report_context = {}
                report_context.update(
                    {
                        "report": args.report,
                        "mode": args.mode,
                        "artifact": "timeseries",
                        "start": args.start,
                        "end": args.end,
                        "baseline_start": baseline_start.isoformat().replace(
                            "+00:00", "Z"
                        ),
                        "table_used": table_used,
                        "granularity": granularity,
                    }
                )
                timeseries_summary["report_context"] = report_context
                print(json.dumps(timeseries_summary, sort_keys=True))
                return NEEDS_MCP_EXIT
            raw_timeseries_value = load_raw_query_result(timeseries_raw_path)
        if args.report == "edge_ops_impact" and args.include_paths:
            path_grain_sql = cache_origin_path_sql(
                args.database,
                start,
                end,
                baseline_start,
                args.host,
                args.scorecard_limit,
            )
            path_table_used = f"{args.database}.bot_agg_path_{granularity}"
            try:
                path_capture_text = run(
                    [
                        sys.executable,
                        str(CAPTURE),
                        "--cluster",
                        args.cluster,
                        "--database",
                        args.database,
                        "--sql",
                        path_grain_sql,
                        "--output",
                        str(path_raw_path),
                    ],
                    allowed_returncodes=(NEEDS_MCP_EXIT,),
                )
            except SystemExit as exc:
                # Path-grain summary table may not exist on every cluster
                # (bot_agg_path_* is optional infrastructure). Degrade
                # gracefully to entity-grain only. The reader-facing
                # warning is humanized (no raw table name) so that an
                # LLM consuming stderr alongside the evidence packet
                # doesn't paste internal table identifiers into prose;
                # the raw exception text is kept on a separate
                # debug-prefix line for operator triage.
                print(
                    "WARNING: per-path cache data is not available on "
                    "this cluster; the path artifact will be omitted.",
                    file=sys.stderr,
                )
                print(
                    f"DEBUG: path-grain capture failed ({exc}); "
                    f"path table used was {path_table_used}.",
                    file=sys.stderr,
                )
                path_capture_text = ""
            try:
                path_capture_summary = json.loads(path_capture_text) if path_capture_text else {}
            except json.JSONDecodeError:
                print(
                    "WARNING: per-path cache data could not be parsed; "
                    "the path artifact will be omitted.",
                    file=sys.stderr,
                )
                path_capture_summary = {}
            if (
                isinstance(path_capture_summary, dict)
                and path_capture_summary.get("schema_version") == HANDOFF_SCHEMA
            ):
                path_report_context = path_capture_summary.get("report_context")
                if not isinstance(path_report_context, dict):
                    path_report_context = {}
                path_report_context.update(
                    {
                        "report": args.report,
                        "mode": args.mode,
                        "artifact": "path",
                        "start": args.start,
                        "end": args.end,
                        "baseline_start": baseline_start.isoformat().replace(
                            "+00:00", "Z"
                        ),
                        "table_used": path_table_used,
                        "granularity": granularity,
                    }
                )
                path_capture_summary["report_context"] = path_report_context
                print(json.dumps(path_capture_summary, sort_keys=True))
                return NEEDS_MCP_EXIT
            if path_raw_path.exists():
                raw_path_value = load_raw_query_result(path_raw_path)

    if args.report == "executive_posture":
        raw_value = add_report_metadata(
            raw_value=raw_value,
            args=args,
            granularity=granularity,
            table_used=table_used,
            baseline_start=baseline_start,
        )
    elif args.report == "control_review":
        raw_value = add_control_metadata(
            raw_value=raw_value,
            args=args,
            granularity=granularity,
            table_used=table_used,
            baseline_start=baseline_start,
        )
    elif args.report in {
        "scorecard_brief",
        "soc_triage",
        "crawler_governance",
        "edge_ops_impact",
    }:
        raw_value = add_scorecard_metadata(
            raw_value=raw_value,
            args=args,
            granularity=granularity,
            table_used=table_used,
            baseline_start=baseline_start,
        )
    else:
        raise AssertionError(args.report)
    raw_path.write_text(
        json.dumps(raw_value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    if args.report in {
        "scorecard_brief",
        "soc_triage",
        "crawler_governance",
        "edge_ops_impact",
    }:
        scorecard_cmd = [
            "uv",
            "run",
            "python",
            "skills/bot-insights/scripts/scorecard.py",
            "--file",
            str(raw_path),
            "--entity-type",
            args.entity_type,
            "--limit",
            str(args.scorecard_limit),
        ]
        if args.domains:
            scorecard_cmd.extend(["--domains", args.domains])
        run(scorecard_cmd, stdout_path=artifact_path, cwd=PUBLIC_SKILLS)
    else:
        run(
            [
                "uv",
                "run",
                "python",
                "skills/bot-insights/scripts/compare_posture.py",
                "--file",
                str(raw_path),
                "--schema",
                compare_schema,
            ],
            stdout_path=artifact_path,
            cwd=PUBLIC_SKILLS,
        )

    artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
    if not isinstance(artifact, dict):
        raise SystemExit(f"Expected {artifact_path} to contain an artifact object.")
    companion_artifacts: list[dict] = []
    path_artifact: dict | None = None
    if args.report == "edge_ops_impact" and raw_path_value is not None:
        path_raw_path.write_text(
            json.dumps(raw_path_value, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        try:
            path_cmd = [
                "uv",
                "run",
                "python",
                "skills/bot-insights/scripts/cache_origin_impact.py",
                "--file",
                str(path_raw_path),
            ]
            run(path_cmd, stdout_path=path_artifact_path, cwd=PUBLIC_SKILLS)
            path_artifact = json.loads(path_artifact_path.read_text(encoding="utf-8"))
            if not isinstance(path_artifact, dict) or not path_artifact.get(
                "candidates"
            ):
                print(
                    "WARNING: path-grain artifact has no candidates; "
                    "path artifact will be omitted.",
                    file=sys.stderr,
                )
                path_artifact = None
        except Exception as exc:  # noqa: BLE001
            print(
                f"WARNING: path-grain processing failed ({exc}); "
                "path artifact will be omitted.",
                file=sys.stderr,
            )
            path_artifact = None
    if args.report == "control_review" and raw_timeseries_value is not None:
        timeseries_artifact = build_timeseries_artifact(
            args=args,
            raw_value=raw_timeseries_value,
            control_artifact=artifact,
            table_used=table_used,
            granularity=granularity,
        )
        if timeseries_artifact.get("metrics"):
            timeseries_artifact_path.write_text(
                json.dumps(timeseries_artifact, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            companion_artifacts.append(timeseries_artifact)
    if args.report == "executive_posture":
        evidence_packet = build_evidence_packet(
            args=args,
            artifact=artifact,
            raw_path=raw_path,
            artifact_path=artifact_path,
            granularity=granularity,
            table_used=table_used,
            baseline_start=baseline_start,
        )
    elif args.report == "control_review":
        evidence_packet = build_control_evidence_packet(
            args=args,
            artifact=artifact,
            raw_path=raw_path,
            artifact_path=artifact_path,
            granularity=granularity,
            table_used=table_used,
            baseline_start=baseline_start,
        )
    elif args.report in {
        "scorecard_brief",
        "soc_triage",
        "crawler_governance",
        "edge_ops_impact",
    }:
        if args.report == "scorecard_brief" and args.fleet:
            # Fleet evidence packet — different shape from the
            # single-entity packet (fleet aggregates instead of
            # selected_entity + evaluated_feature_evidence) so the
            # LLM's prose matches the multi-entity render.
            evidence_packet = build_scorecard_fleet_evidence_packet(
                args=args,
                artifacts=artifact,
                raw_path=raw_path,
                artifact_path=artifact_path,
                granularity=granularity,
                table_used=table_used,
                baseline_start=baseline_start,
            )
        else:
            selected_card = select_scorecard(
                artifact,
                entity_type=args.entity_type if args.entity_value else None,
                entity_value=args.entity_value,
            )
            evidence_packet = build_scorecard_evidence_packet(
                args=args,
                artifacts=artifact,
                selected_card=selected_card,
                raw_path=raw_path,
                artifact_path=artifact_path,
                granularity=granularity,
                table_used=table_used,
                baseline_start=baseline_start,
            )
    else:
        raise AssertionError(args.report)

    # Enrich every emitted evidence packet with reader-friendly
    # ``*_label`` fields and append the label-preference rule to the
    # interpretation_contract. The transformation is additive — every
    # raw identifier is preserved next to its label so the deterministic
    # cross-reference back to the producer artifact still works.
    evidence_packet = humanize_evidence_packet(evidence_packet)

    if args.mode == "evidence":
        output_path.write_text(
            json.dumps(evidence_packet, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    elif args.mode == "template":
        output_path.write_text(
            render_template_packet(evidence_packet), encoding="utf-8"
        )
    else:
        if args.report == "scorecard_brief":
            if args.fleet:
                # Fleet view: keep every emitted scorecard so the
                # engine renders the multi-entity scorecard_brief
                # template (queue table, triage strip, fleet
                # coverage, score landscape) instead of auto-
                # promoting to scorecard_entity_review. The engine's
                # _maybe_promote_singleton only fires when
                # ``len(scorecards) == 1``; including every card
                # keeps the wrapper above that threshold and the
                # ``scorecard_brief`` report_type is preserved.
                scorecards = [
                    card
                    for card in (artifact.get("scorecards") or [])
                    if isinstance(card, dict)
                ]
                if not scorecards:
                    raise SystemExit(
                        "Scorecard artifacts did not contain any "
                        "emitted scorecards; --fleet has nothing to "
                        "render."
                    )
                render_artifacts = []
                if isinstance(artifact.get("index"), dict):
                    render_artifacts.append(artifact["index"])
                render_artifacts.extend(scorecards)
            else:
                selected_card = select_scorecard(
                    artifact,
                    entity_type=args.entity_type if args.entity_value else None,
                    entity_value=args.entity_value,
                )
                render_artifacts = [selected_card]
                if isinstance(artifact.get("index"), dict):
                    render_artifacts.append(artifact["index"])
        elif args.report in {"soc_triage", "crawler_governance"}:
            render_artifacts = []
            if isinstance(artifact.get("index"), dict):
                render_artifacts.append(artifact["index"])
            scorecards = artifact.get("scorecards")
            if isinstance(scorecards, list):
                render_artifacts.extend(
                    card for card in scorecards if isinstance(card, dict)
                )
        elif args.report == "edge_ops_impact":
            render_artifacts = []
            if isinstance(artifact.get("index"), dict):
                render_artifacts.append(artifact["index"])
            scorecards = artifact.get("scorecards")
            if isinstance(scorecards, list):
                render_artifacts.extend(
                    card for card in scorecards if isinstance(card, dict)
                )
            if path_artifact is not None:
                render_artifacts.append(path_artifact)
        else:
            render_artifacts = [artifact, *companion_artifacts]
        wrapper = build_report_wrapper(
            args=args,
            artifacts=render_artifacts,
            analyst_note=analyst_note_from_args(args),
        )
        wrapper_path.write_text(
            json.dumps(wrapper, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        render_cmd = [
            "uv",
            "run",
            "python",
            "skills/bot-insights/scripts/render_report.py",
            "--file",
            str(wrapper_path),
            "--format",
            args.format,
            "--output",
            str(output_path),
        ]
        if args.title:
            render_cmd.extend(["--title", args.title])
        run(render_cmd, cwd=PUBLIC_SKILLS)

    print(
        json.dumps(
            {
                "artifact": str(artifact_path),
                "cluster": args.cluster,
                "database": args.database,
                "granularity": granularity,
                "mode": args.mode,
                "raw": str(raw_path),
                "output": str(output_path),
                "rows": capture_summary.get("rows"),
                "table_used": table_used,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
