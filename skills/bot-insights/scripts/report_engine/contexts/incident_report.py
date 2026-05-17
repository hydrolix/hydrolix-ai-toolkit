"""Context preparer for the Incident Report.

Sits between a top-N panel and a full RCA: confirms an incident window
from summary tables (`bi_summary_*`, `bi_siem_policy_summary_*`), drills
to the cluster's raw `akamai.logs` for actor-level detail, and hands off
to a Grafana dashboard for further exploration.

The three artifacts the wrapper carries —
``bot_incident_scope.v1`` (scope confirmation),
``bot_incident_actors.v1`` (actor rankings), and
``bot_incident_action_targets.v1`` (suspicious-target rows, possibly
empty) — are produced mechanically by the orchestrator. The LLM's only
output is prose into three named slots: ``executive_summary``,
``operational_interpretation``, and ``next_steps``. Everything else on
this page is deterministic.
"""

from __future__ import annotations

from datetime import datetime, timezone

from ..humanize import cluster_display
from ..formatters import big_number
from ..theme import editorial_palette

from .. import findings as findings_mod  # noqa: F401  (re-exported for parity)

import baselines as baselines_mod  # type: ignore  # script-relative import

SCHEMA = "bot_incident_scope.v1"
REPORT_TYPE = "incident_report"
TEMPLATE = "reports/incident_report.html"

# Bidirectional-overlap floor for the "two disjoint cohorts" finding.
# When the actor_cooccurrence payload is present (joint IP × UA cell
# counts from the producer), a forward + reverse share below this floor
# means the flagged-IP population and the flagged-UA population are
# catching essentially different actors. 5% leaves room for accidental
# cross-pollination (one shared cell, a UA the heuristic happened to
# catch from a flagged IP) without forcing the strict 0%.
COHORT_DISJOINT_OVERLAP_FLOOR_PCT = 5.0


# Cap on rows rendered in the "Who Hit It" actor table. Heuristics flag
# all qualifying targets (often dozens in a real incident); past the
# top of the severity+volume sort, share% has typically collapsed below
# 1% and rows stop carrying new signal. Overflow is summarized as a
# footer row pointing readers to Full Evidence, which still lists every
# flagged target.
SUSPICIOUS_TARGETS_DISPLAY_CAP = 10

# Wrapper analyst-note routing. Each note_id maps to one named narrative
# slot in the template. Unmapped note_id values are dropped by the
# renderer (the same behavior every other context module relies on).
NOTE_ID_TO_SLOT = {
    "llm-interpretation": "executive_summary",
    "llm-operational": "operational_interpretation",
    "llm-next-steps": "next_steps",
    "llm-executive-impact": "executive_impact",
    "llm-current-status": "current_status",
    "llm-incident-context": "incident_context",
}

PURPOSE = {
    "kicker": "Bot Insights — incident report",
    "measures": (
        "Window-scoped incident shape. Confirms volume, 429%, 5xx%, "
        "bot-share and SIEM-blocked share against a trailing equal-length "
        "baseline, then ranks actors against the cluster's raw access log."
    ),
    "score_legend": (
        "Risk score scales with attack severity; higher is worse. "
        "Share percentages and deltas are computed mechanically against "
        "the trailing window — severity is qualitative."
    ),
    "cant_say": (
        "Rule-based scorecard. Mechanical features only — no malicious-intent "
        "claim or root-cause attribution."
    ),
    # Risk-score bands for the orientation legend. Incident risk is
    # higher-is-worse (inverted from scorecard reports), so the legend
    # reads observe → critical across 0–100.
    "bands": [
        {"label": "observe · 0–40",    "tone": "observe"},
        {"label": "monitor · 40–70",   "tone": "monitor"},
        {"label": "escalate · 70–90",  "tone": "escalate"},
        {"label": "critical · 90–100", "tone": "critical"},
    ],
}

# Pretty labels for window-confirmation spike flags. Anything not in this
# table renders as a humanized identifier so producer-side novel flags
# don't disappear silently.
SPIKE_FLAG_LABELS = {
    "volume_up": "Volume up",
    "volume_down": "Volume down",
    "rate_429_up": "429 rate up",
    "rate_429_down": "429 rate down",
    "rate_5xx_up": "5xx rate up",
    "rate_5xx_down": "5xx rate down",
    "bot_share_up": "Bot share up",
    "bot_share_down": "Bot share down",
    "blocked_share_up": "SIEM blocked share up",
    "blocked_share_down": "SIEM blocked share down",
}

REASON_FLAG_LABELS = {
    "high_volume_share": "high volume share",
    "high_rate_429_share": "high 429 share",
    "single_path_concentration": "single-path concentration",
    "new_in_window": "new in window",
    "single_asn_cluster": "single-ASN cluster",
    "botnet_member": "coordinated infrastructure cluster",
    "high_volume_new_actor": "high-volume new actor",
    "automation_user_agent": "automation user agent",
    "anomaly": "behavioral anomaly",
}

TARGET_TYPE_LABELS = {
    "client_ip": "Client IP",
    "asn": "Client ASN",
    "user_agent": "User Agent",
    "request_path": "Request Path",
    "country": "Country",
    "cohort": "Traffic cohort",
}

ACTION_CLASS_LABELS = {
    "block":      "Block",
    "challenge":  "Challenge",
    "rate-limit": "Rate-limit",
    "watch":      "Watch",
    "monitor":    "Monitor",
}

# Visual tone for action-class chips. Maps to the same severity-tone
# palette so a "block" chip reads with the same red weight as a
# critical pill — keeps the action ladder visually parallel to the
# severity ladder without inventing a third color system.
ACTION_CLASS_TONE = {
    "block":      "critical",
    "challenge":  "escalate",
    "rate-limit": "escalate",
    "watch":      "monitor",
    "monitor":    "observe",
}


SEVERITY_TONE = {
    "critical": "critical",
    "high": "escalate",
    "medium": "monitor",
    "low": "observe",
    # ``review`` is the v1 vocabulary — kept here so wrappers produced
    # by the older orchestrator continue to render until they are
    # regenerated. v2 emits ``medium`` / ``low`` instead.
    "review": "monitor",
}

# IOC type mapping. The Suspicious Targets table's ``target_type``
# values are the report-internal vocabulary; the IOC export uses the
# broader SOC-tooling vocabulary so the exported indicators drop
# cleanly into a SIEM ingestion pipeline.
#
# ``cohort`` is surfaced as an IOC type even though it isn't a
# traditional indicator — it's actionable in our context (downstream
# WAF can rate-limit by cohort) and SOC tooling already recognizes it.
IOC_TYPE_MAP = {
    "client_ip": "ip",
    "asn": "asn",
    "user_agent": "user_agent",
    "request_path": "url_path",
    "country": "country",
    "cohort": "cohort",
}

# Tableau-tinted tones for the executive-summary criticality badge.
# Five tiers (v2 promoted from four): the new `elevated` step sits
# between `medium` and `high` so the editorial severity ladder can
# show progress through partial-signal incidents (critical/high
# targets that don't yet have spike-flag or raw-drilldown
# concurrence) without forcing the verdict pill to read either
# "medium" (understated) or "high" (overstated).
#
# Note: this 5-tier verdict ladder is INDEPENDENT of the per-target
# IOC `severity` field, which stays 4-tier (`critical/high/medium/low`)
# for downstream SIEM contract stability. See
# `references/incident-analysis.md` for the calibration.
#
# Confidence is rendered with a neutral pill regardless of value: the
# severity palette means "urgency", not "evidence quality", and
# tinting low-confidence in red would mis-read as "this is bad" when
# the actual meaning is "we don't have enough evidence to call it".
CRITICALITY_TONE = {
    "critical": "critical",
    "high": "escalate",
    "elevated": "elevated",
    "medium": "monitor",
    "low": "observe",
}


def assemble(artifacts: list[dict]) -> dict:
    """Reshape a ``bot_report_input.v1`` wrapper's artifacts list into the
    dict ``prepare()`` expects.

    The incident report requires all three artifacts. The actors artifact
    may carry ``raw_drilldown_available: false`` — that surfaces the
    limitation banner in the template instead of the actor tables, but
    is not an error. The action-targets artifact must be present but may
    carry an empty ``targets`` list (renders the explanatory banner).
    """
    scope = next(
        (a for a in artifacts if a.get("schema_version") == "bot_incident_scope.v1"),
        None,
    )
    if scope is None:
        raise ValueError(
            "incident_report wrapper missing bot_incident_scope.v1 artifact"
        )
    actors = next(
        (a for a in artifacts if a.get("schema_version") == "bot_incident_actors.v1"),
        None,
    )
    if actors is None:
        raise ValueError(
            "incident_report wrapper missing bot_incident_actors.v1 artifact"
        )
    action_targets = next(
        (
            a
            for a in artifacts
            if a.get("schema_version") == "bot_incident_action_targets.v1"
        ),
        None,
    )
    if action_targets is None:
        raise ValueError(
            "incident_report wrapper missing bot_incident_action_targets.v1 artifact"
        )
    return {
        "schema_version": SCHEMA,
        "scope": scope,
        "actors": actors,
        "action_targets": action_targets,
    }


def prepare(artifact: dict) -> dict:
    scope_art = artifact["scope"]
    actors_art = artifact["actors"]
    action_targets_art = artifact.get("action_targets") or {}

    scope_meta = scope_art.get("scope") or {}
    cluster = scope_meta.get("cluster") or ""
    host = scope_meta.get("host")
    asn = scope_meta.get("asn")
    path_pattern = scope_meta.get("path_pattern")
    granularity = scope_meta.get("granularity") or ""
    siem_available = bool(scope_meta.get("siem_available"))

    cluster_label = cluster_display(cluster) if cluster else ""
    scope_filters = _scope_filters(host, asn, path_pattern)
    headline_scope = host or cluster_label or "fleet"
    # H1 is scope-only ("Expedia", "www.example.com", etc.). "Incident
    # report" is already in the kicker row above the headline, so
    # prefixing the H1 with the same words is dead repetition. The
    # window the report covers is rendered prominently in the
    # masthead window block on the right (see incident_report.html).
    headline = headline_scope

    window_confirmation = _window_confirmation_view(
        scope_art.get("window_confirmation") or {}
    )

    targeted_hosts_rows = _scope_rows(
        scope_art.get("top_targeted_hosts") or [], value_label="Host"
    )
    path_pattern_rows = _scope_rows(
        scope_art.get("top_targeted_path_patterns") or [],
        value_label="Path pattern",
    )
    # Raw-reqPath drilldown scoped to the suspicious-actor IP set.
    # Lives on the scope artifact as ``top_raw_paths`` when the
    # producer ran the phase-2 drilldown query (cluster-only — the
    # parquet summary doesn't carry raw paths). Each row carries
    # ``share_pct`` as share-of-suspicious-actor-traffic (NOT
    # share-of-window) and a ``distinct_actors`` count so the
    # editorial table can highlight coordinated-many-actors-on-one-URL
    # vs single-actor-scanning patterns.
    top_raw_paths = _top_raw_paths_rows(scope_art.get("top_raw_paths") or [])
    status_mix_rows = _status_mix_rows(scope_art.get("status_mix") or [])
    country_mix_rows = _scope_rows(
        scope_art.get("country_mix") or [], value_label="Country"
    )
    cohort_mix_rows = _cohort_mix_rows(actors_art)
    edge_action_mix_rows = _scope_rows(
        scope_art.get("edge_action_mix") or [], value_label="Action"
    )
    # Akamai writes ``action_applied`` as an empty string for requests
    # that hit no WAF or bot-manager rule (the pass-through bulk). The
    # column value is meaningful, but the editorial table reads as a
    # blank cell unless we humanize it — relabel for display only so
    # the underlying artifact stays raw.
    for row in edge_action_mix_rows:
        if not row["value"]:
            row["value"] = "No Action"
    deny_rule_mix_rows = _scope_rows(
        scope_art.get("deny_rule_mix") or [], value_label="Deny rule"
    )

    if siem_available:
        siem_action_rows = _scope_rows(
            scope_art.get("siem_action_mix") or [], value_label="Action class"
        )
        siem_policy_rows = _scope_rows(
            scope_art.get("siem_policy_mix") or [], value_label="Policy"
        )
        siem_bot_type_rows = _scope_rows(
            scope_art.get("siem_bot_type_mix") or [], value_label="Bot type"
        )
    else:
        siem_action_rows = []
        siem_policy_rows = []
        siem_bot_type_rows = []

    raw_drilldown_available = bool(actors_art.get("raw_drilldown_available"))
    actor_rankings = _actor_rankings_view(actors_art) if raw_drilldown_available else []

    impact = _impact_view(scope_art)
    suspicious_targets = _suspicious_targets_view(
        action_targets_art, actors_artifact=actors_art
    )
    concentration_chart = _concentration_chart_view(suspicious_targets)
    deterministic_summary = _deterministic_summary(
        scope_art, actors_art, action_targets_art, suspicious_targets
    )
    # Editorial extensions (Phase 1 — deterministic-only). Phase 2 will
    # let analyst notes override `incident_findings` and
    # `recommended_actions`; the deterministic generators below are the
    # always-on fallback.
    risk_score = _risk_score(deterministic_summary, suspicious_targets)
    severity_ladder = _severity_ladder(deterministic_summary["level"])
    attack_aggregation = _attack_aggregation(suspicious_targets)
    spike_flags = list(
        (scope_art.get("window_confirmation") or {}).get("spike_flags") or []
    )
    cohort_overlap = _compute_actor_cohort_overlap(suspicious_targets, actors_art)
    # IOC export reads ``cohort_overlap`` and ``actors_art`` (for the
    # actor_cooccurrence cells) so it can embed cohort_topology and
    # project per-indicator seen_at / seen_with scope qualifiers.
    iocs = _ioc_view(
        action_targets_art, scope_meta,
        actors_artifact=actors_art,
        cohort_overlap=cohort_overlap,
    )
    iocs_json_text = _ioc_json_text(iocs)
    incident_findings = _incident_findings(
        suspicious_targets, deterministic_summary, spike_flags,
        cohort_overlap=cohort_overlap,
    )
    recommended_actions = _recommended_actions_view(
        suspicious_targets, scope_art.get("dashboard_url") or "", None
    )

    limitations = (
        list(scope_art.get("limitations") or [])
        + list(actors_art.get("limitations") or [])
        + list(action_targets_art.get("limitations") or [])
    )

    windows = {
        "current": {
            "start": scope_meta.get("start") or "",
            "end": scope_meta.get("end") or "",
        },
        "baseline": {
            "start": scope_meta.get("baseline_start") or "",
            "end": scope_meta.get("baseline_end") or "",
        },
    }

    return {
        "title": "Incident Report",
        "kicker": PURPOSE["kicker"],
        "headline": headline,
        "dek": "Window-scoped incident confirmation with actor-level drilldown.",
        "purpose": None,
        "orientation": {
            "measures": PURPOSE["measures"],
            "score_legend": PURPOSE["score_legend"],
            "cant_say": PURPOSE["cant_say"],
            "bands": PURPOSE["bands"],
        },
        "scope": {
            "cluster": cluster,
            "database": scope_meta.get("database") or "",
            "table_used": (
                f"{scope_meta.get('database') or 'akamai'}.bi_summary_{granularity}"
                if granularity
                else ""
            ),
            "request_host": host or "",
            "asn": asn,
            "path_pattern": path_pattern,
            "granularity": granularity,
            "siem_available": siem_available,
            "scope_filters": scope_filters,
        },
        "windows": windows,
        "window_confirmation": window_confirmation,
        "targeted_hosts_rows": targeted_hosts_rows,
        "path_pattern_rows": path_pattern_rows,
        "top_raw_paths_rows": top_raw_paths,
        "status_mix_rows": status_mix_rows,
        "country_mix_rows": country_mix_rows,
        "cohort_mix_rows": cohort_mix_rows,
        "edge_action_mix_rows": edge_action_mix_rows,
        "deny_rule_mix_rows": deny_rule_mix_rows,
        "siem_action_rows": siem_action_rows,
        "siem_policy_rows": siem_policy_rows,
        "siem_bot_type_rows": siem_bot_type_rows,
        "actor_rankings": actor_rankings,
        "raw_drilldown_available": raw_drilldown_available,
        "raw_table": actors_art.get("raw_table") or "",
        "impact": impact,
        "suspicious_targets": suspicious_targets,
        "suspicious_targets_visible": suspicious_targets[
            :SUSPICIOUS_TARGETS_DISPLAY_CAP
        ],
        "suspicious_targets_hidden_count": max(
            0, len(suspicious_targets) - SUSPICIOUS_TARGETS_DISPLAY_CAP
        ),
        "concentration_chart": concentration_chart,
        "deterministic_summary": deterministic_summary,
        "iocs": iocs,
        "iocs_json_text": iocs_json_text,
        "risk_score": risk_score,
        "severity_ladder": severity_ladder,
        "attack_aggregation": attack_aggregation,
        "incident_findings": incident_findings,
        "recommended_actions": recommended_actions,
        "editorial": editorial_palette(),
        "limitations": limitations,
        "dashboard_url": scope_art.get("dashboard_url") or "",
        "method": {
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
        },
        "confidence": {"reasons": []},
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    }


# ---- helpers ----------------------------------------------------------------


def _impact_view(scope_art: dict) -> dict:
    """Build the top-of-report Impact strip + 'top affected' sentence.

    Five tiles in v2 (Peak/minute is deferred to Phase 3):
    Requests, 429s, 5xx, Edge blocks, Hosts affected. Edge-blocks tile
    renders an em-dash placeholder when the producer could derive
    neither a SIEM-table actionClass share nor an action_applied share
    from raw ``akamai.logs``.

    Also projects a ``volume_chart`` block when the scope artifact
    carries a ``volume_timeseries`` field (per-minute or per-bucket
    request counts for current and baseline). Renders as a SVG chart
    above the KPI tiles; gracefully absent when the artifact has no
    timeseries data.
    """
    window = scope_art.get("window_confirmation") or {}

    requests = _safe_number(window.get("requests")) or 0
    rate_429 = window.get("rate_429_pct") or 0
    rate_5xx = window.get("rate_5xx_pct") or 0
    blocked_share = window.get("blocked_share_pct")

    req_429 = int(requests * (rate_429 or 0) / 100.0) if requests else 0
    req_5xx = int(requests * (rate_5xx or 0) / 100.0) if requests else 0

    hosts_rows = scope_art.get("top_targeted_hosts") or []
    paths_rows = scope_art.get("top_targeted_path_patterns") or []
    hosts_affected = sum(
        1 for row in hosts_rows if (_safe_number(row.get("requests")) or 0) > 0
    )

    tiles = [
        {
            "label": "Requests",
            "value": _format_count(requests),
            "sub": _format_signed_pct(_top_delta(hosts_rows)),
        },
        {
            "label": "429s served",
            "value": _format_count(req_429),
            "sub": _format_pct(rate_429) + " of window",
        },
        {
            "label": "5xx served",
            "value": _format_count(req_5xx),
            "sub": _format_pct(rate_5xx) + " of window",
        },
    ]
    if blocked_share is not None:
        req_blocks = int(requests * (blocked_share or 0) / 100.0) if requests else 0
        tiles.append(
            {
                "label": "Edge blocks",
                "value": _format_count(req_blocks),
                "sub": _format_pct(blocked_share) + " of window",
            }
        )
    else:
        tiles.append(
            {
                "label": "Edge blocks",
                "value": "—",
                "sub": "no edge block data",
            }
        )
    tiles.append(
        {
            "label": "Hosts affected",
            "value": _format_int(hosts_affected),
            "sub": "in window",
        }
    )
    # 6th tile (v2 editorial): top path-pattern share + Δ vs baseline.
    # Mirrors the briefing.html design where the right-most KPI shows
    # which path soaked up the surge. Falls back to em-dashes when the
    # path_pattern_rows are empty so the strip never collapses to 5.
    top_path_row = paths_rows[0] if paths_rows else None
    if top_path_row:
        path_label = str(top_path_row.get("value") or "")
        delta_pct = top_path_row.get("delta_vs_baseline_pct")
        delta_display = _format_signed_pct(delta_pct)
        if path_label and delta_display != "—":
            sub = f"{path_label} · {delta_display}"
        elif path_label:
            sub = path_label
        else:
            sub = delta_display
        tiles.append(
            {
                "label": "Top path share",
                "value": _format_pct(top_path_row.get("share_pct")),
                "sub": sub,
            }
        )
    else:
        tiles.append(
            {
                "label": "Top path share",
                "value": "—",
                "sub": "no path data",
            }
        )

    top_host = hosts_rows[0] if hosts_rows else None
    top_path = paths_rows[0] if paths_rows else None
    top_affected: dict | None = None
    if top_host and top_path:
        top_affected = {
            "host": str(top_host.get("value") or ""),
            "path_pattern": str(top_path.get("value") or ""),
            "requests": _safe_number(top_path.get("requests")),
            "requests_display": _format_count(top_path.get("requests")),
            "share_pct": _safe_number(top_path.get("share_pct")),
            "share_pct_display": _format_pct(top_path.get("share_pct")),
            "delta_pct": _safe_number(top_path.get("delta_vs_baseline_pct")),
            "delta_pct_display": _format_signed_pct(
                top_path.get("delta_vs_baseline_pct")
            ),
        }
    volume_chart = _volume_chart_view(scope_art)

    return {
        "tiles": tiles,
        "top_affected": top_affected,
        "volume_chart": volume_chart,
    }


def _volume_chart_view(scope_art: dict) -> dict | None:
    """Project ``volume_timeseries`` into chart-ready context, or None.

    Returns a dict the template feeds into ``incident_volume_chart()``
    plus a peak label, left/right time labels, and a textual summary.
    Returns ``None`` when the artifact does not carry timeseries data
    (e.g. degraded clusters, v1 wrappers from before this field
    existed), so the template can ``{% if impact.volume_chart %}``
    around it.

    Series selection is mechanical, driven by the dominant spike flag:
      - ``rate_429_up`` fired → plot 429s/minute (rate-limit story)
      - ``bot_share_up`` fired → plot bot-classified/minute
      - default → plot total requests/minute (volume story)
    See :func:`_select_chart_series`. Same inputs produce the same
    chart choice; the rule is unit-tested in tests/test_report_engine.py.
    """
    ts = scope_art.get("volume_timeseries") or {}
    window = scope_art.get("window_confirmation") or {}
    spike_flags = list(window.get("spike_flags") or [])

    # Multi-series shape (v2): ``series`` dict keyed by metric name.
    # Single-series shape (v1 backwards compat): ``current`` + ``baseline``
    # at top level, treated as the requests_per_minute series.
    if "series" in ts:
        series_dict = ts.get("series") or {}
    elif "current" in ts:
        series_dict = {
            "requests_per_minute": {
                "label": "Requests per minute",
                "spike_flag": "volume_up",
                "current": ts.get("current") or [],
                "baseline": ts.get("baseline") or [],
            }
        }
    else:
        series_dict = {}

    if not series_dict:
        return None

    selected_name, selected_series = _select_chart_series(series_dict, spike_flags)
    if selected_series is None:
        return None

    current = selected_series.get("current") or []
    baseline = selected_series.get("baseline") or []
    if len(current) < 2:
        return None

    def _clean(series: list) -> list[float]:
        out: list[float] = []
        for v in series:
            n = _safe_number(v)
            out.append(float(n) if n is not None else 0.0)
        return out

    current_values = _clean(current)
    baseline_values = _clean(baseline) if len(baseline) >= 2 else []

    peak_value = max(current_values)
    peak_idx = current_values.index(peak_value)
    n = len(current_values)
    # Best-effort timestamp interpolation: figure out the peak's
    # position in the window for the X-axis label.
    start = ts.get("start") or scope_art.get("scope", {}).get("start") or ""
    end = ts.get("end") or scope_art.get("scope", {}).get("end") or ""

    spike_flag = selected_series.get("spike_flag") or ""
    granularity = ts.get("granularity") or ""
    # Duration label reflects the *incident scope* window, not the
    # chart's timeseries window — the chart often carries 24h of
    # context for a 1h incident, and the operator-facing label should
    # name the incident, not the chart's framing window.
    scope_start = scope_art.get("scope", {}).get("start") or ""
    scope_end = scope_art.get("scope", {}).get("end") or ""
    return {
        "current": current_values,
        "baseline": baseline_values,
        "peak_value": peak_value,
        "peak_value_display": _format_count(peak_value),
        "peak_index": peak_idx,
        "peak_fraction": peak_idx / (n - 1) if n > 1 else 0.5,
        "peak_time_display": _interpolate_time_label(start, end, peak_idx, n),
        "duration_display": _duration_display(scope_start, scope_end, n, granularity),
        "left_label": _short_iso(start),
        "right_label": _short_iso(end),
        "metric_name": selected_name,
        "metric_label": selected_series.get("label") or selected_name.replace("_", " "),
        "selection_reason": _CHART_SELECTION_REASONS.get(
            spike_flag, "default — total volume tells the story"
        ),
        "baseline_avg_display": (
            _format_count(sum(baseline_values) / len(baseline_values))
            if baseline_values
            else None
        ),
        "granularity": granularity,
    }


def _interpolate_time_label(
    start_iso: str, end_iso: str, idx: int, n: int
) -> str:
    """Return a clock-friendly UTC label for index ``idx`` along
    [start_iso, end_iso] (n samples).

    Returns empty string when the timestamps don't parse cleanly. The
    label is intentionally clock-only (HH:MM UTC); the date is already
    in the window line above the chart.
    """
    if not start_iso or not end_iso or n <= 1:
        return ""
    try:
        start_dt = datetime.fromisoformat(start_iso.replace("Z", "+00:00"))
        end_dt = datetime.fromisoformat(end_iso.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return ""
    total = (end_dt - start_dt).total_seconds()
    if total <= 0:
        return ""
    fraction = idx / (n - 1)
    peak_seconds = total * fraction
    from datetime import timedelta

    peak_dt = start_dt + timedelta(seconds=peak_seconds)
    return f"{peak_dt:%H:%M} UTC"


def _duration_display(
    start_iso: str, end_iso: str, n: int, granularity: str
) -> str:
    """Return a humanized duration ("1 hour", "12 hours", "45 minutes").

    Computed from the timestamp delta; granularity is accepted so the
    label can shade to the producer's sampling step when timestamps are
    coarse. Returns empty string when parsing fails.
    """
    del n, granularity  # reserved for future granularity-aware rendering
    if not start_iso or not end_iso:
        return ""
    try:
        start_dt = datetime.fromisoformat(start_iso.replace("Z", "+00:00"))
        end_dt = datetime.fromisoformat(end_iso.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return ""
    seconds = int((end_dt - start_dt).total_seconds())
    if seconds <= 0:
        return ""
    if seconds % 3600 == 0:
        hours = seconds // 3600
        return f"{hours} hour" if hours == 1 else f"{hours} hours"
    if seconds >= 3600:
        hours = seconds / 3600
        return f"{hours:.1f} hours"
    minutes = max(1, seconds // 60)
    return f"{minutes} minute" if minutes == 1 else f"{minutes} minutes"


# Ordered most-specific first. ``_select_chart_series`` walks this list
# and picks the first preferred metric whose spike flag fired AND whose
# series is present in the artifact. The names are intentionally
# operator-readable so the chart caption can quote them directly.
_CHART_SELECTION_RULE = [
    ("rate_429_up", "req_429_per_minute"),
    ("bot_share_up", "bot_like_requests_per_minute"),
    ("volume_up", "requests_per_minute"),
]

_CHART_SELECTION_REASONS = {
    "rate_429_up": (
        "rate_429_up was the most specific spike flag — the rate-limit "
        "pressure curve is the lede"
    ),
    "bot_share_up": (
        "bot_share_up was the most specific spike flag — the automation "
        "wave shape is the lede"
    ),
    "volume_up": (
        "volume_up was the dominant spike — total request volume is the lede"
    ),
}


def _select_chart_series(
    series_dict: dict, spike_flags: list[str]
) -> tuple[str, dict | None]:
    """Mechanical chart-series selection from the dominant spike flag.

    Walks :data:`_CHART_SELECTION_RULE` in order; the first rule where
    (a) the spike flag is in ``spike_flags`` AND (b) the series is
    present in ``series_dict`` wins. Falls back to whatever's first in
    ``series_dict`` if nothing matches — common case is volume_up
    being the only fired flag, and ``requests_per_minute`` is the
    natural default series.

    Returns ``(metric_name, series_dict_entry)``. The entry is
    ``None`` only when ``series_dict`` is empty.
    """
    if not series_dict:
        return "", None
    spike_set = set(spike_flags)
    for spike_flag, metric_name in _CHART_SELECTION_RULE:
        if spike_flag in spike_set and metric_name in series_dict:
            return metric_name, series_dict[metric_name]
    # Fallback: first key in insertion order. Python dicts preserve
    # insertion order since 3.7, so this is deterministic.
    fallback_name = next(iter(series_dict))
    return fallback_name, series_dict[fallback_name]


def _short_iso(value: str) -> str:
    """Render an ISO timestamp as a chart axis label (HH:MM UTC)."""
    if not value or "T" not in value:
        return value or ""
    try:
        date_part, rest = value.split("T", 1)
        hhmm = rest[:5]
        return f"{date_part} {hhmm}Z"
    except ValueError:
        return value


def _top_delta(rows: list[dict]) -> object:
    """Pull the top-row delta-vs-baseline for the requests tile subscript."""
    if not rows:
        return None
    return rows[0].get("delta_vs_baseline_pct")


def _deterministic_summary(
    scope_art: dict,
    actors_art: dict,
    action_targets_art: dict,
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

    critical_targets = [
        t for t in suspicious_targets if t.get("severity") == "critical"
    ]
    high_targets = [t for t in suspicious_targets if t.get("severity") == "high"]
    medium_targets = [
        t for t in suspicious_targets if t.get("severity") in ("medium", "review")
    ]
    low_targets = [t for t in suspicious_targets if t.get("severity") == "low"]
    any_flagged = bool(suspicious_targets)

    critical_signal = bool(
        critical_targets and "volume_up" in spike_flags and raw_drilldown_available
    )
    high_signal = (
        not critical_signal
        and (critical_targets or high_targets)
        and ({"volume_up", "rate_429_up"} & set(spike_flags))
        and raw_drilldown_available
    )

    # `elevated` fires when critical/high targets exist but the strict
    # high rule did not — typically because the required spike flag is
    # absent or raw drilldown is unavailable. This is the "partial
    # signal" tier the editorial ladder needs so a 4→5 promotion does
    # not have to overstate the verdict.
    elevated_signal = (
        not critical_signal
        and not high_signal
        and bool(critical_targets or high_targets)
    )

    if critical_signal:
        level = "critical"
    elif high_signal:
        level = "high"
    elif elevated_signal:
        level = "elevated"
    elif spike_flags or any_flagged:
        level = "medium"
    else:
        level = "low"

    if raw_drilldown_available and edge_response_available:
        confidence = "high"
    elif raw_drilldown_available or edge_response_available:
        confidence = "medium"
    else:
        confidence = "low"

    # Reasoning sentence: name the specific signals driving the call,
    # not a generic "concentration is high" narration.
    reasons: list[str] = []
    if spike_flags:
        labelled = [SPIKE_FLAG_LABELS.get(f, f.replace("_", " ")) for f in spike_flags]
        reasons.append("spike flags fired (" + ", ".join(labelled) + ")")
    if critical_targets:
        names = ", ".join(
            f"{t.get('target_type_label')} `{t.get('target_value')}`"
            for t in critical_targets[:3]
        )
        reasons.append(
            f"{len(critical_targets)} target(s) at severity:critical — {names}"
        )
    if high_targets:
        names = ", ".join(
            f"{t.get('target_type_label')} `{t.get('target_value')}`"
            for t in high_targets[:3]
        )
        reasons.append(f"{len(high_targets)} target(s) at severity:high — {names}")
    if not critical_targets and not high_targets and medium_targets:
        reasons.append(
            f"{len(medium_targets)} target(s) at severity:medium (single-dimension concentration only)"
        )
    if not critical_targets and not high_targets and not medium_targets and low_targets:
        reasons.append(
            f"{len(low_targets)} target(s) at severity:low (single weak signal, no concurrence)"
        )
    if not raw_drilldown_available:
        reasons.append(
            "raw-log drilldown unavailable on this cluster, so target naming is out of reach"
        )
    if not edge_response_available:
        reasons.append(
            "no edge-response signal available (neither SIEM action class "
            "nor raw action_applied), so block coverage cannot be cross-checked"
        )
    if not reasons:
        reasons.append(
            "no spike flags fired and no targets crossed the heuristic ladder"
        )

    # Headlines are designed to flow after a CISA-cadence
    # "Assessed with [confidence] confidence:" prefix added in the
    # template — lowercase first letter, no leading "This window".
    headline_map = {
        "critical": "this window is consistent with a high-severity targeted incident and warrants escalation.",
        "high": "this window is consistent with a likely targeted incident.",
        "elevated": "this window shows critical-tier targets without full corroborating signal — investigate before standing down.",
        "medium": "this window shows movement worth investigating; the evidence is not yet decisive.",
        "low": "this window does not present evidence of an active incident.",
    }
    headline = headline_map[level]

    return {
        "level": level,
        "level_label": level.title(),
        "level_tone": CRITICALITY_TONE.get(level, "observe"),
        "confidence": confidence,
        "confidence_label": confidence.title(),
        "headline": headline,
        "reasons": reasons,
    }


_SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "review": 2,  # v1 vocabulary, sorts with medium
    "low": 3,
}


# Severity weights for the editorial Risk Score. Higher score = more
# risk. The raw value is `100 * penalty / (50 + penalty)`, so weights
# control how aggressively each flagged target lifts the score:
#   - 1 critical alone        →  penalty 30  → raw 38
#   - 3 criticals + 2 high    →  penalty 120 → raw 71
#   - 5 medium-only           →  penalty  20 → raw 29
# See `_risk_score()`.
_RISK_WEIGHTS = {
    "critical": 30,
    "high": 15,
    "elevated": 8,
    "medium": 4,
    "review": 4,  # v1 vocabulary, weighted with medium
    "low": 1,
}

# Bands the score is clamped into so the verdict pill and the numeric
# score never contradict each other (e.g. level=critical but score=22
# would read as "all clear" to a scanning exec). Higher score = worse,
# so the bands progress upward with severity. Each entry is the
# (inclusive_min, inclusive_max) integer band the level allows.
_RISK_BANDS = {
    "critical": (75, 100),
    "high":     (50, 74),
    "elevated": (35, 49),
    "medium":   (20, 34),
    "low":      ( 0, 19),
}


def _risk_score(deterministic_summary: dict, suspicious_targets: list[dict]) -> dict:
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
    level = deterministic_summary.get("level") or "low"
    counts: dict[str, int] = {}
    for target in suspicious_targets or []:
        sev = target.get("severity") or "review"
        counts[sev] = counts.get(sev, 0) + 1
    penalty = sum(_RISK_WEIGHTS.get(sev, 0) * count for sev, count in counts.items())
    raw_score = 100.0 * penalty / (50.0 + penalty)
    band_min, band_max = _RISK_BANDS.get(level, (0, 100))
    clamped = max(band_min, min(band_max, raw_score))
    return {
        "value": int(round(clamped)),
        "value_display": f"{int(round(clamped))}/100",
    }


# 5-step severity ladder. Step ordering matches the editorial layout:
# left = least severe, right = most severe. The "current" step is the
# rightmost lit one, and is the only step that draws a marker triangle.
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


def _compute_actor_cohort_overlap(
    suspicious_targets: list[dict],
    actors_artifact: dict,
) -> dict | None:
    """Bidirectional overlap between flagged client_ip and user_agent cohorts.

    Returns ``None`` when overlap can't be computed (one side empty, or
    the actors artifact has no ``actor_cooccurrence.client_ip__user_agent``
    payload). When both cohorts are populated, returns:

    - ``forward_pct``: of flagged-IP traffic, share that used a flagged UA
    - ``reverse_pct``: of flagged-UA traffic, share that came from a flagged IP
    - ``joint_requests``: requests in cells where both axes are flagged
    - ``flagged_ip_requests``: total flagged-IP traffic (from the client_ip
      ranking — across every UA the IP used, not just cells in the
      cooccurrence payload).
    - ``flagged_ua_requests``: total flagged-UA traffic (from the user_agent ranking)
    - ``is_disjoint``: True when forward AND reverse < ``COHORT_DISJOINT_OVERLAP_FLOOR_PCT``

    Denominators come from the marginal rankings rather than the joint
    cells, so the math stays correct even when the producer scopes the
    cooccurrence payload to ``top_K_ips × top_K_uas`` (a small, bounded
    set) instead of shipping every cell. The flagged sets are subsets
    of the top-K rankings by construction, so the numerator computed
    from the joint cells is complete.

    The disjoint case is the analytically interesting one — it signals
    the IP and UA heuristics are catching two separate attack populations
    hitting the same target, not one cohort viewed from two angles.
    """
    flagged_ips = {
        t.get("target_value")
        for t in suspicious_targets
        if t.get("target_type") == "client_ip" and t.get("target_value")
    }
    flagged_uas = {
        t.get("target_value")
        for t in suspicious_targets
        if t.get("target_type") == "user_agent" and t.get("target_value")
    }
    if not flagged_ips or not flagged_uas:
        return None

    cooccur = (actors_artifact or {}).get("actor_cooccurrence") or {}
    cells = cooccur.get("client_ip__user_agent") or []
    if not cells:
        return None

    rankings = (actors_artifact or {}).get("actor_rankings") or []
    ip_ranking = next((r for r in rankings if r.get("field") == "client_ip"), None)
    ua_ranking = next((r for r in rankings if r.get("field") == "user_agent"), None)
    if ip_ranking is None or ua_ranking is None:
        return None

    flagged_ip_total = sum(
        int(_safe_number(row.get("requests")) or 0)
        for row in ip_ranking.get("rows") or []
        if str(row.get("value") or "") in flagged_ips
    )
    flagged_ua_total = sum(
        int(_safe_number(row.get("requests")) or 0)
        for row in ua_ranking.get("rows") or []
        if str(row.get("value") or "") in flagged_uas
    )
    if flagged_ip_total == 0 or flagged_ua_total == 0:
        return None

    joint_total = 0
    for cell in cells:
        ip = str(cell.get("ip") or cell.get("client_ip") or "")
        ua = str(cell.get("ua") or cell.get("user_agent") or "")
        reqs = int(_safe_number(cell.get("requests")) or 0)
        if reqs <= 0:
            continue
        if ip in flagged_ips and ua in flagged_uas:
            joint_total += reqs

    forward_pct = 100.0 * joint_total / flagged_ip_total
    reverse_pct = 100.0 * joint_total / flagged_ua_total
    return {
        "forward_pct": round(forward_pct, 2),
        "reverse_pct": round(reverse_pct, 2),
        "joint_requests": joint_total,
        "flagged_ip_requests": flagged_ip_total,
        "flagged_ua_requests": flagged_ua_total,
        "flagged_ip_count": len(flagged_ips),
        "flagged_ua_count": len(flagged_uas),
        "is_disjoint": (
            forward_pct < COHORT_DISJOINT_OVERLAP_FLOOR_PCT
            and reverse_pct < COHORT_DISJOINT_OVERLAP_FLOOR_PCT
        ),
    }


_IOC_SCOPE_VIEW_TOP_N = 3  # entries per seen_at / seen_with list


def _compute_actor_cohort_topology(cohort_overlap: dict | None) -> dict | None:
    """Project the cohort-overlap helper output into the SOAR-facing
    topology block embedded at the IOC export's top level.

    A SOAR consumer reading only ``indicators[]`` can't see Finding 03
    (it's rendered prose, not machine-readable). The topology block
    surfaces the same disjoint-vs-aligned signal so the consumer can
    branch its mitigation policy on a boolean rather than parsing
    the editorial body. Returns ``None`` when overlap can't be
    computed (one cohort empty, or no joint cell payload).
    """
    if not cohort_overlap:
        return None
    disjoint = bool(cohort_overlap.get("is_disjoint"))
    if disjoint:
        interpretation = (
            "Flagged IPs and flagged UAs target the same window from "
            "separate populations — apply mitigations independently."
        )
    else:
        interpretation = (
            "Flagged IPs and flagged UAs overlap meaningfully — "
            "consider composing them into a single mitigation rule."
        )
    return {
        "client_ip_user_agent": {
            "forward_overlap_pct": cohort_overlap.get("forward_pct"),
            "reverse_overlap_pct": cohort_overlap.get("reverse_pct"),
            "joint_requests": cohort_overlap.get("joint_requests"),
            "flagged_ip_requests": cohort_overlap.get("flagged_ip_requests"),
            "flagged_ua_requests": cohort_overlap.get("flagged_ua_requests"),
            "flagged_ip_count": cohort_overlap.get("flagged_ip_count"),
            "flagged_ua_count": cohort_overlap.get("flagged_ua_count"),
            "disjoint": disjoint,
            "interpretation": interpretation,
        }
    }


_EDGE_ACTION_LABELS = {
    "Deny": "Denied",
    "Monitor": "Monitored",
    "Allow": "Passed",
    "Tarpit": "Tarpitted",
}


def _compute_edge_action_for_indicator(
    target: dict, actors_artifact: dict | None
) -> dict | None:
    """Aggregate the per-IP edge-action share for a client_ip indicator.

    Reads the ``client_ip__action_applied`` cooccurrence cells produced
    by the Step 4c joint GROUP BY. Returns ``None`` when the indicator
    is not an IP, or the cooccurrence payload is absent, or no cells
    matched this IP.

    Output shape:
      - ``denied_share`` / ``monitored_share`` / ``passed_share``:
        floats in ``[0, 1]`` measured against the per-IP request total
        observed across the joint cells (denominator is the sum of all
        action cells for this IP, NOT the marginal ranking total —
        the joint query is scoped to top-K candidates so the marginal
        and joint sums match for actors in the top-K set).
      - ``top_action``: the raw Akamai action_applied value with the
        largest share (e.g. ``"Deny"``).
      - ``top_action_label``: human display of ``top_action``
        (``"Denied"``, ``"Monitored"``, ``"Passed"``).
      - ``top_action_share``: share for ``top_action``.
    """
    if (target.get("target_type") or "") != "client_ip":
        return None
    target_value = str(target.get("target_value") or "")
    if not target_value:
        return None
    cooccur = (actors_artifact or {}).get("actor_cooccurrence") or {}
    cells = cooccur.get("client_ip__action_applied") or []
    bucket: dict[str, int] = {}
    for cell in cells:
        if str(cell.get("ip") or "") != target_value:
            continue
        action = str(cell.get("action") or "").strip()
        reqs = int(_safe_number(cell.get("requests")) or 0)
        if not action or reqs <= 0:
            continue
        bucket[action] = bucket.get(action, 0) + reqs
    total = sum(bucket.values())
    if total <= 0:
        return None

    def _share(action: str) -> float:
        return bucket.get(action, 0) / total

    top_action, top_count = max(bucket.items(), key=lambda kv: kv[1])
    return {
        "denied_share": round(_share("Deny"), 4),
        "monitored_share": round(_share("Monitor"), 4),
        "passed_share": round(_share("Allow"), 4),
        "top_action": top_action,
        "top_action_label": _EDGE_ACTION_LABELS.get(top_action, top_action),
        "top_action_share": round(top_count / total, 4),
    }


def _scope_views_for_indicator(
    target: dict,
    actors_artifact: dict,
    top_n: int = _IOC_SCOPE_VIEW_TOP_N,
) -> dict:
    """Project per-indicator ``seen_at`` / ``seen_with`` from the
    actor_cooccurrence cells.

    ``seen_at`` (on actor indicators): the top targets the actor was
    observed hitting, ranked by share of the actor's own request total.
    Lets a SOAR scope a block to a specific path instead of site-wide.

    ``seen_with`` (on indicators of either side): the top counterparty
    entities seen with this one. For an actor: top targets if path
    cooccurrence is available, else top counterparty actors. For a
    target: top actors hitting it. Lets a SOAR pair indicator-level
    actions across the actor / target axis.

    All shares use the marginal rankings as the denominator (per-entity
    total across the full window), not the cooccurrence cells alone —
    so a row's ``share_of_actor_traffic = 0.91`` is honestly
    "91% of this IP's window traffic went to this path" not "91% of
    the IP's traffic-into-the-top-K-paths."
    """
    target_value = str(target.get("target_value") or "")
    target_type = target.get("target_type") or ""
    if not target_value:
        return {}

    cooccur = (actors_artifact or {}).get("actor_cooccurrence") or {}
    ip_path_cells = cooccur.get("client_ip__request_path") or []
    ip_ua_cells = cooccur.get("client_ip__user_agent") or []

    rankings = (actors_artifact or {}).get("actor_rankings") or []
    ranking_by_field = {
        r.get("field"): r for r in rankings if r.get("field")
    }

    def _marginal_total(field: str, value: str) -> int:
        ranking = ranking_by_field.get(field) or {}
        for row in ranking.get("rows") or []:
            if str(row.get("value") or "") == value:
                return int(_safe_number(row.get("requests")) or 0)
        return 0

    def _top_counterparties(
        cells: list[dict],
        key_self: str,
        key_other: str,
        self_value: str,
        denom_total: int,
        other_type_label: str,
    ) -> list[dict]:
        # Aggregate cells where key_self == self_value, sum by other.
        bucket: dict[str, int] = {}
        for cell in cells:
            if str(cell.get(key_self) or "") != self_value:
                continue
            other = str(cell.get(key_other) or "")
            reqs = int(_safe_number(cell.get("requests")) or 0)
            if not other or reqs <= 0:
                continue
            bucket[other] = bucket.get(other, 0) + reqs
        sorted_pairs = sorted(bucket.items(), key=lambda kv: -kv[1])
        out: list[dict] = []
        for other_value, reqs in sorted_pairs[:top_n]:
            share = reqs / denom_total if denom_total > 0 else 0.0
            out.append(
                {
                    "type": other_type_label,
                    "value": other_value,
                    "requests": reqs,
                    "share": round(share, 4),
                }
            )
        return out

    result: dict = {}
    if target_type == "client_ip":
        ip_total = _marginal_total("client_ip", target_value)
        seen_at_paths = _top_counterparties(
            ip_path_cells, "ip", "path", target_value, ip_total, "request_path",
        )
        if seen_at_paths:
            result["seen_at"] = seen_at_paths
        seen_with_uas = _top_counterparties(
            ip_ua_cells, "ip", "ua", target_value, ip_total, "user_agent",
        )
        if seen_with_uas:
            result["seen_with"] = seen_with_uas
    elif target_type == "user_agent":
        ua_total = _marginal_total("user_agent", target_value)
        seen_with_ips = _top_counterparties(
            ip_ua_cells, "ua", "ip", target_value, ua_total, "client_ip",
        )
        if seen_with_ips:
            result["seen_with"] = seen_with_ips
    elif target_type == "request_path":
        path_total = _marginal_total("request_path", target_value)
        seen_with_ips = _top_counterparties(
            ip_path_cells, "path", "ip", target_value, path_total, "client_ip",
        )
        if seen_with_ips:
            result["seen_with"] = seen_with_ips
    edge_action = _compute_edge_action_for_indicator(target, actors_artifact)
    if edge_action:
        result["edge_action"] = edge_action
    return result


def _attack_aggregation(suspicious_targets: list[dict]) -> list[dict]:
    """Aggregate ATT&CK techniques across the suspicious-target list.

    Iterates every target's ``attack_techniques`` list, dedupes by
    technique id, and tallies how many targets reference each id.
    Output is sorted by ``count desc, id asc`` so the editorial
    "Consistent with" panel reads with the most-referenced techniques
    at the top and ties break alphabetically (deterministic).
    """
    tally: dict[str, dict] = {}
    for target in suspicious_targets or []:
        for technique in target.get("attack_techniques") or []:
            tid = technique.get("id") or ""
            if not tid:
                continue
            entry = tally.setdefault(
                tid,
                {
                    "id": tid,
                    "name": technique.get("name") or "",
                    "tactic": technique.get("tactic") or "",
                    "count": 0,
                },
            )
            # Prefer the first-seen name/tactic; later occurrences with
            # blank fields don't overwrite a populated name.
            if not entry["name"] and technique.get("name"):
                entry["name"] = technique.get("name")
            if not entry["tactic"] and technique.get("tactic"):
                entry["tactic"] = technique.get("tactic")
            entry["count"] += 1
    return sorted(
        tally.values(),
        key=lambda r: (-r["count"], r["id"]),
    )


_ACTION_URGENCY_NOW = {"now", "today"}


def _recommended_actions_view(
    suspicious_targets: list[dict],
    dashboard_url: str,
    notes_by_slot: dict | None = None,  # noqa: ARG001  (Phase 2 hook)
) -> list[dict]:
    """Deterministic recommended-actions list (Phase 1).

    Builds a 3–5 item ordered list seeded from the top suspicious
    targets, the dashboard link, and a retro reminder. Each item
    carries ``{num, step, role, urgency}``. Phase 2 wires in
    ``notes_by_slot["next_steps"]`` for LLM-authored steps; the
    ``notes_by_slot`` parameter is accepted now so the signature is
    stable across the two phases.

    Item generation rules:
      - First action targets the top severity:critical or severity:high
        IP / ASN if one exists ("Block at edge").
      - Second action enriches the next 1–3 critical / high targets
        ("Enrich in case management") — collapses to a count phrase
        when the list grows.
      - Third action tightens rate-limit on the top path pattern.
      - Fourth action surfaces any behavioral-anomaly targets for
        AppSec.
      - Fifth action is the post-incident retro reminder.

    Empty-target inputs collapse to the dashboard link + retro pair so
    the list never collapses below two items.
    """
    actions: list[tuple[str, str, str, str | None]] = []  # (step, role, urgency, effect)

    # Filter targets by severity tier for the rules below.
    crits = [t for t in suspicious_targets if t.get("severity") == "critical"]
    highs = [t for t in suspicious_targets if t.get("severity") == "high"]
    crit_or_high = crits + highs
    anomalies = [
        t
        for t in suspicious_targets
        if "behavioral anomaly" in (t.get("reason_flag_labels") or [])
    ]
    # Block-at-edge candidate: prefer the top severity:critical ASN, then
    # severity:critical IP; if none exist, fall back to the top high IP
    # so the recommendation is always concrete when targets exist.
    edge_candidate: dict | None = None
    for target in crit_or_high:
        if target.get("target_type") in ("asn", "client_ip"):
            edge_candidate = target
            break
    if edge_candidate is not None:
        type_label = edge_candidate.get("target_type_label") or ""
        value = edge_candidate.get("target_value") or ""
        actions.append(
            (
                f"Block {type_label} `{value}` at edge for 24h, monitor 429 trajectory",
                "SOC",
                "now",
                _action_effect_block(edge_candidate),
            )
        )

    if crits:
        names = ", ".join(f"`{t.get('target_value')}`" for t in crits[:3])
        suffix = "" if len(crits) <= 3 else f" (+{len(crits) - 3} more)"
        actions.append(
            (
                f"Enrich the {len(crits)} critical target(s) in case management — {names}{suffix}",
                "Threat Intel",
                "today",
                None,
            )
        )

    # Tighten rate-limit on the top path pattern flagged as
    # severity:critical/high if one exists; otherwise on the most-
    # concentrated path target overall.
    path_target = next(
        (t for t in crit_or_high if t.get("target_type") == "request_path"),
        next(
            (t for t in suspicious_targets if t.get("target_type") == "request_path"),
            None,
        ),
    )
    if path_target is not None:
        path_value = path_target.get("target_value") or ""
        actions.append(
            (
                f"Tighten rate-limit on `{path_value}` to a conservative threshold",
                "Platform",
                "today",
                _action_effect_rate_limit(path_target),
            )
        )

    if anomalies:
        names = ", ".join(
            f"{t.get('target_type_label')} `{t.get('target_value')}`"
            for t in anomalies[:2]
        )
        actions.append(
            (
                f"Investigate behavioral-anomaly cohort — {names}",
                "AppSec",
                "this week",
                None,
            )
        )

    if dashboard_url:
        actions.append(
            (
                "Continue investigating in the linked Grafana dashboard (pre-scoped to the incident window)",
                "IR Lead",
                "now",
                None,
            )
        )

    actions.append(
        (
            "Schedule retrospective — review SIEM coverage on affected endpoints",
            "IR Lead",
            "this week",
            None,
        )
    )

    # Cap at 5 and number from 1.
    out: list[dict] = []
    for idx, (step, role, urgency, effect) in enumerate(actions[:5], start=1):
        out.append(
            {
                "num": f"{idx:02d}",
                "step": step,
                "role": role,
                "urgency": urgency,
                "urgency_tone": "critical"
                if urgency in _ACTION_URGENCY_NOW
                else "neutral",
                "effect": effect,
            }
        )
    return out


def _action_effect_block(target: dict) -> str | None:
    """Compose an observed-volume sentence for a block-at-edge action.

    Reads the supporting-metrics fields the suspicious_targets view
    already projects (``requests_display``, ``share_pct_display``,
    ``edge_action_top_label``, ``edge_action_top_share_display``) and
    returns a short sentence the template renders as a mute sub-line
    under the action step. The phrasing is observed-window framing
    ("Observed volume: X"), not predicted reduction — the report does
    not assert what a block will remove, only what the target carried.
    Returns None when no usable supporting metric is present so the
    template can omit the line entirely.
    """
    reqs = target.get("requests_display")
    share = target.get("share_pct_display")
    edge_label = target.get("edge_action_top_label")
    edge_share = target.get("edge_action_top_share_display")
    if not reqs:
        return None
    parts = [f"Observed volume: {reqs}"]
    if share:
        parts[0] = f"Observed volume: {reqs} ({share} of window)"
    parts[0] += "."
    if edge_label and edge_share:
        parts.append(f"Edge currently {edge_share} {edge_label.lower()}.")
    return " ".join(parts)


def _action_effect_rate_limit(target: dict) -> str | None:
    """Compose an observed-volume sentence for a rate-limit action.

    Same observed-window framing as :func:`_action_effect_block` — the
    sentence describes what the target carried during the window, not
    a predicted post-rate-limit reduction.
    """
    reqs = target.get("requests_display")
    share = target.get("share_pct_display")
    distinct_paths = target.get("distinct_paths_display")
    path_value = target.get("target_value") or ""
    if not reqs:
        return None
    label = f"`{path_value}`" if path_value else "flagged path"
    head = f"Observed {label} volume: {reqs}"
    if share:
        head += f" ({share} of window)"
    if distinct_paths and distinct_paths != "—":
        return f"{head}; across {distinct_paths} request paths."
    return f"{head}."


def _finding_entity(target: dict) -> dict:
    """Project a suspicious-target row into the entity-list shape used
    by ``incident_findings[].entities``.

    Entities render as a bulleted list inside a finding body, so each
    one gets a ``value`` (the identifier itself, monospace) and an
    optional ``meta`` annotation (the share, ASN org, etc. — whatever
    short context the analyst would want next to the identifier).
    Inline comma-joined lists of long values (IPs, full UA strings)
    are unreadable; the bulleted shape fixes that.
    """
    supporting = target.get("supporting") or {}
    share_display = target.get("share_pct_display")
    meta_parts: list[str] = []
    asn_id = supporting.get("asn_cluster_id")
    asn_org = supporting.get("asn_cluster_org") or ""
    if asn_id:
        meta_parts.append(f"AS{asn_id}{(' · ' + asn_org) if asn_org else ''}")
    if share_display:
        meta_parts.append(f"{share_display} of window")
    return {
        "value": target.get("target_value") or "",
        "target_type": target.get("target_type") or "",
        "target_type_label": target.get("target_type_label") or "",
        "meta": " · ".join(meta_parts) if meta_parts else "",
        "severity": target.get("severity") or "",
        "severity_tone": target.get("severity_tone", "observe"),
    }


def _incident_findings(
    suspicious_targets: list[dict],
    deterministic_summary: dict,
    spike_flags: list[str],
    cohort_overlap: dict | None = None,
) -> list[dict]:
    """Build the 3-finding editorial verdict block (Phase 1 deterministic).

    Each finding is ``{label, lead, body}`` — the label is the numbered
    eyebrow ("Finding 01"), the lead is a short headline sentence, and
    the body is the supporting evidence paragraph. Findings are
    generated mechanically from the top suspicious targets + spike
    flags so this slot always renders even when no LLM analyst note is
    supplied. Phase 2 layers in an ``llm-incident-findings`` slot that
    replaces this entire list when present.

    Selection rules:
      - Finding 01 always describes the top-tier target group
        (critical IPs if any, otherwise top severity group).
      - Finding 02 describes the next distinct dimension — if Finding
        01 was IP-based, this one prefers UA / ASN / cohort signals.
      - Finding 03 surfaces the most surprising secondary signal: a
        spike flag without a target, or a behavioral-anomaly cohort.

    Always returns exactly 3 items, padding with deterministic
    fallbacks ("No additional flagged signals in this window.") when
    the artifact data is too thin to produce three distinct findings.
    """
    findings: list[dict] = []

    crits = [t for t in suspicious_targets if t.get("severity") == "critical"]
    highs = [t for t in suspicious_targets if t.get("severity") == "high"]
    crit_ips = [t for t in crits if t.get("target_type") == "client_ip"]
    ua_targets = [t for t in suspicious_targets if t.get("target_type") == "user_agent"]
    cohort_targets = [t for t in suspicious_targets if t.get("target_type") == "cohort"]
    anomalies = [
        t
        for t in suspicious_targets
        if "behavioral anomaly" in (t.get("reason_flag_labels") or [])
    ]

    # Finding 01 — top tier group.
    if crit_ips:
        share = sum(float(t.get("share_pct") or 0) for t in crit_ips[:3])
        findings.append(
            {
                "label": "Finding 01",
                "lead": "Critical-tier client IPs coordinated against this window.",
                "body": (
                    f"These IPs drove ~{share:.0f}% of window traffic and "
                    "crossed the multi-signal heuristic ladder (volume + "
                    "429 share + single-path concentration):"
                ),
                "entities": [
                    _finding_entity(t) for t in crit_ips[:3]
                ],
            }
        )
    elif crits or highs:
        top = (crits or highs)[0]
        findings.append(
            {
                "label": "Finding 01",
                "lead": f"{top.get('target_type_label') or 'Top target'} flagged at {top.get('severity_label') or 'high'} severity.",
                "body": (
                    f"`{top.get('target_value')}` accounted for "
                    f"{top.get('share_pct_display') or '—'} of window traffic; "
                    f"reason flags: {', '.join(top.get('reason_flag_labels') or []) or '—'}."
                ),
            }
        )

    # Finding 02 — UA / ASN automation footprint, if distinct.
    if ua_targets:
        share = sum(float(t.get("share_pct") or 0) for t in ua_targets[:2])
        findings.append(
            {
                "label": "Finding 02",
                "lead": "Automation tooling declared in the user agent.",
                "body": (
                    f"These user agents account for ~{share:.0f}% of "
                    "traffic and match curated automation patterns. The "
                    "report does not infer intent from the identifier — "
                    "the names below are what the requests presented:"
                ),
                "entities": [
                    _finding_entity(t) for t in ua_targets[:2]
                ],
            }
        )

    # Finding 03 — slot priority:
    #   1. Disjoint IP / UA cohorts (when the producer supplies joint
    #      cell counts and overlap is below the floor) — the most
    #      surprising secondary signal when it applies: the heuristic
    #      ladder is catching two distinct attack populations hitting
    #      the same target, not one cohort viewed from two angles.
    #   2. Behavioral anomaly cohort.
    #   3. Spike flags fired without a named actor.
    if cohort_overlap and cohort_overlap.get("is_disjoint"):
        findings.append(
            {
                "label": "Finding 03",
                "lead": "Two disjoint attack cohorts on the same window.",
                "body": (
                    f"The {cohort_overlap['flagged_ip_count']} flagged IPs and "
                    f"{cohort_overlap['flagged_ua_count']} flagged UAs barely "
                    f"overlap — only {cohort_overlap['forward_pct']:.1f}% of "
                    "flagged-IP traffic uses a flagged UA, and "
                    f"{cohort_overlap['reverse_pct']:.1f}% of flagged-UA "
                    "traffic comes from a flagged IP. The two heuristic "
                    "ladders are catching different attack populations on the "
                    "same target — treat them as separate cohorts, not one fleet."
                ),
            }
        )
    elif anomalies or cohort_targets:
        anomaly = (anomalies or cohort_targets)[0]
        findings.append(
            {
                "label": "Finding 03",
                "lead": "Behavioral cohort anomaly is the worry.",
                "body": (
                    f"`{anomaly.get('target_value')}` shows a behavioral "
                    "departure from the trailing baseline — consistent "
                    "with sophisticated automation passing bot-classification."
                ),
            }
        )
    elif spike_flags and not suspicious_targets:
        labelled = ", ".join(
            SPIKE_FLAG_LABELS.get(f, f.replace("_", " ")) for f in spike_flags
        )
        findings.append(
            {
                "label": "Finding 03",
                "lead": "Spike flags fired without a named actor.",
                "body": (
                    f"{labelled} confirmed at the scope-table level, but "
                    "the heuristic ladder did not flag any individual "
                    "target — likely a distributed surge spread across "
                    "many small contributors."
                ),
            }
        )

    # Pad to exactly 3 with a deterministic placeholder so the
    # editorial grid never collapses to fewer columns.
    headline = (deterministic_summary or {}).get("headline") or (
        "Findings will populate as the heuristic surfaces flagged targets."
    )
    while len(findings) < 3:
        findings.append(
            {
                "label": f"Finding {len(findings) + 1:02d}",
                "lead": "No additional flagged signals in this window.",
                "body": headline,
            }
        )

    # Renumber labels in case the slots were filled out of order.
    for idx, finding in enumerate(findings, start=1):
        finding["label"] = f"Finding {idx:02d}"
    return findings[:3]


def _concentration_chart_view(suspicious_targets: list[dict]) -> dict:
    """Project the top N suspicious targets into a horizontal-bar shape.

    Designed for C-level scannability: the C-suite reads the report in
    90 seconds; a chart that visually shows "look how few entities own
    most of this" lands faster than a ranked table does. The chart
    sits above the detailed Suspicious Targets table; the table is
    still authoritative.

    Bar widths normalize to 100% of the window (not to the chart max)
    so the lengths read honestly — a 43% bar is 43% of total window
    traffic, not "43% of the chart." Color follows the row's severity
    tone so the visual hierarchy carries through.
    """
    top_n = 5
    # Sort by share_pct desc so the longest bar leads. The detail table
    # below preserves the severity-first ordering; that one is for
    # analysts walking a triage list. This chart is for executives
    # scanning "which entities concentrate the traffic" in one glance.
    by_share = sorted(
        suspicious_targets,
        key=lambda t: -(float(t.get("share_pct") or 0)),
    )
    rows = []
    for target in by_share[:top_n]:
        share = target.get("share_pct") or 0
        try:
            share_value = float(share)
        except (TypeError, ValueError):
            share_value = 0.0
        rows.append(
            {
                "target_type": target.get("target_type"),
                "target_type_label": target.get("target_type_label"),
                "target_value": target.get("target_value"),
                "share_pct": share_value,
                "share_pct_display": target.get("share_pct_display") or "—",
                "severity_tone": target.get("severity_tone", "observe"),
                "severity": target.get("severity"),
                "severity_label": target.get("severity_label"),
                # CSS width in percent — clamped so a single-actor 100%+
                # would still render inside the bar track. The clamp is a
                # rendering-only choice; the displayed share_pct_display
                # text is the source-of-truth value.
                "bar_width_pct": max(0.0, min(100.0, share_value)),
            }
        )
    coverage_pct = sum(r["share_pct"] for r in rows)
    return {
        "rows": rows,
        "top_n": min(top_n, len(suspicious_targets)),
        "total_count": len(suspicious_targets),
        # Note: coverage_pct is informational only. Cross-field rows
        # (e.g. an IP and its containing ASN) do double-count traffic,
        # so this is "sum of named shares" not "share of all traffic."
        # The template uses it to phrase the caption honestly.
        "coverage_pct_display": (f"{coverage_pct:.0f}%" if coverage_pct > 0 else "—"),
    }


def _ioc_view(
    action_targets_art: dict,
    scope_meta: dict,
    actors_artifact: dict | None = None,
    cohort_overlap: dict | None = None,
) -> dict:
    """Project action-targets into a SIEM-ingestion-ready IOC export.

    Wraps the suspicious-target rows in a ``bot_incident_iocs.v1`` shape
    designed for downstream SOC tooling: schema header, scope context,
    optional ``cohort_topology`` describing actor sub-population
    overlap, and a flat ``indicators`` array. Each indicator carries
    its IOC type (using SOC vocabulary, not the report-internal
    target_type), severity, confidence, the analyst window as
    first/last observed timestamps, reason flags, ATT&CK techniques,
    supporting evidence, and (when the actor_cooccurrence payload is
    present) ``seen_at`` / ``seen_with`` scope qualifiers — top
    counterparties so a SOAR consumer can compose path-scoped
    blocks instead of site-wide ones.

    The export is *additive* — the same underlying data lives in
    bot_incident_action_targets.v1; this view is the read model SOC
    automation consumes.
    """
    targets = list(action_targets_art.get("targets") or [])
    cluster = scope_meta.get("cluster") or ""
    actors_artifact = actors_artifact or {}
    indicators: list[dict] = []
    for t in targets:
        target_type = t.get("target_type") or ""
        ioc_type = IOC_TYPE_MAP.get(target_type, target_type)
        supporting = t.get("supporting") or {}
        indicator: dict = {
            "type": ioc_type,
            "value": t.get("target_value"),
            "kind": t.get("kind") or "actor",
            "severity": t.get("severity"),
            "confidence": t.get("confidence"),
            "first_observed": scope_meta.get("start"),
            "last_observed": scope_meta.get("end"),
            "reason_flags": list(t.get("reason_flags") or []),
            "attack_techniques": list(t.get("attack_techniques") or []),
            "supporting": supporting,
            "suggested_action_hint": t.get("suggested_action_hint") or "review",
            "action_class": t.get("action_class") or "watch",
        }
        scope_views = _scope_views_for_indicator(t, actors_artifact)
        if scope_views.get("seen_at"):
            indicator["seen_at"] = scope_views["seen_at"]
        if scope_views.get("seen_with"):
            indicator["seen_with"] = scope_views["seen_with"]
        if scope_views.get("edge_action"):
            indicator["edge_action"] = scope_views["edge_action"]
        indicators.append(indicator)

    view: dict = {
        "schema": "bot_incident_iocs.v1",
        "scope": {
            "cluster": cluster,
            "host": scope_meta.get("host"),
            "asn": scope_meta.get("asn"),
            "path_pattern": scope_meta.get("path_pattern"),
            "window_start": scope_meta.get("start"),
            "window_end": scope_meta.get("end"),
            "baseline_start": scope_meta.get("baseline_start"),
            "baseline_end": scope_meta.get("baseline_end"),
        },
        "source_artifact": "bot_incident_action_targets.v1",
        "heuristic_version": action_targets_art.get("heuristic_version"),
        "indicators": indicators,
    }
    topology = _compute_actor_cohort_topology(cohort_overlap)
    if topology:
        view["cohort_topology"] = topology
    return view


def _ioc_json_text(ioc_view: dict) -> str:
    """Serialize the IOC view as indented JSON for the report's IOC appendix.

    Keys are not sorted — preserving the structured ordering keeps the
    schema/scope/indicators flow obvious to a reader scanning the
    rendered code block.
    """
    import json

    return json.dumps(ioc_view, indent=2)


def _suspicious_targets_view(
    action_targets_art: dict,
    actors_artifact: dict | None = None,
) -> list[dict]:
    """Order action-target rows for rendering: severity desc, then requests desc.

    When ``actors_artifact`` is supplied and carries
    ``actor_cooccurrence["client_ip__action_applied"]`` cells, each
    client_ip row is annotated with an ``edge_action`` payload plus
    display-ready ``edge_action_top_label`` /
    ``edge_action_top_share_display`` fields so the template can stack
    a mute "95% Denied" sub-line under the action chip without redoing
    the share math.
    """
    rows = list(action_targets_art.get("targets") or [])

    def _sort_key(row: dict) -> tuple[int, float]:
        severity = row.get("severity") or "review"
        severity_rank = _SEVERITY_ORDER.get(severity, 99)
        requests = _safe_number((row.get("supporting") or {}).get("requests")) or 0
        return (severity_rank, -float(requests))

    rows_sorted = sorted(rows, key=_sort_key)
    out: list[dict] = []
    for row in rows_sorted:
        supporting = row.get("supporting") or {}
        target_type = row.get("target_type") or ""
        flags = list(row.get("reason_flags") or [])
        attack_techniques = list(row.get("attack_techniques") or [])
        severity = row.get("severity") or "review"
        kind = row.get("kind") or "actor"
        action_class = row.get("action_class") or "watch"
        edge_action = _compute_edge_action_for_indicator(row, actors_artifact)
        edge_action_top_label = (
            edge_action.get("top_action_label") if edge_action else None
        )
        edge_action_top_share_display = (
            _format_pct(round(100.0 * edge_action["top_action_share"], 2))
            if edge_action
            else None
        )
        out.append(
            {
                "target_type": target_type,
                "target_type_label": TARGET_TYPE_LABELS.get(
                    target_type, target_type.replace("_", " ").title()
                ),
                "kind": kind,
                "kind_label": kind.title(),
                "action_class": action_class,
                "action_class_label": ACTION_CLASS_LABELS.get(
                    action_class, action_class.replace("-", " ").title()
                ),
                "action_class_tone": ACTION_CLASS_TONE.get(action_class, "watch"),
                "target_value": str(row.get("target_value") or ""),
                "edge_action": edge_action,
                "edge_action_top_label": edge_action_top_label,
                "edge_action_top_share_display": edge_action_top_share_display,
                "reason_flags": flags,
                "reason_flag_labels": [
                    REASON_FLAG_LABELS.get(flag, flag.replace("_", " "))
                    for flag in flags
                ],
                "attack_techniques": attack_techniques,
                "attack_techniques_summary": ", ".join(
                    t.get("id", "") for t in attack_techniques
                )
                or "—",
                "severity": severity,
                "severity_tone": SEVERITY_TONE.get(severity, "observe"),
                "severity_label": severity.title(),
                "confidence": row.get("confidence") or "",
                "confidence_label": (row.get("confidence") or "").title(),
                "suggested_action_hint": row.get("suggested_action_hint") or "review",
                "requests": _safe_number(supporting.get("requests")),
                "requests_display": _format_count(supporting.get("requests")),
                "share_pct": _safe_number(supporting.get("share_pct")),
                "share_pct_display": _format_pct(supporting.get("share_pct")),
                "req_429": _safe_number(supporting.get("req_429")),
                "req_429_display": _format_count(supporting.get("req_429")),
                "req_429_share_pct": _safe_number(supporting.get("req_429_share_pct")),
                "req_429_share_display": _format_pct(
                    supporting.get("req_429_share_pct")
                ),
                "distinct_paths": _safe_number(supporting.get("distinct_paths")),
                "distinct_paths_display": _format_int(supporting.get("distinct_paths")),
                # Pass the raw supporting dict through (including
                # supporting_extras keys like asn_cluster_id /
                # asn_cluster_org / botnet_cluster_share_pct) so
                # downstream helpers like _finding_entity can annotate
                # entities with cluster context without re-flattening
                # the whole shape into top-level keys.
                "supporting": dict(supporting),
            }
        )
    return out


def _scope_filters(
    host: str | None, asn: str | int | None, path_pattern: str | None
) -> list[dict]:
    parts: list[dict] = []
    if host:
        parts.append({"label": "Host", "value": host})
    if asn not in (None, ""):
        parts.append({"label": "ASN", "value": str(asn)})
    if path_pattern:
        parts.append({"label": "Path pattern", "value": path_pattern})
    return parts


def _short_window(scope_meta: dict) -> str:
    """Render a scope window as a compact headline label.

    Same-day windows collapse to 'YYYY-MM-DD HH:MM-HH:MM UTC' (the
    common case for incident reports — a 3-hour spike inside one day).
    Cross-day windows fall back to a date range. Malformed timestamps
    drop through to a string-only fallback.
    """
    start = scope_meta.get("start") or ""
    end = scope_meta.get("end") or ""

    if not start and not end:
        return ""

    try:
        start_dt = datetime.fromisoformat(start.replace("Z", "+00:00"))
        end_dt = datetime.fromisoformat(end.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        # Date-only fallback for non-ISO inputs.
        def _date(v: str) -> str:
            return v.split("T", 1)[0] if "T" in v else v

        return f"{_date(start)} → {_date(end)}"

    if start_dt.date() == end_dt.date():
        return f"{start_dt:%Y-%m-%d %H:%M}-{end_dt:%H:%M} UTC"
    return f"{start_dt:%Y-%m-%d} → {end_dt:%Y-%m-%d}"


def _window_confirmation_view(window: dict) -> dict:
    spike_flags = window.get("spike_flags") or []
    blocked_share = window.get("blocked_share_pct")
    tiles = [
        {
            "label": "Requests",
            "value": _format_count(window.get("requests")),
            "raw": _safe_number(window.get("requests")),
        },
        {
            "label": "Bot share",
            "value": _format_pct(window.get("bot_share_pct")),
            "raw": _safe_number(window.get("bot_share_pct")),
        },
        {
            "label": "429 rate",
            "value": _format_pct(window.get("rate_429_pct")),
            "raw": _safe_number(window.get("rate_429_pct")),
        },
        {
            "label": "5xx rate",
            "value": _format_pct(window.get("rate_5xx_pct")),
            "raw": _safe_number(window.get("rate_5xx_pct")),
        },
    ]
    if blocked_share is not None:
        tiles.append(
            {
                "label": "Edge blocked share",
                "value": _format_pct(blocked_share),
                "raw": _safe_number(blocked_share),
            }
        )
    return {
        "tiles": tiles,
        "spike_flags": [
            {
                "name": flag,
                "label": SPIKE_FLAG_LABELS.get(
                    flag, flag.replace("_", " ").capitalize()
                ),
            }
            for flag in spike_flags
        ],
    }


def _cohort_mix_rows(actors_artifact: dict) -> list[dict]:
    """Project the ``trafficCohort`` actor-ranking into a mini-table
    view for the editorial geo+cohort row.

    Pairs with Top Countries in the same 2-col section: geographic
    origin on the left, classification on the right. Together they
    describe the shape of attack traffic — where it came from and
    how the upstream classifier bucketed it. The 429% / 5xx% columns
    surface per-cohort response-rate texture (a Bot cohort with 4%
    5xx vs Browser at 0.5% is a real signal even when bot volume is
    small in absolute terms).

    Share is computed against the cohort total across this ranking,
    not against the window-wide request total — the cohorts ARE the
    window's traffic, so summing them and dividing back is the
    honest 100% share split (a fixed-cardinality field with no
    "other" bucket to worry about).
    """
    rankings = (actors_artifact or {}).get("actor_rankings") or []
    cohort = next((r for r in rankings if r.get("field") == "trafficCohort"), None)
    if cohort is None:
        return []
    rows = cohort.get("rows") or []
    total = sum(_safe_number(r.get("requests")) or 0 for r in rows)
    out: list[dict] = []
    for row in rows:
        requests = _safe_number(row.get("requests")) or 0
        share = (100.0 * requests / total) if total > 0 else 0.0
        out.append(
            {
                "value": str(row.get("value") or ""),
                "requests": requests,
                "requests_display": _format_count(requests),
                "share_pct": round(share, 2),
                "share_pct_display": _format_pct(share),
                "req_429_share_pct": _safe_number(row.get("req_429_share_pct")),
                "req_429_share_display": _format_pct(row.get("req_429_share_pct")),
                "req_5xx_share_pct": _safe_number(row.get("req_5xx_share_pct")),
                "req_5xx_share_display": _format_pct(row.get("req_5xx_share_pct")),
                "value_label": "Cohort",
            }
        )
    return out


def _scope_rows(rows: list[dict], *, value_label: str) -> list[dict]:
    out: list[dict] = []
    for row in rows:
        out.append(
            {
                "value": str(row.get("value") if row.get("value") is not None else ""),
                "requests": _safe_number(row.get("requests")),
                "requests_display": _format_count(row.get("requests")),
                "share_pct": _safe_number(row.get("share_pct")),
                "share_pct_display": _format_pct(row.get("share_pct")),
                "delta_vs_baseline_pct": _safe_number(row.get("delta_vs_baseline_pct")),
                "delta_vs_baseline_display": _format_signed_pct(
                    row.get("delta_vs_baseline_pct")
                ),
                "value_label": value_label,
            }
        )
    return out


def _top_raw_paths_rows(rows: list[dict]) -> list[dict]:
    """Project the raw-reqPath drilldown rows for the editorial Top
    Paths panel's "specific URLs" mini-table.

    The producer (a phase-2 raw scan, scoped to the suspicious-actor
    IP set) supplies absolute counts plus a share_pct that's
    share-of-suspicious-actor-traffic (not share-of-window). Each row
    also carries a ``distinct_actors`` count so the renderer can
    surface coordinated-many-actors-on-one-URL signal vs
    single-actor-scanning noise.
    """
    out: list[dict] = []
    for row in rows:
        out.append(
            {
                "value": str(row.get("value") if row.get("value") is not None else ""),
                "requests": _safe_number(row.get("requests")),
                "requests_display": _format_count(row.get("requests")),
                "share_pct": _safe_number(row.get("share_pct")),
                "share_pct_display": _format_pct(row.get("share_pct")),
                "distinct_actors": _safe_number(row.get("distinct_actors")),
                "distinct_actors_display": _format_int(row.get("distinct_actors")),
                "req_429": _safe_number(row.get("req_429")),
                "req_429_display": _format_count(row.get("req_429")),
                "req_5xx": _safe_number(row.get("req_5xx")),
                "req_5xx_display": _format_count(row.get("req_5xx")),
                "req_5xx_share_pct": _safe_number(row.get("req_5xx_share_pct")),
                "req_5xx_share_display": _format_pct(row.get("req_5xx_share_pct")),
            }
        )
    return out


def _status_mix_rows(rows: list[dict]) -> list[dict]:
    out: list[dict] = []
    for row in rows:
        status_code = row.get("status_code")
        if status_code is None:
            display = ""
        else:
            display = str(status_code)
        out.append(
            {
                "value": display,
                "status_code": status_code,
                "requests": _safe_number(row.get("requests")),
                "requests_display": _format_count(row.get("requests")),
                "share_pct": _safe_number(row.get("share_pct")),
                "share_pct_display": _format_pct(row.get("share_pct")),
            }
        )
    return out


def _actor_rankings_view(actors_art: dict) -> list[dict]:
    rankings = actors_art.get("actor_rankings") or []
    out: list[dict] = []
    for ranking in rankings:
        field = ranking.get("field") or ""
        label = ranking.get("field_label") or _default_field_label(field)
        rows = []
        for row in ranking.get("rows") or []:
            rows.append(
                {
                    "value": str(
                        row.get("value") if row.get("value") is not None else ""
                    ),
                    "requests": _safe_number(row.get("requests")),
                    "requests_display": _format_count(row.get("requests")),
                    "bytes": _safe_number(row.get("bytes")),
                    "bytes_display": _format_count(row.get("bytes")),
                    "distinct_paths": _safe_number(row.get("distinct_paths")),
                    "distinct_paths_display": _format_int(row.get("distinct_paths")),
                    "req_429": _safe_number(row.get("req_429")),
                    "req_429_display": _format_count(row.get("req_429")),
                    "req_429_share_pct": _safe_number(row.get("req_429_share_pct")),
                    "req_429_share_display": _format_pct(row.get("req_429_share_pct")),
                    "req_5xx": _safe_number(row.get("req_5xx")),
                    "req_5xx_display": _format_count(row.get("req_5xx")),
                    "req_5xx_share_pct": _safe_number(row.get("req_5xx_share_pct")),
                    "req_5xx_share_display": _format_pct(row.get("req_5xx_share_pct")),
                }
            )
        out.append(
            {
                "field": field,
                "field_label": label,
                "rows": rows,
            }
        )
    return out


_DEFAULT_FIELD_LABELS = {
    "client_ip": "Client IP",
    "asn": "Client ASN",
    "request_path": "Request Path",
    "user_agent": "User Agent",
    "country": "Country",
    "status_code": "Status Code",
    "request_method": "Request Method",
    "trafficCohort": "Traffic cohort",
}


def _default_field_label(field: str) -> str:
    if not field:
        return ""
    if field in _DEFAULT_FIELD_LABELS:
        return _DEFAULT_FIELD_LABELS[field]
    return field.replace("_", " ").title()


def _safe_number(value: object) -> float | int | None:
    number = baselines_mod.to_number(value)
    if number is None:
        return None
    try:
        return baselines_mod.clean_number(number)
    except ValueError:
        return None


def _format_count(value: object) -> str:
    number = baselines_mod.to_number(value)
    if number is None:
        return "—"
    try:
        return big_number(number)
    except Exception:
        return f"{int(number):,}"


def _format_int(value: object) -> str:
    number = baselines_mod.to_number(value)
    if number is None:
        return "—"
    return f"{int(number):,}"


def _format_pct(value: object) -> str:
    number = baselines_mod.to_number(value)
    if number is None:
        return "—"
    if abs(number) >= 100:
        return f"{number:.0f}%"
    if abs(number) >= 10:
        return f"{number:.1f}%"
    return f"{number:.2f}%"


def _format_signed_pct(value: object) -> str:
    number = baselines_mod.to_number(value)
    if number is None:
        return "—"
    sign = "+" if number > 0 else ""
    if abs(number) >= 100:
        return f"{sign}{number:.0f}%"
    if abs(number) >= 10:
        return f"{sign}{number:.1f}%"
    return f"{sign}{number:.2f}%"
