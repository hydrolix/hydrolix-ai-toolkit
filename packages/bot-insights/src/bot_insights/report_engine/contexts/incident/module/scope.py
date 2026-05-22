"""Scope, window, SIEM, and headline context builders."""

from __future__ import annotations

from ....humanize import cluster_display
from ..formatters import _safe_number
from ..views import (
    _cohort_mix_rows,
    _scope_rows,
    _status_mix_rows,
    _top_raw_paths_rows,
)
from ..windows import _scope_filters

from .constants import PURPOSE


def _humanize_edge_action_rows(rows: list[dict]) -> list[dict]:
    """Relabel empty action_applied values to "No Action" for display.

    Akamai writes ``action_applied`` as an empty string for requests
    that hit no WAF or bot-manager rule (the pass-through bulk). The
    column value is meaningful, but the editorial table reads as a
    blank cell unless we humanize it — relabel for display only so
    the underlying artifact stays raw.
    """
    for row in rows:
        if not row["value"]:
            row["value"] = "No Action"
    return rows


def _build_scope_view_rows(scope_art: dict, actors_art: dict) -> dict:
    """Project the scope-artifact dimension lists into table rows.

    The ``top_raw_paths`` projection comes from a phase-2 drilldown
    scoped to the suspicious-actor IP set (cluster-only — the parquet
    summary doesn't carry raw paths). Each row carries ``share_pct``
    as share-of-suspicious-actor-traffic (NOT share-of-window) and a
    ``distinct_actors`` count so the editorial table can highlight
    coordinated-many-actors-on-one-URL vs single-actor-scanning patterns.
    """
    return {
        "targeted_hosts_rows": _scope_rows(
            scope_art.get("top_targeted_hosts") or [], value_label="Host"
        ),
        "path_pattern_rows": _scope_rows(
            scope_art.get("top_targeted_path_patterns") or [],
            value_label="Path pattern",
        ),
        "top_raw_paths_rows": _top_raw_paths_rows(
            scope_art.get("top_raw_paths") or []
        ),
        "status_mix_rows": _status_mix_rows(scope_art.get("status_mix") or []),
        "country_mix_rows": _scope_rows(
            scope_art.get("country_mix") or [], value_label="Country"
        ),
        "cohort_mix_rows": _cohort_mix_rows(actors_art),
        "edge_action_mix_rows": _humanize_edge_action_rows(
            _scope_rows(
                scope_art.get("edge_action_mix") or [], value_label="Action"
            )
        ),
        "deny_rule_mix_rows": _scope_rows(
            scope_art.get("deny_rule_mix") or [], value_label="Deny rule"
        ),
        "bot_source_rows": _scope_rows(
            scope_art.get("bot_source_mix") or [], value_label="Bot source"
        ),
        "proxy_classification_rows": _scope_rows(
            scope_art.get("proxy_classification_mix") or [],
            value_label="Proxy classification",
        ),
    }


def _build_siem_view_rows(scope_art: dict, siem_available: bool) -> dict:
    """SIEM-side dimension rows; empty lists when no SIEM table is available."""
    if not siem_available:
        return {
            "siem_action_rows": [],
            "siem_policy_rows": [],
            "siem_bot_type_rows": [],
        }
    return {
        "siem_action_rows": _scope_rows(
            scope_art.get("siem_action_mix") or [], value_label="Action class"
        ),
        "siem_policy_rows": _scope_rows(
            scope_art.get("siem_policy_mix") or [], value_label="Policy"
        ),
        "siem_bot_type_rows": _scope_rows(
            scope_art.get("siem_bot_type_mix") or [], value_label="Bot type"
        ),
    }


def _build_scope_block(scope_meta: dict, cluster: str) -> dict:
    """The masthead "scope" sub-dict — cluster, host, asn, path filter, etc."""
    host = scope_meta.get("host")
    asn = scope_meta.get("asn")
    path_pattern = scope_meta.get("path_pattern")
    granularity = scope_meta.get("granularity") or ""
    database = scope_meta.get("database") or ""
    return {
        "cluster": cluster,
        "database": database,
        "table_used": (
            f"{database or 'akamai'}.bi_summary_{granularity}" if granularity else ""
        ),
        "request_host": host or "",
        "asn": asn,
        "path_pattern": path_pattern,
        "granularity": granularity,
        "siem_available": bool(scope_meta.get("siem_available")),
        "scope_filters": _scope_filters(host, asn, path_pattern),
    }


def _build_windows_block(scope_meta: dict) -> dict:
    return {
        "current": {
            "start": scope_meta.get("start") or "",
            "end": scope_meta.get("end") or "",
        },
        "baseline": {
            "start": scope_meta.get("baseline_start") or "",
            "end": scope_meta.get("baseline_end") or "",
        },
    }


def _sum_numeric(values: list[object]) -> float:
    return sum(float(_safe_number(value) or 0) for value in values)


def _build_orientation_block() -> dict:
    return {
        "measures": PURPOSE["measures"],
        "score_legend": PURPOSE["score_legend"],
        "cant_say": PURPOSE["cant_say"],
        "bands": PURPOSE["bands"],
    }


def _build_suspicious_targets_visible(suspicious_targets: list[dict]) -> dict:
    """Pre-slice the suspicious-targets list for the masthead's visible/hidden split."""
    from config import active_thresholds

    cap = active_thresholds().display.suspicious_targets_cap
    return {
        "suspicious_targets": suspicious_targets,
        "suspicious_targets_visible": suspicious_targets[:cap],
        "suspicious_targets_hidden_count": max(0, len(suspicious_targets) - cap),
    }


def _build_headline(scope_meta: dict) -> str:
    """H1 is scope-only ("Expedia", "www.example.com", etc.). "Incident
    report" is already in the kicker row above the headline, so
    prefixing the H1 with the same words is dead repetition. The
    window the report covers is rendered prominently in the
    masthead window block on the right (see incident_report.html).
    """
    cluster = scope_meta.get("cluster") or ""
    cluster_label = cluster_display(cluster) if cluster else ""
    host = scope_meta.get("host")
    return host or cluster_label or "fleet"
