"""Heuristic-ladder evaluators for the suspicious-target list.

The orchestrator's ``_compute_suspicious_targets`` walks every
actor ranking, fires per-row primitives (share-based, novelty,
anomaly), runs the cross-row ASN cluster pivots, and emits the
final ``bot_incident_action_targets.v1`` ``targets`` rows.

Decomposed into:
  - Per-row primitives: ``_evaluate_share_flags``,
    ``_evaluate_novelty_flags``, ``_evaluate_anomaly``,
    ``_evaluate_ranking_row``.
  - Cross-row pivots: ``_apply_asn_grouped_pivots``,
    ``_apply_unverified_cluster_pivots``, ``_apply_cluster_pivots``.
  - Tier assignment + emit: ``_assign_severity``,
    ``_build_target_entry``.
  - Orchestrators: ``_evaluate_all_rankings`` (the inner loop) and
    ``_compute_suspicious_targets`` (the top-level entry point).

Per-row primitives are now data-driven (Phase 6b): each
``reason_flag`` lives in ``producers.suspicious_targets.rules`` as a
:class:`Rule` instance with an explicit evaluator + ``applies_to`` set.
The slimmed ``_evaluate_share_flags`` / ``_evaluate_novelty_flags`` /
``_evaluate_anomaly`` wrappers below dispatch to the registry; the
cross-row pivots (``single_asn_cluster``, ``botnet_member``) stay as
post-pass mutators because they read list-wide state, not per-row
state. The orchestrator still honors ``thresholds.disabled_rules`` for
those pivots.

Threshold floors flow through an explicit ``thresholds: Thresholds``
parameter (Phase 6a). ``None`` falls back to
:data:`config.DEFAULT_THRESHOLDS`, which mirrors the historic Python
constants exactly — absence of a ``--config`` file produces identical
output to the pre-Phase-6a baseline.
"""

from __future__ import annotations

from config import DEFAULT_THRESHOLDS, Thresholds
from heuristics import (
    _SEVERITY_RANK,
    _SUSPICIOUS_CONCENTRATION_FLAGS,
    _SUSPICIOUS_QUANT_FLAGS,
    _is_templated_catchall_path,
)
from producers.suspicious_targets.rules import (
    RuleContext,
    active_rules,
    disabled,
)
from producers.suspicious_targets.taxonomy import (
    _INDIVIDUAL_ENTITY_FIELDS,
    _SUSPICIOUS_TARGET_TYPE_BY_FIELD,
    _TARGET_KIND_BY_TYPE,
    _attack_techniques_for_flags,
    _suspicious_action_class,
)


def _resolve(thresholds: Thresholds | None) -> Thresholds:
    return thresholds if thresholds is not None else DEFAULT_THRESHOLDS


def _build_ua_pattern(thresholds: Thresholds):
    """Compile the active automation-UA pattern once per row. Done here
    (vs. importing ``heuristics._AUTOMATION_UA_PATTERN``) so an
    operator overriding ``automation_ua_pattern`` in their config gets
    the override applied without restarting the process."""
    import re

    return re.compile(
        thresholds.suspicious_targets.automation_ua_pattern, re.IGNORECASE
    )


def _build_rule_context(
    *,
    field: str,
    value: str,
    is_individual: bool,
    requests: float,
    share: float,
    share_429: float,
    total_429: float,
    distinct_paths: int,
    current_error_rate: float,
    baseline_data: dict,
    baseline_row: dict | None,
    automation_ua_pattern,
) -> RuleContext:
    return RuleContext(
        field=field,
        value=value,
        is_individual=is_individual,
        requests=requests,
        share=share,
        share_429=share_429,
        total_429=total_429,
        distinct_paths=distinct_paths,
        current_error_rate=current_error_rate,
        baseline_data=baseline_data,
        baseline_row=baseline_row,
        automation_ua_pattern=automation_ua_pattern,
        is_templated_catchall_path=_is_templated_catchall_path,
    )


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
    thresholds: Thresholds | None = None,
) -> list[str]:
    """Share-based primitives (registry-driven).

    Thin wrapper that builds a :class:`RuleContext` and asks the
    registry which share-based rules fire. The set of "share-based"
    rules is determined by name — every builtin that isn't novelty or
    anomaly — so out-of-tree share-tier rules registered through
    :func:`producers.suspicious_targets.rules.register_rule` are
    automatically picked up here.
    """
    t = _resolve(thresholds)
    ctx = _build_rule_context(
        field=field,
        value=value,
        is_individual=is_individual,
        requests=requests,
        share=share,
        share_429=share_429,
        total_429=total_429,
        distinct_paths=distinct_paths,
        current_error_rate=0.0,
        baseline_data={},
        baseline_row=None,
        automation_ua_pattern=_build_ua_pattern(t),
    )
    return _fire_rules(
        ctx,
        thresholds=t,
        accept={
            "high_volume_share",
            "high_rate_429_share",
            "single_path_concentration",
            "automation_user_agent",
        },
    )


def _evaluate_novelty_flags(
    *,
    field: str,
    value: str,
    baseline_data: dict[str, dict],
    share: float,
    requests: float,
    thresholds: Thresholds | None = None,
) -> list[str]:
    """Novelty primitives (registry-driven).

    ``new_in_window`` fires when ``value`` is missing from the
    baseline; ``high_volume_new_actor`` is the magnitude-aware
    companion scoped to ``client_ip``.
    """
    t = _resolve(thresholds)
    ctx = _build_rule_context(
        field=field,
        value=value,
        is_individual=field in _INDIVIDUAL_ENTITY_FIELDS,
        requests=requests,
        share=share,
        share_429=0.0,
        total_429=0.0,
        distinct_paths=0,
        current_error_rate=0.0,
        baseline_data=baseline_data,
        baseline_row=None,
        automation_ua_pattern=_build_ua_pattern(t),
    )
    return _fire_rules(
        ctx,
        thresholds=t,
        accept={"new_in_window", "high_volume_new_actor"},
    )


def _evaluate_anomaly(
    baseline_row: dict | None,
    *,
    requests: float,
    current_error_rate: float,
    clean_number,
    thresholds: Thresholds | None = None,
) -> tuple[list[str], dict]:
    """Baseline-rate departure check (registry-driven). Returns
    ``(["anomaly"], extras)`` when the ``anomaly`` rule fires;
    otherwise ``([], {})``. Extras are computed here (not on the rule)
    because they carry rendering-only fields the orchestrator stitches
    into the row's ``supporting_extras`` map.
    """
    t = _resolve(thresholds)
    ctx = _build_rule_context(
        field="",  # field-agnostic for anomaly; applies_to gates per ranking
        value="",
        is_individual=False,
        requests=requests,
        share=0.0,
        share_429=0.0,
        total_429=0.0,
        distinct_paths=0,
        current_error_rate=current_error_rate,
        baseline_data={},
        baseline_row=baseline_row,
        automation_ua_pattern=_build_ua_pattern(t),
    )
    fired = _fire_rules(ctx, thresholds=t, accept={"anomaly"})
    if not fired:
        return [], {}
    # extras must be derived here — the rule body is a pure bool.
    baseline_requests = (baseline_row or {}).get("requests") or 0
    baseline_errors = (
        ((baseline_row or {}).get("req_429") or 0)
        + ((baseline_row or {}).get("req_5xx") or 0)
    )
    baseline_error_rate = (
        baseline_errors / baseline_requests if baseline_requests > 0 else 0.0
    )
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


def _fire_rules(
    ctx: RuleContext,
    *,
    thresholds: Thresholds,
    accept: set[str],
) -> list[str]:
    """Walk the registry and return every accepted rule that fires for
    ``ctx``. ``accept`` partitions the registry into the share /
    novelty / anomaly groups the orchestrator queries — keeps the
    three legacy entry points behavior-preserving while letting
    out-of-tree rules opt into a specific group by name.
    """
    out: list[str] = []
    for rule in active_rules():
        if rule.name not in accept:
            continue
        if disabled(rule.name, thresholds):
            continue
        if ctx.field and ctx.field not in rule.applies_to and rule.name != "anomaly":
            # ``anomaly`` is field-agnostic from the orchestrator's
            # standpoint (the ranking loop already gates it).
            continue
        if rule.requires_baseline and ctx.baseline_row is None:
            continue
        if rule.evaluator(ctx, thresholds):
            out.append(rule.name)
    return out


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
    thresholds: Thresholds | None = None,
) -> dict | None:
    """Run every per-row primitive against one actor-ranking row.

    Returns an ``intermediate`` entry (the unflagged-clean dict that
    feeds cross-row pivots + final tier assignment), or ``None`` if
    no flags fire. ``intermediate`` carries pre-computed share %s
    and the captured ASN attribution so the cross-row pivots don't
    re-derive them.
    """
    t = _resolve(thresholds)
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
        thresholds=t,
    )
    flags.extend(
        _evaluate_novelty_flags(
            field=field,
            value=value,
            baseline_data=baseline_data,
            share=share,
            requests=requests,
            thresholds=t,
        )
    )
    anomaly_flags, supporting_extras = _evaluate_anomaly(
        baseline_data.get(value),
        requests=requests,
        current_error_rate=current_error_rate,
        clean_number=baselines_mod.clean_number,
        thresholds=t,
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


# ---------------------------------------------------------------------------
# Cross-row pivots. These rules emit ``single_asn_cluster`` and
# ``botnet_member`` based on ranking-wide state, not per-row state, so
# they stay as post-pass mutators rather than registry entries. The
# pivots still honor ``thresholds.disabled_rules`` — the orchestrator
# checks the disabled set before appending flags.
# ---------------------------------------------------------------------------

def _apply_asn_grouped_pivots(
    flagged_client_ips: list[dict],
    total_current: float,
    *,
    clean_number,
    thresholds: Thresholds | None = None,
) -> None:
    """Per-ASN grouping path. Rows without an ASN are excluded from
    clustering entirely — they're attribution-unknown and shouldn't
    claim membership in any specific cluster. Mutates rows in place.
    """
    t = _resolve(thresholds)
    st = t.suspicious_targets
    single_asn_off = disabled("single_asn_cluster", t)
    botnet_off = disabled("botnet_member", t)
    if single_asn_off and botnet_off:
        return
    groups: dict[object, list[dict]] = {}
    for row in flagged_client_ips:
        asn = row.get("asn")
        if asn in (None, "", 0):
            continue
        groups.setdefault(asn, []).append(row)
    for asn, members in groups.items():
        if len(members) < st.asn_cluster_min_ips:
            continue
        asn_org = next(
            (m.get("asn_org") for m in members if m.get("asn_org")), ""
        )
        if not single_asn_off:
            for row in members:
                if "single_asn_cluster" not in row["flags"]:
                    row["flags"].append("single_asn_cluster")
                extras = row.setdefault("supporting_extras", {})
                extras["asn_cluster_id"] = asn
                if asn_org:
                    extras["asn_cluster_org"] = asn_org
                extras["asn_cluster_size"] = len(members)
        if total_current <= 0 or botnet_off:
            continue
        cluster_requests = sum(m["requests"] for m in members)
        cluster_share = cluster_requests / total_current
        if cluster_share < st.botnet_cluster_share_min:
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
    thresholds: Thresholds | None = None,
) -> None:
    """Legacy fallback for producers without per-row ASN attribution.
    Uses the coarse count + total-share rule and marks the
    supporting_extras so downstream consumers can tell this is an
    approximation, not a verified same-ASN cluster. Mutates rows in
    place.
    """
    t = _resolve(thresholds)
    single_asn_off = disabled("single_asn_cluster", t)
    botnet_off = disabled("botnet_member", t)
    if single_asn_off and botnet_off:
        return
    if not single_asn_off:
        for row in flagged_client_ips:
            if "single_asn_cluster" not in row["flags"]:
                row["flags"].append("single_asn_cluster")
            extras = row.setdefault("supporting_extras", {})
            extras["asn_cluster_attribution"] = "unverified"
            extras["asn_cluster_size"] = len(flagged_client_ips)
    if total_current <= 0 or botnet_off:
        return
    cluster_requests = sum(r["requests"] for r in flagged_client_ips)
    cluster_share = cluster_requests / total_current
    if cluster_share < t.suspicious_targets.botnet_cluster_share_min:
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
    thresholds: Thresholds | None = None,
) -> None:
    """Cross-row pivots that add ``single_asn_cluster`` (shape) and
    ``botnet_member`` (magnitude) flags to flagged client_ip rows.
    Routes through per-ASN grouping when the producer carries ASN
    attribution, falling back to the coarse count + total-share rule
    when no row carries an ``asn`` field.
    """
    t = _resolve(thresholds)
    flagged_client_ips = [r for r in intermediate if r["field"] == "client_ip"]
    have_asn_attribution = any(
        r.get("asn") not in (None, "", 0) for r in flagged_client_ips
    )
    if have_asn_attribution:
        _apply_asn_grouped_pivots(
            flagged_client_ips, total_current,
            clean_number=clean_number, thresholds=t,
        )
    elif len(flagged_client_ips) >= t.suspicious_targets.asn_cluster_min_ips:
        _apply_unverified_cluster_pivots(
            flagged_client_ips, total_current,
            clean_number=clean_number, thresholds=t,
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
    thresholds: Thresholds | None = None,
) -> tuple[list[dict], dict[str, int]]:
    """Walk every actor ranking, evaluate each row's heuristic flags,
    and return (intermediate flagged rows, value→appearance count).
    Rankings whose field isn't in the target-type taxonomy are
    skipped silently — that's the contract for unknown producers.
    """
    t = _resolve(thresholds)
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
                thresholds=t,
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
    *,
    thresholds: Thresholds | None = None,
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

    t = _resolve(thresholds)
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
        thresholds=t,
    )
    _apply_cluster_pivots(
        intermediate, total_current,
        clean_number=baselines_mod.clean_number, thresholds=t,
    )

    targets = [_build_target_entry(row, field_appearance) for row in intermediate]
    targets.sort(
        key=lambda t: (
            _SEVERITY_RANK.get(t["severity"], 99),
            -int(t["supporting"]["requests"]),
        )
    )
    return targets
