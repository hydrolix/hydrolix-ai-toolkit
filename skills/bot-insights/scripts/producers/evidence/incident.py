"""Evidence-shaping helpers for the ``incident_report`` flow.

Pure projections that lift already-captured rows into the artifact
shapes the renderer + heuristic ladder expect:

  - ``_incident_split_period_rows`` and
    ``_incident_compute_window_confirmation``: union the
    summary / SIEM / raw-log rows from
    ``_incident_window_confirmation_sql`` into the
    ``window_confirmation`` + ``baseline_stats`` payloads.
  - ``_incident_compute_timeseries``: bucket-aligned current vs.
    baseline volume / 429 / bot-like series for the chart.
  - ``_incident_dimension_rows`` / ``_incident_status_rows``:
    top-N + share + delta projections for the dimension and
    status-code mix tables.
  - ``_incident_actor_rows``: per-row projection for the actor
    ranking (request count, byte sum, distinct paths, 429 / 5xx
    shares, ASN attribution when present).
  - ``_build_action_targets_artifact``: thin wrapper around a list
    of suspicious-target rows in the canonical artifact shape.

Constants:
  - ``_INCIDENT_DEFAULT_FIELDS``: comma-separated field list the
    orchestrator hands to ``--fields`` when no override is supplied.
  - ``_INCIDENT_FIELD_LABELS``: humanized labels for the producer-
    side field identifiers, paired with the raw names in evidence
    packets so the LLM doesn't have to read snake_case.
  - Optional enriched evidence fields: bucketed top-dimension
    timeseries, per-target temporal/dominant evidence, and deterministic
    behavior clusters. These fields are additive and the renderer treats
    their absence as "not available".
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone


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

    raw = _incident_split_period_rows(rows, source="raw")
    raw_current = raw.get("current") or {}
    raw_baseline = raw.get("baseline") or {}
    source = "summary"

    if _num(current, "requests") <= 0 and _num(raw_current, "requests") > 0:
        current = raw_current
        baseline = raw_baseline
        source = "raw"

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
        "source": source,
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


def _incident_bucketed_mix_timeseries(
    rows: list[dict],
    *,
    series_type: str,
    value_label: str,
) -> dict | None:
    """Project bucketed top-dimension rows into an optional evidence block."""
    import baselines as baselines_mod

    if not rows:
        return None
    out: list[dict] = []
    for row in rows:
        value = row.get("value")
        bucket = row.get("bucket")
        requests = baselines_mod.to_number(row.get("requests")) or 0
        if value in (None, "") or bucket in (None, "") or requests <= 0:
            continue
        out.append(
            {
                "bucket": str(bucket),
                "value": str(value),
                "requests": int(requests),
            }
        )
    if not out:
        return None
    return {
        "series_type": series_type,
        "value_label": value_label,
        "points": out,
    }


def _incident_target_evidence_rows(rows: list[dict]) -> dict[str, dict]:
    """Compute optional per-target evidence from target/bucket rows.

    Input rows are intentionally simple so old artifacts remain valid:
    ``target_type``, ``target_value``, ``bucket``, ``requests`` plus
    optional dominant dimension columns. Missing dominant dimensions are
    ignored instead of guessed.
    """
    import baselines as baselines_mod

    grouped: dict[str, list[dict]] = {}
    for row in rows:
        target_type = str(row.get("target_type") or "")
        target_value = str(row.get("target_value") or "")
        bucket = str(row.get("bucket") or "")
        requests = baselines_mod.to_number(row.get("requests")) or 0
        if not target_type or not target_value or not bucket or requests <= 0:
            continue
        key = f"{target_type}:{target_value}"
        grouped.setdefault(key, []).append({**row, "requests": int(requests)})

    evidence: dict[str, dict] = {}
    for key, target_rows in grouped.items():
        target_rows.sort(key=lambda r: str(r.get("bucket") or ""))
        peak = max(target_rows, key=lambda r: int(r.get("requests") or 0))
        total = sum(int(r.get("requests") or 0) for r in target_rows)

        def _dominant(field: str, share_field: str | None = None) -> dict | None:
            counts: dict[str, int] = {}
            for r in target_rows:
                value = str(r.get(field) or "")
                if field == "dominant_edge_action" and not value.strip():
                    value = "No Action"
                if value:
                    counts[value] = counts.get(value, 0) + int(r.get("requests") or 0)
            if not counts:
                return None
            value, requests = max(counts.items(), key=lambda kv: kv[1])
            out = {
                "value": value,
                "requests": requests,
                "share_pct": baselines_mod.clean_number(
                    round(100.0 * requests / total, 2)
                ) if total > 0 else 0,
            }
            if share_field:
                out[share_field] = out["share_pct"]
            return out

        target_type, target_value = key.split(":", 1)
        entry: dict = {
            "target_type": target_type,
            "target_value": target_value,
            "first_seen": str(target_rows[0].get("bucket") or ""),
            "last_seen": str(target_rows[-1].get("bucket") or ""),
            "peak_bucket": str(peak.get("bucket") or ""),
            "peak_requests": int(peak.get("requests") or 0),
            "bucketed_requests": [
                {
                    "bucket": str(r.get("bucket") or ""),
                    "requests": int(r.get("requests") or 0),
                }
                for r in target_rows
            ],
        }
        for field, output_name, share_name in (
            ("dominant_path", "dominant_path", None),
            ("dominant_user_agent", "dominant_user_agent", None),
            ("dominant_cohort", "dominant_cohort", None),
            ("dominant_edge_action", "dominant_edge_action", "action_share_pct"),
        ):
            dominant = _dominant(field, share_name)
            if dominant:
                entry[output_name] = dominant
        evidence[key] = entry
    return evidence


def _target_key(target: dict) -> str:
    return f"{target.get('target_type')}:{target.get('target_value')}"


def _target_requests(target: dict) -> int:
    import baselines as baselines_mod

    return int(baselines_mod.to_number((target.get("supporting") or {}).get("requests")) or 0)


def _target_shared_facets(
    target: dict,
    target_evidence: dict[str, dict],
) -> list[dict]:
    supporting = target.get("supporting") or {}
    evidence = target_evidence.get(_target_key(target)) or {}
    facets: list[dict] = []
    asn = supporting.get("asn_cluster_id") or supporting.get("asn")
    if asn not in (None, ""):
        org = supporting.get("asn_cluster_org")
        facets.append(
            {
                "kind": "asn",
                "basis": "shared_asn",
                "label": "ASN/org",
                "value": str(asn),
                "display": f"{asn} ({org})" if org else str(asn),
            }
        )
    for source_field, basis, label in (
        ("botnet_cluster_id", "shared_botnet_cluster", "Botnet cluster"),
        ("dominant_path", "shared_path", "Dominant path"),
        ("dominant_user_agent", "shared_user_agent", "Dominant UA"),
        ("dominant_cohort", "shared_cohort", "Dominant cohort"),
        ("peak_bucket", "overlapping_peak_bucket", "Peak bucket"),
        ("dominant_edge_action", "shared_edge_action", "Edge action profile"),
    ):
        if source_field.startswith("dominant_"):
            value = (evidence.get(source_field) or {}).get("value")
        elif source_field == "peak_bucket":
            value = evidence.get(source_field)
        else:
            value = supporting.get(source_field)
        if value not in (None, ""):
            facets.append(
                {
                    "kind": source_field,
                    "basis": basis,
                    "label": label,
                    "value": str(value),
                    "display": str(value),
                }
            )
    return facets


def _incident_behavior_clusters(
    suspicious_targets: list[dict],
    target_evidence: dict[str, dict],
) -> list[dict]:
    """Build deterministic behavior clusters from shared observed facets.

    Cluster labels are evidence descriptors, not actor attribution. A
    row joins a cluster when at least two targets share one or more of
    ASN, dominant path, dominant user-agent/cohort, dominant edge action,
    or peak bucket.
    """
    buckets: dict[tuple[str, str], list[str]] = {}
    for target in suspicious_targets:
        target_type = str(target.get("target_type") or "")
        target_value = str(target.get("target_value") or "")
        if not target_type or not target_value:
            continue
        key = f"{target_type}:{target_value}"
        for facet in _target_shared_facets(target, target_evidence):
            buckets.setdefault((facet["basis"], facet["value"]), []).append(key)

    clusters: list[dict] = []
    for (facet, value), members in sorted(buckets.items()):
        unique_members = sorted(set(members))
        if len(unique_members) < 2:
            continue
        clusters.append(
            {
                "cluster_id": f"{facet}:{value}",
                "basis": facet,
                "basis_value": value,
                "target_count": len(unique_members),
                "targets": unique_members,
                "boundary": (
                    "Clustered by shared observed behavior only; this is "
                    "not actor attribution or proof of common control."
                ),
            }
        )
    return sorted(
        clusters,
        key=lambda c: (-int(c["target_count"]), c["basis"], c["basis_value"]),
    )


def _dominant_action_profile(
    members: list[dict],
    target_evidence: dict[str, dict],
) -> dict | None:
    import baselines as baselines_mod

    counts: dict[str, int] = {}
    for target in members:
        evidence = target_evidence.get(_target_key(target)) or {}
        action = (evidence.get("dominant_edge_action") or {}).get("value")
        if not action:
            continue
        counts[str(action)] = counts.get(str(action), 0) + _target_requests(target)
    total = sum(counts.values())
    if total <= 0:
        return None
    action, requests = max(counts.items(), key=lambda kv: kv[1])
    return {
        "action": action or "No Action",
        "requests": requests,
        "share_pct": baselines_mod.clean_number(round(100.0 * requests / total, 2)),
    }


def _incident_entity_clusters(
    suspicious_targets: list[dict],
    target_evidence: dict[str, dict],
) -> list[dict]:
    """Build first-class entity clusters from shared observed facets.

    Clusters stay evidence-bound: request totals are included only when all
    members are the same target type, avoiding unsafe sums across overlapping
    entity views.
    """
    targets_by_key = {
        _target_key(target): target
        for target in suspicious_targets
        if target.get("target_type") and target.get("target_value")
    }
    buckets: dict[tuple[str, str], list[str]] = {}
    facet_lookup: dict[tuple[str, str], dict] = {}
    facets_by_target: dict[str, list[dict]] = {}
    for target in targets_by_key.values():
        target_key = _target_key(target)
        facets = _target_shared_facets(target, target_evidence)
        facets_by_target[target_key] = facets
        for facet in facets:
            facet_key = (facet["basis"], facet["value"])
            buckets.setdefault(facet_key, []).append(target_key)
            facet_lookup.setdefault(facet_key, facet)

    def _shared_facets_for(target_keys: list[str]) -> list[dict]:
        target_key_set = set(target_keys)
        shared: list[dict] = []
        for facet_key, bucket_members in sorted(buckets.items()):
            overlapping_members = sorted(target_key_set & set(bucket_members))
            if len(overlapping_members) < 2:
                continue
            facet = dict(facet_lookup[facet_key])
            facet["member_count"] = len(overlapping_members)
            shared.append(facet)
        return sorted(
            shared,
            key=lambda f: (
                f["basis"] not in {"shared_asn", "shared_botnet_cluster"},
                -int(f.get("member_count") or 0),
                f["label"],
                f["display"],
            ),
        )

    def _cluster_confidence(shared_facets: list[dict], member_count: int) -> tuple[str, str]:
        primary_count = sum(
            1
            for facet in shared_facets
            if facet["basis"] in {"shared_asn", "shared_botnet_cluster"}
        )
        supporting_count = max(0, len(shared_facets) - primary_count)
        if primary_count and supporting_count >= 2 and member_count >= 3:
            return (
                "High",
                "Shared infrastructure metadata plus multiple observed behavior facets.",
            )
        if primary_count or supporting_count >= 2:
            return (
                "Medium",
                "Multiple targets share observed clustering facets.",
            )
        return (
            "Low",
            "Cluster is based on a single observed shared facet.",
        )

    def _target_label(target_key: str) -> str:
        target = targets_by_key.get(target_key) or {}
        return f"{target.get('target_type')}:{target.get('target_value')}"

    primary_buckets: dict[tuple[str, str], set[str]] = {}
    assigned_to_primary: set[str] = set()
    for target_key, facets in facets_by_target.items():
        primary = next(
            (
                facet
                for facet in facets
                if facet["basis"] in {"shared_botnet_cluster", "shared_asn"}
                and len(set(buckets.get((facet["basis"], facet["value"]), []))) >= 2
            ),
            None,
        )
        if primary:
            facet_key = (primary["basis"], primary["value"])
            primary_buckets.setdefault(facet_key, set()).add(target_key)
            assigned_to_primary.add(target_key)

    fallback_buckets: dict[tuple[str, str], set[str]] = {}
    for facet_key, target_keys in buckets.items():
        if facet_key[0] in {"shared_botnet_cluster", "shared_asn"}:
            continue
        unique_keys = sorted(set(target_keys) - assigned_to_primary)
        if len(unique_keys) < 2:
            continue
        fallback_buckets[facet_key] = set(unique_keys)

    facet_rank = {
        "shared_botnet_cluster": 0,
        "shared_asn": 1,
        "shared_path": 2,
        "shared_user_agent": 3,
        "shared_cohort": 4,
        "overlapping_peak_bucket": 5,
        "shared_edge_action": 6,
    }
    all_cluster_buckets = {**primary_buckets, **fallback_buckets}
    clusters: list[dict] = []
    for facet_key, target_key_set in sorted(
        all_cluster_buckets.items(),
        key=lambda item: (facet_rank.get(item[0][0], 99), item[0][1]),
    ):
        unique_keys = sorted(target_key_set)
        if len(unique_keys) < 2:
            continue
        members = [targets_by_key[key] for key in unique_keys if key in targets_by_key]
        if len(members) < 2:
            continue
        member_types = {m.get("target_type") for m in members}
        total_requests = (
            sum(_target_requests(member) for member in members)
            if len(member_types) == 1
            else None
        )
        facet = facet_lookup[facet_key]
        representative = sorted(
            members,
            key=lambda m: (-_target_requests(m), str(m.get("target_value") or "")),
        )[:4]
        shared_facets = _shared_facets_for(unique_keys)
        confidence_label, confidence_basis = _cluster_confidence(
            shared_facets,
            len(members),
        )
        action_profile = _dominant_action_profile(members, target_evidence)
        aggregate_behavior_parts = [
            f"{len(members)} flagged entities shared {len(shared_facets)} observed facet"
            f"{'s' if len(shared_facets) != 1 else ''}"
        ]
        if total_requests is not None:
            aggregate_behavior_parts.append(
                f"{total_requests} non-overlapping observed requests"
            )
        if action_profile:
            aggregate_behavior_parts.append(
                f"{action_profile['share_pct']}% dominant {action_profile['action']} edge-action profile"
            )
        coverage_summary = (
            f"Dominant observed edge action was {action_profile['action']} "
            f"for {action_profile['share_pct']}% of cluster member traffic."
            if action_profile
            else "No per-member edge-action profile was available for this cluster."
        )
        clusters.append(
            {
                "cluster_id": f"{facet['basis']}:{facet['value']}",
                "title": facet["label"],
                "basis": facet["basis"],
                "basis_value": facet["value"],
                "shared_facets": shared_facets,
                "member_count": len(members),
                "targets": [_target_label(key) for key in unique_keys],
                "representative_actors": [
                    {
                        "target_type": m.get("target_type"),
                        "target_value": m.get("target_value"),
                        "requests": _target_requests(m),
                    }
                    for m in representative
                ],
                "total_observed_requests": total_requests,
                "dominant_action_profile": action_profile,
                "confidence_label": confidence_label,
                "confidence_basis": confidence_basis,
                "aggregate_behavior": "; ".join(aggregate_behavior_parts) + ".",
                "coverage_summary": coverage_summary,
                "boundary": (
                    "Clustered by shared observed behavior only; this is not "
                    "attribution or proof of common control."
                ),
            }
        )
    return sorted(
        clusters,
        key=lambda c: (
            -int(c["member_count"]),
            -(int(c["total_observed_requests"]) if c["total_observed_requests"] else 0),
            facet_rank.get(c["basis"], 99),
            c["basis_value"],
        ),
    )


def _incident_mitigation_effectiveness(
    scope_artifact: dict,
    suspicious_targets: list[dict],
) -> dict | None:
    """Summarize observed mitigation coverage from edge-action evidence."""
    edge_rows = list(scope_artifact.get("edge_action_mix") or [])
    if not edge_rows:
        return None

    def _row_share(*names: str) -> float:
        wanted = {name.lower() for name in names}
        total = 0.0
        for row in edge_rows:
            value = str(row.get("value") or "No Action").strip().lower()
            if value in wanted or (not value and "no action" in wanted):
                total += float(row.get("share_pct") or 0)
        return round(total, 2)

    no_action_share = _row_share("no action", "", "allow", "passed")
    deny_share = _row_share("deny", "denied")
    monitor_tarpit_share = _row_share("monitor", "monitored", "tarpit")
    blocked_share = (scope_artifact.get("window_confirmation") or {}).get(
        "blocked_share_pct"
    )
    high_severity_count = sum(
        1
        for target in suspicious_targets
        if target.get("severity") in {"critical", "high"}
    )
    deny_rules = list(scope_artifact.get("deny_rule_mix") or [])
    top_deny_rule = deny_rules[0] if deny_rules else None
    if high_severity_count and no_action_share >= max(deny_share + monitor_tarpit_share, 50):
        interpretation = (
            "Coverage gap: No Action/pass-through dominated while high-severity "
            "indicators were present."
        )
        coverage_assessment = "Low relative to anomaly severity"
        tone = "gap"
    elif deny_share or monitor_tarpit_share or blocked_share:
        interpretation = (
            "Observed edge actions covered part of the window; this does not prove "
            "a control caused recovery."
        )
        coverage_assessment = "Partial observed coverage"
        tone = "partial"
    else:
        interpretation = "Edge-action evidence did not show measurable mitigation coverage."
        coverage_assessment = "Unknown observed coverage"
        tone = "unknown"
    return {
        "no_action_share_pct": no_action_share,
        "deny_share_pct": deny_share,
        "monitor_tarpit_share_pct": monitor_tarpit_share,
        "blocked_share_pct": blocked_share,
        "top_deny_rule": top_deny_rule,
        "high_severity_target_count": high_severity_count,
        "coverage_assessment": coverage_assessment,
        "interpretation": interpretation,
        "tone": tone,
    }


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


def _build_action_targets_artifact(
    scope_meta: dict,
    suspicious_targets: list[dict],
    *,
    heuristic_version: str = "v2",
    limitations: list[str] | None = None,
    target_evidence: dict[str, dict] | None = None,
    behavior_clusters: list[dict] | None = None,
    entity_clusters: list[dict] | None = None,
) -> dict:
    """Wrap a list of suspicious-target rows in the canonical artifact shape."""
    return {
        "artifact_id": "incident-action-targets-1",
        "schema_version": "bot_incident_action_targets.v1",
        "scope": scope_meta,
        "targets": suspicious_targets,
        "heuristic_version": heuristic_version,
        "limitations": list(limitations or []),
        "target_evidence": target_evidence or {},
        "behavior_clusters": behavior_clusters or [],
        "entity_clusters": entity_clusters or [],
    }
