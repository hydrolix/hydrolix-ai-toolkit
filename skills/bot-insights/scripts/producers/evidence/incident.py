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
