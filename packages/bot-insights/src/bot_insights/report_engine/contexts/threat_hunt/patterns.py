from __future__ import annotations

from ._shared import *

def _pattern_link(*keys: str) -> list[dict[str, str]]:
    return [SCRAPER_PATTERN_LINKS[key] for key in keys if key in SCRAPER_PATTERN_LINKS]

def _has_endpoint_pattern(ctx: dict[str, Any]) -> tuple[bool, list[str], float | None]:
    basis: list[str] = []
    max_share: float | None = None

    for campaign in ctx.get("campaigns") or []:
        max_share = _observe_campaign_endpoint_pattern(campaign, basis, max_share)
    for case in ctx.get("scraper_cases") or []:
        max_share = _observe_case_endpoint_pattern(case, basis, max_share)
    for row in ctx.get("endpoints") or []:
        if isinstance(row, dict):
            max_share = _observe_endpoint_pattern(row, "site-level endpoint row", basis, max_share)
    return bool(basis), sorted(set(basis)), max_share

def _observe_campaign_endpoint_pattern(
    campaign: dict[str, Any], basis: list[str], max_share: float | None
) -> float | None:
    summary = campaign.get("endpoint_evidence_summary") or {}
    if summary.get("counts_for_verdict") or summary.get("confirmed_member_count"):
        basis.append("campaign endpoint evidence")
    for row in campaign.get("endpoint_targets") or []:
        if isinstance(row, dict):
            max_share = _observe_endpoint_pattern(
                row, "campaign endpoint target", basis, max_share
            )
    return max_share

def _observe_case_endpoint_pattern(
    case: dict[str, Any], basis: list[str], max_share: float | None
) -> float | None:
    evidence = case.get("endpoint_evidence") or {}
    if evidence.get("counts_for_verdict"):
        basis.append("lead scoped endpoint evidence")
    for row in case.get("endpoint_targets") or []:
        if isinstance(row, dict):
            max_share = _observe_endpoint_pattern(
                row, "lead endpoint target", basis, max_share
            )
    return max_share

def _observe_endpoint_pattern(
    row: dict[str, Any],
    source: str,
    basis: list[str],
    max_share: float | None,
) -> float | None:
    haystack = _endpoint_pattern_haystack(row)
    share = _to_float(row.get("share_pct"))
    if share is None:
        share = _to_float(row.get("request_share_pct"))
    if share is not None:
        max_share = max(max_share or 0.0, share)
    scoped_terms = ("api", "catalog", "search", "listing", "list", "product", "inventory", "graphql")
    if any(term in haystack for term in scoped_terms) or (share is not None and share >= 50.0):
        basis.append(source)
    return max_share

def _endpoint_pattern_haystack(row: dict[str, Any]) -> str:
    return " ".join(
        str(value)
        for value in [
            row.get("endpoint_prefix"),
            row.get("request_path"),
            row.get("value"),
            row.get("endpoint_category"),
            row.get("category"),
            *(row.get("markers") or []),
        ]
        if value
    ).lower()

def _has_timing_pattern(ctx: dict[str, Any]) -> tuple[bool, list[str]]:
    basis: list[str] = []
    for campaign in ctx.get("campaigns") or []:
        pattern = str(campaign.get("temporal_pattern") or "")
        summary = campaign.get("timing_summary") if isinstance(campaign.get("timing_summary"), dict) else {}
        if pattern and pattern not in {"not_established", "unavailable", "unknown"}:
            basis.append(f"campaign timing pattern {campaign.get('temporal_pattern_label') or _label(pattern)}")
        if summary.get("evidence_text"):
            basis.append("campaign timing summary")
    for case in ctx.get("scraper_cases") or []:
        timing = case.get("timing") if isinstance(case.get("timing"), dict) else {}
        raw = case.get("temporal_regularity") if isinstance(case.get("temporal_regularity"), dict) else {}
        sample_size = _to_float(timing.get("sample_size") if timing else raw.get("sample_size"))
        if (timing and timing.get("status") != "unavailable") or raw:
            if sample_size is None or sample_size >= 20:
                basis.append("lead timing regularity")
    return bool(basis), sorted(set(basis))

def _has_ua_pattern(ctx: dict[str, Any]) -> tuple[bool, list[str]]:
    basis: list[str] = []
    for family in ctx.get("ua_families") or []:
        version_count = _to_float(family.get("version_count")) or 0.0
        member_count = _to_float(family.get("member_count")) or 0.0
        checks = " ".join(str(value) for value in family.get("structural_checks") or []).lower()
        if version_count >= 3 and member_count >= 2:
            basis.append("UA-family version rotation")
        if "rotation" in checks or "imperson" in checks or "version" in checks:
            basis.append("UA-family structural check")
    for campaign in ctx.get("campaigns") or []:
        summary = campaign.get("ua_plausibility_summary") or {}
        if summary.get("forged_ua_candidate") or summary.get("anomalous_member_count"):
            basis.append("campaign UA plausibility summary")
    for case in ctx.get("scraper_cases") or []:
        plausibility = case.get("ua_plausibility") or {}
        if plausibility.get("verdict") in {"confirmed", "elevated"}:
            basis.append("lead UA plausibility anomaly")
    return bool(basis), sorted(set(basis))

def _has_fanout_pattern(ctx: dict[str, Any]) -> tuple[bool, list[str], dict[str, float]]:
    basis: list[str] = []
    maxima = {"ips": 0.0, "asns": 0.0, "countries": 0.0}

    def observe(ip_value: Any = None, asn_value: Any = None, country_value: Any = None, source: str = "") -> None:
        ip_count = _to_float(ip_value) or 0.0
        asn_count = _to_float(asn_value) or 0.0
        country_count = _to_float(country_value) or 0.0
        maxima["ips"] = max(maxima["ips"], ip_count)
        maxima["asns"] = max(maxima["asns"], asn_count)
        maxima["countries"] = max(maxima["countries"], country_count)
        if ip_count >= 50 or asn_count >= 3 or country_count >= 3:
            basis.append(source)

    for campaign in ctx.get("campaigns") or []:
        fanout = campaign.get("fanout_summary") or {}
        observe(
            fanout.get("unique_ips_lower_bound") or fanout.get("effective_ips_composite") or campaign.get("unique_client_ips"),
            campaign.get("unique_asns"),
            campaign.get("unique_countries"),
            "campaign fan-out lower bound",
        )
    for case in ctx.get("scraper_cases") or []:
        fanout = case.get("fanout_enrichment") or {}
        observe(
            fanout.get("unique_ips") or fanout.get("unique_client_ips") or case.get("unique_client_ips"),
            case.get("unique_asns"),
            case.get("unique_countries"),
            "lead fan-out lower bound",
        )
    for row in ctx.get("fingerprints") or []:
        if isinstance(row, dict):
            observe(
                row.get("unique_client_ips"),
                row.get("unique_asns"),
                row.get("unique_countries"),
                "fingerprint fan-out lower bound",
            )
    for row in (ctx.get("infrastructure") or {}).get("asn_rollups") or []:
        if isinstance(row, dict):
            observe(row.get("client_ip_count"), 1, row.get("country_count"), "infrastructure rollup")
    return bool(basis), sorted(set(basis)), maxima

def _pattern_note(
    *,
    title: str,
    text: str,
    evidence_basis: list[str],
    links: list[dict[str, str]],
    surface_priority: int,
) -> dict[str, Any]:
    return {
        "title": title,
        "text": text,
        "evidence_basis": evidence_basis,
        "links": links,
        "confidence_boundary": (
            "Pattern note only. It supports validation dimensions and is not classification evidence; "
            "it does not prove intent, operator identity, or enforcement eligibility by itself."
        ),
        "surface_priority": surface_priority,
    }

def _build_pattern_notes(ctx: dict[str, Any]) -> list[dict[str, Any]]:
    assessment = ctx.get("impact_assessment") if isinstance(ctx.get("impact_assessment"), dict) else {}
    hunt = assessment.get("hunt") if isinstance(assessment.get("hunt"), dict) else {}
    request_share = _to_float(hunt.get("request_share"))
    response_share = _to_float(hunt.get("response_body_byte_share"))
    has_endpoint, endpoint_basis, endpoint_share = _has_endpoint_pattern(ctx)
    has_timing, timing_basis = _has_timing_pattern(ctx)
    has_ua, ua_basis = _has_ua_pattern(ctx)
    has_fanout, fanout_basis, fanout_max = _has_fanout_pattern(ctx)
    has_campaign = bool(ctx.get("campaigns"))
    notes: list[dict[str, Any]] = []

    corroborating = _pattern_corroborating_labels(
        has_endpoint, has_timing, has_ua, has_fanout, has_campaign
    )

    light_note = _light_payload_pattern_note(request_share, response_share, corroborating)
    if light_note:
        notes.append(light_note)

    if has_endpoint and (endpoint_share is None or endpoint_share >= 25.0 or request_share is None or request_share >= 0.01):
        notes.append(_endpoint_pattern_note(endpoint_basis))

    if has_timing:
        notes.append(_timing_pattern_note(timing_basis))

    if has_ua:
        notes.append(_ua_pattern_note(ua_basis))

    if has_fanout and (has_endpoint or has_timing or has_ua or has_campaign):
        notes.append(_fanout_pattern_note(fanout_basis, fanout_max))

    return sorted(notes, key=lambda row: int(row.get("surface_priority") or 999))

def _pattern_corroborating_labels(
    has_endpoint: bool,
    has_timing: bool,
    has_ua: bool,
    has_fanout: bool,
    has_campaign: bool,
) -> list[str]:
    labels = [
        ("endpoint targeting", has_endpoint),
        ("timing regularity", has_timing),
        ("UA plausibility or rotation", has_ua),
        ("fan-out", has_fanout),
        ("campaign linkage", has_campaign),
    ]
    return [label for label, present in labels if present]

def _light_payload_pattern_note(
    request_share: float | None,
    response_share: float | None,
    corroborating: list[str],
) -> dict[str, Any] | None:
    if not (
        request_share is not None
        and response_share is not None
        and request_share >= 0.01
        and response_share <= request_share * 0.75
        and request_share - response_share >= 0.01
        and corroborating
    ):
        return None
    return _pattern_note(
        title="Light payload / high hits",
        text=(
            f"The hit share materially exceeds response-byte share "
            f"({_fmt_share(request_share)} hits vs {_fmt_share(response_share)} response bytes). "
            f"That is consistent with many lighter-than-average requests when paired with "
            f"{', '.join(corroborating[:4])}; treat it as supporting context, not a standalone scraper signature."
        ),
        evidence_basis=["hunt request share and response-byte share", *corroborating[:4]],
        links=_pattern_link("owasp_oat_011", "owasp_bot_management", "f5_scraper_patterns"),
        surface_priority=10,
    )

def _endpoint_pattern_note(endpoint_basis: list[str]) -> dict[str, Any]:
    return _pattern_note(
        title="Direct-to-data/API focus",
        text=(
            "Endpoint evidence is concentrated on scoped API, catalog, search, listing, or similarly narrow flow points. "
            "Use this to validate endpoint/session controls and current Bot Manager coverage; do not escalate enforcement from endpoint shape alone."
        ),
        evidence_basis=endpoint_basis,
        links=_pattern_link("owasp_oat_011", "f5_scraper_patterns"),
        surface_priority=20,
    )

def _timing_pattern_note(timing_basis: list[str]) -> dict[str, Any]:
    return _pattern_note(
        title="Boxy or interval cadence",
        text=(
            "Timing evidence shows regular, continuous, or interval-shaped behavior that can diverge from typical human diurnal variation. "
            "Validate with current inter-arrival samples and endpoint context before treating cadence as response evidence."
        ),
        evidence_basis=timing_basis,
        links=_pattern_link("owasp_bot_management", "f5_scraper_patterns", "cloudflare_bot_detection"),
        surface_priority=30,
    )

def _ua_pattern_note(ua_basis: list[str]) -> dict[str, Any]:
    return _pattern_note(
        title="UA impersonation / rotation",
        text=(
            "UA plausibility or version-family evidence suggests the declared client identity should not be trusted alone. "
            "Pair UA strings with behavior, fingerprints, endpoint surface, and session controls before enforcement."
        ),
        evidence_basis=ua_basis,
        links=_pattern_link("owasp_bot_management", "cloudflare_bot_detection", "f5_scraper_patterns"),
        surface_priority=40,
    )

def _fanout_pattern_note(
    fanout_basis: list[str], fanout_max: dict[str, Any]
) -> dict[str, Any]:
    spread_bits = []
    if fanout_max["ips"]:
        spread_bits.append(f"at least {_fmt_num(fanout_max['ips'])} IPs")
    if fanout_max["asns"]:
        spread_bits.append(f"{_fmt_num(fanout_max['asns'])} ASNs")
    if fanout_max["countries"]:
        spread_bits.append(f"{_fmt_num(fanout_max['countries'])} countries")
    return _pattern_note(
        title="Distributed fan-out",
        text=(
            f"Fan-out lower bounds show requests spread across {' / '.join(spread_bits) or 'multiple infrastructure pivots'}. "
            "Evaluate identity, session, endpoint, and behavioral controls; IP-only blocking may be brittle for this evidence shape."
        ),
        evidence_basis=fanout_basis,
        links=_pattern_link("owasp_bot_management", "cloudflare_bot_detection", "f5_scraper_patterns"),
        surface_priority=50,
    )

def _hunt_impact_ui(ctx: dict[str, Any]) -> dict[str, Any] | None:
    assessment = ctx.get("impact_assessment") if isinstance(ctx.get("impact_assessment"), dict) else {}
    hunt = assessment.get("hunt") if isinstance(assessment.get("hunt"), dict) else {}
    if not hunt:
        return None
    view = _impact_view(hunt)
    return {
        "eyebrow": "Hunt impact",
        "scope": ctx.get("headline") or _subject_label(ctx.get("scope") or {}),
        "rows": [
            {
                "label": "Hits",
                "value": view["requests_display"],
                "share": view["request_share_display"],
                "denom": "of window HTTP requests",
            },
            {
                "label": "Hydrolix log ingest",
                "value": _fmt_bytes_long(hunt.get("hydrolix_log_ingest_bytes")),
                "share": view["hydrolix_log_ingest_byte_share_display"],
                "denom": "of customer log volume - Hydrolix bill driver",
            },
            {
                "label": "Response body",
                "value": _fmt_bytes_long(hunt.get("response_body_bytes")),
                "share": view["response_body_byte_share_display"],
                "denom": "response data copied to scrapers",
            },
            {
                "label": "Akamai-billed",
                "value": _fmt_bytes_long(hunt.get("akamai_billed_bytes")),
                "share": view["akamai_billed_byte_share_display"],
                "denom": "of CDN billed bandwidth",
            },
        ],
        "footnote": _hydrolix_ingest_note(assessment),
        "pattern_note": (ctx.get("pattern_notes") or [None])[0],
    }

__all__ = [name for name in globals() if not name.startswith("__")]
