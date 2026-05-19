"""Print-only context adapter for the fixed-page Incident Report."""

from __future__ import annotations

import html
from datetime import datetime, timedelta
from typing import Any


def _text(value: Any, default: str = "") -> str:
    if value is None:
        return default
    return str(value)


def _fmt_dt(value: str, fmt: str) -> str:
    if not value:
        return ""
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return value
    return parsed.strftime(fmt)


def _parse_dt(value: str) -> datetime | None:
    if not value:
        return None
    normalized = value.replace("Z", "+00:00")
    for fmt in ("%Y-%m-%d %H:%M%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return datetime.strptime(normalized, fmt)
        except ValueError:
            pass
    try:
        return datetime.fromisoformat(normalized)
    except ValueError:
        return None


def _window(ctx: dict[str, Any]) -> dict[str, str]:
    current = (ctx.get("windows") or {}).get("current") or {}
    start = _text(current.get("start"))
    end = _text(current.get("end"))
    return {
        "date": _fmt_dt(start, "%b %d, %Y") or "Incident window",
        "start": _fmt_dt(start, "%H:%M") or start,
        "end": _fmt_dt(end, "%H:%M") or end,
        "tz": "UTC",
        "duration_short": "current window",
    }


def severity_band(level: str | None, risk_score: int | float | None = None) -> dict[str, Any]:
    level_key = (level or "").lower()
    if not level_key and risk_score is not None:
        score = float(risk_score)
        if score >= 90:
            level_key = "critical"
        elif score >= 70:
            level_key = "high"
        elif score >= 40:
            level_key = "monitor"
        else:
            level_key = "observe"
    aliases = {"medium": "monitor", "elevated": "elevated", "low": "observe"}
    band = aliases.get(level_key, level_key or "observe")
    position = {
        "observe": 10,
        "monitor": 35,
        "elevated": 58,
        "high": 78,
        "critical": 94,
    }.get(band, 10)
    return {
        "band": band,
        "band_label": {
            "observe": "Observe",
            "monitor": "Monitor",
            "elevated": "Elevated",
            "high": "High",
            "critical": "Critical",
        }.get(band, band.title()),
        "band_position_pct": position,
    }


def series_to_svg_path(
    values: list[int | float],
    *,
    width: int = 456,
    height: int = 156,
    x0: int = 56,
    y0: int = 40,
    max_value: float | None = None,
) -> str:
    if not values:
        return ""
    numeric = [float(v or 0) for v in values]
    high = max(max(numeric), float(max_value or 0), 1.0)
    step = width / max(len(numeric) - 1, 1)
    points = []
    for idx, value in enumerate(numeric):
        x = x0 + idx * step
        y = y0 + height - ((value / high) * height)
        points.append(f"{x:.1f},{y:.1f}")
    first, *rest = points
    return "M " + first + "".join(f" L {point}" for point in rest)


def _ticks(max_value: float) -> list[dict[str, str]]:
    high = max(float(max_value or 0), 1.0)
    return [
        {"y": "196", "label": "0"},
        {"y": "118", "label": _compact(high / 2)},
        {"y": "40", "label": _compact(high)},
    ]


def _compact(value: float | int | None) -> str:
    value = float(value or 0)
    if value >= 1_000_000:
        return f"{value / 1_000_000:.1f}M"
    if value >= 1_000:
        return f"{value / 1_000:.1f}K"
    return str(int(round(value)))


def _x_ticks(
    source: dict[str, Any],
    *,
    plot_x: int,
    plot_width: int,
) -> list[dict[str, Any]]:
    left_label = _text(source.get("left_label"))
    right_label = _text(source.get("right_label"))
    start = _parse_dt(left_label)
    end = _parse_dt(right_label)
    if start is None or end is None or end <= start:
        return [
            {"x": str(plot_x), "label": left_label or "start", "anchor_end": False},
            {
                "x": str(plot_x + plot_width),
                "label": right_label or "end",
                "anchor_end": True,
            },
        ]
    total = (end - start).total_seconds()
    # Six ticks preserves the Claude reference cadence for the 15-hour
    # Expedia viewport: 06:00, 09:00, 12:00, 15:00, 18:00, 21:00.
    ticks = []
    for idx in range(6):
        fraction = idx / 5
        stamp = start + (end - start) * fraction
        ticks.append(
            {
                "x": f"{plot_x + (plot_width * fraction):.1f}",
                "label": stamp.strftime("%H:%M"),
                "anchor_end": idx == 5,
            }
        )
    return ticks


def _series_time(source: dict[str, Any], fraction: float) -> str:
    start = _parse_dt(_text(source.get("left_label")))
    end = _parse_dt(_text(source.get("right_label")))
    if start is None or end is None or end <= start:
        return ""
    fraction = max(0.0, min(float(fraction), 1.0))
    stamp = start + timedelta(seconds=(end - start).total_seconds() * fraction)
    return stamp.strftime("%H:%M")


def _series_time_for_index(source: dict[str, Any], idx: int, count: int) -> str:
    if count <= 1:
        return _series_time(source, 0)
    return _series_time(source, idx / (count - 1))


def _material_threshold(current: list[float], baseline: list[float], peak_value: float) -> float:
    baseline_high = max(baseline or [0])
    baseline_avg = sum(baseline) / len(baseline) if baseline else 0
    return max(peak_value * 0.10, baseline_high * 3, baseline_avg * 8, 1.0)


def _local_crests(
    current: list[float],
    *,
    threshold: float,
    peak_idx: int,
    min_separation: int,
) -> list[int]:
    candidates: list[tuple[float, int]] = []
    for idx in range(1, max(peak_idx, 1)):
        if current[idx] >= threshold and current[idx] >= current[idx - 1] and current[idx] >= current[idx + 1]:
            candidates.append((current[idx], idx))
    selected: list[tuple[float, int]] = []
    for value, idx in sorted(candidates, reverse=True):
        if all(abs(idx - other_idx) >= min_separation for _, other_idx in selected):
            selected.append((value, idx))
        if len(selected) >= 2:
            break
    return [idx for _, idx in sorted(selected, key=lambda item: item[1])]


def _append_timeline_stop(
    stops: list[dict[str, Any]],
    *,
    idx: int,
    time: str,
    phase: str,
    caption: str,
    is_peak: bool = False,
) -> None:
    if not time:
        time = "Window"
    if any(stop.get("time") == time and stop.get("phase") == phase for stop in stops):
        return
    stops.append(
        {
            "time": time,
            "phase": phase,
            "caption_html": html.escape(caption),
            "is_peak": is_peak,
            "_idx": idx,
        }
    )


def _attack_timeline(ctx: dict[str, Any]) -> list[dict[str, Any]]:
    source = ((ctx.get("impact") or {}).get("volume_chart") or {})
    current = [float(v or 0) for v in (source.get("current") or [])]
    baseline = [float(v or 0) for v in (source.get("baseline") or [])]
    if len(current) < 2:
        return [
            {"time": "Start", "phase": "Baseline break", "caption_html": "Current window begins.", "is_peak": False},
            {"time": "Peak", "phase": "Highest pressure", "caption_html": "Highest observed traffic bucket.", "is_peak": True},
            {"time": "End", "phase": "Window close", "caption_html": "Evidence window ends.", "is_peak": False},
        ]

    peak_value = max(current)
    peak_idx = current.index(peak_value)
    count = len(current)
    threshold = _material_threshold(current, baseline, peak_value)
    band_start = source.get("incident_highlight_start")
    band_end = source.get("incident_highlight_end")
    start_idx = round(float(band_start) * (count - 1)) if band_start is not None else 0
    end_idx = round(float(band_end) * (count - 1)) if band_end is not None else count - 1
    start_idx = max(0, min(start_idx, count - 1))
    end_idx = max(start_idx, min(end_idx, count - 1))
    first_elevated = next(
        (idx for idx in range(start_idx, end_idx + 1) if current[idx] >= threshold),
        start_idx,
    )
    last_elevated = next(
        (idx for idx in range(end_idx, start_idx - 1, -1) if current[idx] >= threshold),
        end_idx,
    )
    min_separation = max(10, count // 20)
    crest_indexes = [
        idx
        for idx in _local_crests(
            current,
            threshold=threshold,
            peak_idx=peak_idx,
            min_separation=min_separation,
        )
        if first_elevated < idx < peak_idx
    ]

    stops: list[dict[str, Any]] = []
    _append_timeline_stop(
        stops,
        idx=start_idx,
        time=_series_time_for_index(source, start_idx, count) or "Start",
        phase="Detected start",
        caption="Anomaly window opens.",
    )
    if first_elevated > start_idx:
        _append_timeline_stop(
            stops,
            idx=first_elevated,
            time=_series_time_for_index(source, first_elevated, count),
            phase="Ramp begins",
            caption="Traffic crosses the material elevation threshold.",
        )
    for label, idx in zip(("First crest", "Sustained crest"), crest_indexes[:2]):
        _append_timeline_stop(
            stops,
            idx=idx,
            time=_series_time_for_index(source, idx, count),
            phase=label,
            caption=f"{_compact(current[idx])} requests observed in the bucket.",
        )
    _append_timeline_stop(
        stops,
        idx=peak_idx,
        time=source.get("peak_time_display") or _series_time_for_index(source, peak_idx, count) or "Peak",
        phase="Highest pressure",
        caption=f"Peak bucket reaches {_compact(peak_value)} requests.",
        is_peak=True,
    )
    if last_elevated > peak_idx:
        _append_timeline_stop(
            stops,
            idx=last_elevated,
            time=_series_time_for_index(source, last_elevated, count),
            phase="Sustained tail",
            caption="Elevated traffic remains present after the peak.",
        )
    _append_timeline_stop(
        stops,
        idx=end_idx,
        time=_series_time_for_index(source, end_idx, count) or "End",
        phase="Window close",
        caption="Evidence window closes.",
    )

    stops = sorted(stops, key=lambda stop: stop["_idx"])
    # Keep the fixed-page layout readable while preserving the key shape:
    # opening, ramp/crest activity, peak, tail, and close.
    if len(stops) > 6:
        keep = [stops[0], stops[-1]]
        peak_stop = next((stop for stop in stops if stop.get("is_peak")), None)
        if peak_stop:
            keep.append(peak_stop)
        for stop in stops[1:-1]:
            if stop not in keep:
                keep.append(stop)
            if len(keep) >= 6:
                break
        stops = sorted(keep, key=lambda stop: stop["_idx"])
    for stop in stops:
        stop.pop("_idx", None)
    return stops


def volume_chart(ctx: dict[str, Any]) -> dict[str, Any]:
    source = ((ctx.get("impact") or {}).get("volume_chart") or {})
    current = [float(v or 0) for v in (source.get("current") or [])]
    baseline = [float(v or 0) for v in (source.get("baseline") or [])]
    if not current and not baseline:
        current = [0, 0]
        baseline = [0, 0]
    max_value = max(current + baseline + [1.0])
    peak_value = max(current or [0])
    peak_fraction = source.get("peak_fraction")
    if peak_fraction is None:
        peak_index = current.index(peak_value) if current else 0
        peak_fraction = peak_index / max(len(current) - 1, 1)
    peak_fraction = max(0.0, min(float(peak_fraction), 1.0))

    plot_x = 44
    plot_y = 36
    plot_width = 700
    plot_height = 160
    band_start = source.get("incident_highlight_start")
    band_end = source.get("incident_highlight_end")
    if band_start is None or band_end is None:
        band_start, band_end = 0.0, 1.0
    band_start = max(0.0, min(float(band_start), 1.0))
    band_end = max(band_start, min(float(band_end), 1.0))

    peak_x = plot_x + (plot_width * peak_fraction)
    peak_y = plot_y + plot_height - ((peak_value / max_value) * plot_height)
    windows = ctx.get("windows") or {}
    current_window = windows.get("current") or {}
    start_label = _fmt_dt(_text(current_window.get("start")), "%H:%M UTC")
    end_label = _fmt_dt(_text(current_window.get("end")), "%H:%M UTC")
    return {
        "title": "Traffic Volume",
        "subtitle": "Current period vs baseline",
        "baseline_label": "previous window",
        "baseline_path": series_to_svg_path(
            baseline,
            width=plot_width,
            height=plot_height,
            x0=plot_x,
            y0=plot_y,
            max_value=max_value,
        ),
        "spike_path": series_to_svg_path(
            current,
            width=plot_width,
            height=plot_height,
            x0=plot_x,
            y0=plot_y,
            max_value=max_value,
        ),
        "y_ticks": _ticks(max_value),
        "x_ticks": _x_ticks(source, plot_x=plot_x, plot_width=plot_width),
        "incident_band": {
            "x": f"{plot_x + (plot_width * band_start):.1f}",
            "y": str(plot_y),
            "width": f"{plot_width * (band_end - band_start):.1f}",
            "height": str(plot_height),
            "label_x": f"{plot_x + (plot_width * ((band_start + band_end) / 2)):.1f}",
            "label_y": str(plot_y - 6),
            "label": source.get("highlight_label") or "INCIDENT WINDOW",
        },
        "inflection_points": [
            {
                "x": f"{plot_x + (plot_width * band_start):.1f}",
                "label": f"START · {start_label}" if start_label else "START",
                "label_y": "48",
                "tone": "boundary",
            },
            {
                "x": f"{plot_x + (plot_width * band_end):.1f}",
                "label": f"END · {end_label}" if end_label else "END",
                "label_y": "188",
                "tone": "boundary",
            },
        ],
        "peak": {
            "x": f"{peak_x:.1f}",
            "y": f"{peak_y:.1f}",
            "label_x": f"{min(peak_x + 8, plot_x + plot_width - 120):.1f}",
            "label_y": f"{max(peak_y - 10, 22):.1f}",
            "time": source.get("peak_time_display") or "peak",
            "value": source.get("peak_value_display") or _compact(peak_value),
        },
        "missing": not bool(source.get("current") or source.get("baseline")),
    }


def _html(value: Any) -> str:
    return html.escape(_text(value))


def _prose(value: Any) -> str:
    text = _text(value)
    try:
        from ...markdown import render_safe

        return str(render_safe(text))
    except ModuleNotFoundError:
        escaped = html.escape(text)
        escaped = escaped.replace("**", "")
        return f"<p>{escaped}</p>" if escaped else ""


def _first_actor_rows(ctx: dict[str, Any], limit: int = 10) -> list[dict[str, str]]:
    soc_rows = ctx.get("raw_actor_rows") or []
    if soc_rows:
        return [
            {
                "rank": _text(row.get("rank")),
                "ip": _text(row.get("value")),
                "asn_meta": _text(row.get("asn") or "raw actor"),
                "requests": _text(row.get("requests_display")),
                "share": _text(row.get("share_display")),
                "rate_429": _text(row.get("req_429_rate_display")),
                "severity": _text(row.get("severity_label") or "raw").lower().replace(" ", "-"),
                "severity_label": _text(row.get("severity_label") or "Raw"),
                "edge_action_html": _html(row.get("edge_action")),
                "attck": "target table" if row.get("severity_label") != "Raw volume only" else "raw volume",
            }
            for row in soc_rows[:limit]
        ]
    ranking = next(
        (r for r in ctx.get("actor_rankings") or [] if r.get("field") == "client_ip"),
        None,
    )
    rows = (ranking or {}).get("rows") or []
    out = []
    for idx, row in enumerate(rows[:limit], start=1):
        out.append(
            {
                "rank": str(idx),
                "ip": _text(row.get("value")),
                "asn_meta": _text(row.get("asn") or "raw actor"),
                "requests": _text(row.get("requests_display") or _compact(row.get("requests"))),
                "share": _text(row.get("share_pct_display") or ""),
                "rate_429": _text(row.get("req_429_share_display") or ""),
                "severity": "critical" if idx <= 3 else "high",
                "severity_label": "Critical" if idx <= 3 else "High",
                "edge_action_html": "Observed",
                "attck": "T1498 / T1110",
            }
        )
    return out


def _actions(ctx: dict[str, Any], limit: int = 5) -> list[dict[str, str]]:
    out = []
    for idx, action in enumerate((ctx.get("recommended_actions") or [])[:limit], start=1):
        out.append(
            {
                "n": f"{idx:02d}",
                "severity": _text(action.get("urgency_tone") or "monitor"),
                "chip_text": _text(action.get("urgency") or "next"),
                "team": _text(action.get("role") or "Owner"),
                "action_html": _html(action.get("step")),
                "title_html": _html(action.get("step")),
                "why_html": _html(action.get("reason") or action.get("effect") or ""),
                "meta_html": _html(
                    " · ".join(
                        part
                        for part in (
                            f"Target: {action.get('target')}" if action.get("target") else "",
                            f"Duration: {action.get('duration')}" if action.get("duration") else "",
                            f"Rollback: {action.get('rollback')}" if action.get("rollback") else "",
                        )
                        if part
                    )
                ),
            }
        )
    return out


def _team_short(value: Any) -> str:
    team = _text(value or "Owner").strip()
    return {
        "Security Operations": "SOC",
        "Threat Intel": "Intel",
        "Threat Intelligence": "Intel",
        "Platform": "Edge",
    }.get(team, team[:10])


def _compact_cover_action(value: Any) -> str:
    text = _text(value).replace("`", "")
    if text.startswith("Time-boxed edge control candidate: Client IP "):
        target = text.removeprefix("Time-boxed edge control candidate: Client IP ").split(" ", 1)[0]
        return f"Time-box {target}; monitor 429s"
    if text.startswith("Enrich the "):
        count = text.removeprefix("Enrich the ").split(" ", 1)[0]
        return f"Enrich {count} critical targets in case mgmt"
    if text.startswith("Evaluate conservative rate limit for path-pattern candidate "):
        target = text.removeprefix("Evaluate conservative rate limit for path-pattern candidate ").split(" ", 1)[0]
        return f"Tighten {target} rate limit"
    return text[:82].rstrip() + ("..." if len(text) > 82 else "")


def _cover_actions(ctx: dict[str, Any], limit: int = 3) -> list[dict[str, str]]:
    return [
        {
            "severity": action["severity"],
            "team": _team_short(action["team"]),
            "action_html": _html(_compact_cover_action(action["action_html"])),
        }
        for action in _actions(ctx, limit)
    ]


def _findings(ctx: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for idx, finding in enumerate((ctx.get("incident_findings") or [])[:3], start=1):
        entities = finding.get("entities") or []
        out.append(
            {
                "n": f"{idx:02d}",
                "kicker": _text(finding.get("label") or f"Finding {idx:02d}"),
                "severity": "critical" if idx == 1 else "high",
                "severity_label": "Critical" if idx == 1 else "High",
                "chips": [
                    {"text": _text(entity.get("target_type_label") or "Signal"), "class": "ghost"}
                    for entity in entities[:2]
                ],
                "headline": _text(finding.get("lead")),
                "prose_html": _html(finding.get("body")),
                "ips": [
                    {
                        "ip": _text(entity.get("value")),
                        "tag": _text(entity.get("severity_label") or entity.get("severity")),
                        "asn_label": _text(entity.get("target_type_label")),
                        "volume": _text(entity.get("requests_display") or ""),
                        "share": _text(entity.get("meta") or ""),
                    }
                    for entity in entities[:4]
                ],
                "uas": [
                    {
                        "label_html": _html(entity.get("value")),
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


def _assessment(ctx: dict[str, Any]) -> dict[str, Any]:
    note = (ctx.get("notes_by_slot") or {}).get("executive_summary") or {}
    fallback = ctx.get("analyst_assessment") or {}
    impact_tiles = (ctx.get("impact") or {}).get("tiles") or []
    top_signal_tiles = sorted(
        (
            tile for tile in impact_tiles
            if float(tile.get("rank_score") or 0) > 0 and tile.get("value") != "—"
        ),
        key=lambda tile: float(tile.get("rank_score") or 0),
        reverse=True,
    )[:3]
    why_stood_out = [
        {
            "stat": tile.get("value"),
            "caption_html": _html(f"{tile.get('label')}: {tile.get('sub')}")
        }
        for tile in impact_tiles[:3]
    ]
    prose = note.get("text") or fallback.get("conclusion") or (ctx.get("deterministic_summary") or {}).get("headline")
    if not note and top_signal_tiles:
        signal_text = "; ".join(
            _text(
                f"{tile.get('label')} {tile.get('value')}"
                + (f" ({tile.get('sub')})" if tile.get("sub") else "")
            )
            for tile in top_signal_tiles
            if tile.get("value") or tile.get("label")
        )
        if signal_text:
            prose = f"{prose} Highest signals: {signal_text}."
    return {
        "headline": "Analyst Assessment",
        "prose_html": _prose(prose),
        "observed": ["Volume shift", "Actor concentration", "Edge response"],
        "inferred": ["Automation hypothesis", "Credential-access lead"],
        "why_stood_out": why_stood_out,
    }


def _verdict_prose(ctx: dict[str, Any], summary: dict[str, Any]) -> str:
    claim_profile = ctx.get("claim_profile") or {}
    prose = claim_profile.get("hero_summary") or summary.get("headline")
    return _html(prose)


def _primary(ctx: dict[str, Any]) -> dict[str, Any]:
    source = ctx.get("primary_concern") or {}
    evidence = source.get("evidence") or []
    return {
        "eyebrow": "Primary Concern",
        "chip": "Evidence bounded",
        "chip_severity": "critical",
        "headline_html": _html(source.get("title") or "Primary concern"),
        "prose_html": _html(source.get("summary") or source.get("boundary") or ""),
        "stats": [
            {"label": f"Signal {idx}", "value": _text(value), "detail": ""}
            for idx, value in enumerate(evidence[:3], start=1)
        ],
    }


def _attack_shape(ctx: dict[str, Any]) -> dict[str, Any]:
    paths = ctx.get("top_raw_paths_rows") or ctx.get("path_pattern_rows") or []
    signals = ctx.get("coordination_signals") or []
    return {
        "eyebrow": "Attack Shape",
        "headline": "How the pressure presented",
        "lede_html": "Traffic shape is derived from deterministic window evidence.",
        "timeline": _attack_timeline(ctx),
        "top_path_meta_html": "Top paths by request share",
        "top_paths": [
            {
                "path": _text(row.get("value")),
                "requests": _text(row.get("requests_display") or ""),
                "share": _text(row.get("share_pct_display") or ""),
            }
            for row in paths[:5]
        ],
        "paths_footnote": "Path rows may be unavailable when raw drilldown is degraded.",
        "signals_summary_html": "Observed coordination signals",
        "coordination_signals": [
            {
                "name": _text(sig.get("signal") or sig.get("label") or "Signal"),
                "status": _text(sig.get("status") or "partial").replace("_", "-"),
                "status_label": _text(sig.get("status_label") or sig.get("status") or "Observed"),
            }
            for sig in signals[:5]
        ],
        "signals_footnote": "Signals are mechanical evidence, not attribution claims.",
    }


def _classification(ctx: dict[str, Any]) -> dict[str, Any]:
    cohorts = ctx.get("cohort_mix_rows") or []
    actions = ctx.get("siem_action_rows") or ctx.get("edge_action_mix_rows") or []
    max_cohort = max([float(row.get("share_pct") or 0) for row in cohorts] + [1.0])
    total_actions = sum(float(row.get("requests") or 0) for row in actions) or 1.0
    def action_class(value: Any) -> str:
        lowered = _text(value).lower()
        if "deny" in lowered or "block" in lowered:
            return "a-deny"
        if "monitor" in lowered:
            return "a-monitor"
        if "tarpit" in lowered or "challenge" in lowered or "rate" in lowered:
            return "a-tarpit"
        if "allow" in lowered:
            return "a-allow"
        return "a-noaction"

    return {
        "eyebrow": "Classification / Edge Response",
        "headline": "Classification and response mix",
        "lede_html": "Cohort and action rows preserve source evidence percentages.",
        "cohorts": [
            {
                "name": _text(row.get("value")),
                "bar_width": f"{(float(row.get('share_pct') or 0) / max_cohort) * 100:.1f}%",
                "min_width": "2px",
                "share": _text(row.get("share_pct_display")),
                "requests": _text(row.get("requests_display")),
                "rate_429": _text(row.get("req_429_share_display")),
                "rate_5xx": _text(row.get("req_5xx_share_display")),
                "flagged": idx == 0,
            }
            for idx, row in enumerate(cohorts[:5])
        ],
        "edge_action_stack": [
            {
                "class": action_class(row.get("value")),
                "flex": str(max(float(row.get("requests") or 0), 1.0)),
                "show_label": idx < 3,
                "min_width": "3px",
                "label": _text(row.get("value")),
            }
            for idx, row in enumerate(actions[:5])
        ],
        "edge_action_legend": [
            {
                "class": action_class(row.get("value")),
                "label": _text(row.get("value")),
                "value": f"{(float(row.get('requests') or 0) / total_actions) * 100:.1f}%",
                "delta": _text(row.get("delta_vs_baseline_display") or ""),
            }
            for row in actions[:5]
        ],
        "edge_action_meta_html": "Edge response mix",
        "deny_rules": [
            {
                "rule": _text(row.get("value")),
                "requests": _text(row.get("requests_display")),
                "share": _text(row.get("share_pct_display")),
                "delta": _text(row.get("delta_vs_baseline_display") or ""),
                "delta_class": "critical",
            }
            for row in (ctx.get("deny_rule_mix_rows") or [])[:5]
        ],
    }


def _attck(ctx: dict[str, Any]) -> dict[str, Any]:
    techniques = []
    for item in (ctx.get("attack_aggregation") or [])[:6]:
        techniques.append(
            {
                "tid": _text(item.get("id")),
                "tactic": _text(item.get("tactic")),
                "name": _text(item.get("name")),
                "evidence_html": _html(
                    f"{item.get('mapping_class')}: {item.get('supporting_evidence_text')}"
                ),
                "span_full": False,
            }
        )
    if not techniques:
        techniques.append(
            {
                "tid": "N/A",
                "tactic": "Not mapped",
                "name": "No ATT&CK mapping available",
                "evidence_html": "The available evidence did not include mapped techniques.",
                "span_full": True,
            }
        )
    return {
        "eyebrow": "ATT&CK / Methodology",
        "headline": "Technique mapping and method",
        "lede_html": "Mappings are deterministic labels from observed behavior.",
        "techniques": techniques,
    }


def build_print_report(ctx: dict[str, Any]) -> dict[str, Any]:
    summary = ctx.get("deterministic_summary") or {}
    score = int((ctx.get("risk_score") or {}).get("value") or 0)
    band = severity_band(summary.get("level"), score)
    findings = _findings(ctx)
    actors = _first_actor_rows(ctx)
    classification = _classification(ctx)
    methodology = ctx.get("method") or {}
    tiles = (ctx.get("impact") or {}).get("tiles") or []
    return {
        "customer": ctx.get("headline") or (ctx.get("scope") or {}).get("request_host") or "Incident",
        "meta": {"schema": methodology.get("schema_version") or "bot_incident_scope.v1"},
        "window": _window(ctx),
        "verdict": {
            "risk_score": score,
            "risk_max": 100,
            "confidence": (ctx.get("claim_profile") or {}).get(
                "traffic_anomaly_confidence_label"
            ) or summary.get("confidence_label") or "Evidence bounded",
            "confidence_total": 5,
            "confidence_filled": 4 if summary.get("confidence") == "high" else 3,
            "prose_html": _verdict_prose(ctx, summary),
            "bands": [
                {"label": "Observe", "is_critical": False},
                {"label": "Monitor", "is_critical": False},
                {"label": "Elevated", "is_critical": False},
                {"label": "High", "is_critical": False},
                {"label": "Critical", "is_critical": True},
            ],
            **band,
        },
        "chart": volume_chart(ctx),
        "at_a_glance": {
            "footnote": "Metrics and ranks are deterministic; analyst prose cannot change them.",
            "shape": {
                "subtitle": "Volume shape",
                "hero": tiles[0].get("value") if tiles else "No volume",
                "subline_html": _html(tiles[0].get("sub") if tiles else "Volume series unavailable"),
                "facts": [_html(tile.get("label")) for tile in tiles[1:4]],
            },
            "who": {
                "chip": "Flagged",
                "hero": str(len(ctx.get("suspicious_targets") or actors)),
                "subline_html": "flagged actors or targets",
                "facts": [row["ip"] for row in actors[:3]],
            },
            "do_now": {"subtitle": "Recommended", "items": _cover_actions(ctx, 3)},
        },
        "analyst_assessment": _assessment(ctx),
        "primary_concern": _primary(ctx),
        "findings_page": {
            "eyebrow": "Findings",
            "headline": "Evidence-backed findings",
            "lede_html": "Findings are generated from deterministic suspicious-target evidence.",
        },
        "finding_ip_cluster": findings[0],
        "finding_ua_share": findings[1],
        "actions_page": {
            "eyebrow": "Recommended Actions",
            "headline": "What to do next",
            "lede_html": "Actions are candidates with scope, duration, validation, and rollback criteria.",
        },
        "actions": _actions(ctx),
        "attack_shape": _attack_shape(ctx),
        "actors_page": {
            "eyebrow": "Actors",
            "headline": "Raw actors and action priority",
            "lede_html": "Rows are the highest-volume raw client IPs; severity is only shown when matched to the action-target heuristic.",
            "total_flagged": len(ctx.get("suspicious_targets") or []),
            "appendix_note": "Rows are truncated for fixed-page print layout.",
        },
        "actors": actors,
        "top_hosts": [
            {
                "name": _text(row.get("value")),
                "bar_width": _text(row.get("share_pct_display") or "0%"),
                "bar_class": "critical",
                "pct": _text(row.get("share_pct_display") or ""),
            }
            for row in ((ctx.get("impact") or {}).get("top_affected_hosts") or {}).get("hosts", [])[:5]
        ],
        "top_hosts_meta": "Affected hosts",
        "top_hosts_footnote": "Top host evidence from scope artifact.",
        "geo": [
            {
                "cc": _text(row.get("value")),
                "bar_width": _text(row.get("share_pct_display") or "0%"),
                "requests": _text(row.get("requests_display")),
                "delta": _text(row.get("delta_vs_baseline_display") or ""),
            }
            for row in (ctx.get("country_mix_rows") or [])[:5]
        ],
        "geo_footnote": "Country mix reflects observed request geolocation.",
        "classification": classification,
        **classification,
        "attck_page": _attck(ctx),
        "methodology": {
            "prose_html": (
                "This report is presentation-only. Metrics, ranks, evidence limits, "
                "and scores come from deterministic incident artifacts. Credential "
                "ATT&CK mappings require auth-specific corroboration before being "
                "treated as findings."
            ),
            "window_summary_html": _html(
                f"Current: {(ctx.get('windows') or {}).get('current', {}).get('start')} to {(ctx.get('windows') or {}).get('current', {}).get('end')} "
                f"vs baseline {(ctx.get('windows') or {}).get('baseline', {}).get('start')} to {(ctx.get('windows') or {}).get('baseline', {}).get('end')}"
            ),
            "metadata": [
                {"label": "Schema", "value": methodology.get("schema_version")},
                {"label": "Comparison", "value": methodology.get("comparison_type")},
                {"label": "Rows", "value": methodology.get("result_row_count")},
                {"label": "Baseline", "value": (ctx.get("baseline_context") or {}).get("strategy")},
                {"label": "Constraints", "value": ", ".join(methodology.get("interpretation_constraints") or [])},
            ],
        },
        "page_count": 8,
    }
