"""Chart and timeline helpers for incident print reports."""

from __future__ import annotations

import html
from datetime import timedelta
from typing import Any

from .shared import _compact, _fmt_dt, _parse_dt, _text

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
        return _fallback_attack_timeline()

    peak_value = max(current)
    peak_idx = current.index(peak_value)
    count = len(current)
    threshold = _material_threshold(current, baseline, peak_value)
    start_idx, end_idx = _timeline_highlight_indexes(source, count)
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

    stops = _build_attack_timeline_stops(
        source,
        current,
        count=count,
        start_idx=start_idx,
        first_elevated=first_elevated,
        crest_indexes=crest_indexes,
        peak_idx=peak_idx,
        peak_value=peak_value,
        last_elevated=last_elevated,
        end_idx=end_idx,
    )
    stops = _trim_attack_timeline_stops(stops)
    for stop in stops:
        stop.pop("_idx", None)
    return stops

def _fallback_attack_timeline() -> list[dict[str, Any]]:
    return [
        {"time": "Start", "phase": "Baseline break", "caption_html": "Current window begins.", "is_peak": False},
        {"time": "Peak", "phase": "Highest pressure", "caption_html": "Highest observed traffic bucket.", "is_peak": True},
        {"time": "End", "phase": "Window close", "caption_html": "Evidence window ends.", "is_peak": False},
    ]

def _timeline_highlight_indexes(source: dict[str, Any], count: int) -> tuple[int, int]:
    band_start = source.get("incident_highlight_start")
    band_end = source.get("incident_highlight_end")
    start_idx = round(float(band_start) * (count - 1)) if band_start is not None else 0
    end_idx = round(float(band_end) * (count - 1)) if band_end is not None else count - 1
    start_idx = max(0, min(start_idx, count - 1))
    end_idx = max(start_idx, min(end_idx, count - 1))
    return start_idx, end_idx

def _build_attack_timeline_stops(
    source: dict[str, Any],
    current: list[float],
    *,
    count: int,
    start_idx: int,
    first_elevated: int,
    crest_indexes: list[int],
    peak_idx: int,
    peak_value: float,
    last_elevated: int,
    end_idx: int,
) -> list[dict[str, Any]]:
    stops: list[dict[str, Any]] = []
    _append_timeline_stop(
        stops,
        idx=start_idx,
        time=_series_time_for_index(source, start_idx, count) or "Start",
        phase="Detected start",
        caption="Anomaly window opens.",
    )
    _append_ramp_stop(stops, source, first_elevated, start_idx, count)
    _append_crest_stops(stops, source, current, crest_indexes, count)
    _append_peak_stop(stops, source, peak_idx, peak_value, count)
    _append_tail_stop(stops, source, last_elevated, peak_idx, count)
    _append_timeline_stop(
        stops,
        idx=end_idx,
        time=_series_time_for_index(source, end_idx, count) or "End",
        phase="Window close",
        caption="Evidence window closes.",
    )
    return sorted(stops, key=lambda stop: stop["_idx"])

def _append_ramp_stop(
    stops: list[dict[str, Any]],
    source: dict[str, Any],
    first_elevated: int,
    start_idx: int,
    count: int,
) -> None:
    if first_elevated <= start_idx:
        return
    _append_timeline_stop(
        stops,
        idx=first_elevated,
        time=_series_time_for_index(source, first_elevated, count),
        phase="Ramp begins",
        caption="Traffic crosses the material elevation threshold.",
    )

def _append_crest_stops(
    stops: list[dict[str, Any]],
    source: dict[str, Any],
    current: list[float],
    crest_indexes: list[int],
    count: int,
) -> None:
    for label, idx in zip(("First crest", "Sustained crest"), crest_indexes[:2]):
        _append_timeline_stop(
            stops,
            idx=idx,
            time=_series_time_for_index(source, idx, count),
            phase=label,
            caption=f"{_compact(current[idx])} requests observed in the bucket.",
        )

def _append_peak_stop(
    stops: list[dict[str, Any]],
    source: dict[str, Any],
    peak_idx: int,
    peak_value: float,
    count: int,
) -> None:
    _append_timeline_stop(
        stops,
        idx=peak_idx,
        time=source.get("peak_time_display") or _series_time_for_index(source, peak_idx, count) or "Peak",
        phase="Highest pressure",
        caption=f"Peak bucket reaches {_compact(peak_value)} requests.",
        is_peak=True,
    )

def _append_tail_stop(
    stops: list[dict[str, Any]],
    source: dict[str, Any],
    last_elevated: int,
    peak_idx: int,
    count: int,
) -> None:
    if last_elevated <= peak_idx:
        return
    _append_timeline_stop(
        stops,
        idx=last_elevated,
        time=_series_time_for_index(source, last_elevated, count),
        phase="Sustained tail",
        caption="Elevated traffic remains present after the peak.",
    )

def _trim_attack_timeline_stops(
    stops: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    if len(stops) <= 6:
        return stops
    keep = [stops[0], stops[-1]]
    peak_stop = next((stop for stop in stops if stop.get("is_peak")), None)
    if peak_stop:
        keep.append(peak_stop)
    for stop in stops[1:-1]:
        if stop not in keep:
            keep.append(stop)
        if len(keep) >= 6:
            break
    return sorted(keep, key=lambda stop: stop["_idx"])

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
