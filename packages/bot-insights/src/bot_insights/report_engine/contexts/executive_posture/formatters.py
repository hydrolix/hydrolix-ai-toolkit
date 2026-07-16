"""Tiny formatters / display helpers."""

from __future__ import annotations

from ...humanize import cluster_display
from ...humanize import human_metric_name

__all__ = [
    '_to_float',
    '_cluster_label',
    '_short_window',
    '_metric_label',
    '_confidence_chip',
    '_band_verdict_label',
    '_band_verdict_tone',
]


def _to_float(value: object) -> float | None:
    try:
        if value is None:
            return None
        return float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _cluster_label(scope: dict, posture: dict) -> str:
    """Best-effort display label for the H1.

    Falls through: ``scope.cluster`` → ``scope.request_host`` → "" so the
    headline stays sensible whether the producer carries a tenant cluster
    name or only a host scope.
    """
    cluster = scope.get("cluster")
    if cluster:
        return cluster_display(cluster)
    host = scope.get("request_host") or scope.get("entity") or ""
    return host or ""


def _short_window(window: dict) -> str:
    """'2026-04-07 → 2026-04-14' from {start, end} ISO dates.

    Used inside the H1 only; the comparison strip in the header still
    renders the full timestamp via ``window_fmt``.
    """
    if not window:
        return "n/a"
    start = window.get("start") or ""
    end = window.get("end") or ""

    def _date(v: str) -> str:
        if "T" in v:
            return v.split("T", 1)[0]
        return v

    return f"{_date(start)} → {_date(end)}"


def _metric_label(name: str) -> str:
    return human_metric_name(name)


def _confidence_chip(confidence: str | None) -> dict | None:
    """Surface a chip on metric rows when confidence is below 'high'.

    Mirrors verdicts.confidence_chip — actionability and data-quality are
    different axes; a Watch metric with thin coverage keeps its verdict
    and surfaces the gap as a chip rather than getting demoted to
    Insufficient.
    """
    label = (confidence or "").lower()
    if label == "high":
        return None
    if label == "medium":
        return {"label": "Medium confidence", "tone": "neutral"}
    if label == "low":
        return {"label": "Low confidence", "tone": "neutral"}
    return None


def _band_verdict_label(band: str, triggered: int) -> str:
    if band in {"urgent_review", "high_review"}:
        return "Assign"
    if band in {"medium_review", "low_review"} and triggered:
        return "Assign"
    if triggered:
        return "Watch"
    return "Close — expected"


def _band_verdict_tone(band: str) -> str:
    if band in {"urgent_review", "high_review"}:
        return "escalate"
    if band in {"medium_review", "low_review"}:
        return "monitor"
    return "observe"
