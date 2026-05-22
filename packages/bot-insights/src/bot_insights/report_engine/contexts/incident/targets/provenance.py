"""Bot/proxy provenance projection for target indicators."""

from __future__ import annotations

from ..formatters import _safe_number


def _cell_display_parts(cell: dict, keys: tuple[str, ...]) -> list[str]:
    parts: list[str] = []
    for key in keys:
        value = str(cell.get(key) or "").strip()
        if value and value not in parts:
            parts.append(value)
    return parts


def _top_provenance_labels(
    cells: list[dict],
    ip_value: str,
    *,
    keys: tuple[str, ...],
    limit: int = 2,
) -> list[str]:
    bucket: dict[str, int] = {}
    for cell in cells:
        if str(cell.get("ip") or "") != ip_value:
            continue
        reqs = int(_safe_number(cell.get("requests")) or 0)
        if reqs <= 0:
            continue
        label = " / ".join(_cell_display_parts(cell, keys))
        if not label:
            continue
        bucket[label] = bucket.get(label, 0) + reqs
    return [
        label
        for label, _requests in sorted(bucket.items(), key=lambda kv: (-kv[1], kv[0]))[
            :limit
        ]
    ]


def _compute_provenance_for_indicator(
    target: dict, actors_artifact: dict | None
) -> dict | None:
    """Return source bot/proxy provenance labels for a client IP target.

    These labels are corroborating source metadata only; they do not
    affect target confidence or imply intent/root cause.
    """
    if (target.get("target_type") or "") != "client_ip":
        return None
    target_value = str(target.get("target_value") or "")
    if not target_value:
        return None
    cooccur = (actors_artifact or {}).get("actor_cooccurrence") or {}
    bot_labels = _top_provenance_labels(
        cooccur.get("client_ip__bot_source") or [],
        target_value,
        keys=("bot_category", "bot_type", "botnet_id"),
    )
    proxy_labels = _top_provenance_labels(
        cooccur.get("client_ip__proxy_classification") or [],
        target_value,
        keys=("epd_Category", "epd_ActionName", "epd_Match"),
    )
    if not bot_labels and not proxy_labels:
        return None
    lines: list[str] = []
    if bot_labels:
        lines.append(f"{' / '.join(bot_labels)} observed")
    if proxy_labels:
        lines.append(f"{' / '.join(proxy_labels)} observed")
    return {
        "bot_source_labels": bot_labels,
        "proxy_classification_labels": proxy_labels,
        "display_lines": lines,
        "display": " · ".join(lines),
    }
