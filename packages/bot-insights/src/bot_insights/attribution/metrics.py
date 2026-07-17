from __future__ import annotations

from typing import Any

from .constants import METRIC_ALLOWLIST
from .errors import raise_invalid


METRIC_ALIAS_TO_CANONICAL: dict[str, str] = {}


for canonical_metric, metric_info in METRIC_ALLOWLIST.items():
    METRIC_ALIAS_TO_CANONICAL[canonical_metric] = canonical_metric
    for alias in metric_info["aliases"]:
        METRIC_ALIAS_TO_CANONICAL[alias] = canonical_metric


def normalize_metric_name(name: str) -> str | None:
    text = str(name).strip()
    if not text:
        return None
    return METRIC_ALIAS_TO_CANONICAL.get(text)


def metric_entry(metric_name: str) -> dict[str, Any]:
    canonical = normalize_metric_name(metric_name)
    if canonical is None:
        raise_invalid(
            "unsupported_metric",
            f"Metric '{metric_name}' is not in the reviewed v1 allowlist.",
            details={"metric": metric_name},
        )
    entry = dict(METRIC_ALLOWLIST[canonical])
    entry["name"] = canonical
    return entry


def metric_aliases(metric_name: str) -> tuple[str, ...]:
    entry = metric_entry(metric_name)
    aliases = [entry["name"], *entry["aliases"]]
    return tuple(dict.fromkeys(alias for alias in aliases if alias))


def current_metric_keys(metric_name: str) -> tuple[str, ...]:
    keys = ["current"]
    for alias in metric_aliases(metric_name):
        keys.extend((f"current_{alias}", f"{alias}_current", f"current.{alias}"))
    return tuple(dict.fromkeys(keys))


def baseline_metric_keys(metric_name: str) -> tuple[str, ...]:
    keys = ["baseline"]
    for alias in metric_aliases(metric_name):
        keys.extend((f"baseline_{alias}", f"{alias}_baseline", f"baseline.{alias}"))
    return tuple(dict.fromkeys(keys))


def period_metric_keys(metric_name: str) -> tuple[str, ...]:
    return tuple(
        alias
        for alias in metric_aliases(metric_name)
        if not alias.startswith(("current_", "baseline_"))
        and not alias.endswith(("_current", "_baseline"))
    )
