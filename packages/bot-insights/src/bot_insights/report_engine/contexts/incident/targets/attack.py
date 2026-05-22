"""ATT&CK aggregation for suspicious target rows."""

from __future__ import annotations

from .reasons import _operational_reason_labels
from ..formatters import _format_count, _format_pct
from ..labels import REASON_FLAG_LABELS, TARGET_TYPE_LABELS


def _attack_supporting_evidence(target: dict) -> str:
    type_label = target.get("target_type_label") or TARGET_TYPE_LABELS.get(
        target.get("target_type") or "",
        str(target.get("target_type") or "Target").replace("_", " ").title(),
    )
    value = str(target.get("target_value") or "").strip()
    severity = target.get("severity_label") or str(target.get("severity") or "").title()
    flags = set(target.get("reason_flags") or [])
    labels = [
        REASON_FLAG_LABELS.get(f, f.replace("_", " "))
        for f in target.get("reason_flags") or []
    ]
    concise = _operational_reason_labels(labels, limit=2)
    descriptors: list[str] = []
    if "single_asn_cluster" in flags or (target.get("supporting") or {}).get("asn_cluster_id"):
        descriptors.append("shared ASN")
    if "single_path_concentration" in flags:
        descriptors.append("path concentration")
    if any(flag in flags for flag in ("high_volume_share", "high_volume_new_actor")):
        descriptors.append("high volume")
    if "high_429_share" in flags:
        descriptors.append("elevated 429 rate")
    if "automation_user_agent" in flags:
        descriptors.append("automation UA")
    if not descriptors and concise:
        descriptors.extend(concise)
    if not descriptors:
        descriptors.append("flagged heuristic evidence")
    subject = f"{type_label} `{value}`" if value else type_label
    return (
        f"{severity} {subject} matched "
        f"{', '.join(descriptors[:3])} evidence."
    )


def _attack_metric_chips(target: dict) -> list[str]:
    chips: list[str] = []
    supporting = target.get("supporting") or {}
    requests = _format_count(supporting.get("requests"))
    if requests and requests != "—":
        chips.append(f"{requests} requests")
    share = _format_pct(supporting.get("share_pct"))
    if share and share != "—":
        chips.append(f"{share} of incident requests")
    req_429 = _format_pct(supporting.get("req_429_share_pct"))
    if req_429 and req_429 != "—":
        chips.append(f"{req_429} 429 rate within target traffic")
    return chips[:2]


def _update_attack_tally(tally: dict[str, dict], technique: dict, target: dict) -> None:
    """Merge one technique into the tally. Prefer the first-seen
    name/tactic; later occurrences with blank fields don't overwrite a
    populated name."""
    tid = technique.get("id") or ""
    if not tid:
        return
    entry = tally.setdefault(
        tid,
        {
            "id": tid,
            "name": technique.get("name") or "",
            "tactic": technique.get("tactic") or "",
            "count": 0,
            "supporting_evidence": [],
            "metric_chips": [],
            "mapping_class": _attack_mapping_class(tid),
            "evidence_requirement": _attack_evidence_requirement(tid),
        },
    )
    if not entry["name"] and technique.get("name"):
        entry["name"] = technique.get("name")
    if not entry["tactic"] and technique.get("tactic"):
        entry["tactic"] = technique.get("tactic")
    entry["count"] += 1
    evidence = _attack_supporting_evidence(target)
    if evidence and evidence not in entry["supporting_evidence"]:
        entry["supporting_evidence"].append(evidence)
    for chip in _attack_metric_chips(target):
        if chip not in entry["metric_chips"]:
            entry["metric_chips"].append(chip)


def _attack_mapping_class(technique_id: str) -> str:
    """Conservative display class for ATT&CK rows.

    The incident artifacts can map request pressure to ATT&CK-like
    techniques, but credential-access claims require auth telemetry the
    access-log heuristic does not carry. Keep denial-of-service mappings
    as observed-consistent; downgrade credential mappings to investigation
    leads until auth endpoint/failure/account evidence is present.
    """
    if technique_id in {"T1110", "T1110.004"}:
        return "possible investigation lead"
    return "observed-consistent"


def _attack_evidence_requirement(technique_id: str) -> str:
    if technique_id in {"T1110", "T1110.004"}:
        return (
            "Requires auth-specific telemetry: auth endpoint, failure pattern, "
            "account/user identifiers, or SIEM/auth correlation."
        )
    if technique_id == "T1498":
        return "Supported by request volume, 429 pressure, or error-pressure evidence."
    return "Requires analyst validation before treating as confirmed technique evidence."


def _attack_aggregation(suspicious_targets: list[dict]) -> list[dict]:
    """Aggregate ATT&CK techniques across the suspicious-target list.

    Iterates every target's ``attack_techniques`` list, dedupes by
    technique id, and tallies how many targets reference each id.
    Output is sorted by ``count desc, id asc`` so the editorial
    "Consistent with" panel reads with the most-referenced techniques
    at the top and ties break alphabetically (deterministic).
    """
    tally: dict[str, dict] = {}
    for target in suspicious_targets or []:
        for technique in target.get("attack_techniques") or []:
            _update_attack_tally(tally, technique, target)
    rows = sorted(tally.values(), key=lambda r: (-r["count"], r["id"]))
    for row in rows:
        evidence = row.get("supporting_evidence") or []
        mapping_class = row.get("mapping_class") or _attack_mapping_class(row["id"])
        requirement = row.get("evidence_requirement") or _attack_evidence_requirement(row["id"])
        row["supporting_evidence"] = evidence[:1]
        evidence_text = (evidence[:1] or ["—"])[0]
        if mapping_class == "possible investigation lead":
            evidence_text = (
                f"Possible investigation lead only. Observed signal: "
                f"{evidence_text} {requirement}"
            )
        row["supporting_evidence_text"] = evidence_text
        row["mapping_class"] = mapping_class
        row["evidence_requirement"] = requirement
        row["metric_chips"] = (row.get("metric_chips") or [])[:2]
    return rows
