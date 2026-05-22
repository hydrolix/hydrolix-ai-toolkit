"""Analysis-availability and limitation context builders."""

from __future__ import annotations


def _collect_limitations(*artifacts: dict) -> list[str]:
    """Concatenate ``limitations`` lists from each artifact, in order."""
    out: list[str] = []
    for art in artifacts:
        out.extend(art.get("limitations") or [])
    return out


def _analysis_availability_context(
    scope_art: dict,
    actors_art: dict,
    action_targets_art: dict,
    suspicious_targets: list[dict],
    scope_rows: dict,
) -> dict:
    """Renderer-ready availability notes for deferred incident analyses."""
    rows: list[dict] = []
    asn_ranking = next(
        (
            ranking
            for ranking in actors_art.get("actor_rankings") or []
            if ranking.get("field") in {"asn", "client_asn"}
        ),
        {},
    )
    rows.append(
        {
            "analysis": "ASN / hosting decomposition",
            "status": "Partial" if asn_ranking.get("rows") else "Unavailable",
            "detail": (
                "Observed ASN ranking is present, but the bundled artifacts do not "
                "include hosting-provider taxonomy beyond optional AS reputation context."
                if asn_ranking.get("rows")
                else "No ASN ranking or hosting-provider taxonomy was bundled."
            ),
        }
    )

    emerging = [
        target
        for target in suspicious_targets
        if any(
            flag in {"new_in_window", "high_volume_new_actor"}
            for flag in target.get("reason_flags") or []
        )
    ]
    rows.append(
        {
            "analysis": "Baseline-relative actor emergence",
            "status": "Available" if emerging else "Unavailable",
            "detail": (
                f"{len(emerging)} flagged target(s) carried new-in-window or "
                "high-volume-new-actor evidence."
                if emerging
                else "No flagged target carried baseline-emergence reason flags."
            ),
        }
    )

    edge_rows = scope_rows.get("edge_action_mix_rows") or []
    rows.append(
        {
            "analysis": "Edge-action effectiveness",
            "status": "Observed mix only" if edge_rows else "Unavailable",
            "detail": (
                "Edge action mix is present for validation planning, but the artifacts "
                "do not include before/after evidence needed to claim mitigation effectiveness."
                if edge_rows
                else "No edge action mix was bundled."
            ),
        }
    )

    cluster_count = len(action_targets_art.get("behavior_clusters") or [])
    rows.append(
        {
            "analysis": "Flagged-IP clustering",
            "status": "Available" if cluster_count else "Unavailable",
            "detail": (
                f"{cluster_count} behavior cluster(s) were bundled."
                if cluster_count
                else "No explicit flagged-IP cluster artifact was bundled."
            ),
        }
    )

    protected = scope_art.get("protected_population") or action_targets_art.get(
        "protected_population"
    )
    counterfactual = scope_art.get("counterfactual") or action_targets_art.get(
        "counterfactual"
    )
    rows.append(
        {
            "analysis": "Protected-population / counterfactual check",
            "status": "Available" if protected and counterfactual else "Unavailable",
            "detail": (
                "Protected-population and counterfactual inputs are present."
                if protected and counterfactual
                else "The bundled artifacts cannot evaluate collateral impact or counterfactual outcomes."
            ),
        }
    )
    return {
        "available": True,
        "rows": rows,
        "boundary": (
            "Availability notes prevent unsupported conclusions. Unavailable rows are "
            "limitations, not negative findings."
        ),
    }
