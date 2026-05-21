"""Label-enrichment helpers for evidence packets.

The deterministic capture path emits evidence packets that
identify every producer concept (rule names, domain keys,
confidence reason codes, band keys) by raw snake_case. The LLM
interpretation step tends to copy those identifiers verbatim
into prose unless paired with a human-readable label. This
module enriches a packet in place so the interpretation contract
can direct the LLM to prefer the ``*_label`` fields.

``humanize_evidence_packet`` is the public entry; it covers
single-entity and ``--fleet`` shaped packets and is idempotent.
"""

from __future__ import annotations

# Re-imported under the bot_insights_report alias names so the
# helpers below read identically to the original.
from report_engine import humanize as _humanize
from report_engine.theme import DOMAIN_LABELS as _DOMAIN_LABELS


def _humanize_feature_name(name: object) -> str:
    """Human label for a scorecard rule name. Wraps
    ``humanize_identifier`` so the orchestrator doesn't have to repeat
    the snake_case → Sentence-case rule.
    """
    if not name:
        return ""
    return _humanize.humanize_identifier(str(name))


def _humanize_input_list(inputs: object) -> list[str]:
    if not isinstance(inputs, list):
        return []
    return [_humanize.humanize_identifier(str(x)) for x in inputs if x]


def _enrich_feature_card(card: dict) -> dict:
    """Add human label fields to a single feature/rule entry.

    Mirrors the same enrichment the engine's render-time filters apply,
    so the LLM sees ready-to-paste labels (``Cache miss rate high``,
    ``Origin impact``) instead of the producer-side identifier
    (``cache_miss_rate_high``, ``origin_impact``).
    """
    if not isinstance(card, dict):
        return card
    out = dict(card)
    name = card.get("name")
    if name and "name_label" not in out:
        out["name_label"] = _humanize_feature_name(name)
    domain = card.get("domain")
    if domain and "domain_label" not in out:
        out["domain_label"] = _DOMAIN_LABELS.get(domain, _humanize.humanize_identifier(domain))
    missing_inputs = card.get("missing_inputs")
    if isinstance(missing_inputs, list) and "missing_inputs_labels" not in out:
        out["missing_inputs_labels"] = _humanize_input_list(missing_inputs)
    return out


def humanize_evidence_packet(packet: dict) -> dict:
    """Return a copy of ``packet`` with ``*_label`` fields added next
    to each producer-identifier field. Pure transformation — does not
    rename or remove existing keys. Safe to call on any
    ``bot_report_evidence.v1`` packet shape; missing sections are
    no-ops.
    """
    if not isinstance(packet, dict):
        return packet
    out = dict(packet)

    selected = out.get("selected_entity")
    if isinstance(selected, dict):
        s = dict(selected)
        if s.get("entity_type") and "entity_type_label" not in s:
            s["entity_type_label"] = _humanize.humanize_entity_type(s["entity_type"])
        if s.get("band") and "band_label" not in s:
            s["band_label"] = _humanize.humanize_band(s["band"])
        if s.get("confidence") and "confidence_label" not in s:
            s["confidence_label"] = _humanize.humanize_confidence(s["confidence"])
        if s.get("primary_domain") and "primary_domain_label" not in s:
            s["primary_domain_label"] = _DOMAIN_LABELS.get(
                s["primary_domain"],
                _humanize.humanize_identifier(s["primary_domain"]),
            )
        reasons = s.get("confidence_reasons")
        if isinstance(reasons, list) and "confidence_reasons_labels" not in s:
            s["confidence_reasons_labels"] = [
                _humanize.humanize_confidence_reason(str(r)) for r in reasons
            ]
        out["selected_entity"] = s

    features = out.get("evaluated_feature_evidence")
    if isinstance(features, list):
        out["evaluated_feature_evidence"] = [_enrich_feature_card(c) for c in features]

    not_evaluated = out.get("not_evaluated_features")
    if isinstance(not_evaluated, list):
        out["not_evaluated_features"] = [_enrich_feature_card(c) for c in not_evaluated]

    missing_inputs = out.get("missing_inputs")
    if isinstance(missing_inputs, list) and "missing_inputs_labels" not in out:
        out["missing_inputs_labels"] = _humanize_input_list(missing_inputs)

    rule_results = out.get("rule_results")
    if isinstance(rule_results, list):
        out["rule_results"] = [_enrich_feature_card(c) for c in rule_results]

    domain_scores = out.get("domain_scores")
    if isinstance(domain_scores, dict) and "domain_scores_labeled" not in out:
        out["domain_scores_labeled"] = {
            _DOMAIN_LABELS.get(k, _humanize.humanize_identifier(k)): v
            for k, v in domain_scores.items()
        }

    # --- Fleet-shaped packet enrichment ---------------------------------
    # The scorecard_brief --fleet packet has a different top-level
    # shape: fleet_summary / top_entities / lowest_entities /
    # rule_triggers_across_fleet, none of which existed when the
    # original enrichment was wired. Without the labels here, the
    # fleet packet still hands the LLM raw identifiers
    # (band="low_review", primary_domain="cache_busting",
    # rule_triggers[*].name="volume_delta_high"), defeating the
    # interpretation-step label-preference rule.
    fleet_summary = out.get("fleet_summary")
    if isinstance(fleet_summary, dict):
        fs = dict(fleet_summary)
        band_dist = fs.get("band_distribution")
        if isinstance(band_dist, dict) and "band_distribution_labeled" not in fs:
            fs["band_distribution_labeled"] = {
                _humanize.humanize_band(k): v for k, v in band_dist.items()
            }
        conf_dist = fs.get("confidence_distribution")
        if isinstance(conf_dist, dict) and "confidence_distribution_labeled" not in fs:
            fs["confidence_distribution_labeled"] = {
                _humanize.humanize_confidence(k): v for k, v in conf_dist.items()
            }
        pd_dist = fs.get("primary_domain_distribution")
        if isinstance(pd_dist, dict) and "primary_domain_distribution_labeled" not in fs:
            fs["primary_domain_distribution_labeled"] = {
                _DOMAIN_LABELS.get(k, _humanize.humanize_identifier(k)): v
                for k, v in pd_dist.items()
            }
        mid = fs.get("missing_input_domains")
        if isinstance(mid, dict) and "missing_input_domains_labeled" not in fs:
            fs["missing_input_domains_labeled"] = {
                _DOMAIN_LABELS.get(k, _humanize.humanize_identifier(k)): v
                for k, v in mid.items()
            }
        out["fleet_summary"] = fs

    def _enrich_entity_summary(card: object) -> object:
        if not isinstance(card, dict):
            return card
        e = dict(card)
        if e.get("entity_type") and "entity_type_label" not in e:
            e["entity_type_label"] = _humanize.humanize_entity_type(e["entity_type"])
        if e.get("band") and "band_label" not in e:
            e["band_label"] = _humanize.humanize_band(e["band"])
        if e.get("confidence") and "confidence_label" not in e:
            e["confidence_label"] = _humanize.humanize_confidence(e["confidence"])
        if e.get("primary_domain") and "primary_domain_label" not in e:
            e["primary_domain_label"] = _DOMAIN_LABELS.get(
                e["primary_domain"],
                _humanize.humanize_identifier(e["primary_domain"]),
            )
        return e

    top_entities = out.get("top_entities")
    if isinstance(top_entities, list):
        out["top_entities"] = [_enrich_entity_summary(c) for c in top_entities]

    lowest_entities = out.get("lowest_entities")
    if isinstance(lowest_entities, list):
        out["lowest_entities"] = [_enrich_entity_summary(c) for c in lowest_entities]

    rule_triggers = out.get("rule_triggers_across_fleet")
    if isinstance(rule_triggers, list):
        labelled = []
        for entry in rule_triggers:
            if not isinstance(entry, dict):
                labelled.append(entry)
                continue
            e = dict(entry)
            name = e.get("name")
            if name and "name_label" not in e:
                e["name_label"] = _humanize_feature_name(name)
            labelled.append(e)
        out["rule_triggers_across_fleet"] = labelled

    contract = out.get("interpretation_contract")
    if isinstance(contract, dict):
        out["interpretation_contract"] = _with_label_preference(contract)

    return out


# Common interpretation-contract addendum: instructs the LLM to prefer
# the ``*_label`` fields for prose. Appended to every per-report
# ``allowed`` list. Keeping the rest of the contract untouched
# preserves the existing forbidden constraints.
_LABEL_PREFERENCE_RULE = (
    "Prefer human-readable label fields (entity_type_label, band_label, "
    "confidence_label, primary_domain_label, confidence_reasons_labels, "
    "name_label, domain_label, missing_inputs_labels, "
    "domain_scores_labeled) over the paired raw snake_case identifier "
    "when writing prose. Do not name internal tables (bi_summary_*, "
    "bot_agg_path_*, bi_siem_policy_summary_*) in prose; describe the "
    "data source as 'this report's evidence' or refer to it by the "
    "report type."
)


def _with_label_preference(contract: dict) -> dict:
    """Append ``_LABEL_PREFERENCE_RULE`` to ``allowed`` once."""
    if not isinstance(contract, dict):
        return contract
    out = dict(contract)
    allowed = list(out.get("allowed") or [])
    if _LABEL_PREFERENCE_RULE not in allowed:
        allowed.append(_LABEL_PREFERENCE_RULE)
    out["allowed"] = allowed
    return out


# Formatters live in ``producers.formatting``; see the import block at
# the top of this module.


# ``run``, ``load_raw_query_result``, ``result_rows`` are re-exported
# from ``producers.runtime``; see the import block at the top.








