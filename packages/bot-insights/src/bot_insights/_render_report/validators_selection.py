"""Report-specific artifact selection and metadata compatibility checks."""

from __future__ import annotations

from typing import Any

from report_engine.contexts._shared import companion_compatible, known

from .constants import (
    CONTROL_EXPECTED_BASES,
    CONTROL_SCHEMA,
    INCIDENT_ACTION_TARGETS_SCHEMA,
    INCIDENT_ACTORS_SCHEMA,
    INCIDENT_SCOPE_SCHEMA,
    INDEX_SCHEMA,
    MOVER_SCHEMA,
    POSTURE_SCHEMA,
    SCORECARD_SCHEMA,
    THREAT_HUNT_SCHEMA,
)
from .errors import ReportContext, ReportError
from .validators_normalization import by_schema, schema_of


def require_one(
    artifacts: list[dict[str, Any]], schema: str, report_type: str
) -> dict[str, Any]:
    matches = by_schema(artifacts, schema)
    if not matches:
        raise ReportError(f"{report_type} requires {schema}.")
    if len(matches) > 1:
        raise ReportError(f"{report_type} requires one {schema}; found {len(matches)}.")
    return matches[0]


def filter_compatible_companion(
    primary: dict[str, Any] | None,
    companion: dict[str, Any] | None,
    label: str,
    ctx: ReportContext,
) -> dict[str, Any] | None:
    if companion is None:
        return None
    ok, reason = companion_compatible(primary, companion)
    if ok:
        return companion
    ctx.warn(
        f"Omitting optional {label} {companion.get('artifact_id')} from combined sections: {reason}."
    )
    return None


def validate_report_artifacts(
    report_type: str,
    artifacts: list[dict[str, Any]],
    ctx: ReportContext,
) -> dict[str, Any]:
    if report_type in _REPORT_VALIDATORS:
        return _REPORT_VALIDATORS[report_type](artifacts, report_type, ctx)
    if report_type in {
        "incident_report",
        "incident_executive_view",
        "incident_soc_action_packet",
        "incident_edge_platform_brief",
        "incident_detection_engineering",
    }:
        scope = require_one(artifacts, INCIDENT_SCOPE_SCHEMA, report_type)
        actors = require_one(artifacts, INCIDENT_ACTORS_SCHEMA, report_type)
        action_targets = require_one(
            artifacts, INCIDENT_ACTION_TARGETS_SCHEMA, report_type
        )
        return {
            "scope": scope,
            "actors": actors,
            "action_targets": action_targets,
        }
    if report_type == "threat_hunt":
        threat_hunt = require_one(artifacts, THREAT_HUNT_SCHEMA, report_type)
        return {"threat_hunt": threat_hunt}
    raise ReportError(f"Unsupported report type {report_type}.")


def same_packet(
    left: dict[str, Any], right: dict[str, Any], ctx: ReportContext
) -> bool:
    left_parent = ctx.generated_child_parent.get(str(left.get("artifact_id")))
    right_parent = ctx.generated_child_parent.get(str(right.get("artifact_id")))
    return bool(left_parent and left_parent == right_parent)


def shared_metadata_matches(
    index: dict[str, Any], scorecard: dict[str, Any], ctx: ReportContext
) -> bool:
    if same_packet(index, scorecard, ctx):
        for field in (
            "scope",
            "current_window",
            "baseline_windows",
            "table_used",
            "comparison_type",
        ):
            left = index.get(field)
            right = scorecard.get(field)
            if known(left) and known(right) and left != right:
                raise ReportError(
                    f"Same-packet scorecard metadata mismatch for {field}."
                )
            if not known(left) or not known(right):
                ctx.warn(
                    f"{scorecard.get('artifact_id')} missing same-packet {field} metadata."
                )
        return True

    for field in ("scope", "current_window", "baseline_windows", "table_used"):
        left = index.get(field)
        right = scorecard.get(field)
        if not known(left) or not known(right):
            raise ReportError(
                f"Standalone scorecard pairing requires known {field} metadata."
            )
        if left != right:
            raise ReportError(f"Scorecard metadata mismatch for {field}.")

    left_comparison = index.get("comparison_type")
    right_comparison = scorecard.get("comparison_type")
    if known(left_comparison) != known(right_comparison):
        raise ReportError(
            "Standalone scorecard pairing requires matching comparison_type metadata when present."
        )
    if known(left_comparison) and left_comparison != right_comparison:
        raise ReportError("Scorecard metadata mismatch for comparison_type.")
    return True


def compatible_scorecards_for_index_with_order_status(
    index: dict[str, Any],
    scorecards: list[dict[str, Any]],
    ctx: ReportContext,
    *,
    required: bool,
) -> tuple[list[dict[str, Any]], bool]:
    by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for card in scorecards:
        if not known(card.get("entity_type")) or not known(card.get("entity")):
            continue
        key = (str(card.get("entity_type")), str(card.get("entity")))
        existing = by_key.get(key)
        if existing is not None:
            raise ReportError(
                "Multiple scorecards share entity_type/entity "
                f"{key[0]}={key[1]}; pairing with an index would be ambiguous."
            )
        by_key[key] = card
    compatible: list[dict[str, Any]] = []
    for row in index.get("ranked_entities", []):
        key = (str(row.get("entity_type")), str(row.get("entity")))
        card = by_key.get(key)
        if not card:
            continue
        if shared_metadata_matches(index, card, ctx):
            compatible.append(card)
    if required and scorecards and not compatible:
        raise ReportError("No scorecards are compatible with the selected index.")
    if scorecards and not compatible:
        ctx.warn(
            "No scorecards were compatible with the selected index; using input order."
        )
        return scorecards, False
    return compatible, bool(compatible)


def compatible_scorecards_for_index(
    index: dict[str, Any],
    scorecards: list[dict[str, Any]],
    ctx: ReportContext,
    *,
    required: bool,
) -> list[dict[str, Any]]:
    compatible, _ = compatible_scorecards_for_index_with_order_status(
        index, scorecards, ctx, required=required
    )
    return compatible


def first_or_warn(
    artifacts: list[dict[str, Any]],
    schema: str,
    report_type: str,
    ctx: ReportContext,
) -> dict[str, Any] | None:
    matches = by_schema(artifacts, schema)
    if len(matches) > 1:
        raise ReportError(
            f"{report_type} cannot select between multiple {schema} artifacts."
        )
    return matches[0] if matches else None


def scan_metadata_warnings(artifacts: list[dict[str, Any]], ctx: ReportContext) -> None:
    for artifact in artifacts:
        schema = schema_of(artifact)
        aid = artifact.get("artifact_id")
        if schema in {POSTURE_SCHEMA, SCORECARD_SCHEMA, INDEX_SCHEMA}:
            _scan_window_metadata(artifact, aid, ctx)
        elif schema == CONTROL_SCHEMA:
            _scan_control_metadata(artifact, aid, ctx)
        elif schema == MOVER_SCHEMA:
            _scan_mover_metadata(artifact, aid, ctx)


def _validate_executive_posture(
    artifacts: list[dict[str, Any]], report_type: str, ctx: ReportContext
) -> dict[str, Any]:
    posture = require_one(artifacts, POSTURE_SCHEMA, report_type)
    index = first_or_warn(artifacts, INDEX_SCHEMA, report_type, ctx)
    mover = first_or_warn(artifacts, MOVER_SCHEMA, report_type, ctx)
    index = filter_compatible_companion(posture, index, "index", ctx)
    scorecards: list[dict[str, Any]] = []
    if index:
        scorecards = compatible_scorecards_for_index(
            index, by_schema(artifacts, SCORECARD_SCHEMA), ctx, required=False
        )
    return {
        "posture": posture,
        "index": index,
        "scorecards": scorecards,
        "mover": filter_compatible_companion(posture, mover, "mover", ctx),
    }


def _validate_soc_triage(
    artifacts: list[dict[str, Any]], report_type: str, ctx: ReportContext
) -> dict[str, Any]:
    index = require_one(artifacts, INDEX_SCHEMA, report_type)
    scorecards = compatible_scorecards_for_index(
        index, by_schema(artifacts, SCORECARD_SCHEMA), ctx,
        required=bool(by_schema(artifacts, SCORECARD_SCHEMA)),
    )
    if not scorecards:
        ctx.warn(
            "SOC triage has only bot_scorecard_index.v1 and renders a degraded ranking-only report."
        )
    posture = first_or_warn(artifacts, POSTURE_SCHEMA, report_type, ctx)
    mover = first_or_warn(artifacts, MOVER_SCHEMA, report_type, ctx)
    return {
        "index": index,
        "scorecards": scorecards,
        "posture": filter_compatible_companion(index, posture, "posture", ctx),
        "mover": filter_compatible_companion(index, mover, "mover", ctx),
    }


def _validate_control_review(
    artifacts: list[dict[str, Any]], report_type: str, ctx: ReportContext
) -> dict[str, Any]:
    control = require_one(artifacts, CONTROL_SCHEMA, report_type)
    posture = first_or_warn(artifacts, POSTURE_SCHEMA, report_type, ctx)
    mover = first_or_warn(artifacts, MOVER_SCHEMA, report_type, ctx)
    return {
        "control": control,
        "posture": filter_compatible_companion(control, posture, "posture", ctx),
        "mover": filter_compatible_companion(control, mover, "mover", ctx),
    }


def _validate_scorecard_brief(
    artifacts: list[dict[str, Any]], report_type: str, ctx: ReportContext
) -> dict[str, Any]:
    scorecards = _require_scorecards(artifacts, report_type)
    index = first_or_warn(artifacts, INDEX_SCHEMA, report_type, ctx)
    index_order_usable = False
    if index:
        scorecards, index_order_usable = compatible_scorecards_for_index_with_order_status(
            index, scorecards, ctx, required=True
        )
    return {
        "scorecard": scorecards[0],
        "scorecards": scorecards,
        "index": index,
        "index_order_usable": index_order_usable,
        "is_fleet": bool(index or len(scorecards) > 1),
    }


def _validate_scorecard_family(
    artifacts: list[dict[str, Any]], report_type: str, ctx: ReportContext
) -> dict[str, Any]:
    scorecards = _require_scorecards(artifacts, report_type)
    index = first_or_warn(artifacts, INDEX_SCHEMA, report_type, ctx)
    index_order_usable = False
    if index:
        scorecards, index_order_usable = compatible_scorecards_for_index_with_order_status(
            index, scorecards, ctx, required=False
        )
    reference = index or (scorecards[0] if scorecards else None)
    posture = first_or_warn(artifacts, POSTURE_SCHEMA, report_type, ctx)
    mover = first_or_warn(artifacts, MOVER_SCHEMA, report_type, ctx)
    return {
        "scorecards": scorecards,
        "index": index,
        "index_order_usable": index_order_usable,
        "posture": filter_compatible_companion(reference, posture, "posture", ctx),
        "mover": filter_compatible_companion(reference, mover, "mover", ctx),
    }


def _require_scorecards(
    artifacts: list[dict[str, Any]], report_type: str
) -> list[dict[str, Any]]:
    scorecards = by_schema(artifacts, SCORECARD_SCHEMA)
    if scorecards:
        return scorecards
    if report_type == "scorecard_brief":
        raise ReportError(f"{report_type} requires {SCORECARD_SCHEMA}.")
    raise ReportError(
        f"{report_type} requires bot_entity_scorecard.v1 artifacts or a scorecard packet."
    )


_REPORT_VALIDATORS = {
    "executive_posture": _validate_executive_posture,
    "soc_triage": _validate_soc_triage,
    "control_review": _validate_control_review,
    "scorecard_brief": _validate_scorecard_brief,
    "crawler_governance": _validate_scorecard_family,
    "edge_ops_impact": _validate_scorecard_family,
}


def _scan_window_metadata(
    artifact: dict[str, Any], aid: Any, ctx: ReportContext
) -> None:
    if not artifact.get("current_window"):
        ctx.warn(f"{aid} missing current_window metadata.")
    if not artifact.get("baseline_windows"):
        ctx.warn(f"{aid} missing baseline_windows metadata.")


def _scan_control_metadata(
    artifact: dict[str, Any], aid: Any, ctx: ReportContext
) -> None:
    if not artifact.get("before_window"):
        ctx.warn(f"{aid} missing before_window metadata.")
    if not artifact.get("after_window"):
        ctx.warn(f"{aid} missing after_window metadata.")
    basis = artifact.get("expected_basis")
    if _control_has_expected_effects(artifact) and (
        not isinstance(basis, str) or basis not in CONTROL_EXPECTED_BASES
    ):
        ctx.warn(f"{aid} missing or unknown expected_basis with expected target effects.")
    if basis in {"before_window", "external_model"} and not artifact.get(
        "expected_window"
    ):
        ctx.warn(f"{aid} missing expected_window metadata for expected_basis {basis}.")


def _control_has_expected_effects(artifact: dict[str, Any]) -> bool:
    effects = artifact.get("target_effects") or []
    return any(
        isinstance(effect, dict)
        and "expected" in effect
        and effect.get("expected") is not None
        for effect in effects
    )


def _scan_mover_metadata(
    artifact: dict[str, Any], aid: Any, ctx: ReportContext
) -> None:
    if not artifact.get("dimension"):
        ctx.warn(f"{aid} missing mover dimension metadata.")
    if not artifact.get("metric"):
        ctx.warn(f"{aid} missing mover metric metadata.")
