"""Wrapper artifact selection and validation for incident reports."""

from __future__ import annotations

from .constants import SCHEMA


def assemble(artifacts: list[dict]) -> dict:
    """Reshape a ``bot_report_input.v1`` wrapper's artifacts list into the
    dict ``prepare()`` expects.

    The incident report requires all three artifacts. The actors artifact
    may carry ``raw_drilldown_available: false`` — that surfaces the
    limitation banner in the template instead of the actor tables, but
    is not an error. The action-targets artifact must be present but may
    carry an empty ``targets`` list (renders the explanatory banner).
    """
    scope = next(
        (a for a in artifacts if a.get("schema_version") == "bot_incident_scope.v1"),
        None,
    )
    if scope is None:
        raise ValueError(
            "incident_report wrapper missing bot_incident_scope.v1 artifact"
        )
    actors = next(
        (a for a in artifacts if a.get("schema_version") == "bot_incident_actors.v1"),
        None,
    )
    if actors is None:
        raise ValueError(
            "incident_report wrapper missing bot_incident_actors.v1 artifact"
        )
    action_targets = next(
        (
            a
            for a in artifacts
            if a.get("schema_version") == "bot_incident_action_targets.v1"
        ),
        None,
    )
    if action_targets is None:
        raise ValueError(
            "incident_report wrapper missing bot_incident_action_targets.v1 artifact"
        )
    return {
        "schema_version": SCHEMA,
        "scope": scope,
        "actors": actors,
        "action_targets": action_targets,
    }
