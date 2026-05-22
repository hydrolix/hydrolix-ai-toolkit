"""Legacy Markdown evidence limits and analyst-note helpers."""

from __future__ import annotations

from typing import Any

from .citations import resolve_citation
from .constants import (
    POSTURE_SCHEMA,
    SCORECARD_SCHEMA,
    TIMESERIES_SCHEMA,
)
from .errors import (
    ReportContext,
    ReportError,
)
from .formatters import (
    human_number,
    md_escape,
)
from .scorecard_helpers import (
    _format_list_value,
    _format_scope_value,
    _producer_limit_bullet,
    _source_population_caveat,
    crawler_provenance_gaps,
)
from .tables import (
    artifact_display_name,
    window_text,
)

__all__ = [
    'md_evidence_limits',
    'md_analyst_notes',
    'validate_analyst_notes',
]


def md_evidence_limits(artifacts: list[dict[str, Any]], ctx: ReportContext) -> str:
    sections: list[str] = ["## Evidence Limits"]
    for artifact in artifacts:
        aid = artifact.get("artifact_id") or "unavailable"
        schema = artifact.get("schema_version") or "unavailable"
        if schema == POSTURE_SCHEMA:
            sections.append(_md_posture_limits(artifact))
            continue
        if schema == TIMESERIES_SCHEMA:
            sections.append(_md_timeseries_limits(artifact))
            continue
        sections.append(_md_generic_evidence_limits(artifact, aid, schema))
    sections.append(
        "Reports use emitted artifact fields only. Missing evidence is unavailable, not zero or safe."
    )
    return "\n\n".join(sections)


def _md_posture_limits(artifact: dict[str, Any]) -> str:
    bullets = [
        "- This is a movement report. It does not identify root cause by itself.",
    ]
    return f"### {md_escape(artifact_display_name(artifact))}\n\n" + "\n".join(bullets)


def _md_timeseries_limits(artifact: dict[str, Any]) -> str:
    metrics = artifact.get("metrics")
    metric_count = len(metrics) if isinstance(metrics, list) else 0
    is_control_trend = (
        artifact.get("title") == "Control Review Trends"
        or artifact.get("report_type") == "control_review"
    )
    comparison_label = (
        "after and expected windows" if is_control_trend else "current and prior windows"
    )
    exact_label = "control effects table" if is_control_trend else "metric deltas table"
    bullets = [
        f"- Trend cards: {metric_count} hourly metric series comparing {comparison_label}.",
        f"- Trend cards show shape and direction; exact aggregate values are in the {exact_label}.",
    ]
    return f"### {md_escape(artifact_display_name(artifact))}\n\n" + "\n".join(bullets)


def _md_generic_evidence_limits(
    artifact: dict[str, Any], aid: Any, schema: Any
) -> str:
    bullets = _md_base_limit_bullets(artifact, schema)
    bullets.extend(_md_not_evaluated_bullets(artifact, schema))
    bullets.extend(_md_provenance_gap_bullets(artifact))
    producer_line = _producer_limit_bullet(artifact)
    if producer_line:
        bullets.append(f"- {md_escape(producer_line)}")
    caveat = _source_population_caveat(artifact)
    if caveat:
        bullets.append(f"- {md_escape(caveat)}")
    return f"### Artifact {md_escape(aid)}\n\n" + "\n".join(bullets)


def _md_base_limit_bullets(artifact: dict[str, Any], schema: Any) -> list[str]:
    bullets: list[str] = [f"- Schema: {md_escape(schema)}"]
    parent_id = artifact.get("parent_artifact_id")
    if parent_id:
        pointer = artifact.get("parent_json_pointer")
        parent_line = f"- Parent: {md_escape(parent_id)}"
        if pointer:
            parent_line += f" at {md_escape(pointer)}"
        bullets.append(parent_line)
    bullets.extend(
        [
            f"- Table: {md_escape(artifact.get('table_used') or 'unavailable')}",
            f"- Scope: {md_escape(_format_scope_value(artifact.get('scope')))}",
            f"- Confidence: {md_escape(artifact.get('confidence') or 'unavailable')}",
            f"- Confidence reasons: {md_escape(_format_list_value(artifact.get('confidence_reasons')))}",
            f"- Interpretation constraints: {md_escape(_format_list_value(artifact.get('interpretation_constraints')))}",
        ]
    )
    windows_text = window_text(artifact)
    if windows_text != "unavailable":
        bullets.append(f"- Windows: {md_escape(windows_text)}")
    return bullets


def _md_not_evaluated_bullets(artifact: dict[str, Any], schema: Any) -> list[str]:
    not_evaluated = artifact.get("not_evaluated_features")
    if not isinstance(not_evaluated, list) or not not_evaluated:
        return []
    bullets = ["- Not-evaluated features:"]
    for item in not_evaluated:
        if isinstance(item, dict):
            bullets.append(_md_missing_feature_bullet(item))
    if schema == SCORECARD_SCHEMA and isinstance(artifact.get("domain_scores"), dict):
        bullets.extend(_md_domain_ambiguity_bullets(not_evaluated))
    return bullets


def _md_missing_feature_bullet(item: dict[str, Any]) -> str:
    domain = item.get("domain") or "unavailable"
    name = item.get("name") or "unavailable"
    missing = ", ".join(str(value) for value in item.get("missing_inputs", []))
    reason = item.get("reason") or "unavailable"
    missing_text = missing or "unavailable"
    return (
        f"  - {md_escape(domain)} / {md_escape(name)}"
        f" (missing inputs: {md_escape(missing_text)}; reason: {md_escape(reason)})"
    )


def _md_domain_ambiguity_bullets(not_evaluated: list[Any]) -> list[str]:
    domains = sorted(
        {
            str(item.get("domain"))
            for item in not_evaluated
            if isinstance(item, dict) and item.get("domain")
        }
    )
    if not domains:
        return []
    return [
        "- Domain score ambiguity: emitted numeric domain scores are rendered as-is; "
        "missing inputs remain unresolved for "
        + md_escape(", ".join(domains))
        + "."
    ]


def _md_provenance_gap_bullets(artifact: dict[str, Any]) -> list[str]:
    provenance_gaps = crawler_provenance_gaps(artifact)
    if not provenance_gaps:
        return []
    bullets = ["- Crawler provenance gaps:"]
    for feature in provenance_gaps:
        name = feature.get("name") or "unavailable"
        bullets.append(
            f"  - {md_escape(name)}: structured `rowset_scope`/`feature_provenance` "
            "population is missing or non-crawler; generic 429/5xx feature was not rendered as a crawler finding."
        )
    return bullets


def md_analyst_notes(
    notes: list[dict[str, Any]], artifacts: list[dict[str, Any]], ctx: ReportContext
) -> str:
    if not notes:
        return ""
    parts = [
        "## Analyst Notes",
        "These notes are interpretive narrative, not facts strictly proven by artifact data alone.",
    ]
    for index, note in enumerate(notes, start=1):
        author = note.get("author_type")
        if author not in {"llm", "analyst"}:
            ctx.warn(
                f"Analyst note {note.get('note_id', index)} has unsupported author_type {author}."
            )
            author = "analyst"
        label = "LLM interpretation" if author == "llm" else "Analyst interpretation"
        title = note.get("title") or f"Note {index}"
        parts.append(
            f"### {md_escape(title)}\n\n_{label}._ {md_escape(note.get('text', ''))}"
        )
        if note.get("show_data_sources") is False:
            continue
        sources = note.get("data_sources")
        if not isinstance(sources, list) or not sources:
            ctx.warn(
                f"Analyst note {note.get('note_id', index)} has no cited data sources."
            )
            continue
        citations = []
        for source in sources:
            _artifact, normalized_pointer, resolved = resolve_citation(
                source, artifacts
            )
            label = source.get("label") or "Supporting value"
            percent = normalized_pointer.endswith("/pct_change")
            citations.append(
                f"- {md_escape(label)}: {md_escape(human_number(resolved, percent=percent))}"
            )
        if citations:
            parts.append("Supporting evidence:\n\n" + "\n".join(citations))
    return "\n\n".join(parts)


def validate_analyst_notes(
    notes: list[dict[str, Any]], artifacts: list[dict[str, Any]]
) -> None:
    for index, note in enumerate(notes, start=1):
        note_id = note.get("note_id", index)
        text = note.get("text")
        if not isinstance(text, str) or not text.strip():
            raise ReportError(f"Analyst note {note_id} must include non-empty text.")
        author = note.get("author_type")
        if author not in {"llm", "analyst"}:
            raise ReportError(f"Analyst note {note_id} has unsupported author_type.")
        sources = note.get("data_sources", [])
        if sources is None:
            sources = []
        if not isinstance(sources, list):
            raise ReportError(f"Analyst note {note_id} data_sources must be an array.")
        for source in sources:
            if not isinstance(source, dict):
                raise ReportError(
                    f"Analyst note {note_id} data_sources entries must be objects."
                )
            resolve_citation(source, artifacts)
