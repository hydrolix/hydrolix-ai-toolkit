"""Typed boundary models for Bot Insights package entrypoints."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class ArtifactModel(BaseModel):
    """Generic deterministic artifact accepted by render entrypoints."""

    model_config = ConfigDict(extra="allow")

    schema_version: str
    artifact_id: str | None = None


class AnalystNoteModel(BaseModel):
    """LLM or operator-authored narrative routed into a report slot."""

    model_config = ConfigDict(extra="allow")

    note_id: str | None = None
    slot: str | None = None
    author_type: Literal["human", "llm", "system"] | str = "human"
    text: str = ""
    show_data_sources: bool = True


class ReportInputModel(BaseModel):
    """Validated wrapper around deterministic artifacts for rendering."""

    model_config = ConfigDict(extra="allow")

    schema_version: Literal["bot_report_input.v1"]
    report_type: str
    artifacts: list[ArtifactModel] = Field(default_factory=list)
    analyst_notes: list[AnalystNoteModel] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class CaptureQueryConfigModel(BaseModel):
    """Stable capture/query options shared at CLI and client boundaries."""

    model_config = ConfigDict(extra="forbid")

    cluster: str | None = None
    database: str = "akamai"
    start: str | None = None
    end: str | None = None
    preset: str | None = None
    table_surface: str = "auto"
    granularity: str = "auto"
    require_time_range: bool = True


class BotManagerSourceModel(BaseModel):
    """Source metadata used by threat-hunt Bot Manager enrichment."""

    model_config = ConfigDict(extra="allow")

    source: str
    observed_at: str | None = None
    confidence: float | None = None


class BotManagerContextModel(BaseModel):
    """Normalized Bot Manager context attached to a threat-hunt entity."""

    model_config = ConfigDict(extra="allow")

    entity_type: str
    entity_value: str
    sources: list[BotManagerSourceModel] = Field(default_factory=list)
    mix: dict[str, Any] = Field(default_factory=dict)
