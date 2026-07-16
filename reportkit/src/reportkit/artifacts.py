"""Report artifact contracts and registry helpers."""

from __future__ import annotations

from dataclasses import dataclass, field
from types import ModuleType
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class ReportModule(Protocol):
    """Protocol implemented by report-specific context modules."""

    SCHEMA: str
    REPORT_TYPE: str
    TEMPLATE: str

    def assemble(self, artifacts: list[dict[str, Any]]) -> dict[str, Any]: ...

    def prepare(self, artifact: dict[str, Any]) -> dict[str, Any]: ...


REQUIRED_ATTRS = ("SCHEMA", "REPORT_TYPE", "TEMPLATE", "assemble", "prepare")


@dataclass
class ReportRegistry:
    """Registry keyed by raw schema and wrapper report type."""

    modules: list[ModuleType] = field(default_factory=list)
    schema_exclusions: set[str] = field(default_factory=set)
    schema_registry: dict[str, ModuleType] = field(init=False, default_factory=dict)
    report_type_registry: dict[str, ModuleType] = field(init=False, default_factory=dict)

    def __post_init__(self) -> None:
        self.rebuild()

    def rebuild(self) -> None:
        self.schema_registry.clear()
        self.report_type_registry.clear()
        for module in self.modules:
            self.report_type_registry[module.REPORT_TYPE] = module
            excluded = (
                module.REPORT_TYPE in self.schema_exclusions
                or getattr(module, "EXCLUDE_FROM_SCHEMA_REGISTRY", False)
            )
            if not excluded:
                self.schema_registry[module.SCHEMA] = module

    def register(self, module: ModuleType) -> None:
        missing = [name for name in REQUIRED_ATTRS if not hasattr(module, name)]
        if missing:
            raise TypeError(
                f"Cannot register {module!r}: missing required attribute(s) "
                f"{missing}. Required: {list(REQUIRED_ATTRS)}."
            )
        for idx, existing in enumerate(self.modules):
            if existing.REPORT_TYPE == module.REPORT_TYPE:
                self.modules[idx] = module
                break
        else:
            self.modules.append(module)
        self.rebuild()

    def by_report_type(self, report_type: str) -> ModuleType:
        try:
            return self.report_type_registry[report_type]
        except KeyError as exc:
            raise KeyError(
                f"No context preparer for report_type {report_type!r}. "
                f"Known: {sorted(self.report_type_registry)}"
            ) from exc

    def by_schema(self, schema: str) -> ModuleType:
        try:
            return self.schema_registry[schema]
        except KeyError as exc:
            raise KeyError(
                f"No context preparer for schema {schema!r}. "
                f"Known: {sorted(self.schema_registry)}"
            ) from exc


def detect_input_kind(
    data: dict[str, Any],
    override: str = "auto",
    *,
    wrapper_schema: str = "report_input.v1",
) -> str:
    """Return ``wrapper`` or ``artifact`` for a loaded payload."""

    if override != "auto":
        return override
    if data.get("schema_version") == wrapper_schema:
        return "wrapper"
    return "artifact"


def project_notes_by_slot(
    notes: list[dict[str, Any]] | None,
    note_id_to_slot: dict[str, str],
) -> dict[str, dict[str, Any]]:
    """Project wrapper notes into template slots using first-write-wins."""

    projected: dict[str, dict[str, Any]] = {}
    for note in notes or []:
        slot = note_id_to_slot.get(note.get("note_id", ""))
        if slot:
            projected.setdefault(slot, note)
    return projected


def template_for(module: Any, output_format: str) -> str:
    """Select the HTML template or its Markdown sibling for a report module."""

    if output_format == "markdown":
        if not module.TEMPLATE.endswith(".html"):
            raise ValueError(
                f"{module.REPORT_TYPE} TEMPLATE {module.TEMPLATE!r} does not "
                "end in .html; cannot derive a .md.j2 sibling."
            )
        return module.TEMPLATE[: -len(".html")] + ".md.j2"
    return module.TEMPLATE
