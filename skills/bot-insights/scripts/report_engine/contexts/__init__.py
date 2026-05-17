"""Per-report-type context preparers.

Each module exposes:
  - SCHEMA: the raw artifact schema_version it handles
  - REPORT_TYPE: the wrapper `report_type` it handles
  - TEMPLATE: the relative template path under templates/reports/
  - NOTE_ID_TO_SLOT: mapping from wrapper analyst_notes[].note_id to a
                     narrative slot name templates can render
  - assemble(artifacts: list[dict]) -> dict: reshape a wrapper's artifacts
                     list into the dict shape `prepare()` expects
  - prepare(artifact: dict) -> dict: pure transform from artifact to template
                     context

Out-of-tree report modules can be registered at runtime via
``register(module)`` or by dropping a ``*.py`` file on
``BOT_INSIGHTS_CONTEXTS_PATH`` (colon-separated list of directories).
A discovered module is treated identically to the built-ins — it
contributes to ``SCHEMA_REGISTRY`` (unless its REPORT_TYPE is on the
exclusions set, which a third party can extend by exposing an
``EXCLUDE_FROM_SCHEMA_REGISTRY = True`` module-level flag).
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path
from types import ModuleType

from . import (
    control_review,
    crawler_governance,
    edge_ops_impact,
    executive_posture,
    incident_executive_view,
    incident_report,
    scorecard_brief,
    scorecard_entity_review,
    soc_triage,
)


_MODULES: list[ModuleType] = [
    scorecard_brief,
    scorecard_entity_review,
    executive_posture,
    control_review,
    soc_triage,
    crawler_governance,
    edge_ops_impact,
    incident_report,
    incident_executive_view,
]

# Registry keyed on raw artifact schema_version. ``soc_triage``,
# ``crawler_governance``, and ``edge_ops_impact`` share
# ``bot_scorecard_artifacts.v1`` with ``scorecard_brief`` — the schema
# alone can't disambiguate them. We keep ``scorecard_brief`` as the
# schema-mode default; the others route through ``REPORT_TYPE_REGISTRY``
# via the wrapper's ``report_type`` field, the same path
# ``executive_posture`` uses.
_SCHEMA_REGISTRY_EXCLUSIONS = {
    "soc_triage",
    "crawler_governance",
    "edge_ops_impact",
    # ``incident_executive_view`` shares ``bot_incident_scope.v1`` with
    # ``incident_report``; route via the wrapper's ``report_type`` field.
    "incident_executive_view",
}

SCHEMA_REGISTRY: dict[str, ModuleType] = {}
REPORT_TYPE_REGISTRY: dict[str, ModuleType] = {}


def _rebuild_registries() -> None:
    """Rebuild ``SCHEMA_REGISTRY`` + ``REPORT_TYPE_REGISTRY`` from
    ``_MODULES``. Called after every ``register()`` so the lookup
    tables stay in sync with the live module list.
    """
    SCHEMA_REGISTRY.clear()
    REPORT_TYPE_REGISTRY.clear()
    for mod in _MODULES:
        REPORT_TYPE_REGISTRY[mod.REPORT_TYPE] = mod
        excluded = (
            mod.REPORT_TYPE in _SCHEMA_REGISTRY_EXCLUSIONS
            or getattr(mod, "EXCLUDE_FROM_SCHEMA_REGISTRY", False)
        )
        if not excluded:
            SCHEMA_REGISTRY[mod.SCHEMA] = mod


_REQUIRED_ATTRS = ("SCHEMA", "REPORT_TYPE", "TEMPLATE", "assemble", "prepare")


def register(module: ModuleType) -> None:
    """Register an out-of-tree context module.

    The module must expose ``SCHEMA``, ``REPORT_TYPE``, ``TEMPLATE``,
    ``assemble``, and ``prepare`` (the same surface every built-in
    context module exposes). Registering with a ``REPORT_TYPE`` that's
    already in the registry replaces the prior entry — supports
    overriding a built-in report.
    """
    missing = [a for a in _REQUIRED_ATTRS if not hasattr(module, a)]
    if missing:
        raise TypeError(
            f"Cannot register {module!r}: missing required attribute(s) "
            f"{missing}. Required: {list(_REQUIRED_ATTRS)}."
        )
    # Replace in place when the REPORT_TYPE is already known; otherwise append.
    for i, existing in enumerate(_MODULES):
        if existing.REPORT_TYPE == module.REPORT_TYPE:
            _MODULES[i] = module
            break
    else:
        _MODULES.append(module)
    _rebuild_registries()


def _load_module_from_path(path: Path) -> ModuleType | None:
    """Import a Python file as a module without polluting ``sys.modules``
    with a predictable name. Returns the module (or None if the file
    doesn't expose the required attributes — silent skip lets a
    directory mix context modules with utility scripts)."""
    spec = importlib.util.spec_from_file_location(
        f"bot_insights_oot_context_{path.stem}", path
    )
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    # Register under the spec's name so internal relative-import
    # machinery is happy; this is a namespacing convenience, not a
    # public handle.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    if all(hasattr(module, a) for a in _REQUIRED_ATTRS):
        return module
    return None


def _discover_modules(directory: Path) -> None:
    """Scan ``directory`` for ``*.py`` files and register each one that
    looks like a context module. Skips ``__init__.py`` and any file
    whose name starts with ``_``."""
    if not directory.is_dir():
        return
    for path in sorted(directory.glob("*.py")):
        if path.name == "__init__.py" or path.name.startswith("_"):
            continue
        module = _load_module_from_path(path)
        if module is not None:
            register(module)


def _scan_env_path(env_var: str = "BOT_INSIGHTS_CONTEXTS_PATH") -> None:
    """Discover context modules from every directory on the
    colon-separated ``BOT_INSIGHTS_CONTEXTS_PATH`` environment
    variable."""
    raw = os.environ.get(env_var, "").strip()
    if not raw:
        return
    for entry in raw.split(":"):
        entry = entry.strip()
        if entry:
            _discover_modules(Path(entry).expanduser())


_rebuild_registries()
_scan_env_path()


# Backward-compat alias for the original render.py callsite.
REGISTRY = SCHEMA_REGISTRY
