"""Runtime constants and process helpers shared across producer modules.

Low-level surface used by every orchestrator (the per-report runners
that drive bot_insights_capture.py) and by main(). Keeping these here
breaks the circular dependency that would otherwise form between
``bot_insights_report.py`` (CLI entry) and
``producers.orchestrators.*`` (per-report runners) since both need
the same handoff-protocol constants and subprocess runner.

Exports:
  - ``PUBLIC_SKILLS``: root of the public-skills checkout, derived
    from this file's location so worktree-based development keeps
    routing through the local copy rather than the main checkout.
  - ``CAPTURE``: absolute path to ``bot_insights_capture.py`` (the
    Hydrolix MCP / direct-capture wrapper the orchestrator shells out
    to for every phase query).
  - ``DEFAULT_SAMPLE_ROOT``: default destination for raw + artifact
    JSON files when ``--sample-dir`` isn't supplied.
  - ``NEEDS_MCP_EXIT``: exit code capture returns when the run needs
    to be re-issued via MCP rather than the direct ClickHouse path.
  - ``HANDOFF_SCHEMA``: schema_version string capture emits on the
    MCP-handoff exit; orchestrators re-emit that packet upstream with
    a ``report_context`` block appended.
  - ``run()``: subprocess runner that raises SystemExit on
    non-zero / non-allowed exit codes.
  - ``load_raw_query_result()`` / ``result_rows()``: parsers for the
    raw JSON files capture writes to ``--output``.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path


PUBLIC_SKILLS = Path(__file__).resolve().parents[4]
CAPTURE = (
    Path(__file__).resolve().parents[1] / "bot_insights_capture.py"
)
DEFAULT_SAMPLE_ROOT = Path("/Users/turtlebender/src/sample-data/bot-insights/1.1")
NEEDS_MCP_EXIT = 42
HANDOFF_SCHEMA = "bot_hydrolix_mcp_query_request.v1"


def run(
    cmd: list[str],
    *,
    stdout_path: Path | None = None,
    cwd: Path | None = None,
    allowed_returncodes: tuple[int, ...] = (),
) -> str:
    """Run a subprocess; raise ``SystemExit`` on non-zero (and non-
    allowed) exit codes. Returns stdout when no ``stdout_path`` is
    given, else writes stdout to the path and returns ``""``.
    Allowed-returncodes is how callers opt into capture's
    ``NEEDS_MCP_EXIT`` (42) handoff path without it being treated as
    a failure.
    """
    ok_codes = (0, *allowed_returncodes)
    if stdout_path is None:
        result = subprocess.run(
            cmd, cwd=cwd, text=True, capture_output=True, check=False
        )
        if result.returncode not in ok_codes:
            detail = result.stderr.strip() or result.stdout.strip()
            raise SystemExit(detail)
        return result.stdout
    with stdout_path.open("w", encoding="utf-8") as handle:
        result = subprocess.run(
            cmd,
            cwd=cwd,
            text=True,
            stdout=handle,
            stderr=subprocess.PIPE,
            check=False,
        )
    if result.returncode not in ok_codes:
        raise SystemExit(result.stderr.strip())
    return ""


def load_raw_query_result(path: Path) -> dict:
    """Parse a raw JSON file capture wrote to ``--output``.

    Accepts both the canonical object shape (``{"data": [...]}``)
    and the legacy array shape, normalizing the latter into the same
    object shape so consumers don't have to branch.
    """
    value = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(value, dict):
        return value
    if isinstance(value, list):
        return {"data": value, "rows": len(value)}
    raise SystemExit(
        f"Expected {path} to contain a Hydrolix MCP or ClickHouse JSON object."
    )


def result_rows(value: dict) -> list[dict]:
    """Extract row dicts from a parsed raw query result. Accepts both
    ``data`` and ``rows`` keys (capture has used both historically);
    filters out non-dict entries so a malformed file doesn't poison
    downstream projection."""
    rows = value.get("data")
    if isinstance(rows, list):
        return [row for row in rows if isinstance(row, dict)]
    rows = value.get("rows")
    if isinstance(rows, list):
        return [row for row in rows if isinstance(row, dict)]
    return []
