"""Pytest wrapper for the live bot-insights query-surface validation.

This runs the checks in ``validate_live.py`` against a real Hydrolix cluster and
fails if any check FAILs. It SKIPS cleanly when no cluster is configured, so it
is safe to include in the default test run: offline CI stays green, and live
validation is opt-in via the cluster env (and, for tokens stored as op://
references, a signed-in 1Password CLI).

Run just this suite against the default cluster (demo.trafficpeak.live):

    uv run pytest tests/live/test_live_query_surface.py -v

Point it at another cluster / database:

    BOT_INSIGHTS_LIVE_CLUSTER=<cluster> BOT_INSIGHTS_LIVE_DB=<db> \
        uv run pytest tests/live/test_live_query_surface.py -v

Use quick mode (hour-grain schema probes only) for a faster local check:

    BOT_INSIGHTS_LIVE_QUICK=1 uv run pytest tests/live/test_live_query_surface.py -v
"""
from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("validate_live", HERE / "validate_live.py")
assert _spec and _spec.loader
validate_live = importlib.util.module_from_spec(_spec)
sys.modules["validate_live"] = validate_live  # so dataclass annotations resolve
_spec.loader.exec_module(validate_live)


@pytest.fixture(scope="module")
def live_results():
    cluster = os.environ.get("BOT_INSIGHTS_LIVE_CLUSTER", validate_live.DEFAULT_CLUSTER)
    db = os.environ.get("BOT_INSIGHTS_LIVE_DB", validate_live.DEFAULT_DB)
    conn = validate_live.connect(cluster)
    if conn is None:
        pytest.skip(
            f"no usable cluster env for {cluster!r} "
            f"(~/.config/hydrolix/clusters/{cluster}.env); live validation is opt-in"
        )
    quick = os.environ.get("BOT_INSIGHTS_LIVE_QUICK", "").lower() in ("1", "true", "yes")
    ctx = validate_live.discover(conn, db)
    results: list = []
    validate_live.check_schema(ctx, results, quick=quick)
    validate_live.check_doc_sql(ctx, results)
    validate_live.check_negative(ctx, results)
    validate_live.check_prose(ctx, results)
    validate_live.check_producers(ctx, results)
    return results


def _by_kind(results, kind):
    return [r for r in results if r.kind == kind]


@pytest.mark.parametrize("kind", ["schema", "doc-sql", "negative", "prose", "producer"])
def test_no_failures_by_kind(live_results, kind):
    failed = [r for r in _by_kind(live_results, kind) if r.status == "FAIL"]
    assert not failed, "\n".join(f"{r.name}: {r.detail}" for r in failed)


def test_no_unresolved_doc_sql(live_results):
    """Every deployed-table example in the docs must resolve to runnable SQL."""
    unresolved = [r for r in live_results if r.status == "UNRESOLVED"]
    assert not unresolved, "\n".join(f"{r.name} ({r.source})" for r in unresolved)


def test_something_was_checked(live_results):
    assert live_results, "no checks ran"
