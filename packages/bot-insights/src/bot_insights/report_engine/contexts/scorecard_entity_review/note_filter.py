"""Token-based redundant-note filter (post_prepare hook)."""

from __future__ import annotations

import re

__all__ = [
    '_TOKEN_RE',
    '_tokens',
    '_is_redundant_note',
    'post_prepare',
]


_TOKEN_RE = re.compile(r"[a-z0-9]+")


def _tokens(text: str) -> set[str]:
    return set(_TOKEN_RE.findall((text or "").lower()))


def _is_redundant_note(text: str, finding_tokens: set[str]) -> bool:
    """Heuristic: is this analyst note adding nothing beyond the finding?

    Short notes whose tokens are largely a subset of the deterministic
    finding's tokens are dropped. We keep notes that introduce non-trivial
    new vocabulary (paths, metrics, recommendations).
    """
    note_tokens = _tokens(text)
    if not note_tokens:
        return True
    # Very short notes are most often structural restatements.
    if len(note_tokens) <= 8:
        return True
    if not finding_tokens:
        return False
    # Strip filler tokens — these don't carry meaning either way.
    filler = {
        "the",
        "a",
        "an",
        "and",
        "or",
        "of",
        "to",
        "in",
        "for",
        "with",
        "is",
        "are",
        "was",
        "were",
        "be",
        "this",
        "that",
        "it",
        "as",
        "on",
        "by",
        "from",
        "at",
        "score",
        "rule",
        "rules",
        "host",
        "hosts",
    }
    novel = note_tokens - finding_tokens - filler
    return len(novel) < 5


def post_prepare(ctx: dict) -> None:
    """Suppress structurally-redundant analyst notes after note merge.

    Called by the renderer after ``notes_by_slot`` has been injected. Drops
    the executive_summary note when its non-structural content is dominated
    by tokens already present in the deterministic finding body — saves the
    reader from reading the same fact twice.
    """
    notes = ctx.get("notes_by_slot") or {}
    findings = ctx.get("deterministic_findings") or []
    if not findings:
        return
    body = findings[0].get("body") or ""
    finding_tokens = _tokens(body)

    note = notes.get("executive_summary")
    if note and _is_redundant_note(note.get("text", ""), finding_tokens):
        notes = dict(notes)
        notes.pop("executive_summary", None)
        ctx["notes_by_slot"] = notes
