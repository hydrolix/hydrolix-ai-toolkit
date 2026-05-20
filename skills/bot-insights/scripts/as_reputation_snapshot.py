#!/usr/bin/env python3
"""Generate local AS reputation snapshots for Bot Insights reports."""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from report_engine.contexts.incident.as_reputation import (
    _iter_snapshot_records,
    _record_asns,
)


DEFAULT_SPAMHAUS_ASNDROP_URL = "https://www.spamhaus.org/drop/asndrop.json"
USER_AGENT = "Hydrolix Bot Insights AS Reputation Snapshot/1.0"


class SnapshotError(RuntimeError):
    """Raised for actionable snapshot generation failures."""


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate local AS reputation snapshots for Bot Insights."
    )
    parser.add_argument(
        "--source",
        required=True,
        choices=("spamhaus-asndrop",),
        help="Generic source to normalize.",
    )
    parser.add_argument(
        "--url",
        default=DEFAULT_SPAMHAUS_ASNDROP_URL,
        help="Source URL to fetch when --input is not provided.",
    )
    parser.add_argument(
        "--input",
        type=Path,
        help="Offline/local source JSON to normalize instead of fetching --url.",
    )
    parser.add_argument("--output", type=Path, required=True, help="Snapshot path.")
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Write human-readable indented JSON.",
    )
    return parser.parse_args(argv)


def _read_input(path: Path) -> Any:
    try:
        return _loads_source_payload(path.read_text(encoding="utf-8"), str(path))
    except OSError as exc:
        raise SnapshotError(f"Could not read --input {path}: {exc}") from exc


def _fetch_json(url: str) -> Any:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            body = response.read()
    except urllib.error.URLError as exc:
        raise SnapshotError(f"Could not fetch {url}: {exc}") from exc
    except TimeoutError as exc:
        raise SnapshotError(f"Timed out fetching {url}") from exc
    try:
        return _loads_source_payload(body.decode("utf-8"), url)
    except UnicodeDecodeError as exc:
        raise SnapshotError(f"Could not decode {url} as UTF-8 JSON: {exc}") from exc


def _loads_source_payload(text: str, source_label: str) -> Any:
    try:
        return json.loads(text)
    except json.JSONDecodeError as single_doc_error:
        records: list[Any] = []
        for line_number, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                records.append(json.loads(stripped))
            except json.JSONDecodeError as exc:
                raise SnapshotError(
                    f"Could not parse {source_label} as JSON or JSON Lines: "
                    f"line {line_number}: {exc}"
                ) from exc
        if records:
            return records
        raise SnapshotError(
            f"Could not parse {source_label} as JSON: {single_doc_error}"
        ) from single_doc_error


def _record_name(record: dict[str, Any]) -> str:
    return str(
        record.get("name")
        or record.get("as_name")
        or record.get("asname")
        or record.get("org")
        or record.get("organization")
        or record.get("description")
        or "Spamhaus ASN-DROP listing"
    )


def _record_last_reviewed(record: dict[str, Any]) -> str:
    return str(
        record.get("last_seen")
        or record.get("last_updated")
        or record.get("last_reviewed")
        or ""
    )


def normalize_spamhaus_asndrop(raw: Any, *, source_url: str) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for record in _iter_snapshot_records(raw):
        asns = _record_asns(record)
        if not asns:
            continue
        entries.append(
            {
                "asns": asns,
                "name": _record_name(record),
                "label": str(record.get("label") or "public_threat_enabler"),
                "confidence": str(record.get("confidence") or "medium"),
                "evidence_grade": str(
                    record.get("evidence_grade") or "public_routing_reputation"
                ),
                "last_reviewed": _record_last_reviewed(record),
                "provider": "spamhaus_asndrop",
                "minimum_source_bar": "provider_snapshot",
                "sources": [
                    {
                        "title": "Spamhaus ASN-DROP",
                        "url": source_url,
                        "source_type": "network_intelligence",
                        "summary": (
                            "Spamhaus ASN-DROP public routing and reputation "
                            "context for autonomous systems."
                        ),
                    }
                ],
            }
        )
    if not entries:
        raise SnapshotError(
            "Source payload did not contain any ASN-DROP records with ASN values."
        )
    return entries


def build_snapshot(args: argparse.Namespace) -> dict[str, Any]:
    raw = _read_input(args.input) if args.input else _fetch_json(args.url)
    if args.source == "spamhaus-asndrop":
        entries = normalize_spamhaus_asndrop(raw, source_url=args.url)
        return {
            "snapshot_name": "spamhaus-asndrop",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "source": args.source,
            "source_url": args.url,
            "entries": entries,
        }
    raise SnapshotError(f"Unsupported source {args.source!r}.")


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        snapshot = build_snapshot(args)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(snapshot, indent=2 if args.pretty else None, sort_keys=True)
            + "\n",
            encoding="utf-8",
        )
    except SnapshotError as exc:
        print(f"as_reputation_snapshot.py: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
