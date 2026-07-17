from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .report import build_report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compute cache-busting origin-impact reports from aggregate JSON."
    )
    parser.add_argument(
        "text",
        nargs="*",
        help="Aggregate JSON. If omitted, stdin is read.",
    )
    parser.add_argument(
        "-f",
        "--file",
        type=Path,
        help="Read aggregate JSON from a file instead of positional arguments/stdin.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        help="Optional maximum number of ranked candidates to emit.",
    )
    return parser.parse_args()


def read_input(args: argparse.Namespace) -> str:
    if args.file:
        return args.file.read_text(encoding="utf-8")
    if args.text:
        return " ".join(args.text)
    return sys.stdin.read()


def main() -> int:
    args = parse_args()
    try:
        report = build_report(json.loads(read_input(args)), limit=args.limit)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(report, indent=2, sort_keys=True, allow_nan=False))
    return 0
