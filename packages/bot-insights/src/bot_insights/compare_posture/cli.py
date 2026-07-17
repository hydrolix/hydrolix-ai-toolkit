from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .control import compare_control
from .posture import compare_movers, compare_posture


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compute structured Bot Insights posture analytics from aggregate JSON."
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
        "--schema",
        choices=("auto", "posture", "movers", "control"),
        default="auto",
        help="Output schema to emit.",
    )
    parser.add_argument(
        "--min-count",
        type=float,
        default=100.0,
        help="Minimum current and baseline support count for high confidence.",
    )
    return parser.parse_args()


def read_input(args: argparse.Namespace) -> str:
    if args.file:
        return args.file.read_text(encoding="utf-8")
    if args.text:
        return " ".join(args.text)
    return sys.stdin.read()


def compare(value: Any, schema: str = "auto", min_count: float = 100.0) -> dict[str, Any]:
    selected = schema
    if selected == "auto":
        if isinstance(value, dict) and (
            value.get("comparison_type") == "post_change_vs_expected"
            or "expected" in value
            or "change_time" in value
        ):
            selected = "control"
        elif isinstance(value, dict) and "movers" in value and "current" not in value:
            selected = "movers"
        else:
            selected = "posture"

    if selected == "control":
        return compare_control(value, min_count)
    if selected == "movers":
        return compare_movers(value, min_count)
    return compare_posture(value, min_count)


def main() -> int:
    args = parse_args()
    try:
        value = json.loads(read_input(args))
        result = compare(value, schema=args.schema, min_count=args.min_count)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(result, indent=2, sort_keys=True, allow_nan=False))
    return 0
