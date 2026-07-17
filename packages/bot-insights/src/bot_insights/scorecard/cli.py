from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .assembly import build_artifacts
from .constants import SUPPORTED_ENTITY_TYPES
from .errors import InvalidScorecardInputError


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compute Bot Insights scorecard artifacts from aggregate JSON."
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
        "--entity-type",
        choices=SUPPORTED_ENTITY_TYPES,
        help="Entity type to score. Defaults to metadata or inferred row columns.",
    )
    parser.add_argument(
        "--min-count",
        type=float,
        default=100.0,
        help="Minimum current and baseline support count for high confidence.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Optional maximum number of scorecards and ranked index entries.",
    )
    parser.add_argument(
        "--domains",
        help=(
            "Optional comma-separated scorecard domains to evaluate, such as "
            "security_evidence for SOC or crawler_governance for crawler reports. "
            "Defaults to all domains."
        ),
    )
    parser.add_argument(
        "--output",
        choices=("all", "scorecards", "index"),
        default="all",
        help="Artifact type to emit.",
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
        value = json.loads(read_input(args))
        artifacts = build_artifacts(
            value,
            entity_type=args.entity_type,
            min_count=args.min_count,
            limit=args.limit,
            analysis_domains=args.domains,
        )
    except InvalidScorecardInputError as exc:
        print(json.dumps(exc.document, indent=2, sort_keys=True, allow_nan=False))
        return 2
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    if args.output == "scorecards":
        result: Any = artifacts["scorecards"]
    elif args.output == "index":
        result = artifacts["index"]
    else:
        result = artifacts
    print(json.dumps(result, indent=2, sort_keys=True, allow_nan=False))
    return 0
