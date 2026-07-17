from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from .constants import ANALYSIS_TYPES
from .errors import InvalidInputError, invalid_input_doc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Compute a conservative Bot Insights attribution report from aggregate JSON."
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
        "--metric",
        help="Metric to normalize, such as requests or cnt_all.",
    )
    parser.add_argument(
        "--dimensions",
        help="Comma-separated dimensions to echo in the report and row keys.",
    )
    parser.add_argument(
        "--analysis",
        choices=tuple(sorted(ANALYSIS_TYPES)),
        help="Analysis mode. Use policy_displacement for policy-change displacement review.",
    )
    parser.add_argument(
        "--min-count",
        type=float,
        default=100.0,
        help="Minimum current and baseline support count for medium confidence.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Optional maximum number of ranked movers to return.",
    )
    parser.add_argument(
        "--output",
        choices=("report",),
        default="report",
        help="Output mode. The standalone CLI exposes only the report artifact.",
    )
    return parser


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    return build_parser().parse_args(argv)


def read_input(args: argparse.Namespace) -> str:
    if args.file:
        return args.file.read_text(encoding="utf-8")
    if args.text:
        return " ".join(args.text)
    return sys.stdin.read()


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        input_doc = json.loads(read_input(args))
    except json.JSONDecodeError as exc:
        print(
            json.dumps(
                invalid_input_doc("malformed_json", f"Input is not valid JSON: {exc.msg}.")
            ),
            indent=2,
            sort_keys=True,
        )
        return 2
    except OSError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    # Resolve normalize_attribution from the package namespace at call time so
    # the shim patch point (_package_bootstrap.main_proxy, used by tests and the
    # report wrapper) is honored.
    from bot_insights import attribution as _package

    try:
        result = _package.normalize_attribution(
            input_doc,
            trusted_context=None,
            options={
                "metric": args.metric,
                "dimensions": args.dimensions,
                "analysis": args.analysis,
                "min_count": args.min_count,
                "limit": args.limit,
                "output": args.output,
            },
        )
    except InvalidInputError as exc:
        print(json.dumps(exc.document, indent=2, sort_keys=True))
        return 2

    print(json.dumps(result, indent=2, sort_keys=True))
    return 0
