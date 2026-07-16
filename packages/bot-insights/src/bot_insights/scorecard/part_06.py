from __future__ import annotations

from ._shared import *
from .part_01 import *
from .part_02 import *
from .part_03 import *
from .part_04 import *
from .part_05 import *

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

if __name__ == "__main__":
    raise SystemExit(main())

__all__ = [name for name in globals() if not name.startswith("__")]
