from __future__ import annotations

from ._shared import *
from .part_01 import *

SUMMARY_TABLE_CATALOG.update(
    table_family(
        "bi_summary",
        ("minute", "hour", "day", "month"),
        (
            "request_host",
            "client_asn",
            "user_agent_category",
            "is_bot_traffic",
            "ai_category",
            "ai_source",
            "traffic_cohort",
            "resource_category",
            "request_method",
            "cache_was_cached",
            "response_status_code",
            "request_path_pattern",
            "client_country_iso_code",
        ),
        parent="bot_detection",
    )
)

SUMMARY_TABLE_CATALOG.update(
    table_family(
        "bi_siem_policy_summary",
        ("minute", "hour", "day"),
        (
            "request_host",
            "client_asn",
            "user_agent_category",
            "is_bot_traffic",
            "ai_category",
            "ai_source",
            "resource_category",
            "request_method",
            "response_status_code",
            "client_country_iso_code",
            "policy_id",
            "action_class",
            "bot_type",
        ),
        parent="bot_detection_siem",
    )
)

SUMMARY_TABLE_CATALOG["bot_agg_hour"] = {
    "table": "bot_agg_hour",
    "granularity": "hour",
    "parent": "bot_detection",
    "retained_dimensions": ("request_host",),
}

SUMMARY_TABLE_CATALOG.update(
    table_family(
        "bot_agg_path",
        ("minute", "hour", "day"),
        ("request_host", "request_path_norm", "bot_class", "asn_type"),
        parent="bot_detection",
    )
)

SUMMARY_TABLE_CATALOG["bot_agg_asn_hour"] = {
    "table": "bot_agg_asn_hour",
    "granularity": "hour",
    "parent": "bot_detection",
    "retained_dimensions": ("request_host", "client_asn", "asn_type"),
}

SUMMARY_TABLE_CATALOG["bot_agg_traffic_hour"] = {
    "table": "bot_agg_traffic_hour",
    "granularity": "hour",
    "parent": "bot_detection",
    "retained_dimensions": ("request_host", "is_bot_traffic", "ai_category"),
}

SUMMARY_TABLE_CATALOG["bot_agg_ua_hour"] = {
    "table": "bot_agg_ua_hour",
    "granularity": "hour",
    "parent": "bot_detection",
    "retained_dimensions": ("request_host", "bot_class"),
}

SUMMARY_TABLE_CATALOG.update(
    table_family(
        "bot_agg_resource",
        ("minute", "hour", "day"),
        ("request_host", "resource_category"),
        parent="bot_detection",
    )
)

SUMMARY_FILTER_ALWAYS_RETAINED = {"timestamp"}

FIELD_NAME_ALIASES = {
    "timestamp": ("timestamp", "reqTimeSec"),
    "request_host": ("request_host", "reqHost", "host"),
    "client_asn": ("client_asn", "asn"),
    "client_country_iso_code": ("client_country_iso_code", "country"),
    "client_city": ("client_city", "city"),
    "response_status_code": ("response_status_code", "statusCode", "status"),
    "response_total_bytes": ("response_total_bytes", "totalBytes"),
    "cache_was_cached": ("cache_was_cached", "cacheStatus"),
    "is_bot_traffic": ("is_bot_traffic", "isBotTraffic"),
    "ai_category": ("ai_category", "aiCategory"),
    "ai_source": ("ai_source", "aiSource"),
    "traffic_cohort": ("traffic_cohort", "trafficCohort"),
    "resource_category": ("resource_category", "resourceCategory"),
    "request_method": ("request_method", "reqMethod", "method"),
    "user_agent_category": ("user_agent_category", "userAgentCategory"),
    "request_path_pattern": ("request_path_pattern", "requestPathPattern"),
    "policy_id": ("policy_id", "policyId"),
    "action_class": ("action_class", "actionClass"),
    "bot_type": ("bot_type", "botType"),
}

CONTRIBUTION_REQUIRED_METADATA = [
    "trusted evidence for rowset_complete: true and contribution_basis: complete_rowset",
    "or contribution_basis: complete_scope_pre_limit with trusted complete-scope evidence and an identical denominator",
    "or contribution_basis: provided_complete_scope with trusted evidence that matches metric, dimensions, scope, and windows",
]

ZERO_FILL_REQUIRED_METADATA = [
    "trusted zero_fill_evidence.period_value_trust.<side>: complete_grouped_scope",
    "or trusted zero_fill_evidence.period_value_trust.<side>: trusted_full_scope_join",
]

METRIC_ALIAS_TO_CANONICAL: dict[str, str] = {}

for canonical_metric, metric_info in METRIC_ALLOWLIST.items():
    METRIC_ALIAS_TO_CANONICAL[canonical_metric] = canonical_metric
    for alias in metric_info["aliases"]:
        METRIC_ALIAS_TO_CANONICAL[alias] = canonical_metric

class InvalidInputError(Exception):
    """Typed invalid-input error for CLI and library callers."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        path: str = "$",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.document = invalid_input_doc(code, message, path=path, details=details)

def invalid_input_doc(
    code: str,
    message: str,
    *,
    path: str = "$",
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    error = {
        "code": code,
        "message": message,
        "path": path,
    }
    if details:
        error["details"] = details
    return {
        "schema_version": ERROR_SCHEMA,
        "error_type": "invalid_input",
        "fatal": True,
        "errors": [error],
        "limitations": [],
    }

def raise_invalid(
    code: str,
    message: str,
    *,
    path: str = "$",
    details: dict[str, Any] | None = None,
) -> None:
    raise InvalidInputError(code, message, path=path, details=details)

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

def to_number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None

def to_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        text = value.strip().lower()
        if text == "true":
            return True
        if text == "false":
            return False
    return None

def clean_number(value: float | int | None) -> float | int | None:
    if value is None:
        return None
    rounded = round(float(value), 6)
    if rounded.is_integer():
        return int(rounded)
    return rounded

def direction(delta: float) -> str:
    if delta > 0:
        return "increase"
    if delta < 0:
        return "decrease"
    return "no_change"

def pct_change(current: float, baseline: float) -> float:
    return (current - baseline) / max(baseline, 1.0) * 100.0

def normalize_options(options: Any) -> dict[str, Any]:
    if options is None:
        return {}
    if isinstance(options, argparse.Namespace):
        return vars(options).copy()
    if isinstance(options, dict):
        return dict(options)
    raise TypeError("options must be a dict, argparse.Namespace, or None")

def normalize_analysis_type(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if text not in ANALYSIS_TYPES:
        raise_invalid(
            "analysis_type_invalid",
            f"Unsupported analysis_type '{value}'.",
            details={"analysis_type": value, "supported_analysis_types": sorted(ANALYSIS_TYPES)},
        )
    return text

def resolve_analysis_type(payload: Any, metadata: dict[str, Any], options: dict[str, Any]) -> str:
    cli_analysis = normalize_analysis_type(options.get("analysis"))
    input_analysis = normalize_analysis_type(resolve_value(payload, metadata, "analysis_type"))
    if cli_analysis and input_analysis and cli_analysis != input_analysis:
        raise_invalid(
            "analysis_type_conflict",
            "CLI analysis conflicts with input analysis_type.",
            details={"cli_analysis": cli_analysis, "input_analysis": input_analysis},
        )
    return cli_analysis or input_analysis or "aggregate_delta_attribution"

def unique_strings(values: Iterable[Any]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        text = str(value).strip()
        if not text or text in seen:
            continue
        seen.add(text)
        ordered.append(text)
    return ordered

def parse_dimensions(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return unique_strings(value.split(","))
    if isinstance(value, (list, tuple)):
        return unique_strings(value)
    return unique_strings([value])

def filter_columns(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, dict):
        return unique_strings(value.keys())
    return parse_dimensions(value)

def selected_filter_columns(*values: Any) -> list[str]:
    columns: list[str] = []
    for value in values:
        columns.extend(filter_columns(value))
    return unique_strings(columns)

def summary_table_metadata(table_name: str) -> dict[str, Any] | None:
    table = SUMMARY_TABLE_CATALOG.get(str(table_name).strip())
    if table is None:
        return None
    return {
        "table": table["table"],
        "granularity": table["granularity"],
        "parent": table["parent"],
        "retained_dimensions": list(table["retained_dimensions"]),
    }

def validate_summary_table_support(
    table_name: str,
    grouped_dimensions: Any,
    *,
    scope: Any = None,
    filters: Any = None,
    applied_scope_filters: Any = None,
) -> dict[str, Any]:
    table_text = str(table_name).strip()
    requested_dimensions = parse_dimensions(grouped_dimensions)
    requested_filter_columns = selected_filter_columns(scope, filters, applied_scope_filters)
    table = SUMMARY_TABLE_CATALOG.get(table_text)
    retained_dimensions = set(table["retained_dimensions"]) if table else set()
    retained_filter_columns = retained_dimensions | SUMMARY_FILTER_ALWAYS_RETAINED

    unsupported_dimensions = [
        dimension for dimension in requested_dimensions if dimension not in retained_dimensions
    ]
    unsupported_filters = [
        column for column in requested_filter_columns if column not in retained_filter_columns
    ]
    limitations: list[str] = []
    if unsupported_dimensions:
        limitations.append("unsupported_summary_dimension_set")
    if unsupported_filters:
        limitations.append("unsupported_summary_filter")

    result = {
        "generator_name": SQL_GENERATOR_NAME,
        "generator_version": SQL_GENERATOR_VERSION,
        "selected_table": table_text,
        "summary_table_known": table is not None,
        "retained_dimensions": sorted(retained_dimensions),
        "grouped_dimensions": requested_dimensions,
        "scope_filter_columns": requested_filter_columns,
        "unsupported_grouped_dimensions": unsupported_dimensions,
        "unsupported_filter_columns": unsupported_filters,
        "limitations": limitations,
        "supported": table is not None and not limitations,
    }
    if table:
        result["granularity"] = table["granularity"]
        result["parent"] = table["parent"]
    elif requested_dimensions:
        result["unsupported_grouped_dimensions"] = requested_dimensions
    return result

def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

__all__ = [name for name in globals() if not name.startswith("__")]
