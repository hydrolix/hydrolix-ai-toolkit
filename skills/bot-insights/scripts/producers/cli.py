"""argparse setup + main() dispatch for ``bot_insights_report``.

This module is the script's CLI surface. The original
``bot_insights_report.py`` is now a 60-line shim that re-exports
everything here under its historical name.

Layout:
  - ``parse_args``: argparse setup, ~175 lines. Every report-type-
    specific flag (``--policy-id`` for control_review,
    ``--entity-type`` for the scorecard family, ``--top-n`` /
    ``--fields`` / ``--host`` / ``--asn`` / ``--path-pattern`` /
    ``--grafana-hostname`` / ``--grafana-dashboard-path`` for
    incident_report, etc.) lives here.
  - ``main``: validates the parsed args, picks the right SQL +
    table + evidence builder per ``--report``, runs capture, and
    branches to either evidence-packet emission (``--mode evidence``)
    or the renderer (``--mode html`` / ``--mode markdown``). The
    incident_report flow is dispatched whole to
    ``producers.orchestrators.incident_report._run_incident_report``;
    the other report types stay inline (Phase 2.6 deferred per-
    report orchestrator extraction to a follow-up so the dispatch
    rewiring doesn't entangle with the rest of Phase 2).

Document the full CC + ≤500-line guideline deviations for this
module in the verification commit; both apply because ``main`` is
~700 lines and CC-monster until per-report orchestrator extraction
lands.
"""

from __future__ import annotations

import argparse
import csv
import glob
import gzip
import hashlib
import json
import sys
import tempfile
import time
from pathlib import Path

from producers.evidence.control import build_control_evidence_packet
from producers.evidence.incident import _INCIDENT_DEFAULT_FIELDS
from producers.evidence.labeling import humanize_evidence_packet
from producers.evidence.posture import build_evidence_packet
from producers.evidence.scorecard import (
    build_scorecard_evidence_packet,
    build_scorecard_fleet_evidence_packet,
    select_scorecard,
)
from producers.formatting import choose_granularity, parse_time, sql_literal
from producers.orchestrators.incident_report import _run_incident_report
from producers.runtime import (
    CAPTURE,
    DEFAULT_SAMPLE_ROOT,
    HANDOFF_SCHEMA,
    NEEDS_MCP_EXIT,
    PUBLIC_SKILLS,
    load_raw_query_result,
    run,
)
from producers.rendering import render_report_command
from producers.threat_hunt import (
    build_threat_hunt_artifact,
    export_background_ua_sample,
    export_baseline_ua_timeseries,
    export_fanout_enrichment,
    export_hydrolix_usagemeter_ingest_estimate,
    export_impact_lane_scoped_hunt,
    export_impact_lane_totals,
    export_raw_ua_cooccurrence,
    export_raw_actor_fixtures,
    export_scraper_drilldowns,
    export_scraper_hourly_profiles,
    export_threat_hunt_summary,
    merge_impact_lanes_into_artifact,
    provenance_stage,
    read_impact_lane_rows,
    scraper_drilldown_scope,
    set_provenance_recorder,
    _read_dataset_manifest,
    _run_mux_export,
    validate_replay_grade_dataset,
)
from producers.sql.control_review import (
    control_review_sql,
    control_review_timeseries_sql,
)
from producers.sql.executive_posture import executive_posture_sql
from producers.sql.scorecard import (
    CRAWLER_ENTITY_SQL,
    EDGE_OPS_ENTITY_SQL,
    SCORECARD_ENTITY_SQL,
    SOC_ENTITY_SQL,
    cache_origin_path_sql,
    scorecard_crawler_sql,
    scorecard_edge_ops_sql,
    scorecard_soc_sql,
    scorecard_sql,
)
from producers.wrapper import (
    add_control_metadata,
    add_report_metadata,
    add_scorecard_metadata,
    analyst_note_from_args,
    build_report_wrapper,
    build_timeseries_artifact,
    render_template_packet,
)


THREAT_HUNT_FULL_WORKFLOW_VERSION = "threat_hunt_full_required.v1"
THREAT_HUNT_INPUT_MANIFEST_VERSION = "threat_hunt_input_manifest.v1"
THREAT_HUNT_HARVEST_PLAN_VERSION = "threat_hunt_harvest_plan.v1"
THREAT_HUNT_REPLAY_POLICY_VERSION = "threat_hunt_replay_policy.v1"
_SECRET_ARG_MARKERS = ("password", "token", "secret", "key", "credential")
THREAT_HUNT_FULL_REQUIRED_REPLAY_ROLES = {
    "summary",
    "raw_actor",
    "hydrolix_usagemeter",
    "cooccurrence",
    "scraper_drilldown",
    "scraper_hourly",
    "fanout",
    "background_ua_sample",
    "baseline_ua_timeseries",
    "impact_lane_totals",
    "impact_lane_scoped_hunt",
}
THREAT_HUNT_REPLAY_LOCAL_REQUIRED_ARGS = {
    "summary": "--summary-parquet-glob",
    "raw_actor": "--raw-actor-dir",
    "hydrolix_usagemeter": "--hydrolix-log-ingest-usagemeter-in",
    "cooccurrence": "--cooccurrence-in",
    "scraper_drilldown": "--scraper-drilldown-in",
    "scraper_hourly": "--scraper-hourly-in",
    "fanout": "--fanout-in",
    "background_ua_sample": "--background-ua-sample-in",
    "baseline_ua_timeseries": "--baseline-ua-timeseries-in",
    "impact_lane_totals": "--impact-lane-totals-in",
    "impact_lane_scoped_hunt": "--impact-lane-scoped-hunt-in",
}
THREAT_HUNT_HARVEST_PLAN_REQUIRED_STAGE_IDS = {
    "summary_export",
    "raw_actor_fixtures",
    "hydrolix_usagemeter",
    "cooccurrence",
    "scraper_drilldown",
    "scraper_hourly",
    "fanout",
    "background_ua_sample",
    "baseline_ua_timeseries",
    "impact_lane_totals",
    "impact_lane_scoped_hunt",
}
THREAT_HUNT_HARVEST_PLAN_DYNAMIC_SELECTOR_FAMILIES = {
    "lead_user_agents",
    "public_client_ip_scope",
    "peak_hours_by_user_agent",
    "high_partial_confidence_user_agents",
    "background_excluded_user_agents",
}
THREAT_HUNT_HARVEST_STAGE_ROLES = {
    "summary_export": "summary",
    "raw_actor_fixtures": "raw_actor",
    "hydrolix_usagemeter": "hydrolix_usagemeter",
    "cooccurrence": "cooccurrence",
    "scraper_drilldown": "scraper_drilldown",
    "scraper_hourly": "scraper_hourly",
    "fanout": "fanout",
    "background_ua_sample": "background_ua_sample",
    "baseline_ua_timeseries": "baseline_ua_timeseries",
    "impact_lane_totals": "impact_lane_totals",
    "impact_lane_scoped_hunt": "impact_lane_scoped_hunt",
}
THREAT_HUNT_BI_SUMMARY_REQUIRED_COLUMNS = {
    "reqTimeSec",
    "requestPath",
    "country",
    "trafficCohort",
    "count()",
    "sum(bytes)",
    "sum(totalBytes)",
    "statusCode",
}
THREAT_HUNT_LEGACY_SUMMARY_REQUIRED_COLUMNS = {
    "reqTimeSec",
    "reqPath",
    "country",
    "count()",
    "sum(totalBytes)",
    "statusCode",
}
THREAT_HUNT_RAW_LOG_REQUIRED_COLUMNS = {
    "reqTimeSec",
    "cliIP",
    "UA",
    "statusCode",
    "reqPath",
    "country",
    "bytes",
    "totalBytes",
}
THREAT_HUNT_SUMMARY_HOUR_FANOUT_REQUIRED_COLUMNS = {
    "reqTimeSec",
    "UA",
    "uniq(cliIP)",
    "count()",
    "sum(totalBytes)",
}
THREAT_HUNT_HYDRO_LOGS_REQUIRED_COLUMNS = {
    "timestamp",
    "message",
    "table_name",
    "rows",
    "bytes",
    "catchall",
}



def _redact_argv(argv: list[str]) -> list[str]:
    redacted: list[str] = []
    redact_next = False
    for item in argv:
        lowered = item.lower()
        if redact_next:
            redacted.append("<redacted>")
            redact_next = False
            continue
        if item.startswith("--") and any(marker in lowered for marker in _SECRET_ARG_MARKERS):
            if "=" in item:
                redacted.append(item.split("=", 1)[0] + "=<redacted>")
            else:
                redacted.append(item)
                redact_next = True
            continue
        redacted.append(item)
    return redacted


def _maybe_mocked_legacy_symbol(module, name: str, default):
    value = getattr(module, name, default) if module is not None else default
    if value is not default and value.__class__.__module__.startswith("unittest.mock"):
        return value
    for module_name, candidate_module in list(sys.modules.items()):
        if not module_name.endswith("producers.cli"):
            continue
        candidate = getattr(candidate_module, name, default)
        if candidate is not default and candidate.__class__.__module__.startswith("unittest.mock"):
            return candidate
    return default


def _sha256_file(path: Path) -> str | None:
    if not path.exists() or not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _dataset_metadata_for_input_manifest(path: Path) -> dict[str, object] | None:
    manifest = _read_dataset_manifest(path)
    if not manifest:
        return None
    return {
        key: manifest.get(key)
        for key in (
            "schema_version",
            "stage_id",
            "cluster",
            "database",
            "source_table",
            "query_sha256",
            "columns",
            "row_count",
            "total_row_count",
            "truncated",
            "chunk_index",
            "chunk_count",
            "started_at",
            "finished_at",
            "output_sha256",
            "metadata",
            "field_provenance",
        )
        if key in manifest
    }


def _artifact_row_count(path: Path) -> int | None:
    if not path.exists() or not path.is_file():
        return None
    try:
        if path.suffix == ".jsonl":
            return sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line.strip())
        if path.suffix == ".json":
            value = json.loads(path.read_text(encoding="utf-8") or "null")
            if isinstance(value, list):
                return len(value)
            if isinstance(value, dict):
                rows = value.get("rows")
                if isinstance(rows, list):
                    return len(rows)
                cells = value.get("cells")
                if isinstance(cells, list):
                    return len(cells)
                return 1
        if path.suffix == ".csv":
            with path.open(newline="", encoding="utf-8") as handle:
                return sum(1 for _row in csv.DictReader(handle))
        if "".join(path.suffixes[-2:]) == ".csv.gz":
            with gzip.open(path, mode="rt", newline="", encoding="utf-8") as handle:
                return sum(1 for _row in csv.DictReader(handle))
        if path.suffix == ".parquet":
            try:
                import pyarrow.parquet as pq
            except ImportError:
                return None
            return int(pq.ParquetFile(path).metadata.num_rows)
    except Exception:
        return None
    return None


def _input_manifest_entry(*, role: str, path: Path, source: str) -> dict[str, object]:
    resolved = path.expanduser().resolve()
    record: dict[str, object] = {
        "role": role,
        "source": source,
        "path": str(resolved),
        "exists": resolved.exists(),
        "sha256": _sha256_file(resolved),
        "row_count": _artifact_row_count(resolved),
    }
    dataset_metadata = _dataset_metadata_for_input_manifest(resolved)
    if dataset_metadata:
        record["threat_hunt_dataset"] = dataset_metadata
    return record


def _input_manifest_path_entries(
    entries: list[dict[str, object]],
    *,
    role: str,
    path_value: str | Path | None,
    source: str = "local_input",
) -> None:
    if not path_value:
        return
    entries.append(_input_manifest_entry(role=role, path=Path(path_value), source=source))


def _input_manifest_glob_entries(
    entries: list[dict[str, object]],
    *,
    role: str,
    pattern: str | None,
    source: str = "local_input",
) -> None:
    if not pattern:
        return
    paths = [Path(item) for item in sorted(glob.glob(pattern))]
    if not paths:
        entries.append(
            {
                "role": role,
                "source": source,
                "path": str(Path(pattern).expanduser()),
                "exists": False,
                "sha256": None,
                "row_count": None,
                "glob": pattern,
            }
        )
        return
    for path in paths:
        entry = _input_manifest_entry(role=role, path=path, source=source)
        entry["glob"] = pattern
        entries.append(entry)


def _input_manifest_dir_entries(
    entries: list[dict[str, object]],
    *,
    role: str,
    dir_value: str | Path | None,
    source: str = "local_input",
) -> None:
    if not dir_value:
        return
    directory = Path(dir_value).expanduser().resolve()
    paths = sorted(path for path in directory.glob("*.json") if path.is_file())
    if not paths:
        entries.append(
            {
                "role": role,
                "source": source,
                "path": str(directory),
                "exists": directory.exists(),
                "sha256": None,
                "row_count": None,
                "directory_glob": "*.json",
            }
        )
        return
    for path in paths:
        entry = _input_manifest_entry(role=role, path=path, source=source)
        entry["directory"] = str(directory)
        entries.append(entry)


def build_threat_hunt_input_manifest(
    *,
    summary_parquet_glob: str | None,
    raw_actor_dir: str | None,
    hydrolix_log_ingest_usagemeter_in: str | None = None,
    cooccurrence_in: str | None = None,
    cooccurrence_path_in: str | None = None,
    scraper_drilldown_in: str | None = None,
    scraper_hourly_in: str | None = None,
    fanout_in: str | None = None,
    iat_sample_in: str | None = None,
    background_ua_sample_in: str | None = None,
    baseline_ua_timeseries_in: str | None = None,
    edge_response_in: str | None = None,
    bot_manager_context_in: str | None = None,
    bot_manager_exact_ua_in: str | None = None,
    cost_estimate_config: str | None = None,
    geoip_asn_v4: str | None = None,
    geoip_asn_v6: str | None = None,
    impact_lane_totals_in: str | None = None,
    impact_lane_scoped_hunt_in: str | None = None,
    threat_hunt_artifact: str | Path | None = None,
    wrapper_render_input: str | Path | None = None,
) -> dict[str, object]:
    entries: list[dict[str, object]] = []
    _input_manifest_glob_entries(entries, role="summary", pattern=summary_parquet_glob)
    _input_manifest_dir_entries(entries, role="raw_actor", dir_value=raw_actor_dir)
    for role, path_value in (
        ("hydrolix_usagemeter", hydrolix_log_ingest_usagemeter_in),
        ("cooccurrence", cooccurrence_in),
        ("cooccurrence_path", cooccurrence_path_in),
        ("scraper_drilldown", scraper_drilldown_in),
        ("scraper_hourly", scraper_hourly_in),
        ("fanout", fanout_in),
        ("iat_sample", iat_sample_in),
        ("background_ua_sample", background_ua_sample_in),
        ("baseline_ua_timeseries", baseline_ua_timeseries_in),
        ("edge_response", edge_response_in),
        ("bot_manager_context", bot_manager_context_in),
        ("bot_manager_exact_ua", bot_manager_exact_ua_in),
        ("cost_estimate_config", cost_estimate_config),
        ("geoip_asn_v4", geoip_asn_v4),
        ("geoip_asn_v6", geoip_asn_v6),
        ("impact_lane_totals", impact_lane_totals_in),
        ("impact_lane_scoped_hunt", impact_lane_scoped_hunt_in),
        ("threat_hunt_artifact", threat_hunt_artifact),
        ("wrapper_render_input", wrapper_render_input),
    ):
        _input_manifest_path_entries(entries, role=role, path_value=path_value)
    entries.sort(key=lambda item: (str(item.get("role") or ""), str(item.get("path") or "")))
    return {
        "schema_version": THREAT_HUNT_INPUT_MANIFEST_VERSION,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "input_count": len(entries),
        "inputs": entries,
    }


def _manifest_hash_basis(input_manifest: dict[str, object]) -> dict[str, object]:
    inputs = input_manifest.get("inputs")
    basis_inputs: list[dict[str, object]] = []
    if isinstance(inputs, list):
        for item in inputs:
            if not isinstance(item, dict):
                continue
            dataset = item.get("threat_hunt_dataset")
            dataset_hash = (
                dataset.get("output_sha256")
                if isinstance(dataset, dict)
                else None
            )
            basis_inputs.append(
                {
                    "role": item.get("role"),
                    "path": item.get("path"),
                    "sha256": item.get("sha256"),
                    "row_count": item.get("row_count"),
                    "dataset_output_sha256": dataset_hash,
                }
            )
    basis_inputs.sort(key=lambda item: (str(item.get("role") or ""), str(item.get("path") or "")))
    return {
        "schema_version": input_manifest.get("schema_version"),
        "hash_algorithm": "sha256",
        "fields": ["role", "path", "sha256", "row_count", "dataset_output_sha256"],
        "inputs": basis_inputs,
    }


def _json_hash(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    ).hexdigest()


def _stable_plan_hash_basis(plan: dict[str, object]) -> dict[str, object]:
    return {
        key: value
        for key, value in plan.items()
        if key not in {"hash", "hash_algorithm", "generated_at"}
    }


def _attach_harvest_plan_hash(plan: dict[str, object]) -> dict[str, object]:
    plan = json.loads(json.dumps(plan, sort_keys=True, default=str))
    plan["hash_algorithm"] = "sha256"
    plan["hash"] = _json_hash(_stable_plan_hash_basis(plan))
    return plan


def _catalog_tables_sql(*, database: str) -> str:
    table_names = [
        "logs",
        "summary_hour",
        "bi_summary_minute",
        "bi_summary_hour",
        "bi_summary_day",
    ]
    quoted = ", ".join(sql_literal(name) for name in table_names)
    return f"""
SELECT
  database,
  name
FROM system.tables
WHERE (database = {sql_literal(database)} AND name IN ({quoted}))
   OR (database = 'hydro' AND name = 'logs')
ORDER BY database, name
""".strip()


def _catalog_columns_sql(*, database: str) -> str:
    table_names = [
        "logs",
        "summary_hour",
        "bi_summary_minute",
        "bi_summary_hour",
        "bi_summary_day",
    ]
    quoted = ", ".join(sql_literal(name) for name in table_names)
    return f"""
SELECT
  database,
  table,
  name,
  type
FROM system.columns
WHERE (database = {sql_literal(database)} AND table IN ({quoted}))
   OR (database = 'hydro' AND table = 'logs')
ORDER BY database, table, name
""".strip()


def run_threat_hunt_catalog_query(*, cluster: str, sql: str) -> list[dict[str, object]]:
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json", delete=False) as handle:
        output = Path(handle.name)
    try:
        _run_mux_export(cluster, sql, output)
        value = json.loads(output.read_text(encoding="utf-8") or "[]")
    finally:
        output.unlink(missing_ok=True)
    if isinstance(value, dict):
        rows = value.get("rows") or value.get("cells") or []
    else:
        rows = value
    return [row for row in rows if isinstance(row, dict)]


def inspect_threat_hunt_catalog(*, cluster: str, database: str) -> dict[str, object]:
    tables_sql = _catalog_tables_sql(database=database)
    columns_sql = _catalog_columns_sql(database=database)
    table_rows = run_threat_hunt_catalog_query(cluster=cluster, sql=tables_sql)
    column_rows = run_threat_hunt_catalog_query(cluster=cluster, sql=columns_sql)
    tables = sorted(
        {
            f"{row.get('database')}.{row.get('name')}"
            for row in table_rows
            if row.get("database") and row.get("name")
        }
    )
    columns: dict[str, list[str]] = {}
    column_types: dict[str, dict[str, str]] = {}
    for row in column_rows:
        row_database = row.get("database")
        table = row.get("table")
        name = row.get("name")
        if not row_database or not table or not name:
            continue
        key = f"{row_database}.{table}"
        columns.setdefault(key, [])
        if str(name) not in columns[key]:
            columns[key].append(str(name))
        column_types.setdefault(key, {})[str(name)] = str(row.get("type") or "")
    for key in columns:
        columns[key].sort()
    return {
        "mode": "live_metadata",
        "catalog_queries": [
            {
                "purpose": "table_inventory",
                "sql_sha256": hashlib.sha256(tables_sql.encode("utf-8")).hexdigest(),
            },
            {
                "purpose": "column_inventory",
                "sql_sha256": hashlib.sha256(columns_sql.encode("utf-8")).hexdigest(),
            },
        ],
        "inspected_tables": tables,
        "columns": columns,
        "column_types": column_types,
    }


def _column_set(inspection: dict[str, object], table: str) -> set[str]:
    columns = inspection.get("columns")
    if not isinstance(columns, dict):
        return set()
    values = columns.get(table)
    if not isinstance(values, list):
        return set()
    return {str(value) for value in values}


def _table_observed(inspection: dict[str, object], table: str) -> bool:
    tables = inspection.get("inspected_tables")
    return isinstance(tables, list) and table in {str(value) for value in tables}


def _missing_columns(inspection: dict[str, object], table: str, required: set[str]) -> list[str]:
    return sorted(required - _column_set(inspection, table))


def _stage_plan_record(
    *,
    stage_id: str,
    source_table: str | None,
    required_columns: set[str],
    optional_columns: set[str] | None = None,
    observed_columns: set[str] | None = None,
    sql_template_id: str,
) -> dict[str, object]:
    observed = observed_columns or set()
    return {
        "stage_id": stage_id,
        "required": True,
        "output_role": THREAT_HUNT_HARVEST_STAGE_ROLES[stage_id],
        "source_table": source_table,
        "required_columns": sorted(required_columns),
        "optional_columns": sorted(optional_columns or set()),
        "observed_columns": sorted(observed),
        "missing_columns": sorted(required_columns - observed) if source_table else [],
        "sql_template_id": sql_template_id,
        "sql_hash_policy": "required_recorded",
        "output_hash_policy": "required_recorded",
    }


def _offline_threat_hunt_inspection(*, database: str) -> dict[str, object]:
    return {
        "mode": "offline_heuristic",
        "catalog_queries": [],
        "inspected_tables": [
            f"{database}.bi_summary_minute",
            f"{database}.bi_summary_hour",
            f"{database}.bi_summary_day",
            f"{database}.logs",
            f"{database}.summary_hour",
            "hydro.logs",
        ],
        "columns": {},
        "column_types": {},
    }


def build_offline_threat_hunt_harvest_plan(
    *,
    args: argparse.Namespace,
    start,
    end,
    baseline_start,
    baseline_end,
) -> dict[str, object]:
    """Resolve the legacy no-query full-required harvest contract."""
    summary_granularity = choose_granularity(start, end)
    fanout_strategy = args.fanout_strategy
    if args.ua_fanout_query in {"summary_hour", "logs_probe", "skip"}:
        fanout_strategy = args.ua_fanout_query
    elif args.ua_fanout_query == "off":
        fanout_strategy = "skip"
    if fanout_strategy == "auto":
        fanout_strategy = "summary_hour"
    baseline_granularity = "hour" if (end - baseline_start).total_seconds() <= 172800 else "day"
    raw_table = f"{args.database}.logs"
    summary_table = f"{args.database}.bi_summary_{summary_granularity}"
    summary_hour_table = f"{args.database}.summary_hour"
    raw_required = set(THREAT_HUNT_RAW_LOG_REQUIRED_COLUMNS)
    summary_required = set(THREAT_HUNT_BI_SUMMARY_REQUIRED_COLUMNS)
    hydro_required = set(THREAT_HUNT_HYDRO_LOGS_REQUIRED_COLUMNS)
    fanout_table = summary_hour_table if fanout_strategy == "summary_hour" else raw_table
    fanout_required = (
        set(THREAT_HUNT_SUMMARY_HOUR_FANOUT_REQUIRED_COLUMNS)
        if fanout_strategy == "summary_hour"
        else {"reqTimeSec", "UA", "cliIP", "totalBytes"}
    )
    stages = [
        _stage_plan_record(
            stage_id="summary_export",
            source_table=summary_table,
            required_columns=summary_required,
            observed_columns=summary_required,
            sql_template_id="threat_hunt_summary.bot_insights.v1",
        ),
        _stage_plan_record(
            stage_id="raw_actor_fixtures",
            source_table=raw_table,
            required_columns=raw_required,
            optional_columns={"hydrolix_log_ingest_bytes"},
            observed_columns=raw_required,
            sql_template_id=f"raw_actor.logs.{args.raw_actor_extraction_mode}.v1",
        ),
        _stage_plan_record(
            stage_id="hydrolix_usagemeter",
            source_table="hydro.logs",
            required_columns=hydro_required,
            observed_columns=hydro_required,
            sql_template_id="hydrolix_usagemeter.offline_heuristic.v1",
        ),
        _stage_plan_record(
            stage_id="cooccurrence",
            source_table=raw_table,
            required_columns={"reqTimeSec", "cliIP", "UA", "country"},
            observed_columns={"reqTimeSec", "cliIP", "UA", "country"},
            sql_template_id="raw_ua_cooccurrence.logs.v1",
        ),
        _stage_plan_record(
            stage_id="scraper_drilldown",
            source_table=raw_table,
            required_columns={"reqTimeSec", "cliIP", "UA", "reqPath", "country", "statusCode"},
            observed_columns={"reqTimeSec", "cliIP", "UA", "reqPath", "country", "statusCode"},
            sql_template_id="raw_scraper_drilldown.logs.v1",
        ),
        _stage_plan_record(
            stage_id="scraper_hourly",
            source_table=raw_table,
            required_columns={"reqTimeSec", "UA"},
            observed_columns={"reqTimeSec", "UA"},
            sql_template_id="raw_scraper_hourly.logs.v1",
        ),
        _stage_plan_record(
            stage_id="fanout",
            source_table=fanout_table,
            required_columns=fanout_required,
            observed_columns=fanout_required,
            sql_template_id=f"fanout.{fanout_strategy}.v1",
        ),
        _stage_plan_record(
            stage_id="background_ua_sample",
            source_table=raw_table,
            required_columns={"reqTimeSec", "cliIP", "UA", "reqPath", "statusCode"},
            observed_columns={"reqTimeSec", "cliIP", "UA", "reqPath", "statusCode"},
            sql_template_id="background_ua_sample.logs.v1",
        ),
        _stage_plan_record(
            stage_id="baseline_ua_timeseries",
            source_table=raw_table,
            required_columns={"reqTimeSec", "UA"},
            observed_columns={"reqTimeSec", "UA"},
            sql_template_id="baseline_ua_timeseries.logs.v1",
        ),
        _stage_plan_record(
            stage_id="impact_lane_totals",
            source_table=raw_table,
            required_columns={"reqTimeSec", "bytes", "totalBytes"},
            observed_columns={"reqTimeSec", "bytes", "totalBytes"},
            sql_template_id="impact_lane_totals.logs.v1",
        ),
        _stage_plan_record(
            stage_id="impact_lane_scoped_hunt",
            source_table=raw_table,
            required_columns={"reqTimeSec", "UA", "bytes", "totalBytes"},
            observed_columns={"reqTimeSec", "UA", "bytes", "totalBytes"},
            sql_template_id="impact_lane_scoped_hunt.logs.v1",
        ),
    ]
    plan: dict[str, object] = {
        "schema_version": THREAT_HUNT_HARVEST_PLAN_VERSION,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "cluster": args.cluster,
        "database": args.database,
        "current_window": {
            "start": args.start,
            "end": args.end,
        },
        "baseline_window": {
            "start": baseline_start.isoformat().replace("+00:00", "Z"),
            "end": baseline_end.isoformat().replace("+00:00", "Z"),
        },
        "top_n": int(args.top_n),
        "inspection": _offline_threat_hunt_inspection(database=args.database),
        "planner_decisions": {
            "selected_summary_table": summary_table,
            "selected_fanout_strategy": fanout_strategy,
            "usagemeter_policy": "exact_export"
            if args.hydrolix_log_ingest_usagemeter_project_deployment_id
            else "discovery_then_export",
            "field_provenance_overrides": {},
        },
        "summary": {
            "granularity": summary_granularity,
            "table": summary_table,
            "selection_mode": "top_n_by_period",
            "limit_per_period": 2000,
            "allow_legacy_fallback": False,
        },
        "raw_actor": {
            "table": raw_table,
            "extraction_mode": args.raw_actor_extraction_mode,
            "chunk_seconds": int(args.raw_actor_chunk_seconds),
            "hash_buckets": int(args.raw_actor_hash_buckets),
            "topk_candidate_multiplier": int(args.raw_actor_topk_candidate_multiplier),
        },
        "fanout": {
            "strategy": fanout_strategy,
            "fallback_allowed": False,
        },
        "hydrolix_usagemeter": {
            "table": "hydro.logs",
            "project_deployment_id": args.hydrolix_log_ingest_usagemeter_project_deployment_id,
            "table_name": args.hydrolix_log_ingest_usagemeter_table_name,
            "discovery_allowed": args.hydrolix_log_ingest_usagemeter_project_deployment_id is None,
            "ambiguity_policy": "fail_closed",
        },
        "enrichment_lanes": {
            "background_ua_sample": {"policy": "required", "fallback_allowed": False},
            "baseline_ua_timeseries": {
                "policy": "required",
                "granularity": baseline_granularity,
                "fallback_allowed": False,
            },
            "impact_lanes": {"policy": "required", "fallback_allowed": False},
        },
        "dynamic_selectors": [
            {
                "family": "lead_user_agents",
                "stages": ["cooccurrence", "scraper_drilldown", "scraper_hourly", "fanout"],
                "source": "raw_actor_fixtures",
            },
            {
                "family": "public_client_ip_scope",
                "stages": ["scraper_drilldown"],
                "source": "cooccurrence",
            },
            {
                "family": "peak_hours_by_user_agent",
                "stages": ["fanout"],
                "source": "scraper_hourly",
            },
            {
                "family": "background_excluded_user_agents",
                "stages": ["background_ua_sample"],
                "source": "raw_actor_fixtures",
            },
            {
                "family": "high_partial_confidence_user_agents",
                "stages": ["impact_lane_scoped_hunt"],
                "source": "threat_hunt_artifact",
            },
        ],
        "fallback_policy": {
            "mode": "fail_closed",
            "silent_fanout_fallback": False,
            "auto_usagemeter_ambiguity": False,
            "optional_enrichment_downgrade": False,
        },
        "required_stages": sorted(THREAT_HUNT_HARVEST_PLAN_REQUIRED_STAGE_IDS),
        "stages": stages,
    }
    return _attach_harvest_plan_hash(plan)


def build_threat_hunt_harvest_plan(
    *,
    args: argparse.Namespace,
    start,
    end,
    baseline_start,
    baseline_end,
) -> dict[str, object]:
    """Resolve the full-required harvest contract from metadata only."""
    inspection = inspect_threat_hunt_catalog(cluster=args.cluster, database=args.database)
    summary_granularity = choose_granularity(start, end)
    summary_table_name = f"bi_summary_{summary_granularity}"
    summary_table = f"{args.database}.{summary_table_name}"
    legacy_summary_table = f"{args.database}.summary_hour"
    raw_table = f"{args.database}.logs"
    hydro_table = "hydro.logs"

    raw_required = set(THREAT_HUNT_RAW_LOG_REQUIRED_COLUMNS)
    if args.hydrolix_log_ingest_bytes_column:
        raw_required.add(args.hydrolix_log_ingest_bytes_column)
    raw_missing = _missing_columns(inspection, raw_table, raw_required)
    if raw_missing:
        raise SystemExit(
            f"Cannot build threat-hunt harvest plan: {raw_table} is missing required column(s): "
            + ", ".join(raw_missing)
        )

    if _table_observed(inspection, summary_table):
        summary_required = set(THREAT_HUNT_BI_SUMMARY_REQUIRED_COLUMNS)
        summary_missing = _missing_columns(inspection, summary_table, summary_required)
        if summary_missing:
            raise SystemExit(
                f"Cannot build threat-hunt harvest plan: {summary_table} is missing required column(s): "
                + ", ".join(summary_missing)
            )
        selected_summary_table = summary_table
        selected_summary_source = "bot_insights_summary"
        summary_sql_template = "threat_hunt_summary.bot_insights.v1"
        field_overrides: dict[str, str] = {}
    elif summary_granularity in {"minute", "hour"} and _table_observed(inspection, legacy_summary_table):
        summary_required = set(THREAT_HUNT_LEGACY_SUMMARY_REQUIRED_COLUMNS)
        legacy_missing = _missing_columns(inspection, legacy_summary_table, summary_required)
        if legacy_missing:
            raise SystemExit(
                f"Cannot build threat-hunt harvest plan: {legacy_summary_table} is missing required column(s): "
                + ", ".join(legacy_missing)
            )
        selected_summary_table = legacy_summary_table
        selected_summary_source = "legacy_akamai_summary"
        summary_sql_template = "threat_hunt_summary.legacy_akamai.v1"
        field_overrides = {
            "traffic_cohort": "synthetic_unavailable",
            "bot_requests": "synthetic_unavailable",
            "human_requests": "synthetic_unavailable",
            "response_body_bytes": "synthetic_unavailable",
            "status_429": "synthetic_unavailable",
        }
    else:
        raise SystemExit(
            f"Cannot build threat-hunt harvest plan: no supported summary table for {summary_granularity} granularity."
        )

    requested_fanout = args.fanout_strategy
    if args.ua_fanout_query in {"summary_hour", "logs_probe", "skip"}:
        requested_fanout = args.ua_fanout_query
    elif args.ua_fanout_query == "off":
        requested_fanout = "skip"
    summary_hour_missing = _missing_columns(
        inspection,
        legacy_summary_table,
        THREAT_HUNT_SUMMARY_HOUR_FANOUT_REQUIRED_COLUMNS,
    )
    summary_hour_supported = _table_observed(inspection, legacy_summary_table) and not summary_hour_missing
    if requested_fanout == "skip":
        raise SystemExit("full-required threat-hunt harvest plans cannot skip fanout.")
    if requested_fanout == "summary_hour" and not summary_hour_supported:
        raise SystemExit(
            f"Cannot build threat-hunt harvest plan: {legacy_summary_table} does not support summary_hour fanout."
        )
    if requested_fanout == "logs_probe":
        selected_fanout_strategy = "logs_probe"
    elif summary_hour_supported:
        selected_fanout_strategy = "summary_hour"
    else:
        selected_fanout_strategy = "logs_probe"

    hydro_missing = _missing_columns(inspection, hydro_table, THREAT_HUNT_HYDRO_LOGS_REQUIRED_COLUMNS)
    if hydro_missing:
        raise SystemExit(
            f"Cannot build threat-hunt harvest plan: {hydro_table} is missing required column(s): "
            + ", ".join(hydro_missing)
        )
    usagemeter_policy = (
        "exact_export"
        if args.hydrolix_log_ingest_usagemeter_project_deployment_id
        else "discovery_then_export"
    )
    baseline_granularity = "hour" if (end - baseline_start).total_seconds() <= 172800 else "day"
    raw_observed = _column_set(inspection, raw_table)
    summary_observed = _column_set(inspection, selected_summary_table)
    hydro_observed = _column_set(inspection, hydro_table)
    fanout_table = legacy_summary_table if selected_fanout_strategy == "summary_hour" else raw_table
    fanout_required = (
        THREAT_HUNT_SUMMARY_HOUR_FANOUT_REQUIRED_COLUMNS
        if selected_fanout_strategy == "summary_hour"
        else {"reqTimeSec", "UA", "cliIP", "totalBytes"}
    )
    stages = [
        _stage_plan_record(
            stage_id="summary_export",
            source_table=selected_summary_table,
            required_columns=summary_required,
            observed_columns=summary_observed,
            sql_template_id=summary_sql_template,
        ),
        _stage_plan_record(
            stage_id="raw_actor_fixtures",
            source_table=raw_table,
            required_columns=raw_required,
            optional_columns={"hydrolix_log_ingest_bytes"},
            observed_columns=raw_observed,
            sql_template_id=f"raw_actor.logs.{args.raw_actor_extraction_mode}.v1",
        ),
        _stage_plan_record(
            stage_id="hydrolix_usagemeter",
            source_table=hydro_table,
            required_columns=THREAT_HUNT_HYDRO_LOGS_REQUIRED_COLUMNS,
            observed_columns=hydro_observed,
            sql_template_id=f"hydrolix_usagemeter.{usagemeter_policy}.v1",
        ),
        _stage_plan_record(
            stage_id="cooccurrence",
            source_table=raw_table,
            required_columns={"reqTimeSec", "cliIP", "UA", "country"},
            observed_columns=raw_observed,
            sql_template_id="raw_ua_cooccurrence.logs.v1",
        ),
        _stage_plan_record(
            stage_id="scraper_drilldown",
            source_table=raw_table,
            required_columns={"reqTimeSec", "cliIP", "UA", "reqPath", "country", "statusCode"},
            observed_columns=raw_observed,
            sql_template_id="raw_scraper_drilldown.logs.v1",
        ),
        _stage_plan_record(
            stage_id="scraper_hourly",
            source_table=raw_table,
            required_columns={"reqTimeSec", "UA"},
            observed_columns=raw_observed,
            sql_template_id="raw_scraper_hourly.logs.v1",
        ),
        _stage_plan_record(
            stage_id="fanout",
            source_table=fanout_table,
            required_columns=set(fanout_required),
            observed_columns=_column_set(inspection, fanout_table),
            sql_template_id=f"fanout.{selected_fanout_strategy}.v1",
        ),
        _stage_plan_record(
            stage_id="background_ua_sample",
            source_table=raw_table,
            required_columns={"reqTimeSec", "cliIP", "UA", "reqPath", "statusCode"},
            observed_columns=raw_observed,
            sql_template_id="background_ua_sample.logs.v1",
        ),
        _stage_plan_record(
            stage_id="baseline_ua_timeseries",
            source_table=raw_table,
            required_columns={"reqTimeSec", "UA"},
            observed_columns=raw_observed,
            sql_template_id="baseline_ua_timeseries.logs.v1",
        ),
        _stage_plan_record(
            stage_id="impact_lane_totals",
            source_table=raw_table,
            required_columns={"reqTimeSec", "bytes", "totalBytes"},
            observed_columns=raw_observed,
            sql_template_id="impact_lane_totals.logs.v1",
        ),
        _stage_plan_record(
            stage_id="impact_lane_scoped_hunt",
            source_table=raw_table,
            required_columns={"reqTimeSec", "UA", "bytes", "totalBytes"},
            observed_columns=raw_observed,
            sql_template_id="impact_lane_scoped_hunt.logs.v1",
        ),
    ]
    plan: dict[str, object] = {
        "schema_version": THREAT_HUNT_HARVEST_PLAN_VERSION,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "cluster": args.cluster,
        "database": args.database,
        "current_window": {"start": args.start, "end": args.end},
        "baseline_window": {
            "start": baseline_start.isoformat().replace("+00:00", "Z"),
            "end": baseline_end.isoformat().replace("+00:00", "Z"),
        },
        "top_n": int(args.top_n),
        "inspection": inspection,
        "planner_decisions": {
            "selected_summary_table": selected_summary_table,
            "selected_summary_source": selected_summary_source,
            "selected_fanout_strategy": selected_fanout_strategy,
            "usagemeter_policy": usagemeter_policy,
            "field_provenance_overrides": field_overrides,
        },
        "summary": {
            "granularity": summary_granularity,
            "table": selected_summary_table,
            "source": selected_summary_source,
            "selection_mode": "top_n_by_period",
            "limit_per_period": 2000,
            "allow_legacy_fallback": selected_summary_source == "legacy_akamai_summary",
            "field_provenance_overrides": field_overrides,
        },
        "raw_actor": {
            "table": raw_table,
            "extraction_mode": args.raw_actor_extraction_mode,
            "chunk_seconds": int(args.raw_actor_chunk_seconds),
            "hash_buckets": int(args.raw_actor_hash_buckets),
            "topk_candidate_multiplier": int(args.raw_actor_topk_candidate_multiplier),
        },
        "fanout": {"strategy": selected_fanout_strategy, "fallback_allowed": False},
        "hydrolix_usagemeter": {
            "table": hydro_table,
            "project_deployment_id": args.hydrolix_log_ingest_usagemeter_project_deployment_id,
            "table_name": args.hydrolix_log_ingest_usagemeter_table_name,
            "discovery_allowed": args.hydrolix_log_ingest_usagemeter_project_deployment_id is None,
            "ambiguity_policy": "fail_closed",
            "policy": usagemeter_policy,
        },
        "enrichment_lanes": {
            "background_ua_sample": {"policy": "required", "fallback_allowed": False},
            "baseline_ua_timeseries": {
                "policy": "required",
                "granularity": baseline_granularity,
                "fallback_allowed": False,
            },
            "impact_lanes": {"policy": "required", "fallback_allowed": False},
        },
        "dynamic_selectors": [
            {"family": "lead_user_agents", "stages": ["cooccurrence", "scraper_drilldown", "scraper_hourly", "fanout"], "source": "raw_actor_fixtures"},
            {"family": "public_client_ip_scope", "stages": ["scraper_drilldown"], "source": "cooccurrence"},
            {"family": "peak_hours_by_user_agent", "stages": ["fanout"], "source": "scraper_hourly"},
            {"family": "background_excluded_user_agents", "stages": ["background_ua_sample"], "source": "raw_actor_fixtures"},
            {"family": "high_partial_confidence_user_agents", "stages": ["impact_lane_scoped_hunt"], "source": "threat_hunt_artifact"},
        ],
        "fallback_policy": {
            "mode": "fail_closed",
            "silent_fanout_fallback": False,
            "auto_usagemeter_ambiguity": False,
            "optional_enrichment_downgrade": False,
        },
        "required_stages": sorted(THREAT_HUNT_HARVEST_PLAN_REQUIRED_STAGE_IDS),
        "stages": stages,
    }
    return _attach_harvest_plan_hash(plan)


def load_threat_hunt_harvest_plan(path: Path) -> dict[str, object]:
    try:
        plan = json.loads(path.expanduser().resolve().read_text(encoding="utf-8") or "null")
    except (OSError, ValueError, TypeError) as exc:
        raise SystemExit(f"Could not read threat-hunt harvest plan: {path}: {exc}") from exc
    return validate_threat_hunt_harvest_plan(plan)


def validate_threat_hunt_harvest_plan(plan: dict[str, object]) -> dict[str, object]:
    if not isinstance(plan, dict):
        raise SystemExit("Threat-hunt harvest plan is not a JSON object.")
    if plan.get("schema_version") != THREAT_HUNT_HARVEST_PLAN_VERSION:
        raise SystemExit(
            "Threat-hunt harvest plan has unsupported schema_version: "
            f"{plan.get('schema_version')!r}"
        )
    expected_hash = _json_hash(_stable_plan_hash_basis(plan))
    if plan.get("hash") != expected_hash:
        raise SystemExit("Threat-hunt harvest plan hash does not match its contents.")
    required_stages = set(plan.get("required_stages") or [])
    missing_stages = sorted(THREAT_HUNT_HARVEST_PLAN_REQUIRED_STAGE_IDS - required_stages)
    if missing_stages:
        raise SystemExit(
            "Threat-hunt harvest plan is missing required stage(s): "
            + ", ".join(missing_stages)
        )
    stage_ids = {
        str(stage.get("stage_id"))
        for stage in plan.get("stages") or []
        if isinstance(stage, dict)
    }
    missing_stage_records = sorted(THREAT_HUNT_HARVEST_PLAN_REQUIRED_STAGE_IDS - stage_ids)
    if missing_stage_records:
        raise SystemExit(
            "Threat-hunt harvest plan is missing stage record(s): "
            + ", ".join(missing_stage_records)
        )
    fanout = plan.get("fanout")
    if isinstance(fanout, dict) and fanout.get("strategy") == "auto":
        raise SystemExit("Threat-hunt harvest plan contains unresolved auto value: fanout.strategy")
    for stage in plan.get("stages") or []:
        if not isinstance(stage, dict):
            continue
        stage_id = str(stage.get("stage_id") or "")
        if stage_id in THREAT_HUNT_HARVEST_STAGE_ROLES:
            if stage.get("output_role") != THREAT_HUNT_HARVEST_STAGE_ROLES[stage_id]:
                raise SystemExit(f"Threat-hunt harvest plan stage {stage_id} has the wrong output_role.")
            if stage.get("sql_hash_policy") != "required_recorded":
                raise SystemExit(f"Threat-hunt harvest plan stage {stage_id} must require SQL hashes.")
            if stage.get("output_hash_policy") != "required_recorded":
                raise SystemExit(f"Threat-hunt harvest plan stage {stage_id} must require output hashes.")
            if stage.get("missing_columns"):
                missing = stage.get("missing_columns")
                if isinstance(missing, list) and missing:
                    raise SystemExit(
                        f"Threat-hunt harvest plan stage {stage_id} has unresolved missing column(s): "
                        + ", ".join(str(item) for item in missing)
                    )
            if not stage.get("sql_template_id"):
                raise SystemExit(f"Threat-hunt harvest plan stage {stage_id} is missing sql_template_id.")
            if not stage.get("source_table"):
                raise SystemExit(f"Threat-hunt harvest plan stage {stage_id} is missing source_table.")
    dynamic_families = {
        str(selector.get("family"))
        for selector in plan.get("dynamic_selectors") or []
        if isinstance(selector, dict)
    }
    unsupported = sorted(dynamic_families - THREAT_HUNT_HARVEST_PLAN_DYNAMIC_SELECTOR_FAMILIES)
    if unsupported:
        raise SystemExit(
            "Threat-hunt harvest plan declares unsupported dynamic selector family/families: "
            + ", ".join(unsupported)
        )
    for section, key in (
        ("fanout", "strategy"),
        ("hydrolix_usagemeter", "project_deployment_id"),
        ("enrichment_lanes", "background_ua_sample"),
    ):
        value = (plan.get(section) or {}).get(key) if isinstance(plan.get(section), dict) else None
        if value == "auto":
            raise SystemExit(f"Threat-hunt harvest plan contains unresolved auto value: {section}.{key}")
    if isinstance(fanout, dict) and fanout.get("fallback_allowed") is not False:
        raise SystemExit("Threat-hunt harvest plan must fail closed for fanout fallback.")
    if isinstance(fanout, dict) and fanout.get("strategy") not in {"summary_hour", "logs_probe"}:
        raise SystemExit("Threat-hunt harvest plan fanout.strategy must resolve to summary_hour or logs_probe.")
    inspection = plan.get("inspection")
    if not isinstance(inspection, dict):
        raise SystemExit("Threat-hunt harvest plan is missing inspection metadata.")
    if inspection.get("mode") not in {"live_metadata", "offline_heuristic"}:
        raise SystemExit("Threat-hunt harvest plan has unsupported inspection.mode.")
    if inspection.get("mode") == "live_metadata":
        if not isinstance(inspection.get("catalog_queries"), list) or not inspection.get("catalog_queries"):
            raise SystemExit("Threat-hunt live metadata plan is missing catalog query hashes.")
        if not isinstance(inspection.get("columns"), dict):
            raise SystemExit("Threat-hunt live metadata plan is missing column inventory.")
    fallback_policy = plan.get("fallback_policy")
    if not isinstance(fallback_policy, dict) or fallback_policy.get("mode") != "fail_closed":
        raise SystemExit("Threat-hunt harvest plan must declare fallback_policy.mode=fail_closed.")
    if fallback_policy.get("silent_fanout_fallback") is not False:
        raise SystemExit("Threat-hunt harvest plan must reject silent fanout fallback.")
    if fallback_policy.get("auto_usagemeter_ambiguity") is not False:
        raise SystemExit("Threat-hunt harvest plan must reject usagemeter ambiguity.")
    if fallback_policy.get("optional_enrichment_downgrade") is not False:
        raise SystemExit("Threat-hunt harvest plan must reject optional enrichment downgrade.")
    return plan


def _validate_harvest_plan_scope(
    plan: dict[str, object],
    args: argparse.Namespace,
    baseline_start=None,
    baseline_end=None,
) -> None:
    if plan.get("cluster") != args.cluster or plan.get("database") != args.database:
        raise SystemExit("Threat-hunt harvest plan cluster/database does not match CLI arguments.")
    current_window = plan.get("current_window")
    if not isinstance(current_window, dict) or current_window.get("start") != args.start or current_window.get("end") != args.end:
        raise SystemExit("Threat-hunt harvest plan current window does not match CLI arguments.")
    if int(plan.get("top_n") or -1) != int(args.top_n):
        raise SystemExit("Threat-hunt harvest plan top_n does not match CLI arguments.")
    if baseline_start is not None and baseline_end is not None:
        baseline_window = plan.get("baseline_window")
        expected = {
            "start": baseline_start.isoformat().replace("+00:00", "Z"),
            "end": baseline_end.isoformat().replace("+00:00", "Z"),
        }
        if not isinstance(baseline_window, dict) or baseline_window != expected:
            raise SystemExit("Threat-hunt harvest plan baseline window does not match CLI arguments.")


def _harvest_plan_metadata(plan: dict[str, object]) -> dict[str, object]:
    return {
        "schema_version": plan.get("schema_version"),
        "hash": plan.get("hash"),
        "hash_algorithm": plan.get("hash_algorithm"),
        "inspection": plan.get("inspection"),
        "planner_decisions": plan.get("planner_decisions"),
        "required_stages": plan.get("required_stages"),
        "stages": plan.get("stages"),
        "dynamic_selectors": plan.get("dynamic_selectors"),
        "summary": plan.get("summary"),
        "fanout": plan.get("fanout"),
        "hydrolix_usagemeter": plan.get("hydrolix_usagemeter"),
    }


def _input_manifest_entries_by_role(input_manifest: dict[str, object]) -> dict[str, list[dict[str, object]]]:
    entries_by_role: dict[str, list[dict[str, object]]] = {}
    inputs = input_manifest.get("inputs")
    if not isinstance(inputs, list):
        return entries_by_role
    for item in inputs:
        if not isinstance(item, dict):
            continue
        role = item.get("role")
        if isinstance(role, str) and role:
            entries_by_role.setdefault(role, []).append(item)
    return entries_by_role


def validate_replay_local_input_manifest(input_manifest: dict[str, object]) -> dict[str, object]:
    if input_manifest.get("schema_version") != THREAT_HUNT_INPUT_MANIFEST_VERSION:
        raise SystemExit(f"replay-local requires {THREAT_HUNT_INPUT_MANIFEST_VERSION}.")
    entries_by_role = _input_manifest_entries_by_role(input_manifest)
    missing = sorted(THREAT_HUNT_FULL_REQUIRED_REPLAY_ROLES - set(entries_by_role))
    if missing:
        raise SystemExit(
            "replay-local requires explicit local input(s) for role(s): "
            + ", ".join(missing)
        )
    for role in sorted(THREAT_HUNT_FULL_REQUIRED_REPLAY_ROLES):
        for entry in entries_by_role[role]:
            if entry.get("source") != "local_input":
                raise SystemExit(f"replay-local {role} input must be source=local_input.")
            if entry.get("exists") is not True:
                raise SystemExit(f"replay-local {role} input does not exist: {entry.get('path')}")
            if not entry.get("sha256"):
                raise SystemExit(f"replay-local {role} input is missing sha256: {entry.get('path')}")
            path_value = entry.get("path")
            if not isinstance(path_value, str) or not path_value:
                raise SystemExit(f"replay-local {role} input is missing a path.")
            validate_replay_grade_dataset(Path(path_value), role=role)
    basis = _manifest_hash_basis(input_manifest)
    return {
        "status": "passed",
        "required_roles": sorted(THREAT_HUNT_FULL_REQUIRED_REPLAY_ROLES),
        "input_count": input_manifest.get("input_count"),
        "input_manifest_hash_basis": basis,
        "input_manifest_sha256": _json_hash(basis),
    }


def build_threat_hunt_replay_policy(
    *,
    enabled: bool,
    input_manifest: dict[str, object],
    validation: dict[str, object] | None = None,
) -> dict[str, object]:
    basis = _manifest_hash_basis(input_manifest)
    return {
        "schema_version": THREAT_HUNT_REPLAY_POLICY_VERSION,
        "mode": "local_only" if enabled else "not_replay_local",
        "live_hydrolix_queries_allowed": False if enabled else None,
        "validation": validation or ({"status": "not_applicable"} if not enabled else {"status": "not_run"}),
        "input_manifest": {
            "schema_version": input_manifest.get("schema_version"),
            "hash_algorithm": "sha256",
            "hash_basis": basis,
            "sha256": _json_hash(basis),
        },
    }


class ThreatHuntAudit:
    def __init__(
        self,
        *,
        audit_path: Path,
        manifest_path: Path,
        argv: list[str],
        harvest_plan: dict[str, object] | None = None,
    ) -> None:
        self.audit_path = audit_path
        self.manifest_path = manifest_path
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        self.manifest_path.parent.mkdir(parents=True, exist_ok=True)
        self.sequence = 0
        self.argv = _redact_argv(argv)
        self.events: list[dict[str, object]] = []
        self.artifacts: list[dict[str, object]] = []
        self.decisions: list[dict[str, object]] = []
        self.failures: list[dict[str, object]] = []
        self.harvest_plan = harvest_plan
        self.started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self.audit_path.write_text("", encoding="utf-8")

    def log(self, event_type: str, *, stage_id: str, status: str = "ok", **fields) -> None:
        self.sequence += 1
        event = {
            "sequence": self.sequence,
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "event_type": event_type,
            "stage_id": stage_id,
            "status": status,
            **fields,
        }
        self.events.append(event)
        if status == "failed":
            self.failures.append(event)
        with self.audit_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, sort_keys=True, default=str) + "\n")

    def __call__(self, event: dict[str, object]) -> None:
        event_type = str(event.pop("event_type", "event"))
        stage_id = str(event.pop("stage_id", "unknown"))
        status = str(event.pop("status", "ok"))
        argv = event.get("argv")
        if isinstance(argv, list):
            event["argv"] = _redact_argv([str(item) for item in argv])
        sql = event.get("sql")
        if isinstance(sql, str):
            event.setdefault("sql_sha256", hashlib.sha256(sql.encode("utf-8")).hexdigest())
        self.log(event_type, stage_id=stage_id, status=status, **event)

    def artifact(self, *, stage_id: str, role: str, path_value: str | Path | None, source: str) -> None:
        if not path_value:
            return
        path = Path(path_value).expanduser().resolve()
        record = {
            "role": role,
            "path": str(path),
            "source": source,
            "exists": path.exists(),
            "rows": _artifact_row_count(path),
            "sha256": _sha256_file(path),
        }
        if self.harvest_plan and role in THREAT_HUNT_FULL_REQUIRED_REPLAY_ROLES:
            record["planned"] = True
            record["plan_hash"] = self.harvest_plan.get("hash")
            record["plan_schema_version"] = self.harvest_plan.get("schema_version")
            record["plan_stage_id"] = stage_id
        if path.exists():
            try:
                manifest = validate_replay_grade_dataset(path, role=role)
            except SystemExit:
                manifest = None
            if manifest:
                record.update(
                    {
                        "dataset_schema_version": manifest.get("schema_version"),
                        "dataset_stage_id": manifest.get("stage_id"),
                        "dataset_source_table": manifest.get("source_table"),
                        "dataset_row_count": manifest.get("row_count"),
                        "dataset_total_row_count": manifest.get("total_row_count"),
                        "dataset_truncated": manifest.get("truncated"),
                        "dataset_query_sql": manifest.get("query_sql"),
                        "dataset_query_sha256": manifest.get("query_sha256"),
                        "dataset_output_sha256": manifest.get("output_sha256"),
                        "dataset_metadata": manifest.get("metadata"),
                        "field_provenance": manifest.get("field_provenance"),
                    }
                )
        self.artifacts.append(record)
        self.log("artifact", stage_id=stage_id, **record)

    def decision(self, *, stage_id: str, decision: str, rationale: str, **fields) -> None:
        record = {
            "stage_id": stage_id,
            "decision": decision,
            "rationale": rationale,
            **fields,
        }
        self.decisions.append(record)
        self.log("decision", stage_id=stage_id, decision=decision, rationale=rationale, **fields)

    def replay_context(self) -> dict[str, object]:
        export_events = [
            event
            for event in self.events
            if event.get("event_type") == "mux_export"
        ]
        artifact_roles = sorted(
            {
                str(artifact.get("role"))
                for artifact in self.artifacts
                if artifact.get("exists")
            }
        )
        return {
            "schema_version": "threat_hunt_replay_context.v1",
            "audit_events": self.events,
            "stage_decisions": self.decisions,
            "export_events": export_events,
            "artifact_roles": artifact_roles,
            "artifacts": self.artifacts,
            "validation": {
                "audit_jsonl_required": False,
                "required_artifact_roles": sorted(THREAT_HUNT_FULL_REQUIRED_REPLAY_ROLES),
            },
        }

    def manifest(self, *, status: str, outputs: dict[str, object]) -> None:
        manifest = {
            "schema_version": THREAT_HUNT_FULL_WORKFLOW_VERSION,
            "status": status,
            "harvest_plan": _harvest_plan_metadata(self.harvest_plan)
            if isinstance(self.harvest_plan, dict)
            else None,
            "started_at": self.started_at,
            "finished_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "argv": self.argv,
            "audit_jsonl": str(self.audit_path),
            "outputs": outputs,
            "replay_context": self.replay_context(),
            "artifacts": self.artifacts,
            "decisions": self.decisions,
            "failures": self.failures,
            "non_baked_workflow": [
                "summary export from bi_summary_<granularity>",
                "raw actor fixture harvest",
                "hydro.logs usagemeter discovery/export",
                "UA/IP cooccurrence harvest",
                "scraper drilldown scope dry-run and harvest",
                "scraper hourly harvest",
                "fanout/background/baseline enrichment harvest",
                "raw-log impact lane harvest",
            ],
        }
        self.manifest_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True, default=str) + "\n",
            encoding="utf-8",
        )


def validate_threat_hunt_full_required_provenance(manifest_path: Path) -> dict[str, object]:
    """Validate a full-required provenance manifest without reading audit JSONL."""
    manifest_path = manifest_path.expanduser().resolve()
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8") or "null")
    except (OSError, ValueError, TypeError) as exc:
        raise SystemExit(f"Could not read threat-hunt provenance manifest: {manifest_path}: {exc}") from exc
    if not isinstance(manifest, dict):
        raise SystemExit(f"Threat-hunt provenance manifest is not an object: {manifest_path}")
    if manifest.get("schema_version") != THREAT_HUNT_FULL_WORKFLOW_VERSION:
        raise SystemExit(
            "Threat-hunt provenance manifest has unsupported schema_version: "
            f"{manifest.get('schema_version')!r}"
        )
    harvest_plan = manifest.get("harvest_plan")
    if not isinstance(harvest_plan, dict) or harvest_plan.get("schema_version") != THREAT_HUNT_HARVEST_PLAN_VERSION:
        raise SystemExit(
            "Threat-hunt full-required provenance is missing "
            f"{THREAT_HUNT_HARVEST_PLAN_VERSION} metadata."
        )
    if not harvest_plan.get("hash"):
        raise SystemExit("Threat-hunt full-required provenance harvest_plan is missing hash.")
    plan_stage_roles = {
        str(stage.get("stage_id")): str(stage.get("output_role"))
        for stage in harvest_plan.get("stages") or []
        if isinstance(stage, dict) and stage.get("stage_id")
    }
    plan_stage_tables = {
        str(stage.get("stage_id")): str(stage.get("source_table"))
        for stage in harvest_plan.get("stages") or []
        if isinstance(stage, dict) and stage.get("stage_id") and stage.get("source_table")
    }
    replay_context = manifest.get("replay_context")
    if not isinstance(replay_context, dict):
        raise SystemExit(
            "Threat-hunt full-required provenance is missing embedded replay_context; "
            "audit_jsonl is diagnostic only and cannot satisfy replay validation."
        )
    events = replay_context.get("audit_events")
    if not isinstance(events, list) or not events:
        raise SystemExit("Threat-hunt replay_context is missing ordered audit_events.")
    sequences = [event.get("sequence") for event in events if isinstance(event, dict)]
    if sequences != sorted(sequences) or sequences != list(range(1, len(sequences) + 1)):
        raise SystemExit("Threat-hunt replay_context audit_events are not a complete ordered sequence.")
    artifacts = replay_context.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise SystemExit("Threat-hunt replay_context is missing artifact inventory.")
    generated_or_supplied = [
        artifact
        for artifact in artifacts
        if isinstance(artifact, dict)
        and artifact.get("role") in THREAT_HUNT_FULL_REQUIRED_REPLAY_ROLES
        and artifact.get("exists") is True
    ]
    roles = {str(artifact.get("role")) for artifact in generated_or_supplied}
    missing_roles = sorted(THREAT_HUNT_FULL_REQUIRED_REPLAY_ROLES - roles)
    if missing_roles:
        raise SystemExit(
            "Threat-hunt replay_context artifact inventory is missing required role(s): "
            + ", ".join(missing_roles)
        )
    for artifact in generated_or_supplied:
        role = str(artifact.get("role"))
        if artifact.get("planned") is not True:
            raise SystemExit(f"Threat-hunt replay_context artifact for {role} is not marked planned=true.")
        if artifact.get("plan_hash") != harvest_plan.get("hash"):
            raise SystemExit(f"Threat-hunt replay_context artifact for {role} references the wrong plan hash.")
        plan_stage_id = artifact.get("plan_stage_id")
        if not isinstance(plan_stage_id, str) or plan_stage_id not in THREAT_HUNT_HARVEST_PLAN_REQUIRED_STAGE_IDS:
            raise SystemExit(f"Threat-hunt replay_context artifact for {role} is missing a planned stage id.")
        planned_role = plan_stage_roles.get(plan_stage_id)
        if planned_role and planned_role != role:
            raise SystemExit(f"Threat-hunt replay_context artifact for {role} does not match planned output role.")
        planned_table = plan_stage_tables.get(plan_stage_id)
        if planned_table and artifact.get("dataset_source_table") != planned_table:
            raise SystemExit(
                f"Threat-hunt replay_context artifact for {role} used source table "
                "that does not match the harvest plan."
            )
        artifact_path = artifact.get("path")
        if not isinstance(artifact_path, str) or not artifact_path:
            raise SystemExit(f"Threat-hunt replay_context artifact for {role} is missing a path.")
        validate_replay_grade_dataset(Path(artifact_path), role=role)
        if not artifact.get("dataset_query_sha256"):
            raise SystemExit(
                f"Threat-hunt replay_context artifact for {role} is missing dataset_query_sha256."
            )
        if not artifact.get("dataset_output_sha256"):
            raise SystemExit(
                f"Threat-hunt replay_context artifact for {role} is missing dataset_output_sha256."
            )
    derived = [
        artifact
        for artifact in artifacts
        if isinstance(artifact, dict)
        and artifact.get("role") in {"threat_hunt_artifact", "threat_hunt_wrapper"}
        and artifact.get("exists") is True
    ]
    for artifact in derived:
        role = str(artifact.get("role"))
        path_value = artifact.get("path")
        if not isinstance(path_value, str) or not path_value:
            raise SystemExit(f"Threat-hunt derived artifact for {role} is missing a path.")
        try:
            payload = json.loads(Path(path_value).read_text(encoding="utf-8") or "null")
        except (OSError, ValueError, TypeError) as exc:
            raise SystemExit(f"Could not read threat-hunt derived artifact {path_value}: {exc}") from exc
        if not isinstance(payload, dict):
            raise SystemExit(f"Threat-hunt derived artifact for {role} is not a JSON object.")
        if role == "threat_hunt_artifact":
            input_manifest = (payload.get("artifact_metadata") or {}).get("input_manifest")
            replay_policy = (payload.get("artifact_metadata") or {}).get("replay_policy")
        else:
            input_manifest = payload.get("input_manifest")
            replay_policy = payload.get("replay_policy")
            embedded_artifacts = payload.get("artifacts")
            embedded_hunt = (
                embedded_artifacts[0]
                if isinstance(embedded_artifacts, list) and embedded_artifacts
                else {}
            )
            embedded_manifest = (
                (embedded_hunt.get("artifact_metadata") or {}).get("input_manifest")
                if isinstance(embedded_hunt, dict)
                else None
            )
            if not isinstance(embedded_manifest, dict) or embedded_manifest.get("schema_version") != THREAT_HUNT_INPUT_MANIFEST_VERSION:
                raise SystemExit("Threat-hunt wrapper embedded artifact is missing artifact_metadata.input_manifest.")
        if not isinstance(input_manifest, dict) or input_manifest.get("schema_version") != THREAT_HUNT_INPUT_MANIFEST_VERSION:
            raise SystemExit(f"Threat-hunt derived artifact for {role} is missing {THREAT_HUNT_INPUT_MANIFEST_VERSION}.")
        if isinstance(replay_policy, dict) and replay_policy.get("mode") == "local_only":
            if replay_policy.get("live_hydrolix_queries_allowed") is not False:
                raise SystemExit(f"Threat-hunt derived artifact for {role} has replay-local policy that allows live Hydrolix queries.")
            validate_replay_local_input_manifest(input_manifest)
            source_by_role = {
                str(item.get("role")): str(item.get("source"))
                for item in input_manifest.get("inputs", [])
                if isinstance(item, dict) and item.get("role") in THREAT_HUNT_FULL_REQUIRED_REPLAY_ROLES
            }
            generated_roles = sorted(
                role_name
                for role_name, source in source_by_role.items()
                if source in {"generated", "live_harvest", "render_input"}
            )
            if generated_roles:
                raise SystemExit(
                    "Threat-hunt replay-local derived artifact includes generated/live role(s): "
                    + ", ".join(generated_roles)
                )
        inputs = input_manifest.get("inputs")
        if not isinstance(inputs, list) or not inputs:
            raise SystemExit(f"Threat-hunt input manifest for {role} is empty.")
        for item in inputs:
            if not isinstance(item, dict):
                raise SystemExit(f"Threat-hunt input manifest for {role} contains a non-object entry.")
            if not item.get("role") or not item.get("path"):
                raise SystemExit(f"Threat-hunt input manifest for {role} contains an entry without role/path.")
            if item.get("exists") is True and not item.get("sha256"):
                raise SystemExit(
                    f"Threat-hunt input manifest entry {item.get('role')} is missing sha256."
                )
    for event in events:
        if not isinstance(event, dict) or event.get("event_type") != "mux_export":
            continue
        if event.get("argv") and not isinstance(event.get("argv"), list):
            raise SystemExit("Threat-hunt mux_export replay event has non-list argv.")
        if event.get("sql") and not event.get("sql_sha256"):
            raise SystemExit("Threat-hunt mux_export replay event has SQL text without sql_sha256.")
    for decision in replay_context.get("stage_decisions") or []:
        if not isinstance(decision, dict):
            continue
        if decision.get("decision") == "resolved_summary_table" and decision.get("source") == "legacy_akamai_summary":
            raise SystemExit("Threat-hunt full-required provenance records an unplanned summary-table fallback.")
        fallback_errors = decision.get("fallback_errors")
        if fallback_errors:
            raise SystemExit("Threat-hunt full-required provenance records fanout fallback errors.")
    return manifest


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="bot-insights-report",
        description="Generate Bot Insights reports from Hydrolix summary data via local artifacts.",
    )
    parser.add_argument(
        "--cluster", required=True, help="Hydrolix cluster alias or .env file path."
    )
    parser.add_argument(
        "--database", default="akamai", help="Hydrolix database/project."
    )
    parser.add_argument(
        "--report",
        choices=(
            "executive_posture",
            "control_review",
            "scorecard_brief",
            "soc_triage",
            "crawler_governance",
            "edge_ops_impact",
            "incident_report",
            "threat_hunt",
        ),
        default="executive_posture",
        help="Report type to generate.",
    )
    parser.add_argument(
        "--mode",
        choices=("report", "evidence", "template"),
        default="report",
        help="Output a deterministic report, an LLM evidence packet, or a Markdown template scaffold.",
    )
    parser.add_argument(
        "--start", required=True, help="Inclusive ISO-8601 current-window start."
    )
    parser.add_argument(
        "--end", required=True, help="Exclusive ISO-8601 current-window end."
    )
    parser.add_argument(
        "--baseline-start",
        help="Inclusive ISO-8601 baseline start. Defaults to the equal-length previous window.",
    )
    parser.add_argument(
        "--baseline-end",
        help="Exclusive ISO-8601 baseline end. Defaults to --start for legacy windows.",
    )
    parser.add_argument(
        "--sample-dir",
        help="Directory for intermediate local JSON. Defaults to ~/src/sample-data/bot-insights/1.1/<cluster>.",
    )
    parser.add_argument(
        "--output", help="Output path for the selected mode."
    )
    parser.add_argument(
        "--raw-input",
        help="Resume from a saved Hydrolix MCP or ClickHouse JSON result instead of running capture.",
    )
    parser.add_argument(
        "--raw-path-input",
        type=str,
        default=None,
        help="Resume edge_ops_impact from a saved path-grain JSON result alongside --raw-input.",
    )
    parser.add_argument(
        "--format",
        choices=("markdown", "html"),
        default="html",
        help="Rendered report format.",
    )
    parser.add_argument("--title", help="Optional rendered report title.")
    parser.add_argument(
        "--policy-id", help="Optional SIEM policyId filter for control_review."
    )
    parser.add_argument(
        "--control-source",
        choices=("siem-policy", "posture"),
        default="siem-policy",
        help="Summary surface for control_review evidence.",
    )
    parser.add_argument(
        "--change-time",
        help="Optional control change timestamp. Defaults to --start for control_review.",
    )
    parser.add_argument(
        "--entity-type",
        choices=tuple(SCORECARD_ENTITY_SQL),
        default="request_host",
        help="Entity type to score for scorecard_brief.",
    )
    parser.add_argument(
        "--entity-value",
        help="Optional explicit entity value to render for scorecard_brief. Defaults to top-ranked scorecard entity.",
    )
    parser.add_argument(
        "--fleet",
        action="store_true",
        default=False,
        help=(
            "Render scorecard_brief as a fleet (multi-entity) view "
            "instead of collapsing to a single entity. The default "
            "(no flag, no --entity-value) selects the top-ranked "
            "entity and the engine auto-promotes to "
            "scorecard_entity_review for that one host. --fleet "
            "keeps every ranked scorecard in the wrapper so the "
            "report renders as scorecard_brief with the queue table, "
            "triage strip, and coverage detail; --mode evidence with "
            "--fleet also emits a fleet-shaped packet (band "
            "distribution, rule trigger counts across hosts, top "
            "entities) instead of the single-entity packet shape, so "
            "the LLM's interpretation prose matches the rendered "
            "framing. Only valid for --report scorecard_brief."
        ),
    )
    parser.add_argument(
        "--scorecard-limit",
        type=int,
        default=20,
        help="Maximum aggregate rows/scorecards to keep for scorecard_brief.",
    )
    parser.add_argument(
        "--host",
        type=str,
        default=None,
        help="Optional hostname filter for edge_ops_impact path-grain query (scopes path candidates to a single request_host).",
    )
    parser.add_argument(
        "--include-paths",
        action="store_true",
        default=False,
        help=(
            "Opt in to the edge_ops_impact path-grain capture against "
            "bot_agg_path_<granularity>. This table is not currently "
            "deployed on any production cluster, so the path-grain query "
            "is off by default; enabling it falls back gracefully when "
            "the table is missing."
        ),
    )
    parser.add_argument(
        "--domains",
        help="Optional comma-separated scorecard domains to evaluate.",
    )
    parser.add_argument(
        "--asn",
        default=None,
        help="Optional client ASN scope filter for incident_report.",
    )
    parser.add_argument(
        "--path-pattern",
        default=None,
        help=(
            "Optional path-pattern scope filter for incident_report "
            "(requestPathPattern bucket for summary queries; SQL LIKE for "
            "raw drilldown)."
        ),
    )
    parser.add_argument(
        "--incident-view",
        choices=(
            "analyst",
            "executive",
            "soc_action_packet",
            "edge_platform_brief",
            "detection_engineering",
        ),
        default="analyst",
        help=(
            "Incident-only render audience. Changes the wrapper report_type "
            "and template only; evidence capture semantics are unchanged."
        ),
    )
    parser.add_argument(
        "--fields",
        default=None,
        help=(
            "Comma-separated akamai.logs column names to rank in the "
            "incident_report actors section. Default: "
            f"{_INCIDENT_DEFAULT_FIELDS}."
        ),
    )
    parser.add_argument(
        "--top-n",
        type=int,
        default=10,
        help="Top-N row cap for incident_report queries or threat_hunt tables.",
    )
    parser.add_argument(
        "--summary-parquet-glob",
        help="Local summary parquet glob for threat_hunt. JSON/CSV rows are also accepted for fixtures.",
    )
    parser.add_argument(
        "--threat-hunt-harvest",
        choices=("existing", "full-required", "replay-local"),
        default="existing",
        help=(
            "Threat-hunt input harvest mode. existing preserves the legacy local-artifact flow; "
            "full-required harvests missing deterministic inputs under --sample-dir and fails "
            "closed when required rows cannot be produced; replay-local consumes only explicit "
            "local replay-grade inputs and never queries Hydrolix for missing data."
        ),
    )
    parser.add_argument(
        "--threat-hunt-harvest-plan-out",
        type=Path,
        help=(
            "Write a resolved threat_hunt_harvest_plan.v1 for full-required "
            "threat-hunt harvest and exit without producing the report."
        ),
    )
    parser.add_argument(
        "--threat-hunt-harvest-plan-offline",
        action="store_true",
        default=False,
        help=(
            "Generate --threat-hunt-harvest-plan-out without live catalog inspection. "
            "The plan is marked inspection.mode=offline_heuristic and is intended "
            "only for tests or disconnected environments."
        ),
    )
    parser.add_argument(
        "--threat-hunt-harvest-plan",
        type=Path,
        help=(
            "Required threat_hunt_harvest_plan.v1 file for "
            "--threat-hunt-harvest full-required execution."
        ),
    )
    parser.add_argument(
        "--raw-actor-dir",
        help="Directory containing threat_hunt raw actor JSON exports.",
    )
    parser.add_argument(
        "--raw-actor-chunk-seconds",
        type=int,
        default=3600,
        help=(
            "Maximum seconds per raw-log actor export query when --raw-actor-dir "
            "is omitted. Smaller chunks reduce Hydrolix memory pressure."
        ),
    )
    parser.add_argument(
        "--raw-actor-extraction-mode",
        choices=("topk", "hash"),
        default="topk",
        help=(
            "Raw actor extraction strategy when --raw-actor-dir is omitted. "
            "topk is the fast bounded default; hash is exact hash-bucket "
            "chunking for diagnostics and reproduction."
        ),
    )
    parser.add_argument(
        "--raw-actor-hash-buckets",
        type=int,
        default=16,
        help=(
            "Number of deterministic hash buckets per client_ip raw actor time "
            "chunk when --raw-actor-dir is omitted. user_agent exports remain "
            "time-only by default. Higher values reduce GROUP BY memory pressure "
            "at the cost of more queries."
        ),
    )
    parser.add_argument(
        "--raw-actor-topk-candidate-multiplier",
        type=int,
        default=5,
        help=(
            "Candidate multiplier for --raw-actor-extraction-mode topk. "
            "The producer computes exact metrics for topK(top_n * multiplier) "
            "candidate actors per time chunk."
        ),
    )
    parser.add_argument(
        "--hydrolix-log-ingest-bytes-column",
        help=(
            "Optional akamai.logs column to sum as Hydrolix log ingest bytes "
            "for threat_hunt raw actor exports. When omitted, the ingest lane "
            "is rendered as unavailable instead of inferred from response or "
            "CDN-billed bytes."
        ),
    )
    parser.add_argument(
        "--hydrolix-log-ingest-usagemeter-in",
        help=(
            "Optional local hydro.logs usagemeter JSON/CSV artifact for threat_hunt "
            "Hydrolix ingest estimates."
        ),
    )
    parser.add_argument(
        "--hydrolix-log-ingest-usagemeter-project-deployment-id",
        help=(
            "Project deployment id used to export hydro.logs usagemeter rows, "
            "for example expediagroup__akamai."
        ),
    )
    parser.add_argument(
        "--hydrolix-log-ingest-usagemeter-table-name",
        default="logs",
        help="hydro.logs table_name value for the raw customer log table. Default: logs.",
    )
    parser.add_argument(
        "--hydrolix-log-ingest-usagemeter-query",
        choices=("auto", "off", "required"),
        default="auto",
        help=(
            "Threat-hunt hydro.logs usagemeter query behavior. auto discovers "
            "and exports Hydrolix log-ingest billing bytes when no local artifact "
            "is supplied, off skips querying, required fails if discovery or "
            "export cannot produce positive rows and billing_bytes."
        ),
    )
    parser.add_argument(
        "--impact-lane-query",
        choices=("auto", "off", "required"),
        default="auto",
        help=(
            "Threat-hunt raw-log impact lane behavior. auto exports raw-log "
            "response-body and Akamai-billed totals when possible, off skips "
            "lane merging, required fails if supplied or exported lane rows "
            "are unavailable."
        ),
    )
    parser.add_argument(
        "--impact-lane-totals-in",
        help=(
            "Optional saved total-window impact lane rows for threat_hunt "
            "(current_total, baseline_total)."
        ),
    )
    parser.add_argument(
        "--impact-lane-scoped-hunt-in",
        help=(
            "Optional saved high/partial-confidence Hunt Impact lane rows for "
            "threat_hunt (current_high_partial, baseline_high_partial)."
        ),
    )
    parser.add_argument(
        "--geoip-asn-v4",
        help="Optional threat_hunt IPv4 GeoIP/ASN JSON or CSV enrichment file.",
    )
    parser.add_argument(
        "--geoip-asn-v6",
        help="Optional threat_hunt IPv6 GeoIP/ASN JSON or CSV enrichment file.",
    )
    parser.add_argument(
        "--cooccurrence-in",
        help="Optional threat_hunt UA/IP cooccurrence JSON or CSV artifact.",
    )
    parser.add_argument(
        "--cooccurrence-path-in",
        help="Optional threat_hunt UA/IP/path cooccurrence JSON or CSV artifact.",
    )
    parser.add_argument(
        "--scraper-drilldown-in",
        help=(
            "Optional bounded threat_hunt scraper drilldown JSON or CSV artifact "
            "(user_agent, client_ip, request_path, hour, country, status_429, status_5xx, requests)."
        ),
    )
    parser.add_argument(
        "--scraper-hourly-in",
        help=(
            "Optional complete threat_hunt scraper hourly JSON or CSV artifact "
            "(user_agent, hour, requests). Used for coverage-aware hourly timing."
        ),
    )
    parser.add_argument(
        "--fanout-in",
        help=(
            "Optional source-aware threat_hunt per-UA fan-out artifact "
            "(user_agent, unique_ips, hits, bytes, source, probe_window_hours)."
        ),
    )
    parser.add_argument(
        "--fanout-strategy",
        choices=("auto", "summary_hour", "logs_probe", "skip"),
        default="auto",
        help=(
            "Threat-hunt fan-out enrichment strategy. auto tries summary_hour, "
            "then logs_probe, then cooccurrence lower-bound fallback."
        ),
    )
    parser.add_argument(
        "--ua-fanout-in",
        dest="ua_fanout_in",
        help=(
            "Backward-compatible alias for --fanout-in. Accepts legacy "
            "(user_agent, unique_client_ips, requests) rows."
        ),
    )
    parser.add_argument(
        "--ua-fanout-query",
        choices=("auto", "off", "required", "summary_hour", "logs_probe", "skip"),
        default="auto",
        help=(
            "Backward-compatible alias for --fanout-strategy. off maps to skip; "
            "required keeps legacy fail-if-missing behavior."
        ),
    )
    parser.add_argument(
        "--iat-sample-in",
        help=(
            "Optional bounded threat_hunt request-level timing sample JSON or CSV artifact "
            "(user_agent, client_ip, timestamp or reqTimeSec; optional request_path, status_code, response_time_ms)."
        ),
    )
    parser.add_argument(
        "--background-ua-sample-in",
        help=(
            "Optional threat_hunt mid-volume organic UA background sample JSON or CSV artifact "
            "used to estimate evidence-family background rates."
        ),
    )
    parser.add_argument(
        "--background-query",
        choices=("auto", "off", "required"),
        default="auto",
        help=(
            "Threat-hunt background UA sample behavior. auto exports a bounded "
            "sample when possible, off skips it, required fails if unavailable."
        ),
    )
    parser.add_argument(
        "--baseline-ua-timeseries-in",
        help=(
            "Optional threat_hunt per-UA baseline bucket JSON or CSV artifact "
            "(user_agent, bucket, requests) for z-score significance."
        ),
    )
    parser.add_argument(
        "--baseline-significance-query",
        choices=("auto", "off", "required"),
        default="auto",
        help=(
            "Threat-hunt per-UA baseline bucket query behavior. auto exports "
            "selected-lead buckets when possible, off skips it, required fails if unavailable."
        ),
    )
    parser.add_argument(
        "--edge-response-in",
        help="Optional threat_hunt edge/Bot/SIEM coverage JSON or CSV artifact.",
    )
    parser.add_argument(
        "--bot-manager-context-in",
        help=(
            "Optional aggregate threat_hunt Bot Manager context JSON or CSV artifact "
            "from bi_siem_policy_summary_* rows. Display-only enrichment."
        ),
    )
    parser.add_argument(
        "--bot-manager-siem-summary-in",
        dest="bot_manager_context_in",
        help=(
            "Alias for --bot-manager-context-in. Accepts aggregate "
            "bi_siem_policy_summary_* context rows."
        ),
    )
    parser.add_argument(
        "--bot-manager-exact-ua-in",
        help=(
            "Optional exact-UA Bot Manager or edge export JSON or CSV artifact. "
            "Rows are attached only to matching user_agent values for display."
        ),
    )
    parser.add_argument(
        "--cost-estimate-config",
        help=(
            "Optional threat_hunt JSON cost assumptions file. When enabled, "
            "adds CDN egress low/high estimates derived from observed bytes."
        ),
    )
    parser.add_argument(
        "--analyst-notes",
        help="LLM interpretation prose to include in the final report wrapper.",
    )
    parser.add_argument(
        "--analyst-notes-file",
        help="Read LLM interpretation prose from a file for the final report wrapper.",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help=(
            "Path to a threshold-override file (YAML/TOML/JSON). Overlays onto "
            "the dataclass defaults defined in scripts/config.py; any key "
            "omitted falls through to its default. See "
            "skills/bot-insights/config/defaults.yaml for the full tunable "
            "surface."
        ),
    )
    return parser.parse_args()


def main() -> int:
    # Late-bind ``run`` through the ``bot_insights_report`` shim so tests
    # that patch ``mock.patch.object(bot_insights_report, "run", ...)``
    # intercept the capture subprocess calls below. Module-level
    # ``from producers.runtime import run`` would bind to the unpatched
    # function once and miss the patch entirely.
    import bot_insights_report as _bir
    run = _bir.run
    load_raw_query_result = _bir.load_raw_query_result
    legacy_cli = sys.modules.get("producers.cli")
    incident_report_runner = _maybe_mocked_legacy_symbol(
        legacy_cli, "_run_incident_report", _run_incident_report
    )
    export_raw_actor_fixtures_runner = _maybe_mocked_legacy_symbol(
        legacy_cli, "export_raw_actor_fixtures", export_raw_actor_fixtures
    )

    args = parse_args()
    # Prime the active-thresholds singleton from --config so renderer-side
    # display caps and risk-score bands honor the override when the
    # producer drives both capture and render in one process.
    from config import load_thresholds, set_active_thresholds

    set_active_thresholds(load_thresholds(args.config))
    start = parse_time(args.start, "start")
    end = parse_time(args.end, "end")
    window = end - start
    if args.baseline_start:
        baseline_start = parse_time(args.baseline_start, "baseline-start")
    else:
        baseline_start = start - window
    if args.baseline_end:
        baseline_end = parse_time(args.baseline_end, "baseline-end")
    else:
        baseline_end = start
    if baseline_start >= baseline_end:
        raise SystemExit("--baseline-start must be earlier than --baseline-end")
    if baseline_end > start:
        raise SystemExit("--baseline-end must be earlier than or equal to --start")
    if baseline_end - baseline_start != window:
        raise SystemExit("--baseline window must match the current window duration")
    if args.baseline_end and args.report not in {"incident_report", "threat_hunt"}:
        raise SystemExit("--baseline-end is only supported with --report incident_report or --report threat_hunt.")
    if args.scorecard_limit < 0:
        raise SystemExit("--scorecard-limit must be zero or a positive integer.")
    scorecard_reports = {
        "scorecard_brief",
        "soc_triage",
        "crawler_governance",
        "edge_ops_impact",
    }
    if args.report not in scorecard_reports and args.entity_value:
        raise SystemExit(
            "--entity-value is only supported with --report scorecard_brief, --report soc_triage, "
            "--report crawler_governance, or --report edge_ops_impact."
        )
    if args.fleet and args.report != "scorecard_brief":
        raise SystemExit(
            "--fleet is only supported with --report scorecard_brief; "
            "soc_triage, crawler_governance, and edge_ops_impact "
            "already render multi-entity views by default."
        )
    if args.fleet and args.entity_value:
        raise SystemExit(
            "--fleet and --entity-value are mutually exclusive: "
            "--fleet renders every emitted scorecard, while "
            "--entity-value pins to one specific entity."
        )
    if args.report == "soc_triage" and args.entity_type not in SOC_ENTITY_SQL:
        raise SystemExit(
            "--entity-type "
            + args.entity_type
            + " is not supported for soc_triage; use one of "
            + ", ".join(sorted(SOC_ENTITY_SQL))
        )
    if (
        args.report == "crawler_governance"
        and args.entity_type not in CRAWLER_ENTITY_SQL
    ):
        raise SystemExit(
            "--entity-type "
            + args.entity_type
            + " is not supported for crawler_governance; use one of "
            + ", ".join(sorted(CRAWLER_ENTITY_SQL))
        )
    if args.report == "edge_ops_impact" and args.entity_type not in EDGE_OPS_ENTITY_SQL:
        raise SystemExit(
            "--entity-type "
            + args.entity_type
            + " is not supported for edge_ops_impact; use one of "
            + ", ".join(sorted(EDGE_OPS_ENTITY_SQL))
        )
    if args.raw_path_input and not args.raw_input:
        raise SystemExit(
            "--raw-path-input requires --raw-input to also be supplied "
            "(both raw inputs must be provided to resume an edge_ops_impact run)."
        )
    if args.raw_path_input and args.report != "edge_ops_impact":
        raise SystemExit(
            "--raw-path-input is only valid with --report edge_ops_impact."
        )
    if args.report == "soc_triage" and not args.domains:
        # SOC scorecards must evaluate only the security_evidence domain so
        # crawler/Edge/Ops features do not surface as missing SOC evidence.
        args.domains = "security_evidence"
    if args.report == "crawler_governance" and not args.domains:
        # Crawler governance scorecards must evaluate only the
        # crawler_governance domain so SOC/Edge features do not surface as
        # missing crawler evidence.
        args.domains = "crawler_governance"
    if args.report == "edge_ops_impact" and not args.domains:
        # Edge/Ops scorecards evaluate cache_busting and origin_impact domains
        # so SOC/crawler features do not surface as missing edge evidence.
        args.domains = "cache_busting,origin_impact"
    if args.report != "incident_report" and args.incident_view != "analyst":
        raise SystemExit("--incident-view is only supported with --report incident_report.")
    threat_hunt_full_required = (
        args.report == "threat_hunt" and args.threat_hunt_harvest == "full-required"
    )
    threat_hunt_replay_local = (
        args.report == "threat_hunt" and args.threat_hunt_harvest == "replay-local"
    )
    if args.report != "threat_hunt" and (
        args.threat_hunt_harvest_plan_out
        or args.threat_hunt_harvest_plan
        or args.threat_hunt_harvest_plan_offline
    ):
        raise SystemExit("--threat-hunt-harvest-plan* options are only supported with --report threat_hunt.")
    if args.threat_hunt_harvest_plan_offline and not args.threat_hunt_harvest_plan_out:
        raise SystemExit("--threat-hunt-harvest-plan-offline requires --threat-hunt-harvest-plan-out.")
    if args.threat_hunt_harvest_plan_out and args.threat_hunt_harvest_plan:
        raise SystemExit("--threat-hunt-harvest-plan-out and --threat-hunt-harvest-plan are mutually exclusive.")
    if threat_hunt_full_required and not args.threat_hunt_harvest_plan and not args.threat_hunt_harvest_plan_out:
        raise SystemExit(
            "--threat-hunt-harvest full-required requires --threat-hunt-harvest-plan. "
            "Use --threat-hunt-harvest-plan-out first to generate the plan."
        )
    if not args.output and not args.threat_hunt_harvest_plan_out:
        raise SystemExit("--output is required unless --threat-hunt-harvest-plan-out is used.")
    if (
        args.report == "threat_hunt"
        and not args.summary_parquet_glob
        and not threat_hunt_full_required
        and not threat_hunt_replay_local
        and not args.threat_hunt_harvest_plan_out
    ):
        raise SystemExit("--report threat_hunt requires --summary-parquet-glob.")
    if threat_hunt_replay_local:
        replay_values = {
            "summary": args.summary_parquet_glob,
            "raw_actor": args.raw_actor_dir,
            "hydrolix_usagemeter": args.hydrolix_log_ingest_usagemeter_in,
            "cooccurrence": args.cooccurrence_in,
            "scraper_drilldown": args.scraper_drilldown_in,
            "scraper_hourly": args.scraper_hourly_in,
            "fanout": args.fanout_in or args.ua_fanout_in,
            "background_ua_sample": args.background_ua_sample_in,
            "baseline_ua_timeseries": args.baseline_ua_timeseries_in,
            "impact_lane_totals": args.impact_lane_totals_in,
            "impact_lane_scoped_hunt": args.impact_lane_scoped_hunt_in,
        }
        missing_replay_args = [
            THREAT_HUNT_REPLAY_LOCAL_REQUIRED_ARGS[role]
            for role, value in replay_values.items()
            if not value
        ]
        if missing_replay_args:
            raise SystemExit(
                "--threat-hunt-harvest replay-local requires explicit local inputs: "
                + ", ".join(missing_replay_args)
            )
    if args.report != "threat_hunt":
        local_flags = {
            "--threat-hunt-harvest": None
            if args.threat_hunt_harvest == "existing"
            else args.threat_hunt_harvest,
            "--summary-parquet-glob": args.summary_parquet_glob,
            "--raw-actor-dir": args.raw_actor_dir,
            "--hydrolix-log-ingest-bytes-column": args.hydrolix_log_ingest_bytes_column,
            "--hydrolix-log-ingest-usagemeter-in": args.hydrolix_log_ingest_usagemeter_in,
            "--hydrolix-log-ingest-usagemeter-project-deployment-id": args.hydrolix_log_ingest_usagemeter_project_deployment_id,
            "--hydrolix-log-ingest-usagemeter-query": None
            if args.hydrolix_log_ingest_usagemeter_query == "auto"
            else args.hydrolix_log_ingest_usagemeter_query,
            "--impact-lane-totals-in": args.impact_lane_totals_in,
            "--impact-lane-scoped-hunt-in": args.impact_lane_scoped_hunt_in,
            "--geoip-asn-v4": args.geoip_asn_v4,
            "--geoip-asn-v6": args.geoip_asn_v6,
            "--cooccurrence-in": args.cooccurrence_in,
            "--cooccurrence-path-in": args.cooccurrence_path_in,
            "--scraper-drilldown-in": args.scraper_drilldown_in,
            "--scraper-hourly-in": args.scraper_hourly_in,
            "--fanout-in": args.fanout_in,
            "--ua-fanout-in": args.ua_fanout_in,
            "--iat-sample-in": args.iat_sample_in,
            "--background-ua-sample-in": args.background_ua_sample_in,
            "--baseline-ua-timeseries-in": args.baseline_ua_timeseries_in,
            "--edge-response-in": args.edge_response_in,
            "--bot-manager-context-in": args.bot_manager_context_in,
            "--bot-manager-exact-ua-in": args.bot_manager_exact_ua_in,
            "--cost-estimate-config": args.cost_estimate_config,
        }
        supplied = [flag for flag, value in local_flags.items() if value]
        if supplied:
            raise SystemExit(
                ", ".join(supplied) + " are only supported with --report threat_hunt."
            )

    sample_dir = (
        Path(args.sample_dir).expanduser().resolve()
        if args.sample_dir
        else DEFAULT_SAMPLE_ROOT / args.cluster
    )
    sample_dir.mkdir(parents=True, exist_ok=True)
    threat_hunt_harvest_plan: dict[str, object] | None = None
    if args.report == "threat_hunt" and args.threat_hunt_harvest_plan_out:
        plan_builder = (
            build_offline_threat_hunt_harvest_plan
            if args.threat_hunt_harvest_plan_offline
            else build_threat_hunt_harvest_plan
        )
        threat_hunt_harvest_plan = plan_builder(
            args=args,
            start=start,
            end=end,
            baseline_start=baseline_start,
            baseline_end=baseline_end,
        )
        plan_out = args.threat_hunt_harvest_plan_out.expanduser().resolve()
        plan_out.parent.mkdir(parents=True, exist_ok=True)
        plan_out.write_text(
            json.dumps(threat_hunt_harvest_plan, indent=2, sort_keys=True, default=str) + "\n",
            encoding="utf-8",
        )
        print(json.dumps({"harvest_plan": str(plan_out), "hash": threat_hunt_harvest_plan["hash"]}, sort_keys=True))
        return 0
    if args.report == "threat_hunt" and args.threat_hunt_harvest_plan:
        threat_hunt_harvest_plan = load_threat_hunt_harvest_plan(args.threat_hunt_harvest_plan)
        _validate_harvest_plan_scope(
            threat_hunt_harvest_plan,
            args,
            baseline_start=baseline_start,
            baseline_end=baseline_end,
        )

    if args.report == "incident_report":
        incident_report_types = {
            "analyst": "incident_report",
            "executive": "incident_executive_view",
            "soc_action_packet": "incident_soc_action_packet",
            "edge_platform_brief": "incident_edge_platform_brief",
            "detection_engineering": "incident_detection_engineering",
        }
        args.incident_report_type = incident_report_types[args.incident_view]
        output_path = Path(args.output).expanduser().resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        return incident_report_runner(
            args,
            start,
            end,
            baseline_start,
            baseline_end,
            sample_dir,
            output_path,
        )

    if args.report == "threat_hunt":
        output_path = Path(args.output).expanduser().resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        artifact_path = sample_dir / "threat_hunt-artifact.json"
        wrapper_path = sample_dir / "threat_hunt-wrapper.json"
        audit = (
            ThreatHuntAudit(
                audit_path=sample_dir / "threat_hunt-audit.jsonl",
                manifest_path=sample_dir / "threat_hunt-provenance.json",
                argv=sys.argv,
                harvest_plan=threat_hunt_harvest_plan,
            )
            if threat_hunt_full_required
            else None
        )
        if audit:
            set_provenance_recorder(audit)
            audit.log(
                "workflow_start",
                stage_id="workflow",
                mode=args.mode,
                cluster=args.cluster,
                database=args.database,
                harvest=args.threat_hunt_harvest,
                start=args.start,
                end=args.end,
                baseline_start=baseline_start.isoformat().replace("+00:00", "Z"),
                baseline_end=baseline_end.isoformat().replace("+00:00", "Z"),
            )
        replay_local_validation: dict[str, object] | None = None
        if threat_hunt_replay_local:
            replay_local_manifest = build_threat_hunt_input_manifest(
                summary_parquet_glob=args.summary_parquet_glob,
                raw_actor_dir=args.raw_actor_dir,
                hydrolix_log_ingest_usagemeter_in=args.hydrolix_log_ingest_usagemeter_in,
                cooccurrence_in=args.cooccurrence_in,
                cooccurrence_path_in=args.cooccurrence_path_in,
                scraper_drilldown_in=args.scraper_drilldown_in,
                scraper_hourly_in=args.scraper_hourly_in,
                fanout_in=args.fanout_in or args.ua_fanout_in,
                iat_sample_in=args.iat_sample_in,
                background_ua_sample_in=args.background_ua_sample_in,
                baseline_ua_timeseries_in=args.baseline_ua_timeseries_in,
                edge_response_in=args.edge_response_in,
                bot_manager_context_in=args.bot_manager_context_in,
                bot_manager_exact_ua_in=args.bot_manager_exact_ua_in,
                cost_estimate_config=args.cost_estimate_config,
                geoip_asn_v4=args.geoip_asn_v4,
                geoip_asn_v6=args.geoip_asn_v6,
                impact_lane_totals_in=args.impact_lane_totals_in,
                impact_lane_scoped_hunt_in=args.impact_lane_scoped_hunt_in,
            )
            replay_local_validation = validate_replay_local_input_manifest(replay_local_manifest)
        summary_parquet_glob = args.summary_parquet_glob
        if summary_parquet_glob:
            if audit:
                audit.artifact(
                    stage_id="summary_input",
                    role="summary",
                    path_value=summary_parquet_glob,
                    source="supplied",
                )
        elif threat_hunt_full_required:
            summary_path = sample_dir / "threat_hunt-summary.json"
            summary_plan = (
                threat_hunt_harvest_plan.get("summary")
                if isinstance(threat_hunt_harvest_plan, dict)
                else {}
            )
            summary_granularity = str(
                (summary_plan or {}).get("granularity") or choose_granularity(start, end)
            )
            planned_summary_table = str(
                (summary_plan or {}).get("table") or f"{args.database}.bi_summary_{summary_granularity}"
            )
            if audit:
                audit.decision(
                    stage_id="summary_export",
                    decision="selected_summary_table",
                    rationale="Summary table was resolved by the harvest plan.",
                    granularity=summary_granularity,
                    table=planned_summary_table,
                )
            with provenance_stage("summary_export"):
                export_threat_hunt_summary(
                    output=str(summary_path),
                    start=args.start,
                    end=args.end,
                    baseline_start=baseline_start.isoformat().replace("+00:00", "Z"),
                    baseline_end=baseline_end.isoformat().replace("+00:00", "Z"),
                    cluster=args.cluster,
                    database=args.database,
                    granularity=summary_granularity,
                    allow_legacy_fallback=bool((summary_plan or {}).get("allow_legacy_fallback", True)),
                    planned_table=planned_summary_table,
                )
            summary_parquet_glob = str(summary_path)
            if audit:
                audit.artifact(
                    stage_id="summary_export",
                    role="summary",
                    path_value=summary_path,
                    source="generated",
                )
        raw_actor_dir = args.raw_actor_dir
        if raw_actor_dir is None:
            raw_actor_dir = str(sample_dir / "threat_hunt-actors")
            with provenance_stage("raw_actor_fixtures"):
                export_raw_actor_fixtures_runner(
                    actor_dir=raw_actor_dir,
                    start=args.start,
                    end=args.end,
                    baseline_start=baseline_start.isoformat().replace("+00:00", "Z"),
                    baseline_end=baseline_end.isoformat().replace("+00:00", "Z"),
                    cluster=args.cluster,
                    database=args.database,
                    top_n=args.top_n,
                    hydrolix_log_ingest_bytes_column=args.hydrolix_log_ingest_bytes_column,
                    chunk_seconds=int(
                        ((threat_hunt_harvest_plan or {}).get("raw_actor") or {}).get(
                            "chunk_seconds", args.raw_actor_chunk_seconds
                        )
                    ),
                    extraction_mode=str(
                        ((threat_hunt_harvest_plan or {}).get("raw_actor") or {}).get(
                            "extraction_mode", args.raw_actor_extraction_mode
                        )
                    ),
                    hash_buckets=int(
                        ((threat_hunt_harvest_plan or {}).get("raw_actor") or {}).get(
                            "hash_buckets", args.raw_actor_hash_buckets
                        )
                    ),
                    topk_candidate_multiplier=int(
                        ((threat_hunt_harvest_plan or {}).get("raw_actor") or {}).get(
                            "topk_candidate_multiplier", args.raw_actor_topk_candidate_multiplier
                        )
                    ),
                    replay_grade=threat_hunt_full_required,
                )
            if audit:
                for actor_path in sorted(Path(raw_actor_dir).glob("*.json")):
                    audit.artifact(
                        stage_id="raw_actor_fixtures",
                        role="raw_actor",
                        path_value=actor_path,
                        source="generated",
                    )
        elif audit:
            for actor_path in sorted(Path(raw_actor_dir).expanduser().glob("*.json")):
                audit.artifact(
                    stage_id="raw_actor_fixtures",
                    role="raw_actor",
                    path_value=actor_path,
                    source="supplied",
                )
        hydrolix_log_ingest_usagemeter_in = args.hydrolix_log_ingest_usagemeter_in
        usagemeter_plan = (
            threat_hunt_harvest_plan.get("hydrolix_usagemeter")
            if isinstance(threat_hunt_harvest_plan, dict)
            else {}
        )
        planned_usagemeter_project_id = (
            (usagemeter_plan or {}).get("project_deployment_id")
            if isinstance(usagemeter_plan, dict)
            else None
        )
        planned_usagemeter_table_name = (
            (usagemeter_plan or {}).get("table_name")
            if isinstance(usagemeter_plan, dict)
            else None
        )
        hydrolix_usagemeter_query = (
            "required"
            if threat_hunt_full_required and hydrolix_log_ingest_usagemeter_in is None
            else args.hydrolix_log_ingest_usagemeter_query
        )
        if hydrolix_log_ingest_usagemeter_in and audit:
            audit.artifact(
                stage_id="hydrolix_usagemeter",
                role="hydrolix_usagemeter",
                path_value=hydrolix_log_ingest_usagemeter_in,
                source="supplied",
            )
        if (
            hydrolix_log_ingest_usagemeter_in is None
            and hydrolix_usagemeter_query != "off"
        ):
            usagemeter_path = sample_dir / "threat_hunt-hydrolix-usagemeter.json"
            try:
                with provenance_stage("hydrolix_usagemeter"):
                    export_hydrolix_usagemeter_ingest_estimate(
                        output=str(usagemeter_path),
                        start=args.start,
                        end=args.end,
                        baseline_start=baseline_start.isoformat().replace("+00:00", "Z"),
                        baseline_end=baseline_end.isoformat().replace("+00:00", "Z"),
                        cluster=args.cluster,
                        database=args.database,
                        project_deployment_id=planned_usagemeter_project_id
                        if isinstance(planned_usagemeter_project_id, str)
                        else args.hydrolix_log_ingest_usagemeter_project_deployment_id,
                        table_name=planned_usagemeter_table_name
                        if isinstance(planned_usagemeter_table_name, str)
                        else args.hydrolix_log_ingest_usagemeter_table_name,
                    )
                hydrolix_log_ingest_usagemeter_in = str(usagemeter_path)
                if audit:
                    audit.artifact(
                        stage_id="hydrolix_usagemeter",
                        role="hydrolix_usagemeter",
                        path_value=usagemeter_path,
                        source="generated",
                    )
            except SystemExit:
                if hydrolix_usagemeter_query == "required":
                    raise
                print(
                    "WARNING: hydro.logs usagemeter Hydrolix log-ingest estimate unavailable; Hydrolix ingest lane remains unavailable.",
                    file=sys.stderr,
                )
        cooccurrence_in = args.cooccurrence_in
        if cooccurrence_in and audit:
            audit.artifact(
                stage_id="cooccurrence",
                role="cooccurrence",
                path_value=cooccurrence_in,
                source="supplied",
            )
        if cooccurrence_in is None and threat_hunt_full_required:
            cooccurrence_path = sample_dir / "threat_hunt-cooccurrence.json"
            with provenance_stage("cooccurrence"):
                rows = export_raw_ua_cooccurrence(
                    actor_dir=raw_actor_dir,
                    start=args.start,
                    end=args.end,
                    cluster=args.cluster,
                    database=args.database,
                    top_n=args.top_n,
                    output=str(cooccurrence_path),
                    replay_grade=threat_hunt_full_required,
                )
            if not rows:
                raise SystemExit("full-required threat-hunt cooccurrence export produced no rows.")
            cooccurrence_in = str(cooccurrence_path)
            if audit:
                audit.artifact(
                    stage_id="cooccurrence",
                    role="cooccurrence",
                    path_value=cooccurrence_path,
                    source="generated",
                )
        scraper_drilldown_in = args.scraper_drilldown_in
        if scraper_drilldown_in and audit:
            audit.artifact(
                stage_id="scraper_drilldown",
                role="scraper_drilldown",
                path_value=scraper_drilldown_in,
                source="supplied",
            )
        if scraper_drilldown_in is None and threat_hunt_full_required:
            drilldown_path = sample_dir / "threat_hunt-scraper-drilldown.json"
            with provenance_stage("scraper_drilldown_scope"):
                scope = scraper_drilldown_scope(
                    actor_dir=raw_actor_dir,
                    cooccurrence_in=cooccurrence_in,
                    start=args.start,
                    end=args.end,
                    database=args.database,
                    top_leads=args.top_n,
                )
            if audit:
                audit.decision(
                    stage_id="scraper_drilldown_scope",
                    decision="selected_scraper_scope",
                    rationale="Selected top current-window user agents and public client IPs by request volume/cooccurrence.",
                    selected_user_agents=scope.get("selected_user_agents"),
                    selected_client_ips=scope.get("selected_client_ips"),
                    excluded_non_public_client_ips=scope.get("excluded_non_public_client_ips"),
                    chunks=scope.get("chunks"),
                    first_sql=scope.get("first_sql"),
                )
            with provenance_stage("scraper_drilldown"):
                rows = export_scraper_drilldowns(
                    actor_dir=raw_actor_dir,
                    cooccurrence_in=cooccurrence_in,
                    start=args.start,
                    end=args.end,
                    cluster=args.cluster,
                    database=args.database,
                    top_leads=args.top_n,
                    output=str(drilldown_path),
                    replay_grade=threat_hunt_full_required,
                )
            if not rows:
                raise SystemExit("full-required threat-hunt scraper drilldown export produced no rows.")
            scraper_drilldown_in = str(drilldown_path)
            if audit:
                audit.artifact(
                    stage_id="scraper_drilldown",
                    role="scraper_drilldown",
                    path_value=drilldown_path,
                    source="generated",
                )
        scraper_hourly_in = args.scraper_hourly_in
        if scraper_hourly_in and audit:
            audit.artifact(
                stage_id="scraper_hourly",
                role="scraper_hourly",
                path_value=scraper_hourly_in,
                source="supplied",
            )
        if scraper_hourly_in is None and threat_hunt_full_required:
            hourly_path = sample_dir / "threat_hunt-scraper-hourly.json"
            hourly_summary: dict[str, object] = {}
            with provenance_stage("scraper_hourly"):
                rows = export_scraper_hourly_profiles(
                    actor_dir=raw_actor_dir,
                    cooccurrence_in=cooccurrence_in,
                    start=args.start,
                    end=args.end,
                    cluster=args.cluster,
                    database=args.database,
                    top_leads=args.top_n,
                    output=str(hourly_path),
                    run_summary=hourly_summary,
                    replay_grade=threat_hunt_full_required,
                )
            if not rows:
                raise SystemExit("full-required threat-hunt scraper hourly export produced no rows.")
            scraper_hourly_in = str(hourly_path)
            if audit:
                audit.decision(
                    stage_id="scraper_hourly",
                    decision="selected_hourly_user_agents",
                    rationale="Selected top current-window user agents by actor/cooccurrence request volume.",
                    **hourly_summary,
                )
                audit.artifact(
                    stage_id="scraper_hourly",
                    role="scraper_hourly",
                    path_value=hourly_path,
                    source="generated",
                )
        fanout_strategy = args.fanout_strategy
        if args.ua_fanout_query in {"summary_hour", "logs_probe", "skip"}:
            fanout_strategy = args.ua_fanout_query
        elif args.ua_fanout_query == "off":
            fanout_strategy = "skip"
        if threat_hunt_full_required:
            fanout_strategy = str(((threat_hunt_harvest_plan or {}).get("fanout") or {}).get("strategy"))
            if fanout_strategy in {"", "None", "auto"}:
                raise SystemExit("full-required threat-hunt harvest plan must resolve fanout.strategy.")
        ua_fanout_query = "required" if threat_hunt_full_required else args.ua_fanout_query
        fanout_in = args.fanout_in or args.ua_fanout_in
        if fanout_in and audit:
            audit.artifact(
                stage_id="fanout",
                role="fanout",
                path_value=fanout_in,
                source="supplied",
            )
        if fanout_in is None and fanout_strategy != "skip":
            fanout_path = sample_dir / "threat_hunt-fanout.json"
            try:
                fanout_summary: dict[str, object] = {}
                with provenance_stage("fanout"):
                    rows = export_fanout_enrichment(
                        actor_dir=raw_actor_dir,
                        start=args.start,
                        end=args.end,
                        cluster=args.cluster,
                        database=args.database,
                        top_leads=args.top_n,
                        output=str(fanout_path),
                        strategy=fanout_strategy,
                        scraper_hourly_in=scraper_hourly_in,
                        cooccurrence_in=cooccurrence_in,
                        run_summary=fanout_summary,
                        replay_grade=threat_hunt_full_required,
                    )
                if threat_hunt_full_required and not rows:
                    raise SystemExit("full-required threat-hunt fanout export produced no rows.")
                fanout_in = str(fanout_path)
                if audit:
                    audit.decision(
                        stage_id="fanout",
                        decision="selected_fanout_strategy",
                        rationale="Fanout strategy follows CLI/default strategy and available summary/log/cooccurrence evidence.",
                        **fanout_summary,
                    )
                    audit.artifact(
                        stage_id="fanout",
                        role="fanout",
                        path_value=fanout_path,
                        source="generated",
                    )
            except SystemExit:
                if ua_fanout_query == "required":
                    raise
                print(
                    "WARNING: source-aware fanout enrichment unavailable; falling back to supplied cooccurrence lower-bound counts.",
                    file=sys.stderr,
                )
        elif fanout_in is None and fanout_strategy == "skip" and cooccurrence_in:
            fanout_path = sample_dir / "threat_hunt-fanout.json"
            with provenance_stage("fanout"):
                export_fanout_enrichment(
                    actor_dir=raw_actor_dir,
                    start=args.start,
                    end=args.end,
                    cluster=args.cluster,
                    database=args.database,
                    top_leads=args.top_n,
                    output=str(fanout_path),
                    strategy="skip",
                    cooccurrence_in=cooccurrence_in,
                    replay_grade=threat_hunt_full_required,
                )
            fanout_in = str(fanout_path)
            if audit:
                audit.artifact(
                    stage_id="fanout",
                    role="fanout",
                    path_value=fanout_path,
                    source="generated",
                )
        selected_user_agents: list[str] = []
        current_ua_path = Path(raw_actor_dir) / "expedia-actors-current-user_agent.json"
        if current_ua_path.exists():
            try:
                value = json.loads(current_ua_path.read_text(encoding="utf-8"))
                rows = value.get("rows") if isinstance(value, dict) else value
                if isinstance(rows, list):
                    rows = sorted(
                        [row for row in rows if isinstance(row, dict)],
                        key=lambda row: (-float(row.get("requests") or 0), str(row.get("user_agent") or row.get("value") or "")),
                    )
                    selected_user_agents = [
                        str(row.get("user_agent") or row.get("value"))
                        for row in rows[: args.top_n]
                        if row.get("user_agent") or row.get("value")
                    ]
            except (OSError, ValueError, TypeError):
                selected_user_agents = []
        background_ua_sample_in = args.background_ua_sample_in
        background_query = "required" if threat_hunt_full_required else args.background_query
        if background_ua_sample_in and audit:
            audit.artifact(
                stage_id="background_ua_sample",
                role="background_ua_sample",
                path_value=background_ua_sample_in,
                source="supplied",
            )
        if background_ua_sample_in is None and background_query in {"auto", "required"}:
            background_path = sample_dir / "threat_hunt-background-ua-sample.json"
            try:
                background_summary: dict[str, object] = {}
                with provenance_stage("background_ua_sample"):
                    rows = export_background_ua_sample(
                        start=args.start,
                        end=args.end,
                        cluster=args.cluster,
                        database=args.database,
                        excluded_user_agents=selected_user_agents,
                        output=str(background_path),
                        run_summary=background_summary,
                        replay_grade=threat_hunt_full_required,
                    )
                if threat_hunt_full_required and not rows:
                    raise SystemExit("full-required threat-hunt background UA sample produced no rows.")
                background_ua_sample_in = str(background_path)
                if audit:
                    audit.decision(
                        stage_id="background_ua_sample",
                        decision="excluded_selected_user_agents",
                        rationale="Background sample excludes selected lead user agents so rates represent organic mid-volume comparators.",
                        excluded_user_agents=selected_user_agents,
                        **background_summary,
                    )
                    audit.artifact(
                        stage_id="background_ua_sample",
                        role="background_ua_sample",
                        path_value=background_path,
                        source="generated",
                    )
            except SystemExit:
                if background_query == "required":
                    raise
                print(
                    "WARNING: background UA sample query unavailable; confidence background rates marked unavailable.",
                    file=sys.stderr,
                )
        baseline_ua_timeseries_in = args.baseline_ua_timeseries_in
        baseline_significance_query = (
            "required" if threat_hunt_full_required else args.baseline_significance_query
        )
        if baseline_ua_timeseries_in and audit:
            audit.artifact(
                stage_id="baseline_ua_timeseries",
                role="baseline_ua_timeseries",
                path_value=baseline_ua_timeseries_in,
                source="supplied",
            )
        if baseline_ua_timeseries_in is None and baseline_significance_query in {"auto", "required"}:
            baseline_ua_path = sample_dir / "threat_hunt-baseline-ua-timeseries.json"
            try:
                baseline_summary: dict[str, object] = {}
                baseline_granularity = "hour" if (end - baseline_start).total_seconds() <= 172800 else "day"
                with provenance_stage("baseline_ua_timeseries"):
                    rows = export_baseline_ua_timeseries(
                        baseline_start=baseline_start.isoformat().replace("+00:00", "Z"),
                        baseline_end=baseline_end.isoformat().replace("+00:00", "Z"),
                        user_agents=selected_user_agents,
                        cluster=args.cluster,
                        database=args.database,
                        output=str(baseline_ua_path),
                        granularity=baseline_granularity,
                        run_summary=baseline_summary,
                        replay_grade=threat_hunt_full_required,
                    )
                if threat_hunt_full_required and not rows:
                    raise SystemExit("full-required threat-hunt baseline UA timeseries produced no rows.")
                baseline_ua_timeseries_in = str(baseline_ua_path)
                if audit:
                    audit.decision(
                        stage_id="baseline_ua_timeseries",
                        decision="selected_baseline_user_agents",
                        rationale="Baseline significance samples the selected current-window lead user agents.",
                        **baseline_summary,
                    )
                    audit.artifact(
                        stage_id="baseline_ua_timeseries",
                        role="baseline_ua_timeseries",
                        path_value=baseline_ua_path,
                        source="generated",
                    )
            except SystemExit:
                if baseline_significance_query == "required":
                    raise
                print(
                    "WARNING: baseline UA timeseries query unavailable; baseline z-scores marked unavailable.",
                    file=sys.stderr,
                )
        artifact = build_threat_hunt_artifact(
            cluster=args.cluster,
            database=args.database,
            summary_parquet_glob=summary_parquet_glob,
            start=args.start,
            end=args.end,
            baseline_start=baseline_start.isoformat().replace("+00:00", "Z"),
            baseline_end=baseline_end.isoformat().replace("+00:00", "Z"),
            raw_actor_dir=raw_actor_dir,
            top_n=args.top_n,
            geoip_asn_v4=args.geoip_asn_v4,
            geoip_asn_v6=args.geoip_asn_v6,
            cooccurrence_in=cooccurrence_in,
            cooccurrence_path_in=args.cooccurrence_path_in,
            scraper_drilldown_in=scraper_drilldown_in,
            scraper_hourly_in=scraper_hourly_in,
            fanout_in=fanout_in,
            fanout_strategy=fanout_strategy,
            ua_fanout_in=args.ua_fanout_in,
            ua_fanout_query=ua_fanout_query,
            iat_sample_in=args.iat_sample_in,
            background_ua_sample_in=background_ua_sample_in,
            background_query=background_query,
            baseline_ua_timeseries_in=baseline_ua_timeseries_in,
            baseline_significance_query=baseline_significance_query,
            edge_response_in=args.edge_response_in,
            bot_manager_context_in=args.bot_manager_context_in,
            bot_manager_exact_ua_in=args.bot_manager_exact_ua_in,
            cost_estimate_config=args.cost_estimate_config,
            hydrolix_log_ingest_usagemeter_in=hydrolix_log_ingest_usagemeter_in,
            hydrolix_log_ingest_project_deployment_id=planned_usagemeter_project_id
            if isinstance(planned_usagemeter_project_id, str)
            else args.hydrolix_log_ingest_usagemeter_project_deployment_id,
            hydrolix_log_ingest_table_name=planned_usagemeter_table_name
            if isinstance(planned_usagemeter_table_name, str)
            else args.hydrolix_log_ingest_usagemeter_table_name,
            require_replay_grade=threat_hunt_full_required or threat_hunt_replay_local,
        )
        impact_lane_query = "required" if threat_hunt_full_required else args.impact_lane_query
        lane_totals_in = args.impact_lane_totals_in
        lane_scoped_in = args.impact_lane_scoped_hunt_in
        if impact_lane_query != "off":
            impact_lane_required = impact_lane_query == "required"
            if lane_totals_in and audit:
                audit.artifact(
                    stage_id="impact_lanes",
                    role="impact_lane_totals",
                    path_value=lane_totals_in,
                    source="supplied",
                )
            if lane_scoped_in and audit:
                audit.artifact(
                    stage_id="impact_lanes",
                    role="impact_lane_scoped_hunt",
                    path_value=lane_scoped_in,
                    source="supplied",
                )
            try:
                if lane_totals_in is None:
                    lane_totals_path = sample_dir / "threat_hunt-impact-lane-totals.json"
                    with provenance_stage("impact_lane_totals"):
                        rows = export_impact_lane_totals(
                            output=str(lane_totals_path),
                            start=args.start,
                            end=args.end,
                            baseline_start=baseline_start.isoformat().replace("+00:00", "Z"),
                            baseline_end=baseline_end.isoformat().replace("+00:00", "Z"),
                            cluster=args.cluster,
                            database=args.database,
                            replay_grade=threat_hunt_full_required,
                        )
                    if threat_hunt_full_required and not rows:
                        raise SystemExit("full-required threat-hunt impact lane totals produced no rows.")
                    lane_totals_in = str(lane_totals_path)
                    if audit:
                        audit.artifact(
                            stage_id="impact_lane_totals",
                            role="impact_lane_totals",
                            path_value=lane_totals_path,
                            source="generated",
                        )
                if lane_scoped_in is None:
                    lane_scoped_path = sample_dir / "threat_hunt-impact-lane-scoped-hunt.json"
                    hunt_user_agents = [
                        str(ua)
                        for ua in (
                            ((artifact.get("impact_assessment") or {}).get("hunt") or {}).get("user_agents")
                            or []
                        )
                        if str(ua)
                    ]
                    if audit:
                        audit.decision(
                            stage_id="impact_lane_scoped_hunt",
                            decision="selected_hunt_user_agents",
                            rationale="Impact lane scope uses high/partial confidence threat-hunt user agents from the deterministic artifact.",
                            selected_user_agents=hunt_user_agents,
                        )
                    with provenance_stage("impact_lane_scoped_hunt"):
                        rows = export_impact_lane_scoped_hunt(
                            output=str(lane_scoped_path),
                            start=args.start,
                            end=args.end,
                            baseline_start=baseline_start.isoformat().replace("+00:00", "Z"),
                            baseline_end=baseline_end.isoformat().replace("+00:00", "Z"),
                            cluster=args.cluster,
                            database=args.database,
                            user_agents=hunt_user_agents,
                            replay_grade=threat_hunt_full_required,
                        )
                    if threat_hunt_full_required and not rows:
                        raise SystemExit("full-required threat-hunt scoped impact lanes produced no rows.")
                    lane_scoped_in = str(lane_scoped_path)
                    if audit:
                        audit.artifact(
                            stage_id="impact_lane_scoped_hunt",
                            role="impact_lane_scoped_hunt",
                            path_value=lane_scoped_path,
                            source="generated",
                        )
                if threat_hunt_full_required:
                    validate_replay_grade_dataset(
                        Path(lane_totals_in).expanduser().resolve(),
                        role="impact_lane_totals",
                    )
                    validate_replay_grade_dataset(
                        Path(lane_scoped_in).expanduser().resolve(),
                        role="impact_lane_scoped_hunt",
                    )
                merge_impact_lanes_into_artifact(
                    artifact,
                    total_rows=read_impact_lane_rows(lane_totals_in),
                    scoped_hunt_rows=read_impact_lane_rows(lane_scoped_in),
                    required=impact_lane_required,
                )
            except SystemExit:
                if impact_lane_required:
                    raise
                print(
                    "WARNING: raw-log impact lane export/merge unavailable; keeping summary-derived impact lanes.",
                    file=sys.stderr,
                )
        artifact_input_manifest = build_threat_hunt_input_manifest(
            summary_parquet_glob=summary_parquet_glob,
            raw_actor_dir=raw_actor_dir,
            hydrolix_log_ingest_usagemeter_in=hydrolix_log_ingest_usagemeter_in,
            cooccurrence_in=cooccurrence_in,
            cooccurrence_path_in=args.cooccurrence_path_in,
            scraper_drilldown_in=scraper_drilldown_in,
            scraper_hourly_in=scraper_hourly_in,
            fanout_in=fanout_in,
            iat_sample_in=args.iat_sample_in,
            background_ua_sample_in=background_ua_sample_in,
            baseline_ua_timeseries_in=baseline_ua_timeseries_in,
            edge_response_in=args.edge_response_in,
            bot_manager_context_in=args.bot_manager_context_in,
            bot_manager_exact_ua_in=args.bot_manager_exact_ua_in,
            cost_estimate_config=args.cost_estimate_config,
            geoip_asn_v4=args.geoip_asn_v4,
            geoip_asn_v6=args.geoip_asn_v6,
            impact_lane_totals_in=lane_totals_in,
            impact_lane_scoped_hunt_in=lane_scoped_in,
        )
        artifact_metadata = artifact.setdefault("artifact_metadata", {})
        artifact_metadata["input_manifest"] = artifact_input_manifest
        if isinstance(threat_hunt_harvest_plan, dict):
            artifact_metadata["harvest_plan"] = _harvest_plan_metadata(threat_hunt_harvest_plan)
        if threat_hunt_replay_local:
            replay_local_validation = validate_replay_local_input_manifest(artifact_input_manifest)
            artifact_metadata["replay_policy"] = build_threat_hunt_replay_policy(
                enabled=True,
                input_manifest=artifact_input_manifest,
                validation=replay_local_validation,
            )
        artifact_path.write_text(
            json.dumps(artifact, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        if audit:
            audit.artifact(
                stage_id="artifact_build",
                role="threat_hunt_artifact",
                path_value=artifact_path,
                source="generated",
            )
        if args.mode == "evidence":
            output_path.write_text(
                json.dumps(artifact, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        elif args.mode == "template":
            output_path.write_text(
                "# Threat Hunt Interpretation\n\n"
                "Summarize only the deterministic evidence in this artifact. "
                "Do not claim malicious intent, operator identity, or cross-customer reuse.\n",
                encoding="utf-8",
            )
        else:
            wrapper = build_report_wrapper(
                args=args,
                artifacts=[artifact],
                analyst_note=analyst_note_from_args(args),
            )
            wrapper["input_manifest"] = build_threat_hunt_input_manifest(
                summary_parquet_glob=summary_parquet_glob,
                raw_actor_dir=raw_actor_dir,
                hydrolix_log_ingest_usagemeter_in=hydrolix_log_ingest_usagemeter_in,
                cooccurrence_in=cooccurrence_in,
                cooccurrence_path_in=args.cooccurrence_path_in,
                scraper_drilldown_in=scraper_drilldown_in,
                scraper_hourly_in=scraper_hourly_in,
                fanout_in=fanout_in,
                iat_sample_in=args.iat_sample_in,
                background_ua_sample_in=background_ua_sample_in,
                baseline_ua_timeseries_in=baseline_ua_timeseries_in,
                edge_response_in=args.edge_response_in,
                bot_manager_context_in=args.bot_manager_context_in,
                bot_manager_exact_ua_in=args.bot_manager_exact_ua_in,
                cost_estimate_config=args.cost_estimate_config,
                geoip_asn_v4=args.geoip_asn_v4,
                geoip_asn_v6=args.geoip_asn_v6,
                impact_lane_totals_in=lane_totals_in,
                impact_lane_scoped_hunt_in=lane_scoped_in,
                threat_hunt_artifact=artifact_path,
            )
            if isinstance(threat_hunt_harvest_plan, dict):
                wrapper["harvest_plan"] = _harvest_plan_metadata(threat_hunt_harvest_plan)
            if threat_hunt_replay_local:
                wrapper["replay_policy"] = build_threat_hunt_replay_policy(
                    enabled=True,
                    input_manifest=artifact_input_manifest,
                    validation=replay_local_validation,
                )
            wrapper_path.write_text(
                json.dumps(wrapper, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            if audit:
                audit.artifact(
                    stage_id="wrapper_build",
                    role="threat_hunt_wrapper",
                    path_value=wrapper_path,
                    source="generated",
                )
            run(
                render_report_command(
                    wrapper_path=wrapper_path,
                    output_path=output_path,
                    output_format=args.format,
                    config_path=args.config,
                    title=args.title,
                ),
                cwd=PUBLIC_SKILLS,
            )
        if audit:
            audit.artifact(
                stage_id="output",
                role="selected_output",
                path_value=output_path,
                source="generated",
            )
            audit.manifest(
                status="ok",
                outputs={
                    "artifact": str(artifact_path),
                    "wrapper": str(wrapper_path) if wrapper_path.exists() else None,
                    "output": str(output_path),
                    "raw_actor_dir": raw_actor_dir,
                },
            )
            validate_threat_hunt_full_required_provenance(sample_dir / "threat_hunt-provenance.json")
            set_provenance_recorder(None)
        print(
            json.dumps(
                {
                    "artifact": str(artifact_path),
                    "audit": str(sample_dir / "threat_hunt-audit.jsonl") if audit else None,
                    "cluster": args.cluster,
                    "database": args.database,
                    "harvest": args.threat_hunt_harvest,
                    "mode": args.mode,
                    "output": str(output_path),
                    "provenance": str(sample_dir / "threat_hunt-provenance.json") if audit else None,
                    "raw_actor_dir": raw_actor_dir,
                    "rows": len(artifact.get("endpoints") or []),
                    "table_used": "local_summary_parquet",
                },
                sort_keys=True,
            )
        )
        return 0

    raw_path = sample_dir / f"{args.report}-raw.json"
    artifact_path = sample_dir / f"{args.report}-artifact.json"
    timeseries_raw_path = sample_dir / f"{args.report}-timeseries-raw.json"
    timeseries_artifact_path = sample_dir / f"{args.report}-timeseries.json"
    path_raw_path = sample_dir / f"{args.report}-path-raw.json"
    path_artifact_path = sample_dir / f"{args.report}-path-artifact.json"
    wrapper_path = sample_dir / f"{args.report}-wrapper.json"
    output_path = Path(args.output).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if args.report == "executive_posture":
        sql = executive_posture_sql(args.database, start, end, baseline_start)
        granularity = choose_granularity(start, end)
        table_used = f"{args.database}.bi_summary_{granularity}"
        compare_schema = "posture"
    elif args.report == "control_review":
        sql = control_review_sql(
            args.database,
            start,
            end,
            baseline_start,
            args.policy_id,
            args.control_source,
        )
        granularity = choose_granularity(start, end)
        if args.control_source == "posture":
            table_used = f"{args.database}.bi_summary_{granularity}"
        else:
            table_used = f"{args.database}.bi_siem_policy_summary_{granularity}"
        compare_schema = "control"
    elif args.report == "scorecard_brief":
        sql = scorecard_sql(
            args.database,
            start,
            end,
            baseline_start,
            args.entity_type,
            args.scorecard_limit,
        )
        granularity = choose_granularity(start, end)
        table_used = f"{args.database}.bi_summary_{granularity}"
        compare_schema = None
    elif args.report == "soc_triage":
        sql = scorecard_soc_sql(
            args.database,
            start,
            end,
            baseline_start,
            args.entity_type,
            args.scorecard_limit,
        )
        granularity = choose_granularity(start, end)
        table_used = f"{args.database}.bi_siem_policy_summary_{granularity}"
        compare_schema = None
    elif args.report == "crawler_governance":
        sql = scorecard_crawler_sql(
            args.database,
            start,
            end,
            baseline_start,
            args.entity_type,
            args.scorecard_limit,
        )
        granularity = choose_granularity(start, end)
        table_used = f"{args.database}.bi_summary_{granularity}"
        compare_schema = None
    elif args.report == "edge_ops_impact":
        sql = scorecard_edge_ops_sql(
            args.database,
            start,
            end,
            baseline_start,
            args.entity_type,
            args.scorecard_limit,
        )
        granularity = choose_granularity(start, end)
        table_used = f"{args.database}.bi_summary_{granularity}"
        compare_schema = None
    else:
        raise AssertionError(args.report)

    capture_summary: dict[str, object] = {"rows": None}
    raw_timeseries_value: dict | None = None
    raw_path_value: dict | None = None
    if args.raw_input:
        raw_value = load_raw_query_result(Path(args.raw_input).expanduser().resolve())
        if args.report == "control_review" and timeseries_raw_path.exists():
            raw_timeseries_value = load_raw_query_result(timeseries_raw_path)
        if args.report == "edge_ops_impact":
            if args.raw_path_input:
                raw_path_value = load_raw_query_result(
                    Path(args.raw_path_input).expanduser().resolve()
                )
            elif args.include_paths:
                print(
                    "WARNING: --raw-path-input not supplied for edge_ops_impact; "
                    "path-grain artifact will be omitted.",
                    file=sys.stderr,
                )
    else:
        try:
            capture_summary_text = run(
                [
                    sys.executable,
                    str(CAPTURE),
                    "--cluster",
                    args.cluster,
                    "--database",
                    args.database,
                    "--sql",
                    sql,
                    "--output",
                    str(raw_path),
                ],
                allowed_returncodes=(NEEDS_MCP_EXIT,),
            )
        except SystemExit as exc:
            # SOC triage depends on bi_siem_policy_summary_<granularity>,
            # which is not deployed on every cluster. Without SIEM data the
            # script cannot produce a SOC report, so warn clearly and exit
            # cleanly rather than crash with a raw capture traceback.
            if args.report == "soc_triage":
                print(
                    "WARNING: SOC capture failed; "
                    f"{table_used} may not be deployed on this cluster ({exc}). "
                    "soc_triage requires SIEM policy summary data; skipping report.",
                    file=sys.stderr,
                )
                return 0
            raise
        try:
            capture_summary = json.loads(capture_summary_text)
        except json.JSONDecodeError as exc:
            raise SystemExit("Capture did not return machine-readable JSON.") from exc
        if (
            isinstance(capture_summary, dict)
            and capture_summary.get("schema_version") == HANDOFF_SCHEMA
        ):
            report_context = capture_summary.get("report_context")
            if not isinstance(report_context, dict):
                report_context = {}
            report_context.update(
                {
                    "report": args.report,
                    "mode": args.mode,
                    "start": args.start,
                    "end": args.end,
                    "baseline_start": baseline_start.isoformat().replace("+00:00", "Z"),
                    "table_used": table_used,
                    "granularity": granularity,
                }
            )
            if args.report in {
                "scorecard_brief",
                "soc_triage",
                "crawler_governance",
                "edge_ops_impact",
            }:
                report_context.update(
                    {
                        "entity_type": args.entity_type,
                        "entity_value": args.entity_value,
                        "producer_limit": args.scorecard_limit,
                        "analysis_domains": args.domains,
                    }
                )
            if args.report == "edge_ops_impact":
                report_context["artifact"] = "scorecard"
            capture_summary["report_context"] = report_context
            print(json.dumps(capture_summary, sort_keys=True))
            return NEEDS_MCP_EXIT
        raw_value = load_raw_query_result(raw_path)
        if args.report == "control_review":
            timeseries_sql = control_review_timeseries_sql(
                args.database,
                start,
                end,
                baseline_start,
                args.policy_id,
                args.control_source,
            )
            timeseries_summary_text = run(
                [
                    sys.executable,
                    str(CAPTURE),
                    "--cluster",
                    args.cluster,
                    "--database",
                    args.database,
                    "--sql",
                    timeseries_sql,
                    "--output",
                    str(timeseries_raw_path),
                ],
                allowed_returncodes=(NEEDS_MCP_EXIT,),
            )
            try:
                timeseries_summary = json.loads(timeseries_summary_text)
            except json.JSONDecodeError as exc:
                raise SystemExit(
                    "Timeseries capture did not return machine-readable JSON."
                ) from exc
            if (
                isinstance(timeseries_summary, dict)
                and timeseries_summary.get("schema_version") == HANDOFF_SCHEMA
            ):
                report_context = timeseries_summary.get("report_context")
                if not isinstance(report_context, dict):
                    report_context = {}
                report_context.update(
                    {
                        "report": args.report,
                        "mode": args.mode,
                        "artifact": "timeseries",
                        "start": args.start,
                        "end": args.end,
                        "baseline_start": baseline_start.isoformat().replace(
                            "+00:00", "Z"
                        ),
                        "table_used": table_used,
                        "granularity": granularity,
                    }
                )
                timeseries_summary["report_context"] = report_context
                print(json.dumps(timeseries_summary, sort_keys=True))
                return NEEDS_MCP_EXIT
            raw_timeseries_value = load_raw_query_result(timeseries_raw_path)
        if args.report == "edge_ops_impact" and args.include_paths:
            path_grain_sql = cache_origin_path_sql(
                args.database,
                start,
                end,
                baseline_start,
                args.host,
                args.scorecard_limit,
            )
            path_table_used = f"{args.database}.bot_agg_path_{granularity}"
            try:
                path_capture_text = run(
                    [
                        sys.executable,
                        str(CAPTURE),
                        "--cluster",
                        args.cluster,
                        "--database",
                        args.database,
                        "--sql",
                        path_grain_sql,
                        "--output",
                        str(path_raw_path),
                    ],
                    allowed_returncodes=(NEEDS_MCP_EXIT,),
                )
            except SystemExit as exc:
                # Path-grain summary table may not exist on every cluster
                # (bot_agg_path_* is optional infrastructure). Degrade
                # gracefully to entity-grain only. The reader-facing
                # warning is humanized (no raw table name) so that an
                # LLM consuming stderr alongside the evidence packet
                # doesn't paste internal table identifiers into prose;
                # the raw exception text is kept on a separate
                # debug-prefix line for operator triage.
                print(
                    "WARNING: per-path cache data is not available on "
                    "this cluster; the path artifact will be omitted.",
                    file=sys.stderr,
                )
                print(
                    f"DEBUG: path-grain capture failed ({exc}); "
                    f"path table used was {path_table_used}.",
                    file=sys.stderr,
                )
                path_capture_text = ""
            try:
                path_capture_summary = json.loads(path_capture_text) if path_capture_text else {}
            except json.JSONDecodeError:
                print(
                    "WARNING: per-path cache data could not be parsed; "
                    "the path artifact will be omitted.",
                    file=sys.stderr,
                )
                path_capture_summary = {}
            if (
                isinstance(path_capture_summary, dict)
                and path_capture_summary.get("schema_version") == HANDOFF_SCHEMA
            ):
                path_report_context = path_capture_summary.get("report_context")
                if not isinstance(path_report_context, dict):
                    path_report_context = {}
                path_report_context.update(
                    {
                        "report": args.report,
                        "mode": args.mode,
                        "artifact": "path",
                        "start": args.start,
                        "end": args.end,
                        "baseline_start": baseline_start.isoformat().replace(
                            "+00:00", "Z"
                        ),
                        "table_used": path_table_used,
                        "granularity": granularity,
                    }
                )
                path_capture_summary["report_context"] = path_report_context
                print(json.dumps(path_capture_summary, sort_keys=True))
                return NEEDS_MCP_EXIT
            if path_raw_path.exists():
                raw_path_value = load_raw_query_result(path_raw_path)

    if args.report == "executive_posture":
        raw_value = add_report_metadata(
            raw_value=raw_value,
            args=args,
            granularity=granularity,
            table_used=table_used,
            baseline_start=baseline_start,
        )
    elif args.report == "control_review":
        raw_value = add_control_metadata(
            raw_value=raw_value,
            args=args,
            granularity=granularity,
            table_used=table_used,
            baseline_start=baseline_start,
        )
    elif args.report in {
        "scorecard_brief",
        "soc_triage",
        "crawler_governance",
        "edge_ops_impact",
    }:
        raw_value = add_scorecard_metadata(
            raw_value=raw_value,
            args=args,
            granularity=granularity,
            table_used=table_used,
            baseline_start=baseline_start,
        )
    else:
        raise AssertionError(args.report)
    raw_path.write_text(
        json.dumps(raw_value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    if args.report in {
        "scorecard_brief",
        "soc_triage",
        "crawler_governance",
        "edge_ops_impact",
    }:
        scorecard_cmd = [
            "uv",
            "run",
            "python",
            "skills/bot-insights/scripts/scorecard.py",
            "--file",
            str(raw_path),
            "--entity-type",
            args.entity_type,
            "--limit",
            str(args.scorecard_limit),
        ]
        if args.domains:
            scorecard_cmd.extend(["--domains", args.domains])
        run(scorecard_cmd, stdout_path=artifact_path, cwd=PUBLIC_SKILLS)
    else:
        run(
            [
                "uv",
                "run",
                "python",
                "skills/bot-insights/scripts/compare_posture.py",
                "--file",
                str(raw_path),
                "--schema",
                compare_schema,
            ],
            stdout_path=artifact_path,
            cwd=PUBLIC_SKILLS,
        )

    artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
    if not isinstance(artifact, dict):
        raise SystemExit(f"Expected {artifact_path} to contain an artifact object.")
    companion_artifacts: list[dict] = []
    path_artifact: dict | None = None
    if args.report == "edge_ops_impact" and raw_path_value is not None:
        path_raw_path.write_text(
            json.dumps(raw_path_value, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        try:
            path_cmd = [
                "uv",
                "run",
                "python",
                "skills/bot-insights/scripts/cache_origin_impact.py",
                "--file",
                str(path_raw_path),
            ]
            run(path_cmd, stdout_path=path_artifact_path, cwd=PUBLIC_SKILLS)
            path_artifact = json.loads(path_artifact_path.read_text(encoding="utf-8"))
            if not isinstance(path_artifact, dict) or not path_artifact.get(
                "candidates"
            ):
                print(
                    "WARNING: path-grain artifact has no candidates; "
                    "path artifact will be omitted.",
                    file=sys.stderr,
                )
                path_artifact = None
        except Exception as exc:  # noqa: BLE001
            print(
                f"WARNING: path-grain processing failed ({exc}); "
                "path artifact will be omitted.",
                file=sys.stderr,
            )
            path_artifact = None
    if args.report == "control_review" and raw_timeseries_value is not None:
        timeseries_artifact = build_timeseries_artifact(
            args=args,
            raw_value=raw_timeseries_value,
            control_artifact=artifact,
            table_used=table_used,
            granularity=granularity,
        )
        if timeseries_artifact.get("metrics"):
            timeseries_artifact_path.write_text(
                json.dumps(timeseries_artifact, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            companion_artifacts.append(timeseries_artifact)
    if args.report == "executive_posture":
        evidence_packet = build_evidence_packet(
            args=args,
            artifact=artifact,
            raw_path=raw_path,
            artifact_path=artifact_path,
            granularity=granularity,
            table_used=table_used,
            baseline_start=baseline_start,
        )
    elif args.report == "control_review":
        evidence_packet = build_control_evidence_packet(
            args=args,
            artifact=artifact,
            raw_path=raw_path,
            artifact_path=artifact_path,
            granularity=granularity,
            table_used=table_used,
            baseline_start=baseline_start,
        )
    elif args.report in {
        "scorecard_brief",
        "soc_triage",
        "crawler_governance",
        "edge_ops_impact",
    }:
        if args.report == "scorecard_brief" and args.fleet:
            # Fleet evidence packet — different shape from the
            # single-entity packet (fleet aggregates instead of
            # selected_entity + evaluated_feature_evidence) so the
            # LLM's prose matches the multi-entity render.
            evidence_packet = build_scorecard_fleet_evidence_packet(
                args=args,
                artifacts=artifact,
                raw_path=raw_path,
                artifact_path=artifact_path,
                granularity=granularity,
                table_used=table_used,
                baseline_start=baseline_start,
            )
        else:
            selected_card = select_scorecard(
                artifact,
                entity_type=args.entity_type if args.entity_value else None,
                entity_value=args.entity_value,
            )
            evidence_packet = build_scorecard_evidence_packet(
                args=args,
                artifacts=artifact,
                selected_card=selected_card,
                raw_path=raw_path,
                artifact_path=artifact_path,
                granularity=granularity,
                table_used=table_used,
                baseline_start=baseline_start,
            )
    else:
        raise AssertionError(args.report)

    # Enrich every emitted evidence packet with reader-friendly
    # ``*_label`` fields and append the label-preference rule to the
    # interpretation_contract. The transformation is additive — every
    # raw identifier is preserved next to its label so the deterministic
    # cross-reference back to the producer artifact still works.
    evidence_packet = humanize_evidence_packet(evidence_packet)

    if args.mode == "evidence":
        output_path.write_text(
            json.dumps(evidence_packet, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    elif args.mode == "template":
        output_path.write_text(
            render_template_packet(evidence_packet), encoding="utf-8"
        )
    else:
        if args.report == "scorecard_brief":
            if args.fleet:
                # Fleet view: keep every emitted scorecard so the
                # engine renders the multi-entity scorecard_brief
                # template (queue table, triage strip, fleet
                # coverage, score landscape) instead of auto-
                # promoting to scorecard_entity_review. The engine's
                # _maybe_promote_singleton only fires when
                # ``len(scorecards) == 1``; including every card
                # keeps the wrapper above that threshold and the
                # ``scorecard_brief`` report_type is preserved.
                scorecards = [
                    card
                    for card in (artifact.get("scorecards") or [])
                    if isinstance(card, dict)
                ]
                if not scorecards:
                    raise SystemExit(
                        "Scorecard artifacts did not contain any "
                        "emitted scorecards; --fleet has nothing to "
                        "render."
                    )
                render_artifacts = []
                if isinstance(artifact.get("index"), dict):
                    render_artifacts.append(artifact["index"])
                render_artifacts.extend(scorecards)
            else:
                selected_card = select_scorecard(
                    artifact,
                    entity_type=args.entity_type if args.entity_value else None,
                    entity_value=args.entity_value,
                )
                render_artifacts = [selected_card]
                if isinstance(artifact.get("index"), dict):
                    render_artifacts.append(artifact["index"])
        elif args.report in {"soc_triage", "crawler_governance"}:
            render_artifacts = []
            if isinstance(artifact.get("index"), dict):
                render_artifacts.append(artifact["index"])
            scorecards = artifact.get("scorecards")
            if isinstance(scorecards, list):
                render_artifacts.extend(
                    card for card in scorecards if isinstance(card, dict)
                )
        elif args.report == "edge_ops_impact":
            render_artifacts = []
            if isinstance(artifact.get("index"), dict):
                render_artifacts.append(artifact["index"])
            scorecards = artifact.get("scorecards")
            if isinstance(scorecards, list):
                render_artifacts.extend(
                    card for card in scorecards if isinstance(card, dict)
                )
            if path_artifact is not None:
                render_artifacts.append(path_artifact)
        else:
            render_artifacts = [artifact, *companion_artifacts]
        wrapper = build_report_wrapper(
            args=args,
            artifacts=render_artifacts,
            analyst_note=analyst_note_from_args(args),
        )
        wrapper_path.write_text(
            json.dumps(wrapper, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        run(
            render_report_command(
                wrapper_path=wrapper_path,
                output_path=output_path,
                output_format=args.format,
                config_path=args.config,
                title=args.title,
            ),
            cwd=PUBLIC_SKILLS,
        )

    print(
        json.dumps(
            {
                "artifact": str(artifact_path),
                "cluster": args.cluster,
                "database": args.database,
                "granularity": granularity,
                "mode": args.mode,
                "raw": str(raw_path),
                "output": str(output_path),
                "rows": capture_summary.get("rows"),
                "table_used": table_used,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
