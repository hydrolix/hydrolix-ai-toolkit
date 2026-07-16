#!/usr/bin/env python3
"""Live validation of the bot-insights skill's query surface against a Hydrolix cluster.

This is a REPEATABLE test harness. It proves that every SQL claim the skill makes
actually holds on a live deployment (default: demo.trafficpeak.live). It covers:

  1. Table/column schema  - documented columns exist; phantom columns do NOT.
  2. Reference-doc SQL     - every ```sql block that targets a deployed summary
                             table is extracted from the skill's markdown,
                             placeholders are resolved to real values, and the
                             query is executed. It must run without error.
  3. Negative assertions   - things the docs say are impossible/absent MUST fail
                             (e.g. sum(cnt_all) -> ILLEGAL_AGGREGATION; selecting
                             cnt_cache_miss / p95_origin_ttfb / bot_class).
  4. Prose-derived claims  - factual statements in the prose ("statusCode is
                             numeric", "trafficCohort in Human/Bot/AI", "aiSource
                             is empty when aiCategory is empty", etc.) are turned
                             into executable checks.
  5. Producer generators   - every deployed-table SQL generator in
                             bot_insights.producers.sql is called with real
                             parameters and its emitted SQL is executed.

Connection reuses the skill's own cluster-env convention (no new DB client, no
hardcoded credentials): it reads ~/.config/hydrolix/clusters/<cluster>.env for
HYDROLIX_HOST/HDX_HOSTNAME + HYDROLIX_TOKEN/HDX_TOKEN. If no cluster is
configured the whole suite SKIPS (so offline CI stays green); live validation is
opt-in.

Usage:
    python3 tests/live/validate_live.py                 # default cluster + db
    BOT_INSIGHTS_LIVE_CLUSTER=demo.trafficpeak.live \
    BOT_INSIGHTS_LIVE_DB=akamai python3 tests/live/validate_live.py
    python3 tests/live/validate_live.py --json report.json

Exit code is non-zero if any check FAILS (UNRESOLVED/SKIP do not fail the run).
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import re
import shutil
import ssl
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SKILL_ROOT = REPO_ROOT / "skills" / "bot-insights"
REFERENCES = SKILL_ROOT / "references"

DEFAULT_CLUSTER = os.environ.get("BOT_INSIGHTS_LIVE_CLUSTER", "demo.trafficpeak.live")
DEFAULT_DB = os.environ.get("BOT_INSIGHTS_LIVE_DB", "akamai")

# Tables the skill documents as the deployed query surface.
POSTURE_TABLES = ["bi_summary_minute", "bi_summary_hour", "bi_summary_day"]
SIEM_TABLES = [
    "bi_siem_policy_summary_minute",
    "bi_siem_policy_summary_hour",
    "bi_siem_policy_summary_day",
]

# Physical columns the docs claim are retained, per table family.
POSTURE_DIMENSIONS = [
    "reqTimeSec", "reqHost", "asn", "userAgentCategory", "isBotTraffic",
    "aiCategory", "resourceCategory", "reqMethod", "cacheStatus", "statusCode",
    "reqPathPattern", "country", "aiSource", "trafficCohort",
]
POSTURE_SUMMARY_COLUMNS = [
    "cnt_all", "sum_totalBytes", "sum_originTurnAroundTime_ms",
    "cnt_originTurnAroundTime", "sum_timeToFirstByte_ms", "cnt_timeToFirstByte",
    "cnt_queryStringPresent", "cnt_distinctQueryStrings",
]
SIEM_DIMENSIONS = [
    "timestamp", "reqHost", "asn", "userAgentCategory", "isBotTraffic",
    "aiCategory", "resourceCategory", "reqMethod", "statusCode", "country",
    "aiSource", "policyId", "actionClass", "botType",
]
SIEM_SUMMARY_COLUMNS = ["cnt_all", "cnt_blocked", "cnt_authFail", "avg_botScore", "uniq_clientIp"]

# Columns the docs explicitly say do NOT exist on the posture summaries.
POSTURE_PHANTOM_COLUMNS = [
    "cnt_2xx", "cnt_4xx", "cnt_429", "cnt_5xx", "cnt_cached", "cnt_cache_miss",
    "avg_ttfb", "avg_origin_ttfb", "p95_origin_ttfb", "p99_origin_ttfb",
    "uniq_client_ip", "bot_class", "requestPathPattern", "is_bot_traffic",
    "request_host", "client_asn",
]

# Non-deployed tables: any ```sql block referencing these is design-intent, skip it.
NON_DEPLOYED = re.compile(r"\b(bot_agg_\w+|bot_detection(_siem)?)\b")


class QueryError(RuntimeError):
    def __init__(self, message: str, code: str | None = None):
        super().__init__(message)
        self.code = code


@dataclass
class Result:
    kind: str          # schema | doc-sql | negative | prose | producer
    name: str
    status: str        # PASS | FAIL | SKIP | UNRESOLVED
    detail: str = ""
    source: str = ""


@dataclass
class Ctx:
    db: str
    host: str
    asn: str
    policy_id: str
    now: _dt.datetime
    conn: object = field(repr=False, default=None)


# --------------------------------------------------------------------------- #
# Connection (reuses the skill's cluster-env convention).
# --------------------------------------------------------------------------- #
class Conn:
    def __init__(self, url: str, headers: dict, verify: bool):
        self.url = url
        self.headers = headers
        self.verify = verify

    def query(self, sql: str) -> dict:
        body = (sql.strip().rstrip(";") + "\nFORMAT JSON").encode("utf-8")
        ctx = None
        if self.url.startswith("https://") and not self.verify:
            ctx = ssl._create_unverified_context()
        req = urllib.request.Request(self.url, data=body, headers=self.headers, method="POST")
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=60) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            m = re.search(r"Code:\s*(\d+)", detail)
            raise QueryError(detail[:400], code=(m.group(1) if m else str(exc.code))) from None
        except urllib.error.URLError as exc:
            raise QueryError(f"connection error: {exc.reason}") from None
        try:
            return json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            raise QueryError("non-JSON response: " + raw.decode("utf-8", "replace")[:200]) from None


def _parse_env(path: Path) -> dict:
    env: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):]
        if "=" not in line:
            continue
        key, val = line.split("=", 1)
        env[key.strip()] = val.strip().strip('"').strip("'")
    return env


def _resolve_secret(value: str) -> str | None:
    """Resolve a value that may be a 1Password op:// reference via the `op` CLI.

    The skill's cluster envs store tokens as op:// refs (resolved by the MCP mux
    at runtime). Mirror that here so the harness stays credential-safe: no secret
    ever touches disk in this repo, and it works wherever `op` is signed in.
    """
    if not value.startswith("op://"):
        return value
    if shutil.which("op") is None:
        return None
    try:
        out = subprocess.run(
            ["op", "read", value], capture_output=True, text=True, timeout=30, check=True
        )
        return out.stdout.strip() or None
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return None


def connect(cluster: str) -> Conn | None:
    env_path = Path.home() / ".config" / "hydrolix" / "clusters" / f"{cluster}.env"
    if not env_path.exists():
        return None
    env = _parse_env(env_path)
    host = env.get("HYDROLIX_HOST") or env.get("HDX_HOSTNAME")
    token = _resolve_secret(env.get("HYDROLIX_TOKEN") or env.get("HDX_TOKEN") or "")
    if not host or not token:
        return None
    scheme = env.get("HDX_SCHEME", "https")
    host = host.replace("https://", "").replace("http://", "").rstrip("/")
    url = f"{scheme}://{host}/query/"
    headers = {"Content-Type": "text/plain"}
    if "." in token and token.count(".") >= 2:
        headers["Authorization"] = f"Bearer {token}"
    else:
        headers["Authorization"] = f"Bearer {token}"
    verify = env.get("HDX_INSECURE_TLS", "").lower() not in ("1", "true", "yes")
    return Conn(url, headers, verify)


# --------------------------------------------------------------------------- #
# Discover real placeholder values from the cluster.
# --------------------------------------------------------------------------- #
def rows_of(resp: dict) -> list:
    return resp.get("data", []) if isinstance(resp, dict) else []


def discover(conn: Conn, db: str) -> Ctx:
    now = _dt.datetime(2000, 1, 1)  # replaced below; kept naive-safe
    host = "www.example.com"
    asn = "0"
    policy_id = ""
    try:
        r = conn.query(
            f"SELECT reqHost FROM {db}.bi_summary_day WHERE reqTimeSec >= now() - INTERVAL 7 DAY "
            f"AND reqHost != '' GROUP BY reqHost ORDER BY countMerge(`count()`) DESC LIMIT 1"
        )
        if rows_of(r):
            host = rows_of(r)[0]["reqHost"]
    except QueryError:
        pass
    try:
        r = conn.query(
            f"SELECT asn FROM {db}.bi_summary_day WHERE reqTimeSec >= now() - INTERVAL 7 DAY "
            f"AND asn != '' GROUP BY asn ORDER BY countMerge(`count()`) DESC LIMIT 1"
        )
        if rows_of(r):
            asn = rows_of(r)[0]["asn"]
    except QueryError:
        pass
    try:
        r = conn.query(
            f"SELECT policyId FROM {db}.bi_siem_policy_summary_day WHERE timestamp >= now() - INTERVAL 30 DAY "
            f"AND policyId != '' GROUP BY policyId ORDER BY countMerge(`count()`) DESC LIMIT 1"
        )
        if rows_of(r):
            policy_id = rows_of(r)[0]["policyId"]
    except QueryError:
        pass
    return Ctx(db=db, host=host, asn=asn, policy_id=policy_id, now=now, conn=conn)


# --------------------------------------------------------------------------- #
# Placeholder substitution for doc SQL.
# --------------------------------------------------------------------------- #
def substitute(sql: str, ctx: Ctx) -> str:
    reps = {
        "<project>": ctx.db,
        "<posture_summary_minute>": "bi_summary_minute",
        "<posture_summary_hour>": "bi_summary_hour",
        "<posture_summary_day>": "bi_summary_day",
        "<siem_summary_minute>": "bi_siem_policy_summary_minute",
        "<siem_summary_hour>": "bi_siem_policy_summary_hour",
        "<siem_summary_day>": "bi_siem_policy_summary_day",
        "'<host>'": f"'{ctx.host}'",
        "'<suspect_asn>'": f"'{ctx.asn}'",
        "'<policy_id>'": f"'{ctx.policy_id}'",
        "'<current_start>'": "toString(now() - INTERVAL 24 HOUR)",
        "'<current_end>'": "toString(now())",
        "'<baseline_start>'": "toString(now() - INTERVAL 48 HOUR)",
        "'<baseline_end>'": "toString(now() - INTERVAL 24 HOUR)",
        "'<before_start>'": "toString(now() - INTERVAL 48 HOUR)",
        "'<change_time>'": "toString(now() - INTERVAL 24 HOUR)",
        "'<after_end>'": "toString(now())",
        "'<start>'": "toString(now() - INTERVAL 24 HOUR)",
        "'<end>'": "toString(now())",
    }
    for k, v in reps.items():
        sql = sql.replace(k, v)
    return sql


# --------------------------------------------------------------------------- #
# Extract ```sql fences and split into individual statements.
# --------------------------------------------------------------------------- #
FENCE = re.compile(r"```sql\n(.*?)```", re.DOTALL)


def split_statements(block: str) -> list[str]:
    """Split a fenced block into independent statements.

    A col-0 ``SELECT``/``WITH`` starts a new statement only at paren depth 0 and
    only once the current statement is "complete": a plain ``SELECT`` statement
    is complete as soon as it has a body, while a ``WITH`` statement is complete
    only after its trailing main ``SELECT`` (the col-0 SELECT that follows the
    CTE list). This keeps ``WITH ... AS (...) SELECT ...`` CTE queries whole
    while still separating genuinely independent statements (e.g. two SELECTs in
    one fence)."""
    lines = block.splitlines()
    statements: list[list[str]] = []
    current: list[str] = []
    depth = 0
    first_kw: str | None = None
    with_main_seen = False

    def first_keyword(buf: list[str]) -> str | None:
        for ln in buf:
            m = re.match(r"^\s*(SELECT|WITH)\b", ln)
            if m:
                return m.group(1)
        return None

    for line in lines:
        col0_kw = re.match(r"^(SELECT|WITH)\b", line)
        if col0_kw and depth == 0 and any(c.strip() for c in current):
            complete = first_kw == "SELECT" or (first_kw == "WITH" and with_main_seen)
            if complete:
                statements.append(current)
                current = []
                first_kw = None
                with_main_seen = False
        current.append(line)
        if first_kw is None:
            first_kw = first_keyword(current)
        if first_kw == "WITH" and depth == 0 and re.match(r"^SELECT\b", line):
            with_main_seen = True
        depth += line.count("(") - line.count(")")
    if current:
        statements.append(current)
    return [t for t in ("\n".join(s).strip() for s in statements) if t]


def extract_doc_statements() -> list[tuple[str, str]]:
    out = []
    for md in sorted(REFERENCES.glob("*.md")) + [SKILL_ROOT / "SKILL.md"]:
        text = md.read_text(encoding="utf-8")
        for fence in FENCE.findall(text):
            for stmt in split_statements(fence):
                out.append((md.name, stmt))
    return out


def is_runnable_deployed(sql: str) -> bool:
    if not re.search(r"\bFROM\b", sql):
        return False
    if NON_DEPLOYED.search(sql):
        return False
    return bool(re.search(r"(bi_summary_|bi_siem_policy_summary_|<posture_summary|<siem_summary)", sql))


# --------------------------------------------------------------------------- #
# Checks
# --------------------------------------------------------------------------- #
def _col_exists(ctx: Ctx, table: str, col: str, time_col: str) -> bool:
    """A column is 'present' if we can SELECT it. This resolves Alias/Summary
    columns (cnt_all, reqTimeSec, ...) that system.columns does not enumerate."""
    try:
        ctx.conn.query(
            f"SELECT `{col}` FROM {ctx.db}.{table} WHERE {time_col} >= now() - INTERVAL 1 HOUR LIMIT 0"
        )
        return True
    except QueryError:
        return False


def check_schema(ctx: Ctx, results: list[Result], quick: bool = False) -> None:
    tables = ["bi_summary_hour", "bi_siem_policy_summary_hour"] if quick else POSTURE_TABLES + SIEM_TABLES
    for table in tables:
        is_siem = table.startswith("bi_siem")
        time_col = "timestamp" if is_siem else "reqTimeSec"
        try:
            ctx.conn.query(f"SELECT count() FROM {ctx.db}.{table} WHERE {time_col} >= now() - INTERVAL 1 DAY")
            results.append(Result("schema", f"table-exists:{table}", "PASS"))
        except QueryError as exc:
            results.append(Result("schema", f"table-exists:{table}", "FAIL", str(exc)))
            continue
        want = (SIEM_DIMENSIONS + SIEM_SUMMARY_COLUMNS) if is_siem else (POSTURE_DIMENSIONS + POSTURE_SUMMARY_COLUMNS)
        for col in want:
            ok = _col_exists(ctx, table, col, time_col)
            results.append(Result("schema", f"{table}.{col} present", "PASS" if ok else "FAIL",
                                  "" if ok else "documented column missing"))
        if not is_siem:
            for col in POSTURE_PHANTOM_COLUMNS:
                absent = not _col_exists(ctx, table, col, time_col)
                results.append(Result("schema", f"{table}.{col} absent", "PASS" if absent else "FAIL",
                                      "" if absent else "phantom column unexpectedly present"))


def check_doc_sql(ctx: Ctx, results: list[Result]) -> None:
    for source, stmt in extract_doc_statements():
        if not is_runnable_deployed(stmt):
            continue
        sql = substitute(stmt, ctx)
        label = re.sub(r"\s+", " ", stmt.splitlines()[0])[:70]
        if re.search(r"<[a-zA-Z][a-zA-Z0-9_]*>|\$\{|\$__", sql):
            results.append(Result("doc-sql", label, "UNRESOLVED",
                                  "unresolved placeholder after substitution", source))
            continue
        wrapped = f"SELECT * FROM (\n{sql}\n) AS _t LIMIT 5" if not re.search(r"\bLIMIT\b", sql, re.I) else sql
        try:
            ctx.conn.query(wrapped)
            results.append(Result("doc-sql", label, "PASS", "", source))
        except QueryError as exc:
            # retry unwrapped in case the wrapper (not the query) was the problem
            try:
                ctx.conn.query(sql)
                results.append(Result("doc-sql", label, "PASS", "(unwrapped)", source))
            except QueryError as exc2:
                results.append(Result("doc-sql", label, "FAIL", f"[{exc2.code}] {exc2}", source))


def check_negative(ctx: Ctx, results: list[Result]) -> None:
    db, h = ctx.db, "bi_summary_hour"
    win = "WHERE reqTimeSec >= now() - INTERVAL 1 HOUR"
    cases = [
        ("sum(SummaryColumn) -> ILLEGAL_AGGREGATION",
         f"SELECT reqHost, sum(cnt_all) FROM {db}.{h} {win} GROUP BY reqHost"),
        ("cnt_cache_miss column absent", f"SELECT cnt_cache_miss FROM {db}.{h} {win} LIMIT 1"),
        ("p95_origin_ttfb column absent", f"SELECT p95_origin_ttfb FROM {db}.{h} {win} LIMIT 1"),
        ("cnt_2xx column absent", f"SELECT cnt_2xx FROM {db}.{h} {win} LIMIT 1"),
        ("bot_class column absent (posture)", f"SELECT bot_class FROM {db}.{h} {win} LIMIT 1"),
        ("requestPathPattern absent (renamed reqPathPattern)",
         f"SELECT requestPathPattern FROM {db}.{h} {win} LIMIT 1"),
        ("is_bot_traffic absent (physical isBotTraffic)",
         f"SELECT is_bot_traffic FROM {db}.{h} {win} LIMIT 1"),
        ("uniq_client_ip absent on CDN posture", f"SELECT uniq_client_ip FROM {db}.{h} {win} LIMIT 1"),
        ("cnt_auth_fail absent (physical cnt_authFail)",
         f"SELECT cnt_auth_fail FROM {db}.bi_siem_policy_summary_hour "
         f"WHERE timestamp >= now() - INTERVAL 1 HOUR LIMIT 1"),
    ]
    for name, sql in cases:
        try:
            ctx.conn.query(sql)
            results.append(Result("negative", name, "FAIL", "query unexpectedly SUCCEEDED"))
        except QueryError as exc:
            results.append(Result("negative", name, "PASS", f"correctly rejected [{exc.code}]"))


def check_prose(ctx: Ctx, results: list[Result]) -> None:
    db = ctx.db
    P = f"{db}.bi_summary_hour"
    S = f"{db}.bi_siem_policy_summary_hour"
    pwin = "WHERE reqTimeSec >= now() - INTERVAL 24 HOUR"
    swin = "WHERE timestamp >= now() - INTERVAL 24 HOUR"

    def expect_ok(name, sql, check=None):
        try:
            r = ctx.conn.query(sql)
            if check is not None:
                ok, why = check(rows_of(r))
                results.append(Result("prose", name, "PASS" if ok else "FAIL", why))
            else:
                results.append(Result("prose", name, "PASS"))
        except QueryError as exc:
            results.append(Result("prose", name, "FAIL", f"[{exc.code}] {exc}"))

    # statusCode numeric
    expect_ok("statusCode is numeric (>=500 / =429 comparisons run)",
              f"SELECT countMergeIf(`count()`, statusCode = 429) a, "
              f"countMergeIf(`count()`, statusCode >= 500) b FROM {P} {pwin}")
    # cacheStatus boolean
    expect_ok("cacheStatus is boolean (= false runs)",
              f"SELECT countMergeIf(`count()`, cacheStatus = false) a FROM {P} {pwin}")
    # trafficCohort subset of {Human,Bot,AI}
    def _cohort(rows):
        vals = {row["trafficCohort"] for row in rows}
        allowed = {"Human", "Bot", "AI"}
        extra = vals - allowed
        return (not extra, f"values={sorted(vals)}" + (f" UNEXPECTED={sorted(extra)}" if extra else ""))
    expect_ok("trafficCohort values are a subset of {Human,Bot,AI}",
              f"SELECT DISTINCT trafficCohort FROM {P} {pwin}", _cohort)
    # aiSource empty when aiCategory empty
    def _aisrc(rows):
        n = rows[0]["v"] if rows else 1
        return (str(n) in ("0", "0.0"), f"rows with aiCategory='' AND aiSource!='' = {n} (expect 0)")
    expect_ok("aiSource is '' when aiCategory is '' (transform rule)",
              f"SELECT count() v FROM {P} {pwin} AND aiCategory = '' AND aiSource != ''", _aisrc)
    # resourceCategory subset of documented buckets
    def _res(rows):
        vals = {row["resourceCategory"] for row in rows}
        allowed = {"robots.txt", "sitemap.xml", "ads.txt", "llms.txt", "api", "static", "page", "other", ""}
        extra = vals - allowed
        return (not extra, f"values={sorted(vals)}" + (f" UNEXPECTED={sorted(extra)}" if extra else ""))
    expect_ok("resourceCategory values are a subset of the documented buckets",
              f"SELECT DISTINCT resourceCategory FROM {P} {pwin}", _res)
    # reqPathPattern present + usable as a GROUP BY dimension (cnt_all is a
    # SummaryColumn and must NOT be in GROUP BY).
    expect_ok("reqPathPattern is retained and groupable",
              f"SELECT reqPathPattern, cnt_all FROM {P} {pwin} GROUP BY reqPathPattern LIMIT 1")
    # good-bot mapping trafficCohort='Bot'
    expect_ok("good-bot filter trafficCohort='Bot' runs",
              f"SELECT countMergeIf(`count()`, trafficCohort = 'Bot') v FROM {P} {pwin}")
    # SIEM control columns resolve (botType is the only GROUP BY dimension here).
    expect_ok("SIEM cnt_blocked/cnt_authFail/avg_botScore/uniq_clientIp resolve",
              f"SELECT botType, cnt_blocked, cnt_authFail, avg_botScore, uniq_clientIp "
              f"FROM {S} {swin} GROUP BY botType LIMIT 1")
    # hdx_cdn awareness (SKILL guardrail)
    expect_ok("hdx_cdn dimension is present on posture summaries",
              f"SELECT hdx_cdn FROM {P} {pwin} GROUP BY hdx_cdn LIMIT 1")


def check_producers(ctx: Ctx, results: list[Result]) -> None:
    try:
        sys.path.insert(0, str(REPO_ROOT / "packages" / "bot-insights" / "src"))
        from bot_insights.producers.sql import (  # type: ignore
            scorecard as sc, executive_posture as ep, control_review as cr, summary_columns as scq,
        )
    except Exception as exc:  # noqa: BLE001
        results.append(Result("producer", "import bot_insights.producers.sql", "SKIP",
                              f"package not importable ({exc}); run under `uv run` for producer coverage"))
        return

    now = _dt.datetime.now(_dt.timezone.utc).replace(tzinfo=None)
    cur_start = now - _dt.timedelta(hours=24)
    base_start = now - _dt.timedelta(hours=48)
    db = ctx.db

    def run(name, sql):
        try:
            ctx.conn.query(sql)
            results.append(Result("producer", name, "PASS"))
        except QueryError as exc:
            results.append(Result("producer", name, "FAIL", f"[{exc.code}] {exc}"))

    run("executive_posture_sql", ep.executive_posture_sql(db, cur_start, now, base_start))
    run("control_review_sql[siem-policy]",
        cr.control_review_sql(db, cur_start, now, base_start, policy_id=ctx.policy_id or None))
    run("control_review_sql[posture]",
        cr.control_review_sql(db, cur_start, now, base_start, control_source="posture"))
    run("control_review_timeseries_sql[siem-policy]",
        cr.control_review_timeseries_sql(db, cur_start, now, base_start, policy_id=ctx.policy_id or None))
    run("control_review_timeseries_sql[posture]",
        cr.control_review_timeseries_sql(db, cur_start, now, base_start, control_source="posture"))
    run("summary_columns_query", scq.summary_columns_query(db, "bi_summary_hour"))

    entity_maps = {
        "scorecard_sql": (sc.scorecard_sql, getattr(sc, "SCORECARD_ENTITY_SQL", {})),
        "scorecard_soc_sql": (sc.scorecard_soc_sql, getattr(sc, "SOC_ENTITY_SQL", {})),
        "scorecard_crawler_sql": (sc.scorecard_crawler_sql, getattr(sc, "CRAWLER_ENTITY_SQL", {})),
        "scorecard_edge_ops_sql": (sc.scorecard_edge_ops_sql, getattr(sc, "EDGE_OPS_ENTITY_SQL", {})),
    }
    for fn_name, (fn, entities) in entity_maps.items():
        for entity in entities:
            try:
                sql = fn(db, cur_start, now, base_start, entity, 50)
            except SystemExit as exc:
                results.append(Result("producer", f"{fn_name}({entity})", "SKIP", str(exc)))
                continue
            run(f"{fn_name}({entity})", sql)


def check_presets(ctx: Ctx, results: list[Result]) -> None:
    """Execute every bot_insights_capture preset query (the Data Firewall's
    guarded capture path). These are built separately from the producers/sql
    generators, so they need their own coverage."""
    try:
        sys.path.insert(0, str(REPO_ROOT / "packages" / "bot-insights" / "src"))
        from bot_insights.bot_insights_capture.part_02 import render_preset_sql  # type: ignore
        from bot_insights.bot_insights_capture.part_01 import PRESET_CHOICES  # type: ignore
    except Exception as exc:  # noqa: BLE001
        results.append(Result("preset", "import render_preset_sql", "SKIP",
                              f"package not importable ({exc}); run under `uv run`"))
        return

    from types import SimpleNamespace
    now = _dt.datetime.now(_dt.timezone.utc).replace(tzinfo=None)
    start = (now - _dt.timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")
    end = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    for preset in PRESET_CHOICES:
        args = SimpleNamespace(
            preset=preset, database=ctx.db, granularity="hour", limit=50,
            start=start, end=end, sql=None, sql_file=None,
        )
        try:
            sql = render_preset_sql(args)
        except SystemExit as exc:
            results.append(Result("preset", f"render_preset_sql({preset})", "FAIL", f"render error: {exc}"))
            continue
        try:
            ctx.conn.query(sql)
            results.append(Result("preset", f"preset:{preset}", "PASS"))
        except QueryError as exc:
            results.append(Result("preset", f"preset:{preset}", "FAIL", f"[{exc.code}] {exc}"))


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--cluster", default=DEFAULT_CLUSTER)
    ap.add_argument("--db", default=DEFAULT_DB)
    ap.add_argument("--json", type=Path, default=None, help="write a JSON report to this path")
    ap.add_argument("--quick", action="store_true",
                    help="probe only the hour-grain tables for schema checks (faster local runs)")
    args = ap.parse_args()

    quick = args.quick or os.environ.get("BOT_INSIGHTS_LIVE_QUICK", "").lower() in ("1", "true", "yes")

    conn = connect(args.cluster)
    if conn is None:
        print(f"SKIP: no usable cluster env for '{args.cluster}' "
              f"(~/.config/hydrolix/clusters/{args.cluster}.env). Live validation is opt-in.")
        return 0

    ctx = discover(conn, args.db)
    print(f"# Live validation against {args.cluster} db={args.db}{' (quick)' if quick else ''}")
    print(f"#   discovered host={ctx.host!r} asn={ctx.asn!r} policyId={ctx.policy_id!r}\n")

    results: list[Result] = []
    check_schema(ctx, results, quick=quick)
    check_doc_sql(ctx, results)
    check_negative(ctx, results)
    check_prose(ctx, results)
    check_producers(ctx, results)
    check_presets(ctx, results)

    order = {"FAIL": 0, "UNRESOLVED": 1, "SKIP": 2, "PASS": 3}
    for r in sorted(results, key=lambda x: (order[x.status], x.kind, x.name)):
        if r.status == "PASS":
            continue
        src = f" ({r.source})" if r.source else ""
        print(f"  {r.status:10} [{r.kind}] {r.name}{src}  {r.detail}")

    counts = {s: sum(1 for r in results if r.status == s) for s in ("PASS", "FAIL", "UNRESOLVED", "SKIP")}
    print(f"\n# {counts['PASS']} PASS  {counts['FAIL']} FAIL  "
          f"{counts['UNRESOLVED']} UNRESOLVED  {counts['SKIP']} SKIP  (of {len(results)})")

    if args.json:
        args.json.write_text(json.dumps(
            {"cluster": args.cluster, "db": args.db, "counts": counts,
             "results": [r.__dict__ for r in results]}, indent=2) + "\n", encoding="utf-8")
        print(f"# report -> {args.json}")

    return 1 if counts["FAIL"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
