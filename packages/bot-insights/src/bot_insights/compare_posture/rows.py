from __future__ import annotations

from typing import Any


def column_names(columns: list[Any]) -> list[str]:
    names: list[str] = []
    for column in columns:
        if isinstance(column, str):
            names.append(column)
        elif isinstance(column, dict):
            names.append(str(column.get("name") or column.get("column") or ""))
        else:
            names.append(str(column))
    return names


def result_rows(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [row for row in value if isinstance(row, dict)]

    if not isinstance(value, dict):
        return []

    rows = value.get("rows")
    if not isinstance(rows, list):
        rows = value.get("data")
    if not isinstance(rows, list):
        return []

    if not rows:
        return []
    if all(isinstance(row, dict) for row in rows):
        return rows

    columns = value.get("columns", [])
    if not isinstance(columns, list):
        return []
    names = column_names(columns)
    converted: list[dict[str, Any]] = []
    for row in rows:
        if isinstance(row, list):
            converted.append({name: row[index] for index, name in enumerate(names) if index < len(row)})
    return converted


def rows_to_periods(value: Any) -> dict[str, dict[str, Any]]:
    if isinstance(value, dict):
        current = value.get("current")
        baseline = value.get("baseline")
        if isinstance(current, dict) and isinstance(baseline, dict):
            return {"current": current, "baseline": baseline}

    periods: dict[str, dict[str, Any]] = {}
    for row in result_rows(value):
        period = str(row.get("period", "")).lower()
        if period in {"current", "baseline", "before", "after"}:
            periods[period] = row

    if "current" in periods and "baseline" in periods:
        return {"current": periods["current"], "baseline": periods["baseline"]}
    if "after" in periods and "before" in periods:
        return {"current": periods["after"], "baseline": periods["before"]}
    raise ValueError(
        "Input must contain current/baseline objects or period rows with current/baseline."
    )
