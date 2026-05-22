"""Feature-vector construction for campaign linking."""

from __future__ import annotations

import ipaddress
from collections import Counter
from typing import Any

from .endpoints import endpoint_prefix
from .numbers import _num


def _geo_for_ip(ip: str, geo: dict[str, dict[str, Any]]) -> dict[str, Any]:
    if ip in geo:
        return geo[ip]
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return {}
    for key, value in geo.items():
        try:
            network = ipaddress.ip_network(key, strict=False)
        except ValueError:
            continue
        if address in network:
            return value
    return {}


def _feature_vectors(
    scraper_cases: list[dict[str, Any]],
    cooccurrence_rows: list[dict[str, Any]],
    drilldown_rows: list[dict[str, Any]],
    geo: dict[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    uas = {str(case.get("user_agent") or "") for case in scraper_cases if case.get("user_agent")}
    features: dict[str, dict[str, Any]] = {
        ua: {
            "user_agent": ua,
            "client_ips": set(),
            "countries": Counter(),
            "asns": Counter(),
            "paths": Counter(),
            "hours": Counter(),
        }
        for ua in uas
    }

    _accumulate_cooccurrence_features(features, cooccurrence_rows, geo)
    _accumulate_drilldown_features(features, drilldown_rows, geo)
    _accumulate_case_features(features, scraper_cases)
    return features


def _accumulate_cooccurrence_features(
    features: dict[str, dict[str, Any]],
    cooccurrence_rows: list[dict[str, Any]],
    geo: dict[str, dict[str, Any]],
) -> None:
    for row in cooccurrence_rows:
        ua = str(row.get("user_agent") or "")
        ip = str(row.get("client_ip") or "")
        if ua not in features or not ip:
            continue
        requests = _num(row.get("requests"), 1.0) or 1.0
        item = features[ua]
        item["client_ips"].add(ip)
        geo_row = _geo_for_ip(ip, geo)
        country = str(row.get("country") or geo_row.get("country") or "").strip()
        if country:
            item["countries"][country] += requests
        asn = str(geo_row.get("asn") or "").strip()
        if asn:
            item["asns"][asn] += requests


def _accumulate_drilldown_features(
    features: dict[str, dict[str, Any]],
    drilldown_rows: list[dict[str, Any]],
    geo: dict[str, dict[str, Any]],
) -> None:
    for row in drilldown_rows:
        ua = str(row.get("user_agent") or "")
        if ua not in features:
            continue
        requests = _num(row.get("requests"), 1.0) or 1.0
        item = features[ua]
        ip = str(row.get("client_ip") or "")
        if ip:
            item["client_ips"].add(ip)
            geo_row = _geo_for_ip(ip, geo)
            asn = str(geo_row.get("asn") or "").strip()
            if asn:
                item["asns"][asn] += requests
            country = str(row.get("country") or geo_row.get("country") or "").strip()
            if country:
                item["countries"][country] += requests
        prefix = endpoint_prefix(str(row.get("request_path") or ""))
        if prefix:
            item["paths"][prefix] += requests
        hour = str(row.get("hour") or "").strip()
        if hour:
            item["hours"][hour] += requests


def _accumulate_case_features(
    features: dict[str, dict[str, Any]], scraper_cases: list[dict[str, Any]]
) -> None:
    for case in scraper_cases:
        ua = str(case.get("user_agent") or "")
        if ua not in features:
            continue
        item = features[ua]
        _accumulate_case_timing(item, case)
        if not case.get("drilldown_available"):
            continue
        _accumulate_case_endpoint_targets(item, case)
        _accumulate_case_hourly_bursts(item, case)
        _accumulate_case_geo_lists(item, case)


def _accumulate_case_timing(item: dict[str, Any], case: dict[str, Any]) -> None:
    timing = case.get("temporal_regularity")
    if not isinstance(timing, dict):
        return
    for row in timing.get("hourly_profile") or []:
        if isinstance(row, dict):
            _add_hour_feature(item, row)


def _accumulate_case_endpoint_targets(
    item: dict[str, Any], case: dict[str, Any]
) -> None:
    for row in case.get("endpoint_targets") or []:
        if not isinstance(row, dict):
            continue
        prefix = endpoint_prefix(str(row.get("request_path") or row.get("value") or ""))
        if prefix:
            item["paths"][prefix] += _num(row.get("requests"), 1.0) or 1.0


def _accumulate_case_hourly_bursts(
    item: dict[str, Any], case: dict[str, Any]
) -> None:
    for row in case.get("hourly_bursts") or []:
        if isinstance(row, dict):
            _add_hour_feature(item, row)


def _add_hour_feature(item: dict[str, Any], row: dict[str, Any]) -> None:
    hour = str(row.get("hour") or "").strip()
    if hour:
        item["hours"][hour] += _num(row.get("requests"), 1.0) or 1.0


def _accumulate_case_geo_lists(item: dict[str, Any], case: dict[str, Any]) -> None:
    for country in case.get("countries") or []:
        if isinstance(country, str) and country:
            item["countries"][country] += 1.0
    for asn in case.get("asns") or []:
        if isinstance(asn, str) and asn:
            item["asns"][asn] += 1.0
    for row in case.get("client_ips") or []:
        if isinstance(row, dict) and row.get("client_ip"):
            item["client_ips"].add(str(row["client_ip"]))
