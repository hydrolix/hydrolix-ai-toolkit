"""Incident evidence constants."""

from __future__ import annotations

_INCIDENT_DEFAULT_FIELDS = (
    "client_ip,asn,request_path,user_agent,country,status_code,request_method,trafficCohort"
)
_INCIDENT_FIELD_LABELS = {
    "client_ip": "Client IP",
    "asn": "Client ASN",
    "request_path": "Request Path",
    "user_agent": "User Agent",
    "country": "Country",
    "status_code": "Status Code",
    "request_method": "Request Method",
    "trafficCohort": "Traffic cohort",
}
