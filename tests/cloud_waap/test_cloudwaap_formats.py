from __future__ import annotations

import re

from logging_agent.cloud_waap.cloudwaap_json_to_cef import json_to_cef
from logging_agent.cloud_waap.cloudwaap_json_to_leef import json_to_leef

FIELD_MAPPINGS = {
    "cloud_waap": {
        "Access": {
            "cef": {
                "prefix": "rdwrCld",
                "header": {
                    "vendor": "Radware",
                    "product": "Cloud WAAP",
                    "version": "1.0",
                    "log_type": "Access",
                    "title": "fromlog",
                    "severity": "fromlog",
                },
                "static_mapping": {"action": "act"},
            },
            "leef": {
                "prefix": "rdwrCld",
                "header": {
                    "vendor": "Radware",
                    "product": "Cloud WAAP",
                    "version": "1.0",
                    "log_type": "Access",
                },
                "static_mapping": {"action": "action"},
            },
        }
    }
}


def test_json_to_cef_includes_syslog_header_and_sanitizes() -> None:
    log = {
        "name": "Example=Event",
        "severity": "high",
        "action": "Allowed",
        "tenantName": "Tenant",
        "tenant_name": "Tenant",
        "custom_field": "needs escaping",
    }
    options = {
        "severity_format": 3,
        "syslog_header": {"generate_header": True, "host": "tenant"},
    }

    output = json_to_cef(log.copy(), "Access", "cloud_waap", FIELD_MAPPINGS, options)

    assert output is not None
    assert output.startswith("202")
    assert " Tenant CEF:0|Radware|Cloud WAAP|1.0|Access|Example=Event|7|" in output
    assert "act=Allowed" in output
    assert "rdwrCldCustomField=needs escaping" in output


def test_json_to_leef_generates_tab_delimited_output() -> None:
    log = {
        "name": "Example",
        "severity": "info",
        "action": "Blocked",
        "tenantName": "Tenant",
        "custom_field": "value",
    }
    options = {"severity_format": 2, "syslog_header": {"generate_header": True, "host": "product"}}

    output = json_to_leef(log.copy(), "Access", "cloud_waap", FIELD_MAPPINGS, options)

    assert output is not None
    assert output.startswith("202")
    assert " Cloud WAAP LEEF:2.0" in output
    assert "action=Blocked" in output
    assert "rdwrCldCustomField=value" in output
    assert "rdwrCldSeverity=Unknown" in output

