from __future__ import annotations

import copy

import pytest

from logging_agent.cloud_waap.cloudwaap_enrich import (
    enrich_access_log,
    enrich_bot_log,
    enrich_csp_log,
    enrich_ddos_log,
    enrich_waf_log,
    enrich_webddos_log,
)


@pytest.fixture
def format_options() -> dict[str, object]:
    return {"unify_fields": True, "time_format": "ISO8601"}


def test_enrich_access_log_normalizes_request(format_options: dict[str, object]) -> None:
    event = {
        "time": "27/Jan/2024:00:49:40.000 +0000",
        "request": "GET /user/login HTTP/1.1",
        "protocol": "https",
        "host": "securedemo.radware.net",
        "http_method": "GET",
        "accept_language": "en-US",
        "http_bytes_in": 10,
        "http_bytes_out": 20,
    }
    metadata: dict[str, object] = {}

    enriched = enrich_access_log(copy.deepcopy(event), format_options, "json", metadata, "Access")

    assert enriched["logType"] == "Access"
    assert enriched["product"] == "Cloud WAAP"
    assert enriched["request"].startswith("https://securedemo.radware.net")
    assert enriched["uri"] == "/user/login"
    assert enriched["httpMethod"] == "GET"
    assert enriched["severity"] == "Info"
    assert enriched["time"].endswith("Z")  # ISO8601 conversion


def test_enrich_waf_log_populates_metadata(format_options: dict[str, object]) -> None:
    event = {
        "receivedTimeStamp": "1706302854000",
        "request": "GET /api/resource HTTP/1.1\r\nCookie: token=abc\r\nUser-Agent: Test\r\nReferer: https://example.com\r\n",
        "protocol": "https",
        "host": "api.example.com",
        "enrichmentContainer": {"geoLocation.countryCode": "US", "tenant": "tenant-id"},
    }
    metadata = {"tenant_name": "DEMO", "application_name": "App"}

    enriched = enrich_waf_log(copy.deepcopy(event), format_options, "json", metadata, "WAF")

    assert enriched["tenantName"] == "DEMO"
    assert enriched["applicationName"] == "App"
    assert enriched["httpMethod"] == "GET"
    assert enriched["cookie"] == "token=abc"
    assert enriched["userAgent"] == "Test"
    assert enriched["referrer"].startswith("https://example.com")
    assert enriched["countryCode"] == "US"
    assert enriched["time"].endswith("Z")


def test_enrich_bot_log_renames_fields(format_options: dict[str, object]) -> None:
    event = {
        "time": "1706302854000",
        "url": "https://example.com/login",
        "violation_reason": "Blocked",
        "bot_category": "Suspicious",
        "site": "example.com",
        "tid": "1234",
        "ua": "ExampleAgent",
    }
    metadata = {"key": "logs/tenant/app123/data/file", "tenant_name": "Tenant"}

    enriched = enrich_bot_log(copy.deepcopy(event), format_options, "json", metadata, "Bot")

    assert enriched["logType"] == "Bot"
    assert enriched["tenantName"] == "Tenant"
    assert enriched["applicationId"] == "app123"
    assert enriched["request"] == "https://example.com/login"
    assert enriched["uri"] == "/login"
    assert enriched["name"] == "Blocked"
    assert enriched["category"] == "Suspicious"
    assert enriched["reason"] == "Blocked, Suspicious"
    assert enriched["transId"] == "1234"
    assert enriched["userAgent"] == "ExampleAgent"


def test_enrich_ddos_log_updates_fields(format_options: dict[str, object]) -> None:
    event = {
        "sourceIP": "1.1.1.1",
        "destinationIP": "2.2.2.2",
        "category": "Network",
        "name": "Attack",
        "ID": "abc",
        "time": "31-01-2024 12:00:00",
        "enrichmentContainer": {"geoLocation.countryCode": "GB"},
    }
    metadata = {"tenant_name": "DemoTenant", "application_name": "DemoApp"}

    enriched = enrich_ddos_log(copy.deepcopy(event), format_options, "json", metadata, "DDoS")

    assert enriched["tenantName"] == "DemoTenant"
    assert enriched["applicationName"] == "DemoApp"
    assert enriched["sourceIp"] == "1.1.1.1"
    assert enriched["destinationIp"] == "2.2.2.2"
    assert enriched["reason"] == "Network, Attack"
    assert enriched["transId"] == "abc"
    assert enriched["countryCode"] == "GB"
    assert enriched["time"].endswith("Z")


def test_enrich_webddos_log_handles_attack_vector(format_options: dict[str, object]) -> None:
    event = {
        "startTime": "1706300000000",
        "endTime": "1706303600000",
        "currentTimestamp": "2024-01-26T23:00:28.597742015Z",
        "attackID": "attack-1",
        "attackVector": "HTTP_Flood_Attack",
        "detection": {"ApplicationBehavior": {"value": 1}},
        "mitigation": {"totalRequests": {"received": 10}},
        "rps": {"inbound": 5},
        "enrichmentContainer": {"applicationId": "app-1"},
    }
    metadata = {"tenant_name": "Tenant", "application_name": "App"}

    enriched = enrich_webddos_log(copy.deepcopy(event), format_options, "json", metadata, "WebDDoS")

    assert enriched["tenantName"] == "Tenant"
    assert enriched["applicationName"] == "App"
    assert enriched["transId"] == "attack-1"
    assert enriched["name"] == "HTTP_Flood_Attack"
    assert "reason" in enriched and "HTTP Flood Attack" in enriched["reason"]
    assert enriched["category"] == "WebDDoS HTTP Flood Attack"
    assert enriched["time"].endswith("Z")


def test_enrich_csp_log_flattens_enrichment(format_options: dict[str, object]) -> None:
    event = {
        "receivedTimeStamp": "1706302854000",
        "violationType": "DOM XSS",
        "details": "Details",
        "transId": "12",
        "aggregatedUserAgent": ["Chrome", "Edge"],
        "urls": ["https://example.com"],
        "enrichmentContainer": {"contractId": "contract", "tenant": "tenant-id"},
    }
    metadata = {"tenant_name": "Tenant", "application_name": "App"}

    enriched = enrich_csp_log(copy.deepcopy(event), format_options, "json", metadata, "CSP")

    assert enriched["tenantName"] == "Tenant"
    assert enriched["applicationName"] == "App"
    assert enriched["name"] == "DOM XSS"
    assert enriched["reason"] == "Details"
    assert enriched["contractId"] == "contract"
    assert enriched["tenantId"] == "tenant-id"
    assert enriched["logType"] == "CSP"
    assert enriched["aggregatedUserAgent"] == ["Chrome", "Edge"]
    assert enriched["urls"] == ["https://example.com"]

