from __future__ import annotations

import datetime as dt

from logging_agent.cloud_waap.cloudwaap_log_utils import CloudWAAPProcessor


def test_parse_access_request_handles_valid_request() -> None:
    method, full_url, http_version, uri = CloudWAAPProcessor.parse_access_request(
        "GET /path HTTP/1.1", "https", "example.com", "GET"
    )

    assert method == "GET"
    assert full_url == "https://example.com/path"
    assert http_version == "HTTP/1.1"
    assert uri == "/path"


def test_parse_waf_request_extracts_headers() -> None:
    request = "GET / HTTP/1.1\r\nHost: alt.example\r\nCookie: a=1\r\nUser-Agent: Agent\r\nReferer: https://ref\r\nX-Test: value"
    result = CloudWAAPProcessor.parse_waf_request(request, "https", "origin.example")

    method, full_url, http_version, cookie, user_agent, referrer, headers = result
    assert method == "GET"
    assert full_url == "https://alt.example/"
    assert http_version == "HTTP/1.1"
    assert cookie == "a=1"
    assert user_agent == "Agent"
    assert referrer == "https://ref"
    assert "X-Test: value" in headers


def test_process_enrichment_container_promotes_fields() -> None:
    log = {
        "enrichmentContainer": {
            "geoLocation.countryCode": "US",
            "applicationId": "app",
            "contractId": "contract",
            "tenant": "tenant",
        }
    }

    result = CloudWAAPProcessor.process_enrichment_container(log)

    assert result["countryCode"] == "US"
    assert result["applicationId"] == "app"
    assert result["contractId"] == "contract"
    assert result["tenantId"] == "tenant"
    assert "enrichmentContainer" not in result


def test_transform_time_accepts_multiple_formats() -> None:
    now = dt.datetime(2024, 1, 1, 0, 0, 0, tzinfo=dt.timezone.utc)
    epoch_ms = int(now.timestamp() * 1000)

    result = CloudWAAPProcessor.transform_time(epoch_ms, ["epoch_ms", "%Y-%m-%d"], "ISO8601")

    assert result.startswith("2024-01-01T00:00:00")


def test_get_candidate_time_formats_merges_custom_formats() -> None:
    options = {"input_time_formats": {"cloud_waap": {"Access": ["%d-%m-%Y %H:%M:%S"]}}}

    result = CloudWAAPProcessor.get_candidate_time_formats("%d/%b/%Y:%H:%M:%S %z", options, "cloud_waap", "Access")

    assert "%d/%b/%Y:%H:%M:%S %z" in result
    assert "%d-%m-%Y %H:%M:%S" in result


def test_extract_metadata_returns_expected_fields() -> None:
    key = "bucket/tenant/AppDemo/data/rdwr_event_tenant_AppDemo_20240101H010000.json"

    result = CloudWAAPProcessor.extract_metadata(key, "cloud_waap", "WAF")

    assert result["tenant_name"] == "tenant"
    assert result["application_name"] == "AppDemo"
    assert result["product"] == "Cloud WAAP"

