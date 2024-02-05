import pytest
from logging_agent.cloud_waap.cloudwaap_log_utils import CloudWAAPProcessor
from unittest.mock import patch
from datetime import datetime

# Test parse_access_request with different request patterns
@pytest.mark.parametrize("http_request, protocol, host, http_method, expected_output", [
    ("GET / HTTP/1.1", "http", "example.com", "GET", ("GET", "http://example.com/", "HTTP/1.1", "/")),
    ("SDS / HTTP/1.1", "http", "example.com", "-", ("-", "http://example.com/SDS / HTTP/1.1", "-", "SDS / HTTP/1.1")),
    ("// HTTP/1.1", "http", "example.com", "-", ("-", "http://example.com/// HTTP/1.1", "-", "// HTTP/1.1")),
    ("GET /!@$ASD", "http", "example.com", "GET", ("GET", "http://example.com/!@$ASD", "-", "-"))
])
def test_parse_access_request(http_request, protocol, host, http_method, expected_output):
    result = CloudWAAPProcessor.parse_access_request(http_request, protocol, host, http_method)
    assert result == expected_output