import pytest
from logging_agent.cloud_waap.cloudwaap_log_utils import CloudWAAPProcessor
from unittest.mock import patch
from datetime import datetime


# Test parse_waf_request with different request patterns
@pytest.mark.parametrize("waf_request, expected_output", [
    # Regular well-formed request
    ("GET /api/customerAddress?page=1&text=example HTTP/1.1\r\nCookie: sessionId=abc123\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0)\r\nReferer: http://example.com/home\r\n",
     ("GET", "http://example.com/api/customerAddress?page=1&text=example", "HTTP/1.1", "sessionId=abc123", "Mozilla/5.0 (Windows NT 10.0)", "http://example.com/home", "Cookie: sessionId=abc123; User-Agent: Mozilla/5.0 (Windows NT 10.0); Referer: http://example.com/home")),

    # Incomplete request line (missing HTTP version)
    ("GET /api/path\r\nHost: example.com\r\n",
     ("GET", "http://example.com/api/path", "", "", "", "", "Host: example.com")),

    # Missing Headers
    ("GET / HTTP/1.1\r\n",
     ("GET", "http://example.com/", "HTTP/1.1", "", "", "", "")),

    # Malformed Headers
    ("GET / HTTP/1.1\r\nCookie\r\nUser-Agent: \r\n",
     ("GET", "http://example.com/", "HTTP/1.1", "", "", "", "Cookie; User-Agent: ")),

    # Special Characters in URI
    ("GET /api?param=%20%21 HTTP/1.1\r\n",
     ("GET", "http://example.com/api?param=%20%21", "HTTP/1.1", "", "", "", "")),

    # Empty Request
    ("",
     ("", "", "", "", "", "", "")),

    # Malformed Request Line
    ("MALFORMED REQUEST\r\n",
     ("", "", "", "", "", "", ""))
])
def test_parse_waf_request(waf_request, expected_output):
    result = CloudWAAPProcessor.parse_waf_request(waf_request, "http", "example.com")
    assert result == expected_output
