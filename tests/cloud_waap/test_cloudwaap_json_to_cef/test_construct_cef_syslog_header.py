import pytest
from unittest.mock import patch
from datetime import datetime
from logging_agent.cloud_waap.cloudwaap_json_to_cef import construct_cef_syslog_header

# Fixture to mock current time for consistent testing
@pytest.fixture(autouse=True)
def mock_datetime():
    with patch('logging_agent.cloud_waap.cloudwaap_json_to_cef.datetime') as mock_datetime:
        mock_datetime.now.return_value = datetime(2022, 1, 1, 12, 0, 0)
        yield

# Test cases for constructing the syslog header
@pytest.mark.parametrize("format_options, log, expected_header_start", [
    ({"syslog_header": {}, "time_format": '%Y-%m-%dT%H:%M:%S%z'}, {}, "2022-01-01T12:00:00 Radware-CloudWAAP "),
    ({"syslog_header": {"host": "tenant"}, "time_format": '%Y-%m-%dT%H:%M:%S%z'}, {"tenant_name": "ExampleTenant"}, "2022-01-01T12:00:00 ExampleTenant "),
    ({"syslog_header": {"host": "application"}, "time_format": '%Y-%m-%dT%H:%M:%S%z'}, {"application_name": "ExampleApp"}, "2022-01-01T12:00:00 ExampleApp "),
    ({"syslog_header": {"host": "product"}, "time_format": 'epoch_ms_str'}, {}, "1641038400000 Radware-CloudWAAP "),
])
def test_construct_cef_syslog_header(format_options, log, expected_header_start):
    header = construct_cef_syslog_header(format_options, log)
    assert header.startswith(expected_header_start), f"Syslog header does not match expected start. Expected '{expected_header_start}', got '{header}'"
