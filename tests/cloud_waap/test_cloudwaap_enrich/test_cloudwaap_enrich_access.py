import pytest
from unittest.mock import patch
from logging_agent.cloud_waap.cloudwaap_enrich import enrich_access_log, enrich_waf_log, enrich_bot_log, enrich_webddos_log, enrich_ddos_log, enrich_csp_log

# Sample access log event for testing
SAMPLE_ACCESS_EVENT = {
    "time": "23/Jan/2024:00:06:00 +0000",
    "source_ip": "31.22.123.21",
    "source_port": 47488,
    "destination_ip": "66.22.79.113",
    "destination_port": 443,
    "protocol": "https",
    "http_method": "GET",
    "host": "securedemo.radware.net",
    "request": "GET /user/login HTTP/1.1",
    "directory": "/user",
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko",
    "accept_language": "-",
    "x-forwarded-for": "-",
    "referrer": "-",
    "cookie": "sample_cookie_data",
    "request_time": "0.000",
    "response_code": 403,
    "http_bytes_in": 831,
    "http_bytes_out": 406,
    "country_code": "--",
    "action": "Blocked",
    "application_id": "cb64959b-2f53-41f2-87ad-9c5810313a74",
    "application_name": "CWAF Secure Demo",
    "tenant_name": "DEMO"
}

SAMPLE_ACCESS_METADATA = {
    # Sample metadata (if needed)
}

# Test `unify_fields` flag and `output_format`
@pytest.mark.parametrize("unify_fields, output_format", [
    (False, 'json'),
    (True, 'json'),
    (True, 'cef'),
    (True, 'leef')
])
def test_enrich_access_log_with_different_formats(unify_fields, output_format):
    format_options = {'unify_fields': unify_fields, 'time_format': 'epoch_ms_str'}
    enriched_event = enrich_access_log(SAMPLE_ACCESS_EVENT.copy(), format_options, output_format, SAMPLE_ACCESS_METADATA, 'access')

    # Assertions
    if unify_fields:
        assert 'cookie' not in enriched_event or enriched_event['cookie'] != "-"
        assert 'referrer' not in enriched_event or enriched_event['referrer'] != "-"
        assert 'country_code' not in enriched_event or enriched_event['country_code'] not in {"", "--"}
    if output_format == 'json':
        assert 'log_type' in enriched_event

# Mocking External Dependencies with Unexpected Returns
@patch('logging_agent.cloud_waap.cloudwaap_enrich.CloudWAAPProcessor.transform_time', return_value=None)
@patch('logging_agent.cloud_waap.cloudwaap_enrich.CloudWAAPProcessor.parse_access_request', return_value=(None, None, None, None))
def test_enrich_access_log_with_unexpected_returns_from_dependencies(mock_parse_request, mock_transform_time):
    enriched_event = enrich_access_log(SAMPLE_ACCESS_EVENT.copy(), {'unify_fields': True, 'time_format': 'epoch_ms_str'}, 'json', SAMPLE_ACCESS_METADATA, 'access')
    # Revised Assertions
    assert enriched_event.get('time') is None

    # If all required fields are present, then parse_access_request is called, and keys will be present but with None values.
    # If any required fields are missing, then parse_access_request is not called, and these keys will not be present.
    required_fields = ['request', 'protocol', 'host', 'http_method']
    if all(field in SAMPLE_ACCESS_EVENT for field in required_fields):
        assert all(enriched_event.get(key) is None for key in ['http_method', 'request', 'http_version', 'uri'])
    else:
        assert all(key not in enriched_event for key in ['http_method', 'request', 'http_version', 'uri'])

@patch('logging_agent.cloud_waap.cloudwaap_enrich.CloudWAAPProcessor.transform_time', side_effect=Exception("Error in transform_time"))
@patch('logging_agent.cloud_waap.cloudwaap_enrich.CloudWAAPProcessor.parse_access_request', side_effect=Exception("Error in parse_access_request"))
def test_enrich_access_log_with_exceptions_from_dependencies(mock_parse_request, mock_transform_time):
    enriched_event = enrich_access_log(SAMPLE_ACCESS_EVENT.copy(), {'unify_fields': True, 'time_format': 'epoch_ms_str'}, 'json', SAMPLE_ACCESS_METADATA, 'access')
    # Assertions
    assert enriched_event == {}


# Test when `unify_fields` is False and `output_format` is 'json'
@pytest.mark.parametrize("output_format", ['json'])
def test_enrich_access_log_unify_fields_false_json(output_format):
    format_options = {'unify_fields': False, 'time_format': 'epoch_ms_str'}
    enriched_event = enrich_access_log(SAMPLE_ACCESS_EVENT.copy(), format_options, output_format, SAMPLE_ACCESS_METADATA, 'access')

    # Assertions
    # Check if the only change is the addition of the log_type field
    assert enriched_event.get('log_type') == 'access'
    for key in SAMPLE_ACCESS_EVENT:
        if key != 'log_type':
            assert enriched_event.get(key) == SAMPLE_ACCESS_EVENT.get(key)



def test_enrich_access_log_malformed_source_ip():
    event = SAMPLE_ACCESS_EVENT.copy()
    event["source_ip"] = "31.22.%123.<script>21"
    enriched_event = enrich_access_log(event, {'unify_fields': True, 'time_format': 'epoch_ms_str'}, 'json', {}, 'access')

    assert enriched_event.get('source_ip') == "31.22.%123.<script>21"
    assert 'log_type' in enriched_event  # As log_type should still be added


# Test with Incorrect Time Format
def test_enrich_access_log_incorrect_time_format():
    event = SAMPLE_ACCESS_EVENT.copy()
    event["time"] = "not-a-real-time"
    enriched_event = enrich_access_log(event, {'unify_fields': True, 'time_format': 'epoch_ms_str'}, 'json', {},
                                       'access')

    # Updated assertion based on the assumption that transform_time returns None for invalid format
    assert enriched_event.get('time') is None
# Test with Malformed `request`
def test_enrich_access_log_malformed_request():
    event = SAMPLE_ACCESS_EVENT.copy()
    event["request"] = "INVALID REQUEST FORMAT"
    enriched_event = enrich_access_log(event, {'unify_fields': True, 'time_format': 'epoch_ms_str'}, 'json', {}, 'access')
    assert 'http_method' not in enriched_event or enriched_event.get(
        'http_method') == "GET"  # Assuming default handling
    assert 'request' not in enriched_event or enriched_event.get('request') == "INVALID REQUEST FORMAT"


# Mocking External Dependencies with Exceptions
@patch('logging_agent.cloud_waap.cloudwaap_enrich.CloudWAAPProcessor.transform_time', side_effect=Exception("Error in transform_time"))
@patch('logging_agent.cloud_waap.cloudwaap_enrich.CloudWAAPProcessor.parse_access_request', side_effect=Exception("Error in parse_access_request"))
def test_enrich_access_log_with_exceptions_from_dependencies(mock_parse_request, mock_transform_time):
    enriched_event = enrich_access_log(SAMPLE_ACCESS_EVENT.copy(), {'unify_fields': True, 'time_format': 'epoch_ms_str'}, 'json', {}, 'access')
    assert enriched_event == {}

