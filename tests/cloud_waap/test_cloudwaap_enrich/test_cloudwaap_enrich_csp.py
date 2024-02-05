import pytest
from unittest.mock import patch
from logging_agent.cloud_waap.cloudwaap_enrich import enrich_access_log, enrich_waf_log, enrich_bot_log, enrich_webddos_log, enrich_ddos_log, enrich_csp_log
from datetime import datetime, timezone



SAMPLE_CSP_EVENT =   {
    "applicationName": "juiceshopSecure",
    "enrichmentContainer": {
      "geoLocation.countryCode": "",
      "contractId": "63bce674-e83d-4fae-909d-84b309ba0cd9",
      "applicationId": "12a3cfe3-3c39-4ecd-88d3-cea560f70bda",
      "tenant": "75292c67-8443-4714-babe-851b29de7cab"
    },
    "severity": "High",
    "targetModule": "Client-Side Protection",
    "transId": "40073466",
    "count": 1,
    "aggregated": True,
    "urls": [
      "https://juiceshopsecure.radwarecloud.com/#/search?q=\u003ciframe src%3D\"javascript:alert(`This is XSS attack that WAF cannot block`)\"\u003e"
      "https://juiceshopsecure.radwarecloud.com/#/search?q=\u003ciframe src%3D\"javascript:alert(`This is XSS attack that WAF no cannot block`)\"\u003e"
    ],
    "violationType": "DOM Based XSS",
    "host": "juiceshopsecure.radwarecloud.com",
    "action": "Reported",
    "aggregatedUserAgent": [
      "Edge",
	  "Chrome"
    ],
    "details": "Client-side protection intercepted a suspicious request, which includes a DOM Based XSS pattern.\nA DOM-based XSS attack is possible if the web application writes data to the DOM without proper sanitization.\nThe attacker can manipulate this data to include suspicious JavaScript code.\nPattern: script",
    "receivedTimeStamp": "1706103011000",
    "applicationId": "12a3cfe3-3c39-4ecd-88d3-cea560f70bda",
    "externalIp": 0,
    "domainName": ""
  }

SAMPLE_CSP_EVENT_2 =   {
    "applicationName": "juiceshopSecure",
    "enrichmentContainer": {
      "geoLocation.countryCode": "",
      "contractId": "63bce674-e83d-4fae-909d-84b309ba0cd9",
      "applicationId": "12a3cfe3-3c39-4ecd-88d3-cea560f70bda",
      "tenant": "75292c67-8443-4714-babe-851b29de7cab"
    },
    "severity": "High",
    "targetModule": "Client-Side Protection",
    "transId": "40073466",
    "count": 1,
    "aggregated": True,
    "urls": [],
    "violationType": "DOM Based XSS",
    "host": "juiceshopsecure.radwarecloud.com",
    "action": "Reported",
    "aggregatedUserAgent": [],
    "details": "Client-side protection intercepted a suspicious request, which includes a DOM Based XSS pattern.\nA DOM-based XSS attack is possible if the web application writes data to the DOM without proper sanitization.\nThe attacker can manipulate this data to include suspicious JavaScript code.\nPattern: script",
    "receivedTimeStamp": "1706103011000",
    "applicationId": "12a3cfe3-3c39-4ecd-88d3-cea560f70bda",
    "externalIp": 0,
    "domainName": ""
  }

SAMPLE_CSP_METADATA = {
    "application_name": "juiceshopSecure",
    "tenant_name": "DEMO"
}


# Test enrich_csp_log with a standard CSP log entry
def test_enrich_csp_log_standard():
    format_options = {'unify_fields': True, 'time_format': 'epoch_ms_str'}
    output_format = 'json'
    log_type = 'csp'
    enriched_event = enrich_csp_log(SAMPLE_CSP_EVENT.copy(), format_options, output_format, SAMPLE_CSP_METADATA, log_type)

    # Assertions
    assert enriched_event.get('application_name') == SAMPLE_CSP_METADATA['application_name']
    assert enriched_event.get('tenant_name') == SAMPLE_CSP_METADATA['tenant_name']
    assert enriched_event.get('log_type') == log_type
    # Add additional assertions as needed

# Test with missing fields
def test_enrich_csp_log_missing_fields():
    incomplete_log = SAMPLE_CSP_EVENT.copy()
    incomplete_log.pop("receivedTimeStamp", None)  # Example field to remove
    format_options = {'unify_fields': True, 'time_format': 'epoch_ms_str'}
    output_format = 'json'
    log_type = 'csp'
    enriched_event = enrich_csp_log(incomplete_log, format_options, output_format, SAMPLE_CSP_METADATA, log_type)
    # Assertions
    assert 'time' not in enriched_event or enriched_event['time'] == ""  # 'time' should not be present or empty

# Test with different output formats
@pytest.mark.parametrize("output_format", ['json', 'ndjson', 'cef', 'leef'])
def test_enrich_csp_log_output_formats(output_format):
    log_type = 'csp'
    format_options = {'unify_fields': True, 'time_format': 'epoch_ms_str'}
    enriched_log = enrich_csp_log(SAMPLE_CSP_EVENT.copy(), format_options, output_format, SAMPLE_CSP_METADATA, log_type)

    # Assertions for flattened `enrichmentContainer`
    assert 'country_code' in enriched_log
    assert 'application_id' in enriched_log
    assert 'contract_id' in enriched_log
    assert 'tenant_id' in enriched_log
    assert 'enrichmentContainer' not in enriched_log  # Ensure it's removed

    if output_format in ['cef', 'leef']:
        # Assert that if aggregatedUserAgent field is present then it is of type str
        if 'aggregatedUserAgent' in enriched_log:
            assert isinstance(enriched_log['aggregatedUserAgent'],
                              str), "aggregatedUserAgent should be a string in CEF/LEEF formats"

        # Assert that if urls field is present then it is of type str
        if 'urls' in enriched_log:
            assert isinstance(enriched_log['urls'], str), "urls should be a string in CEF/LEEF formats"

    elif output_format in ['json', 'ndjson']:
        # Assert that if aggregatedUserAgent field is present then it is a list
        if 'aggregatedUserAgent' in enriched_log:
            assert isinstance(enriched_log['aggregatedUserAgent'],
                              list), "aggregatedUserAgent should be a list in JSON/NDJSON formats"

        # Assert that if urls field is present then it is a list
        if 'urls' in enriched_log:
            assert isinstance(enriched_log['urls'], list), "urls should be a list in JSON/NDJSON formats"

    # Define the test with parametrization for each time format
@pytest.mark.parametrize("time_format", ['epoch_ms_str', 'epoch_ms_int', 'MM dd yyyy HH:mm:ss', 'ISO8601'])
def test_enrich_csp_log_time_transformation(time_format):
    log_type = 'csp'
    output_format = 'json'  # Assuming JSON for simplicity
    format_options = {'unify_fields': True, 'time_format': time_format}

    enriched_log = enrich_csp_log(SAMPLE_CSP_EVENT.copy(), format_options, output_format, SAMPLE_CSP_METADATA, log_type)

    # Ensure the 'time' field exists after transformation
    assert 'time' in enriched_log, "The 'time' field should exist in the enriched log."

    # Convert the original epoch ms string to a datetime object for comparison
    original_time_epoch_ms = int(SAMPLE_CSP_EVENT["receivedTimeStamp"])
    original_datetime = datetime.utcfromtimestamp(original_time_epoch_ms / 1000.0)

    transformed_time = enriched_log['time']

    # Assertions based on the time format
    if time_format == 'epoch_ms_str':
        assert transformed_time == str(
            original_time_epoch_ms), "The transformed time should match the original epoch ms string."
    elif time_format == 'epoch_ms_int':
        assert int(
            transformed_time) == original_time_epoch_ms, "The transformed time should match the original epoch ms as an integer."
    elif time_format == 'MM dd yyyy HH:mm:ss':
        expected_str = original_datetime.strftime('%m %d %Y %H:%M:%S')
        assert transformed_time == expected_str, "The transformed time should match the custom date-time string format."
    elif time_format == 'ISO8601':
        expected_iso = original_datetime.isoformat() + 'Z'  # Adding 'Z' to indicate UTC
        assert transformed_time.startswith(
            expected_iso[:19]), "The transformed time should match the ISO8601 format."

