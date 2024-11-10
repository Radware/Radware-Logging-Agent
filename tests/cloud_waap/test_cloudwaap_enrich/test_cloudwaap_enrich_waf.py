import pytest
from unittest.mock import patch
from logging_agent.cloud_waap.cloudwaap_enrich import enrich_access_log, enrich_waf_log, enrich_bot_log, enrich_webddos_log, enrich_ddos_log, enrich_csp_log
from datetime import datetime, timezone



SAMPLE_WAF_EVENT = {
    "applicationName": "CWAF Secure Demo",
    "action": "Blocked",
    "appPath": "/api/customerAddress",
    "destinationIp": "10.35.101.159",
    "destinationPort": "54009",
    "directory": "/api",
    "enrichmentContainer": {
      "geoLocation.countryCode": "US",
      "contractId": "63bce674-e83d-4fae-909d-84b309ba0cd9",
      "applicationId": "cb64959b-2f53-41f2-87ad-9c5810313a74",
      "tenant": "75292c67-8443-4714-babe-851b29de7cab",
      "owaspCategory2021": "A1"
    },
    "externalIp": "56.55.55.11",
    "host": "securedemo.radware.net",
    "method": "GET",
    "paramName": "text",
    "paramType": "URI",
    "paramValue": "../../../../",
    "protocol": "HTTP",
    "receivedTimeStamp": "1705971298168",
    "request": "GET /api/customerAddress?page=1\u0026text=Li4vLi4vLi4vLi4v HTTP/1.1\r\nAccept-Encoding: gzip\r\nHost: securedemo.radware.net\r\nX-RDWR-IP: 56.55.55.11\r\nX-RDWR-PORT: 60866\r\nX-RDWR-PORT-MM-ORIG-FE-PORT: 443\r\nX-RDWR-PORT-MM: 443\r\nX-RDWR-APP-ID: cb64959b-2f53-41f2-87ad-9c5810313a74\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36 Edg/89.0.774.50\r\naccept: application/json\r\nx-remote-ip: 56.55.55.11\r\nNotBot: True\r\nShieldSquare-Response: 0\r\n\r\n",
    "role": "public",
    "RuleID": "8001",
    "security": True,
    "severity": "High",
    "sourceIp": "56.55.55.11",
    "sourcePort": "57793",
    "targetModule": "Vulnerabilities",
    "title": "Pattern Violation Detected",
    "transId": "2669590124",
    "URI": "/api/customerAddress",
    "user": "public",
    "vhost": "\u0026lt;Any Host\u0026gt;",
    "violationCategory": "Path Traversal",
    "violationDetails": "Vulnerabilities Security Filter intercepted a malicious request, which includes a blocked pattern.\n8001\nDescription: An attempt to performed a Path Traversal attack on web server's directory structure was intercepted. (Severity: High)\nValue Encoding: Base64;\n\nNo Src Page: might be manual hacking attempt !\nAuthenticated as Public\n",
    "violationType": "Path Traversal",
    "webApp": "App_DEMO_CWAF_Secure_Demo"
  }

SAMPLE_WAF_METADATA = {
    "application_name": "CWAF Secure Demo",
    "tenant_name": "DEMO"
}
# Test enrich_waf_log with a standard WAF log entry
def test_enrich_waf_log_standard():
    format_options = {'unify_fields': True, 'time_format': 'epoch_ms_str'}
    output_format = 'json'
    log_type = 'waf'
    enriched_event = enrich_waf_log(SAMPLE_WAF_EVENT.copy(), format_options, output_format, SAMPLE_WAF_METADATA, log_type)

    # Assertions
    assert enriched_event.get('application_name') == SAMPLE_WAF_METADATA['application_name']
    assert enriched_event.get('tenant_name') == SAMPLE_WAF_METADATA['tenant_name']
    # Add additional assertions as needed

# Test with missing fields
def test_enrich_waf_log_missing_fields():
    incomplete_log = SAMPLE_WAF_EVENT.copy()
    incomplete_log.pop("sourceIp", None)  # Removing a field for testing
    format_options = {'unify_fields': True, 'time_format': 'epoch_ms_str'}
    output_format = 'json'
    log_type = 'waf'
    enriched_event = enrich_waf_log(incomplete_log, format_options, output_format, SAMPLE_WAF_METADATA, log_type)

    # Assertions
    assert 'source_ip' not in enriched_event  # 'source_ip' should not be present

# Test with different output formats
@pytest.mark.parametrize("output_format", ['json', 'cef', 'leef'])
def test_enrich_waf_log_output_formats(output_format):
    format_options = {'unify_fields': True, 'time_format': 'epoch_ms_str'}
    log_type = 'waf'
    enriched_event = enrich_waf_log(SAMPLE_WAF_EVENT.copy(), format_options, output_format, SAMPLE_WAF_METADATA, log_type)

    # Assertions
    # Check if the log is enriched correctly for each output format



@pytest.mark.parametrize("time_format", ['epoch_ms_str', 'epoch_ms_int', 'MM dd yyyy HH:mm:ss', 'ISO8601'])
def test_enrich_csp_log_time_transformation(time_format):
    log_type = 'WAF'
    output_format = 'json'  # Assuming JSON for simplicity
    format_options = {'unify_fields': True, 'time_format': time_format}

    enriched_log = enrich_csp_log(SAMPLE_WAF_EVENT.copy(), format_options, output_format, SAMPLE_WAF_METADATA, log_type)

    # Ensure the 'time' field exists after transformation
    assert 'time' in enriched_log, "The 'time' field should exist in the enriched log."

    # Convert the original epoch ms string to a datetime object for comparison
    original_time_epoch_ms = int(SAMPLE_WAF_EVENT["receivedTimeStamp"])
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

