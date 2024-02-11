import pytest
from unittest.mock import patch
from logging_agent.cloud_waap.cloudwaap_enrich import enrich_access_log, enrich_waf_log, enrich_bot_log, enrich_webddos_log, enrich_ddos_log, enrich_csp_log
from urllib.parse import urlparse



SAMPLE_DDOS_EVENT =   {
    "applicationName": "CWAF Secure Demo",
    "destinationIP": "66.22.79.113",
    "destinationPort": "80",
    "totalVolume": 78,
    "protocol": "TCP",
    "sourceIP": "124.107.121.92",
    "sourcePort": "64870",
    "name": "Invalid TCP Flags",
    "category": "Anomalies",
    "enrichmentContainer": {
      "geoLocation.countryCode": "PH",
      "contractId": "63bce674-e83d-4fae-909d-84b309ba0cd9",
      "applicationId": "cb64959b-2f53-41f2-87ad-9c5810313a74",
      "tenant": "75292c67-8443-4714-babe-851b29de7cab"
    },
    "ID": "FFFFFFFF-FFFF-FFFF-000E-000064FD858F",
    "action": "drop",
    "totalPackets": 1,
    "country": "PH",
    "time": "28-01-2024 00:07:36"
  }

SAMPLE_DDOS_METADATA = {
    "application_name": "CWAF Secure Demo",
    "tenant_name": "DEMO"
}


# Test enrich_ddos_log with a standard DDoS log entry
def test_enrich_ddos_log_standard():
    format_options = {'unify_fields': True, 'time_format': 'epoch_ms_str'}
    output_format = 'json'
    log_type = 'ddos'
    enriched_event = enrich_ddos_log(SAMPLE_DDOS_EVENT.copy(), format_options, output_format, SAMPLE_DDOS_METADATA, log_type)

    # Assertions
    assert enriched_event.get('application_name') == SAMPLE_DDOS_METADATA['application_name']
    assert enriched_event.get('tenant_name') == SAMPLE_DDOS_METADATA['tenant_name']
    # Add additional assertions as needed

# Test with missing fields
def test_enrich_ddos_log_missing_fields():
    incomplete_log = SAMPLE_DDOS_EVENT.copy()
    incomplete_log.pop("sourceIP", None)  # Example field to remove
    format_options = {'unify_fields': True, 'time_format': 'epoch_ms_str'}
    output_format = 'json'
    log_type = 'ddos'
    enriched_event = enrich_ddos_log(incomplete_log, format_options, output_format, SAMPLE_DDOS_METADATA, log_type)

    # Assertions
    assert 'source_ip' not in enriched_event  # 'source_ip' should not be present

# Test with different output formats
@pytest.mark.parametrize("output_format", ['json', 'cef', 'leef'])
def test_enrich_ddos_log_output_formats(output_format):
    format_options = {'unify_fields': True, 'time_format': 'epoch_ms_str'}
    log_type = 'ddos'
    enriched_event = enrich_ddos_log(SAMPLE_DDOS_EVENT.copy(), format_options, output_format, SAMPLE_DDOS_METADATA, log_type)

    # Assertions
    # Check if the log is enriched correctly for each output format