import pytest
from unittest.mock import patch
from logging_agent.cloud_waap.cloudwaap_enrich import enrich_access_log, enrich_waf_log, enrich_bot_log, enrich_webddos_log, enrich_ddos_log, enrich_csp_log
from urllib.parse import urlparse



SAMPLE_BOT_EVENT = {
    "application_name": "CWAF Secure Demo",
    "action": "Challenge CAPTCHA",
    "tid": "2188e026-c2vf-4e8f-88d2-f19e5bd995a9",
    "status": "Mitigated",
    "time": 1705966616016,
    "site": "securedemo.radware.net",
    "url": "https://securedemo.radware.net/user/login",
    "ip": "218.153.231.193",
    "country_code": "KR",
    "bot_category": "Programmatic Session behavior",
    "referrer": "",
    "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:87.0) Gecko/20100101 Firefox/87.0",
    "session_cookie": "c0cd1b50-854d-4887-a4ed-68a297041869",
    "headers": "Accept : text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9, Accept-Language : en-US,en;q=0.9, Accept-Encoding : gzip, deflate ",
    "violation_reason": "Programmatic browser behavior",
    "policy_id": "rabce4",
    "signature_pattern": "IP:218.153.231.193; User Session: "
  }

SAMPLE_BOT_METADATA = {
    "application_name": "CWAF Secure Demo",
    "tenant_name": "DEMO"
}

# Test enrich_bot_log with a standard Bot log entry
def test_enrich_bot_log_standard():
    format_options = {'unify_fields': True, 'time_format': 'epoch_ms_str'}
    output_format = 'json'
    log_type = 'bot'
    enriched_event = enrich_bot_log(SAMPLE_BOT_EVENT.copy(), format_options, output_format, SAMPLE_BOT_METADATA, log_type)

    # Assertions
    assert enriched_event.get('application_name') == SAMPLE_BOT_METADATA['application_name']
    assert enriched_event.get('tenant_name') == SAMPLE_BOT_METADATA['tenant_name']
    # Add additional assertions as needed

# Test with missing fields
def test_enrich_bot_log_missing_fields():
    incomplete_log = SAMPLE_BOT_EVENT.copy()
    incomplete_log.pop("ip", None)  # Example field to remove
    format_options = {'unify_fields': True, 'time_format': 'epoch_ms_str'}
    output_format = 'json'
    log_type = 'bot'
    enriched_event = enrich_bot_log(incomplete_log, format_options, output_format, SAMPLE_BOT_METADATA, log_type)

    # Assertions
    assert 'source_ip' not in enriched_event  # 'source_ip' should not be present

# Test with different output formats
@pytest.mark.parametrize("output_format", ['json', 'cef', 'leef'])
def test_enrich_bot_log_output_formats(output_format):
    format_options = {'unify_fields': True, 'time_format': 'epoch_ms_str'}
    log_type = 'bot'
    enriched_event = enrich_bot_log(SAMPLE_BOT_EVENT.copy(), format_options, output_format, SAMPLE_BOT_METADATA, log_type)

    # Assertions
    # Check if the log is enriched correctly for each output format
