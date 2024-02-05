import pytest
from logging_agent.cloud_waap.cloudwaap_log_utils import CloudWAAPProcessor
from unittest.mock import patch
from datetime import datetime

# Test enrich_waf_log with valid inputs
def test_enrich_waf_log_standard():
    original_log = {'someKey': 'someValue'}
    method = 'GET'
    full_url = 'http://example.com'
    http_version = 'HTTP/1.1'
    cookie = 'sessionId=abc123'
    user_agent = 'Mozilla/5.0'
    referrer = 'http://referrer.com'
    headers = 'Cookie: sessionId=abc123; User-Agent: Mozilla/5.0'

    enriched_log = CloudWAAPProcessor.enrich_waf_log(original_log.copy(), method, full_url, http_version, cookie, user_agent, referrer, headers)

    assert enriched_log.get('http_method') == method
    assert enriched_log.get('request') == full_url
    assert enriched_log.get('http_version') == http_version
    assert enriched_log.get('cookie') == cookie
    assert enriched_log.get('user_agent') == user_agent
    assert enriched_log.get('referrer') == referrer
    assert enriched_log.get('headers') == headers
    assert 'method' not in enriched_log  # 'method' field should be removed

# Test enrich_waf_log with missing or empty fields
def test_enrich_waf_log_missing_fields():
    original_log = {'someKey': 'someValue'}
    enriched_log = CloudWAAPProcessor.enrich_waf_log(original_log.copy(), '', '', '', '', '', '', '')

    assert all(key in enriched_log for key in ['http_method', 'request', 'http_version', 'cookie', 'user_agent', 'referrer', 'headers'])
    assert all(enriched_log[key] == '' for key in ['http_method', 'request', 'http_version', 'cookie', 'user_agent', 'referrer', 'headers'])
