from logging_agent.cloud_waap.cloudwaap_log_utils import CloudWAAPProcessor


def test_identify_log_type_access_from_payload():
    sample = {
        "request": "GET /index.html HTTP/1.1",
        "protocol": "https",
        "http_method": "GET",
        "http_bytes_in": 120,
        "http_bytes_out": 64,
        "response_code": 200,
    }

    result = CloudWAAPProcessor.identify_log_type("flat/access.json", sample)

    assert result == "Access"


def test_identify_log_type_waf_from_payload():
    sample = {
        "receivedTimeStamp": "1706302854000",
        "violationCategory": "SQL Injection",
        "request": "GET /login HTTP/1.1",
        "protocol": "https",
    }

    result = CloudWAAPProcessor.identify_log_type("flat/waf.json", sample)

    assert result == "WAF"


def test_identify_log_type_bot_from_payload():
    sample = {
        "bot_category": "Suspicious",
        "session_cookie": "abc",
        "signature_pattern": "Pattern",
        "url": "https://example.com",
        "tid": "123",
    }

    result = CloudWAAPProcessor.identify_log_type("flat/bot.json", sample)

    assert result == "Bot"


def test_identify_log_type_ddos_from_payload():
    sample = {
        "sourceIP": "1.1.1.1",
        "destinationIP": "2.2.2.2",
        "category": "Network",
        "name": "Attack",
        "ID": "abc",
    }

    result = CloudWAAPProcessor.identify_log_type("flat/ddos.json", sample)

    assert result == "DDoS"


def test_identify_log_type_webddos_from_payload():
    sample = {
        "attackVector": "HTTP_Flood",
        "currentTimestamp": "2024-01-26T23:00:28.597742015Z",
        "rps": {"inbound": 5},
        "mitigation": {"status": "active"},
        "detection": {"ApplicationBehavior": {"value": 1}},
    }

    result = CloudWAAPProcessor.identify_log_type("flat/webddos.json", sample)

    assert result == "WebDDoS"


def test_identify_log_type_csp_from_payload():
    sample = {
        "receivedTimeStamp": "1706302854000",
        "violationType": "DOM XSS",
        "target_module": "script",
        "details": "blocked",
        "urls": ["https://example.com"],
    }

    result = CloudWAAPProcessor.identify_log_type("flat/csp.json", sample)

    assert result == "CSP"


def test_identify_log_type_returns_unknown_when_no_markers():
    sample = {"unexpected_field": "value"}

    result = CloudWAAPProcessor.identify_log_type("flat/unknown.json", sample)

    assert result == "Unknown"


def test_identify_log_type_prefers_payload_over_key_guess():
    sample = {
        "receivedTimeStamp": "1706302854000",
        "violationCategory": "SQL Injection",
        "request": "GET /login HTTP/1.1",
        "protocol": "https",
    }

    result = CloudWAAPProcessor.identify_log_type("rdwr_log_access.json", sample)

    assert result == "WAF"
