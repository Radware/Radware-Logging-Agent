import pytest
from logging_agent.cloud_waap.cloudwaap_json_to_cef import construct_cef_header, map_severity_format

# Sample field mappings based on the provided partial mapping file
FIELD_MAPPINGS = {
    "cloud_waap": {
        "Access": {
            "cef": {
                "header": {
                    "vendor": "Radware",
                    "product": "Cloud WAAP",
                    "version": "1.0",
                    "log_type": "Access",
                    "title": "Access Log",
                    "severity": "Info"
                }
            }
        },
        "WAF": {
            "cef": {
                "header": {
                    "vendor": "Radware",
                    "product": "Cloud WAAP",
                    "version": "1.0",
                    "log_type": "WAF",
                    "title": "fromlog",
                    "severity": "fromlog"
                }
            }
        }
    }
}

# Test data
@pytest.mark.parametrize("product, log_type, log, severity_format, expected_header", [
    # Test case 1: Access log with static severity
    ("cloud_waap", "Access", {}, 1, "CEF:0|Radware|Cloud WAAP|1.0|Access|Access Log|Info|"),
    # Test case 2: WAF log with dynamic severity and title from log
    ("cloud_waap", "WAF", {"name": "SQL Injection", "severity": "High"}, 2, "CEF:0|Radware|Cloud WAAP|1.0|WAF|SQL Injection|High|"),
    # Test case 3: Unknown product and log type
    ("unknown_product", "unknown_log_type", {}, 1, "CEF:0|Unknown|Unknown|Unknown|Unknown|Unknown|info|"),
    # Additional cases as needed, including testing different severity_format values
])
def test_get_cef_header(product, log_type, log, severity_format, expected_header):
    header = construct_cef_header(product, log_type, log, FIELD_MAPPINGS, severity_format)
    assert header == expected_header
