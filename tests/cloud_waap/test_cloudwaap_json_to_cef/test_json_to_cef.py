from logging_agent.cloud_waap.cloudwaap_json_to_cef import json_to_cef

import pytest


# Sample log entry and configuration for testing
log = {
    'time': '01 28 2024 20:00:12',
    'source_ip': '183.136.47.8',
    'source_port': 37678,
    'destination_ip': '204.93.139.200',
    'destination_port': 443,
    'protocol': 'https',
    'http_method': 'GET',
    'host': 'autodemo.radware.net',
    'request': 'https://autodemo.radware.net/',
    'directory': '/',
    'user_agent': 'Mozilla/5.0 (iPad; CPU OS 6_0 like Mac OS X) AppleWebKit/536.26 (KHTML, like Gecko) Version/6.0 Mobile/10A5355d Safari/8536.25',
    'accept_language': 'en-US,en;q=0.9',
    'x-forwarded-for': '183.136.47.8',
    'request_time': '0.074',
    'response_code': 200,
    'http_bytes_in': 752,
    'http_bytes_out': 66298,
    'country_code': 'CN',
    'action': 'Allowed',
    'application_id': '805c88ac-aaf9-471a-9030-391c0393990d',
    'application_name': 'New CWAF Automated Demo',
    'tenant_name': 'DEMO',
    'http_version': 'HTTP/1.0',
    'uri': '/'
}

log_type = "Access"
product = "cloud_waap"
field_mappings = {
    "cloud_waap": {
        "Access": {
            "cef": {
                "header": {
                    "log_type": "Access",
                    "product": "Cloud WAAP",
                    "severity": "Info",
                    "title": "Access Log",
                    "vendor": "Radware",
                    "version": "1.0"
                },
                "prefix": "rdwrCld",
                "static_mapping": {
                    "action": "act",
                    "cookie": "requestCookies",
                    "destination_ip": "dst",
                    "destination_port": "dpt",
                    "host": "dhost",
                    "http_bytes_in": "in",
                    "http_bytes_out": "out",
                    "http_method": "method",
                    "protocol": "app",
                    "referrer": "requestContext",
                    "request": "request",
                    "source_ip": "src",
                    "source_port": "spt",
                    "time": "rt",
                    "uri": "uri",
                    "user_agent": "requestClientApplication"
                }
            },
            "leef": {
                "header": {
                    "log_type": "Access",
                    "product": "Cloud WAAP",
                    "vendor": "Radware",
                    "version": "1.0"
                },
                "prefix": "rdwrCld",
                "static_mapping": {
                    "action": "action",
                    "cookie": "cookie",
                    "destination_ip": "dst",
                    "destination_port": "dstPort",
                    "host": "dhost",
                    "http_bytes_in": "bytesIn",
                    "http_bytes_out": "bytesOut",
                    "http_method": "method",
                    "protocol": "proto",
                    "referrer": "referrer",
                    "request": "url",
                    "response_code": "responseCode",
                    "source_ip": "src",
                    "source_port": "srcPort",
                    "time": "eventTime",
                    "uri": "uri",
                    "user_agent": "userAgent"
                }
            }
        },
        "Bot": {
            "cef": {
                "header": {
                    "log_type": "Bot",
                    "product": "Cloud WAAP",
                    "severity": "Info",
                    "title": "fromlog",
                    "vendor": "Radware",
                    "version": "1.0"
                },
                "prefix": "rdwrCld",
                "static_mapping": {
                    "action": "act",
                    "category": "cat",
                    "host": "dhost",
                    "reason": "reason",
                    "referrer": "requestContext",
                    "request": "request",
                    "source_ip": "src",
                    "time": "rt",
                    "uri": "uri",
                    "user_agent": "requestClientApplication"
                }
            },
            "leef": {
                "header": {
                    "log_type": "Bot",
                    "product": "Cloud WAAP",
                    "vendor": "Radware",
                    "version": "1.0"
                },
                "prefix": "rdwrCld",
                "static_mapping": {
                    "action": "action",
                    "category": "cat",
                    "host": "dhost",
                    "name": "name",
                    "reason": "reason",
                    "referrer": "referrer",
                    "request": "request",
                    "source_ip": "src",
                    "time": "eventTime",
                    "uri": "uri",
                    "user_agent": "userAgent"
                }
            }
        },
        "CSP": {
            "cef": {
                "header": {
                    "log_type": "CSP",
                    "product": "Cloud WAAP",
                    "severity": "fromlog",
                    "title": "fromlog",
                    "vendor": "Radware",
                    "version": "1.0"
                },
                "prefix": "rdwrCld",
                "static_mapping": {
                    "action": "act",
                    "category": "category",
                    "count": "cnt",
                    "host": "dhost",
                    "reason": "reason",
                    "time": "rt"
                }
            },
            "leef": {
                "header": {
                    "log_type": "WebDDoS",
                    "product": "Cloud WAAP",
                    "vendor": "Radware",
                    "version": "1.0"
                },
                "prefix": "rdwrCld",
                "static_mapping": {
                    "action": "action",
                    "category": "category",
                    "count": "cnt",
                    "host": "dhost",
                    "name": "name",
                    "reason": "reason",
                    "severity": "sev",
                    "time": "eventTime"
                }
            }
        },
        "DDoS": {
            "cef": {
                "header": {
                    "log_type": "DDoS",
                    "product": "CloudWAAP",
                    "severity": "Info",
                    "title": "fromlog",
                    "vendor": "Radware",
                    "version": "1.0"
                },
                "prefix": "rdwrCld",
                "static_mapping": {
                    "action": "act",
                    "category": "cat",
                    "destination_ip": "dst",
                    "destination_port": "dpt",
                    "protocol": "app",
                    "reason": "reason",
                    "source_ip": "src",
                    "source_port": "spt",
                    "time": "rt"
                }
            },
            "leef": {
                "header": {
                    "log_type": "DDoS",
                    "product": "Cloud WAAP",
                    "vendor": "Radware",
                    "version": "1.0"
                },
                "prefix": "rdwrCld",
                "static_mapping": {
                    "action": "action",
                    "category": "cat",
                    "destination_ip": "dst",
                    "destination_port": "dstPort",
                    "name": "name",
                    "protocol": "proto",
                    "reason": "reason",
                    "source_ip": "src",
                    "source_port": "srcPort",
                    "time": "eventTime"
                }
            }
        },
        "WAF": {
            "cef": {
                "header": {
                    "log_type": "WAF",
                    "product": "Cloud WAAP",
                    "severity": "fromlog",
                    "title": "fromlog",
                    "vendor": "Radware",
                    "version": "1.0"
                },
                "prefix": "rdwrCld",
                "static_mapping": {
                    "action": "act",
                    "category": "cat",
                    "cookie": "requestCookies",
                    "destination_ip": "dst",
                    "destination_port": "dpt",
                    "host": "dhost",
                    "http_method": "requestMethod",
                    "protocol": "app",
                    "reason": "reason",
                    "referrer": "requestContext",
                    "request": "request",
                    "source_ip": "src",
                    "source_port": "spt",
                    "time": "rt",
                    "uri": "uri",
                    "user_agent": "requestClientApplication"
                }
            },
            "leef": {
                "header": {
                    "log_type": "WAF",
                    "product": "Cloud WAAP",
                    "vendor": "Radware",
                    "version": "1.0"
                },
                "prefix": "rdwrCld",
                "static_mapping": {
                    "action": "action",
                    "category": "cat",
                    "cookie": "cookie",
                    "destination_ip": "dst",
                    "destination_port": "dstPort",
                    "host": "dhost",
                    "http_method": "method",
                    "name": "name",
                    "protocol": "proto",
                    "reason": "reason",
                    "referrer": "referrer",
                    "request": "request",
                    "severity": "sev",
                    "source_ip": "src",
                    "source_port": "srcPort",
                    "time": "eventTime",
                    "user_agent": "userAgent"
                }
            }
        },
        "WebDDoS": {
            "cef": {
                "header": {
                    "log_type": "WebDDoS",
                    "product": "Cloud WAAP",
                    "severity": "Critical",
                    "title": "fromlog",
                    "vendor": "Radware",
                    "version": "1.0"
                },
                "prefix": "rdwrCld",
                "static_mapping": {
                    "action": "act",
                    "category": "category",
                    "endTime": "end",
                    "host": "dhost",
                    "reason": "reason",
                    "startTime": "start",
                    "time": "rt"
                }
            },
            "leef": {
                "header": {
                    "log_type": "WebDDoS",
                    "product": "Cloud WAAP",
                    "vendor": "Radware",
                    "version": "1.0"
                },
                "prefix": "rdwrCld",
                "static_mapping": {
                    "action": "action",
                    "category": "cat",
                    "host": "dhost",
                    "name": "name",
                    "reason": "reason",
                    "severity": "sev",
                    "time": "eventTime"
                }
            }
        }
    }
}
format_options = {
    'delimiter': '\n',
    'time_format': 'MM dd yyyy HH:mm:ss',
    'unify_fields': True,
    'severity_format': 1,
    'syslog_header': {'generate_header': True, 'host': 'product'}
}

# Expected CEF string part (simplified for example purposes)
expected_cef_part = "CEF:0|Radware|Cloud WAAP|1.0|Access|Access Log|Info|"

@pytest.mark.parametrize("test_log, expected_output", [
    (log, expected_cef_part)
])
def test_json_to_cef(test_log, expected_output):
    result = json_to_cef(test_log, log_type, product, field_mappings, format_options)
    assert expected_output in result, "The CEF transformation did not produce the expected output."


@pytest.mark.parametrize("test_log,expected_in_output,description", [
    # Special Characters
    ({**log, "user_agent": "\\Mozilla/5.0\r\n <script>alert('XSS')</script>"}, "\\\\Mozilla/5.0\\r\\n <script>alert('XSS')</script>", "Escapes special characters"),
    # Unrecognized Severity
    ({**log, "severity": "unrecognized"}, "Info", "Defaults to Info on unrecognized severity"),
    # Invalid Time Format
    ({**log, "time": "invalid-time-format"}, "rt=invalid-time-format", "Handles invalid time formats gracefully"),
    # Syslog Header Customization with Missing Config
    ({}, "Radware-CloudWAAP ", "Defaults to product name when syslog host config missing"),
    # Very Large Field Values
    ({**log, "request": "a" * 100000}, "a" * 255, "Truncates or handles very large field values"),
])
def test_json_to_cef_edge_cases(test_log, expected_in_output, description):
    result = json_to_cef(test_log, log_type, product, field_mappings, format_options)
    assert expected_in_output in result, f"Failed to handle case: {description}"


