import pytest
from logging_agent.cloud_waap.cloudwaap_json_to_cef import sanitize_cef_value

# Test cases for sanitizing CEF values
@pytest.mark.parametrize("input_value, expected_output", [
    ("normalText", "normalText"),
    ("text\\with\\backslashes", "text\\\\with\\\\backslashes"),
    ("carriage\rreturn", "carriage\\rreturn"),
    ("new\nline", "new\\nline"),
    ("equals=sign", "equals\\=sign"),
    ("pipe|character", "pipe\\|character"),
    ("comma,separated", "comma\\,separated"),
    ("semicolon;split", "semicolon\\;split"),
    ("quote\"double", "quote\\\"double"),
    (12345, "12345"),  # Non-string input
    ({"key": "value"}, "{'key': 'value'}"),  # Dict input converted to string
    ([1, 2, 3], "[1\\, 2\\, 3]"),  # List input converted to string
    # Combination of characters
    ("complex;value=with|many,special\\characters\"and\nnew\rline",
     "complex\\;value\\=with\\|many\\,special\\\\characters\\\"and\\nnew\\rline"),

    # Multiple carriage returns and new lines before other characters
    ("\r\nmultiple\r\nlines\r\nbefore=others", "\\r\\nmultiple\\r\\nlines\\r\\nbefore\\=others"),

    # String that starts with a backslash and contains characters resembling escape sequences
    ("\\telecom\\relevant;data=with|special,chars", "\\\\telecom\\\\relevant\\;data\\=with\\|special\\,chars"),

    # String with complex combination of special characters and escape-like sequences
    ("complex\n\rsequence\\with\\all=special|characters,including;\"quotes\"and\\telecom",
     "complex\\n\\rsequence\\\\with\\\\all\\=special\\|characters\\,including\\;\\\"quotes\\\"and\\\\telecom"),

    # Ensure escape-like sequences are treated literally and not as escape sequences
    ("\\t\\n\\r\\f\\v", "\\\\t\\\\n\\\\r\\\\f\\\\v")
])
def test_sanitize_cef_value(input_value, expected_output):
    sanitized_value = sanitize_cef_value(input_value)
    assert sanitized_value == expected_output, f"Sanitized value does not match expected output. Expected '{expected_output}', got '{sanitized_value}'"
