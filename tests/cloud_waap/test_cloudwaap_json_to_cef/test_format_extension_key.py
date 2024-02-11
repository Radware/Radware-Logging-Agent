import pytest
from logging_agent.cloud_waap.cloudwaap_json_to_cef  import format_extension_key  # Adjust the import path as necessary

# Test cases for formatting extension keys with a prefix
@pytest.mark.parametrize("key, prefix, expected_result", [
    # Simple case with no special characters
    ("action", "rdwrCld", "rdwrCldAction"),
    # Key with spaces
    ("source ip", "rdwrCld", "rdwrCldSourceIp"),
    # Key with underscores
    ("http_method", "rdwrCld", "rdwrCldHttpMethod"),
    # Key with hyphens
    ("user-agent", "rdwrCld", "rdwrCldUserAgent"),
    # Key with mixed characters
    ("x-forwarded-for", "rdwrCld", "rdwrCldXForwardedFor"),

    # Key that is already in the desired format
    ("DestinationPort", "rdwrCld", "rdwrCldDestinationPort"),
    # Edge case: empty key
    ("", "rdwrCld", "rdwrCldUnknownKey"),
    # Case with mixed capitalization and abbreviation
    ("DestinationIp", "rdwrCld", "rdwrCldDestinationIp"),
    ("sourcePort", "rdwrCld", "rdwrCldSourcePort"),

    # Additional test case to ensure handling of already correctly formatted keys
    ("SourceIP", "rdwrCld", "rdwrCldSourceIP"),
    ("DestinationIP", "rdwrCld", "rdwrCldDestinationIP"),
    # Handling mixed cases and preserving parts of the abbreviation
    ("sourceIP", "rdwrCld", "rdwrCldSourceIP")
])
def test_format_extension_key(key, prefix, expected_result):
    result = format_extension_key(key, prefix)
    assert result == expected_result, f"Expected '{expected_result}', got '{result}'"
