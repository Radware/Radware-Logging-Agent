import pytest
from logging_agent.cloud_waap.cloudwaap_json_to_cef import is_value_valid  # Adjust import path as necessary


@pytest.mark.parametrize("value, expected", [
    # Test cases for unwanted values
    ("", False),
    ("-", False),
    (" - ", False),
    ("--", False),
    (None, False),

    # Test cases for valid values
    ("value", True),
    ("123", True),
    ("0", True),
    ("Valid-Value", True),
    ("Valid Value", True),
    ("Valid_Value", True),
    (0, True),  # Assuming numeric zero is considered a valid value
    (123, True),  # Valid numeric value
    (True, True),  # Boolean true
    (False, True),  # Boolean false, assuming it's considered a valid "value"
])
def test_is_value_valid(value, expected):
    result = is_value_valid(value)
    assert result == expected, f"Expected '{expected}' for value '{value}', got '{result}'"
