import pytest
from logging_agent.cloud_waap.cloudwaap_json_to_cef import map_severity_format  # Adjust the import according to your module structure

# Test cases for mapping severity levels to different formats
@pytest.mark.parametrize("input_severity, severity_format, expected_output", [
    # Test original severity format
    ("info", 1, "info"),
    ("low", 1, "low"),
    ("warning", 1, "warning"),
    ("high", 1, "high"),
    ("critical", 1, "critical"),
    # Test descriptive textual representations
    ("info", 2, "Unknown"),
    ("low", 2, "Low"),
    ("warning", 2, "Medium"),
    ("high", 2, "High"),
    ("critical", 2, "Very-High"),
    # Test numeric severity levels
    ("info", 3, "1"),
    ("low", 3, "2"),
    ("warning", 3, "5"),
    ("high", 3, "7"),
    ("critical", 3, "10"),
    # Test unrecognized severity level
    ("unknown_severity", 2, "Unknown"),
    # Test unrecognized format option
    ("info", 999, "info"),
])
def test_map_severity_format(input_severity, severity_format, expected_output):
    result = map_severity_format(input_severity, severity_format)
    assert result == expected_output, f"Expected mapped severity for '{input_severity}' with format '{severity_format}' to be '{expected_output}', got '{result}' instead."
