import pytest
from logging_agent.cloud_waap.cloudwaap_log_utils import CloudWAAPProcessor
from unittest.mock import patch
from datetime import datetime

# Tests for transform_time
@pytest.mark.parametrize("time_string, input_format, output_format, expected", [
    ("1585835450", 'epoch_ms', 'epoch_ms_str', "1585835450000"),
    ("01/Jan/2020:00:00:00 +0000", '%d/%b/%Y:%H:%M:%S %z', 'ISO8601', "2020-01-01T00:00:00.000Z"),
    ("invalid_time", '%d/%b/%Y:%H:%M:%S %z', 'ISO8601', "invalid_time"),
])
def test_transform_time(time_string, input_format, output_format, expected):
    result = CloudWAAPProcessor.transform_time(time_string, input_format, output_format)
    assert result == expected


def test_transform_time_with_multiple_formats_success():
    time_string = "01/Jan/2020:00:00:00 +0000"
    input_formats = ['%d/%b/%Y:%H:%M:%S.%f %z', '%d/%b/%Y:%H:%M:%S %z']
    expected = "2020-01-01T00:00:00.000Z"
    result = CloudWAAPProcessor.transform_time(time_string, input_formats, 'ISO8601')
    assert result == expected


def test_transform_time_with_multiple_formats_fallback():
    time_string = "not-a-real-time"
    input_formats = ['%d/%b/%Y:%H:%M:%S.%f %z', '%d/%b/%Y:%H:%M:%S %z']
    result = CloudWAAPProcessor.transform_time(time_string, input_formats, 'ISO8601')
    assert result == time_string
