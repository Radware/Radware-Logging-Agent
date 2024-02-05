import pytest
from logging_agent.cloud_waap.cloudwaap_log_utils import CloudWAAPProcessor
from unittest.mock import patch
from datetime import datetime

# Sample data for testing
sample_log_data = {
    "field1": {"subfield1": "value1", "subfield2": "value2"},
    "field2": ["item1", "item2", "item3"],
    "field3": "regularValue"
}

# Tests for update_log_with_flattened_fields
def test_update_log_with_flattened_fields():
    fields_to_flatten = ["field1"]
    result = CloudWAAPProcessor.update_log_with_flattened_fields(sample_log_data.copy(), fields_to_flatten)
    assert "field1" not in result
    assert "field1_subfield1" in result
    assert "field1_subfield2" in result

def test_update_log_fields_not_found():
    fields_to_flatten = ["nonExistingField"]
    result = CloudWAAPProcessor.update_log_with_flattened_fields(sample_log_data.copy(), fields_to_flatten)
    assert "nonExistingField" not in result