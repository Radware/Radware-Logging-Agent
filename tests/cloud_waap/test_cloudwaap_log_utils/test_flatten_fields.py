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

def test_flatten_fields():
    fields_to_flatten = ["field2"]
    result = CloudWAAPProcessor.flatten_csp_fields(sample_log_data.copy(), fields_to_flatten)
    assert result["field2"] == "item1,item2,item3"

def test_flatten_fields_non_list():
    fields_to_flatten = ["field3"]
    result = CloudWAAPProcessor.flatten_csp_fields(sample_log_data.copy(), fields_to_flatten)
    assert "field3" in result and isinstance(result["field3"], str)