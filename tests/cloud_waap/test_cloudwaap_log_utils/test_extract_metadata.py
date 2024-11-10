import pytest
from logging_agent.cloud_waap.cloudwaap_log_utils import CloudWAAPProcessor
from unittest.mock import patch

# Sample data for testing
valid_key = "valid_key_example"
invalid_key = "invalid_key_example"
# Tests for extract_metadata
def test_extract_metadata_valid():
    result = CloudWAAPProcessor.extract_metadata(valid_key, "cloud_waap", "WebDDoS")
    # Assertions based on valid_key

def test_extract_metadata_invalid():
    result = CloudWAAPProcessor.extract_metadata(invalid_key, "invalid_product", "Access")
    assert result == {"tenant_name": None, "application_name": None}