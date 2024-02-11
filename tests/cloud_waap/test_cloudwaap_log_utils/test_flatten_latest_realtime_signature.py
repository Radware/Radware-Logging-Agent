import pytest
from logging_agent.cloud_waap.cloudwaap_log_utils import CloudWAAPProcessor
from unittest.mock import patch
from datetime import datetime

log_data_with_signature = {'latestRealTimeSignature': {'Pattern': [{'Name': 'Pattern1', 'Values': ['Val1', 'Val2']}]}}

# Tests for flatten_latest_realtime_signature
def test_flatten_latest_realtime_signature_with_data():
    result = CloudWAAPProcessor.flatten_latest_realtime_signature(log_data_with_signature)
    # Assertions based on log_data_with_signature

def test_flatten_latest_realtime_signature_without_data():
    result = CloudWAAPProcessor.flatten_latest_realtime_signature({})
    assert result == ""