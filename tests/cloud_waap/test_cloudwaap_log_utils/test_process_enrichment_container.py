import pytest
from logging_agent.cloud_waap.cloudwaap_log_utils import CloudWAAPProcessor
from unittest.mock import patch
from datetime import datetime

def test_process_enrichment_container_standard():
    log = {
        "enrichmentContainer": {
            "geoLocation.countryCode": "US",
            "applicationId": "app123",
            "contractId": "contract123",
            "tenant": "tenant123"
        }
    }
    result = CloudWAAPProcessor.process_enrichment_container(log)
    assert result["country_code"] == "US"
    assert result["application_id"] == "app123"
    assert result["contract_id"] == "contract123"
    assert result["tenant_id"] == "tenant123"
    assert "enrichmentContainer" not in result

def test_process_enrichment_container_missing():
    log = {"someKey": "someValue"}
    result = CloudWAAPProcessor.process_enrichment_container(log)
    assert "country_code" not in result
    assert "application_id" not in result
