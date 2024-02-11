import pytest
from logging_agent.cloud_waap.cloudwaap_log_utils import CloudWAAPProcessor
from unittest.mock import patch
from datetime import datetime

@pytest.mark.parametrize("key, expected_application_name", [
    ("CWAAP-Logs-unprocessed/Security-Logs/DEMO/805c88ac-aaf9-471a-9030-391c0393990d/WebDDoS/rdwr_event_DEMO_New CWAF Automated Demo_20240122H235723_20240123H000223_5792ecff-7f6b-46a3-b760-1c2d5ba15736.json.gz", "New CWAF Automated Demo"),
    ("CWAAP-Logs-unprocessed/Security-Logs/DEMO/cb64959b-2f53-41f2-87ad-9c5810313a74/WAF/rdwr_event_DEMO_CWAF Secure Demo_20240123H000223_20240123H000723_5738c0ff-85ed-437e-b3e2-2986ba279873.json.gz", "CWAF Secure Demo"),
    ("CWAAP-Logs-unprocessed/Security-Logs/cus_12_/390b3d9c-3bdc-4955-bfce-71bd3f65957a/DDoS/rdwr_event_cus_12__HackazonApiMode_20240123H191707_20240123H192207_d4ff42f2-ee1b-49b2-93a5-0e764938c0af.json.gz", "HackazonApiMode"),
    ("unidentified/log/pattern.log", None)
])
def test_parse_application_name(key, expected_application_name):
    application_name = CloudWAAPProcessor.parse_application_name(key)
    assert application_name == expected_application_name