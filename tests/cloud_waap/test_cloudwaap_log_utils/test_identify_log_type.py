import pytest
from logging_agent.cloud_waap.cloudwaap_log_utils import CloudWAAPProcessor
from unittest.mock import patch
from datetime import datetime


# Expanded test cases for identify_log_type with different key patterns
@pytest.mark.parametrize("key, expected_log_type", [
    ("CWAAP-Logs-unprocessed/Access-Logs/805c88ac-aaf9-471a-9030-391c0393990d/rdwr_log_DEMO_New CWAF Automated Demo_20240122H235500_20240123H000000_23bdcde2-ca77-4da7-b274-dbe5b306441c.json.gz", "Access"),
    ("CWAAP-Logs-unprocessed/Access-Logs/cb64959b-2f53-41f2-87ad-9c5810313a74/rdwr_log_DEMO_CWAF Secure Demo_20240123H003000_20240123H003500_7fe28734-0c94-4a52-97b0-ae81bfd8440b.json.gz", "Access"),
    ("CWAAP-Logs-unprocessed/Security-Logs/DEMO/805c88ac-aaf9-471a-9030-391c0393990d/WebDDoS/rdwr_event_DEMO_New CWAF Automated Demo_20240122H235723_20240123H000223_5792ecff-7f6b-46a3-b760-1c2d5ba15736.json.gz", "WebDDoS"),
    ("CWAAP-Logs-unprocessed/Security-Logs/DEMO/cb64959b-2f53-41f2-87ad-9c5810313a74/WAF/rdwr_event_DEMO_CWAF Secure Demo_20240123H000223_20240123H000723_5738c0ff-85ed-437e-b3e2-2986ba279873.json.gz", "WAF"),
    ("CWAAP-Logs-unprocessed/Security-Logs/DEMO/390b3d9c-3bdc-4955-bfce-71bd3f65957a/DDoS/rdwr_event_DEMO_HackazonApiMode_20240123H191707_20240123H192207_d4ff42f2-ee1b-49b2-93a5-0e764938c0af.json.gz", "DDoS"),
    ("CWAAP-Logs-unprocessed/Security-Logs/DEMO/12a3cfe3-3c39-4ecd-88d3-cea560f70bda/CSP/rdwr_event_DEMO_juiceshopSecure_20240124H132707_20240124H133207_4bcccedc-fc11-4c73-9dee-ab03cee16c5b.json.gz", "CSP"),
    ("CWAAP-Logs-unprocessed/Security-Logs/DEMO/cb64959b-2f53-41f2-87ad-9c5810313a74/Bot/rdwr_event_DEMO_CWAF Secure Demo_20240122H233400_20240122H234900_cfef5c30-2da4-4698-afdb-46fdf39e49ea.json.gz", "Bot"),
    ("DEMO/cb64959b-2f53-41f2-87ad-9c5810313a74/Bot/rdwr_event_DEMO_CWAF Secure Demo_20240122H233400_20240122H234900_cfef5c30-2da4-4698-afdb-46fdf39e49ea.json.gz", "Bot"),
    ("805c88ac-aaf9-471a-9030-391c0393990d/rdwr_log_DEMO_New CWAF Automated Demo_20240122H235500_20240123H000000_23bdcde2-ca77-4da7-b274-dbe5b306441c.json.gz", "Access"),
    ("unidentified/log/pattern.log", "Unknown")  # Test case for an unidentified log pattern
])
def test_identify_log_type(key, expected_log_type):
    log_type = CloudWAAPProcessor.identify_log_type(key)
    assert log_type == expected_log_type

