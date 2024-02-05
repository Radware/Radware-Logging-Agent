
from logging_agent.cloud_waap.cloudwaap_enrich import enrich_webddos_log
import pytest
from datetime import datetime, timezone
import time





SAMPLE_WEBDDOS_EVENT = {
    "applicationName": "New CWAF Automated Demo",
    "currentTimestamp": "2024-01-23T01:00:28.611658252Z",
    "enrichmentContainer": {
      "geoLocation.countryCode": "",
      "contractId": "63bce674-e83d-4fae-909d-84b309ba0cd9",
      "applicationId": "805c88ac-aaf9-471a-9030-391c0393990d",
      "tenant": "75292c67-8443-4714-babe-851b29de7cab"
    },
    "attackID": "805c88ac-aaf9-471a-9030-391c0393990d-1705971620",
    "action": "Blocked",
    "startTime": 1705971620,
    "severity": "Critical",
    "attackVector": "HTTP_Flood_Attack",
    "host": "autodemo.radware.net",
    "status": "Ongoing",
    "latestRealTimeSignature": {
      "Pattern": [
        {
          "Name": "cookies",
          "Values": [
            "0"
          ]
        },
        {
          "Name": "header cache*",
          "Values": [
            "true"
          ]
        },
        {
          "Name": "header content*",
          "Values": [
            "false"
          ]
        },
        {
          "Name": "header pragma",
          "Values": [
            "true"
          ]
        },
        {
          "Name": "header sec-*",
          "Values": [
            "true"
          ]
        },
        {
          "Name": "header upgrade-insecure-requests",
          "Values": [
            "true"
          ]
        },
        {
          "Name": "header via",
          "Values": [
            "true"
          ]
        },
        {
          "Name": "known",
          "Values": [
            "9"
          ]
        },
        {
          "Name": "method",
          "Values": [
            "get"
          ]
        },
        {
          "Name": "path",
          "Values": [
            "0"
          ]
        },
        {
          "Name": "query",
          "Values": [
            "0"
          ]
        },
        {
          "Name": "unknown",
          "Values": [
            "3"
          ]
        }
      ]
    },
    "detection": {
      "ApplicationBehavior": {
        "attackThreshold": 51.505054
      }
    },
    "mitigation": {
      "totalRequests": {
        "received": 590.6,
        "dropped": 0
      },
      "averageValues": 590.6,
      "maximumValues": 590.6
    },
    "rps": {
      "inbound": 590.6,
      "blocked": 0,
      "clean": 590.6,
      "attackThreshold": 51.505054
    }
  }


SAMPLE_WEBDDOS_METADATA = {
    "application_name": "New CWAF Automated Demo",
    "tenant_name": "DEMO"
}
SAMPLE_WEBDDOS_EVENT_2 = {
    "currentTimestamp": "2024-01-23T01:00:38.597738521Z",
    "enrichmentContainer": {
      "geoLocation.countryCode": "",
      "contractId": "63bce674-e83d-4fae-909d-84b309ba0cd9",
      "applicationId": "805c88ac-aaf9-471a-9030-391c0393990d",
      "tenant": "75292c67-8443-4714-babe-851b29de7cab"
    },
    "startTime": 1705971620,
    "status": "NotStartOrEndAttack",
    "latestRealTimeSignature": {
      "Pattern": [
        {
          "Name": "cookies",
          "Values": [
            "0"
          ]
        },
        {
          "Name": "header cache*",
          "Values": [
            "true"
          ]
        },
        {
          "Name": "header content*",
          "Values": [
            "false"
          ]
        },
        {
          "Name": "header pragma",
          "Values": [
            "true"
          ]
        },
        {
          "Name": "header sec-*",
          "Values": [
            "true"
          ]
        },
        {
          "Name": "header upgrade-insecure-requests",
          "Values": [
            "true"
          ]
        },
        {
          "Name": "header via",
          "Values": [
            "true"
          ]
        },
        {
          "Name": "known",
          "Values": [
            "9"
          ]
        },
        {
          "Name": "method",
          "Values": [
            "get"
          ]
        },
        {
          "Name": "path",
          "Values": [
            "0"
          ]
        },
        {
          "Name": "query",
          "Values": [
            "0"
          ]
        },
        {
          "Name": "unknown",
          "Values": [
            "3"
          ]
        }
      ]
    },
    "detection": {
      "ApplicationBehavior": {
        "attackThreshold": 51.505054
      }
    },
    "mitigation": {
      "totalRequests": {
        "received": 2661.3,
        "dropped": 2169.2
      },
      "averageValues": 1625.95,
      "maximumValues": 2661.3
    },
    "rps": {
      "inbound": 2661.3,
      "blocked": 2169.2,
      "clean": 492.10000000000036,
      "attackThreshold": 51.505054
    }
  }

SAMPLE_WEBDDOS_EVENT_3 =  {
    "applicationName": "New CWAF Automated Demo",
    "currentTimestamp": "2024-01-30T07:25:46.912897474Z",
    "enrichmentContainer": {
      "geoLocation.countryCode": "",
      "contractId": "63bce674-e83d-4fae-909d-84b309ba0cd9",
      "applicationId": "805c88ac-aaf9-471a-9030-391c0393990d",
      "tenant": "75292c67-8443-4714-babe-851b29de7cab"
    },
    "attackID": "805c88ac-aaf9-471a-9030-391c0393990d-1706598020",
    "action": "Blocked",
    "startTime": 1706598020,
    "endTime": 1706599530000,
    "duration": "00:25:10",
    "severity": "Critical",
    "attackVector": "HTTP_Flood_Attack",
    "host": "autodemo.radware.net",
    "status": "Terminated",
    "detection": {
      "ApplicationBehavior": {
        "attackThreshold": 33.61927
      }
    },
    "mitigation": {
      "totalRequests": {
        "received": 7.9,
        "dropped": 0
      },
      "averageValues": 0,
      "maximumValues": 0
    },
    "rps": {
      "inbound": 7.9,
      "blocked": 0,
      "clean": 7.9,
      "attackThreshold": 33.61927
    }
  }

EXAMPLE_TIME_FIELDS = {"time": "2024-01-30T07:25:46.912897474Z", "startTime":1706598020 , "endTime":1706599530000}
TIME_FIELD_INPUT_TYPE = {"time" :"ISO8601_NS", "startTime": "epoch_ms", "endTime": "epoch_ms"}
@pytest.mark.parametrize("output_format", ['json', 'ndjson', 'cef', 'leef'])
def test_enrich_webddos_log_standard(output_format):
    format_options = {'unify_fields': True, 'time_format': 'epoch_ms_str'}
    log_type = 'webddos'
    enriched_event = enrich_webddos_log(SAMPLE_WEBDDOS_EVENT.copy(), format_options, output_format, SAMPLE_WEBDDOS_METADATA, log_type)

    # Assertions
    assert enriched_event.get('application_name') == SAMPLE_WEBDDOS_METADATA['application_name']
    assert enriched_event['trans_id'] == SAMPLE_WEBDDOS_EVENT.get('attackID', "")

    if output_format in ['cef', 'leef']:
        # Fields should be flattened for CEF and LEEF formats
        assert 'detection' not in enriched_event
        assert 'mitigation' not in enriched_event
        assert 'rps' not in enriched_event
    else:
        # Fields should not be flattened for JSON and NDJSON formats
        assert enriched_event.get('log_type') == log_type

        assert 'latestRealTimeSignature' in enriched_event
        assert 'detection' in enriched_event
        assert 'mitigation' in enriched_event
        assert 'rps' in enriched_event



# Test with missing fields
def test_enrich_webddos_log_variations():
    # Predefined format options, output format, and log type for WebDDoS
    format_options = {'unify_fields': True, 'time_format': 'epoch_ms_str'}
    output_format = 'json'  # Assuming JSON is the standard format for testing
    log_type = 'WebDDoS'  # Consistent log type for WebDDoS logs

    # Setup for multiple variations of the WebDDoS log
    for log_event in [SAMPLE_WEBDDOS_EVENT, SAMPLE_WEBDDOS_EVENT_2, SAMPLE_WEBDDOS_EVENT_3]:
        enriched_event = enrich_webddos_log(log_event.copy(), format_options, output_format, SAMPLE_WEBDDOS_METADATA, log_type)

        # Check if 'attackVector' is processed correctly, if present
        if 'attackVector' in log_event:
            assert enriched_event['reason'] == f"WebDDoS module has detected a {log_event['attackVector']}"
            assert enriched_event['name'] == log_event['attackVector']
            assert enriched_event['category'] == log_event['attackVector']



# Adjusted test function to correctly handle time conversions
def test_enrich_webddos_log_time_formats():
    log_type = 'WebDDoS'
    output_format = 'json'  # Standard format for testing
    time_formats = ['epoch_ms_str', 'epoch_ms_int', 'MM dd yyyy HH:mm:ss', 'ISO8601']
    original_event = SAMPLE_WEBDDOS_EVENT_3.copy()
    original_event['time'] = original_event.pop('currentTimestamp')
    for time_format in time_formats:
        format_options = {'unify_fields': True, 'time_format': time_format}
        # Ensure log_event includes the correct example time fields
        log_event = {**SAMPLE_WEBDDOS_EVENT_3, **EXAMPLE_TIME_FIELDS}
        log_event= SAMPLE_WEBDDOS_EVENT_3.copy()
        enriched_event = enrich_webddos_log(log_event, format_options, output_format, SAMPLE_WEBDDOS_METADATA, log_type)

        print(f"\nTesting time formats with output format '{time_format}'")

        # Assertions for each time field, considering their specific input formats
        for field, input_type in TIME_FIELD_INPUT_TYPE.items():
            original_time = original_event[field]
            transformed_time = enriched_event.get(field)
            print(f"Field '{field}', Input Type '{input_type}', Original Time '{original_time}', Transformed Time '{transformed_time}'")

            if input_type == "ISO8601_NS":
                # Handle ISO8601 formatted string with nanoseconds
                base_time, ns = original_time[:-1].split('.')
                parsed_time = datetime.strptime(base_time, '%Y-%m-%dT%H:%M:%S')
                epoch_ms = int(parsed_time.timestamp() * 1000) + int(ns[:3])
            else:
                # Direct handling of epoch milliseconds for startTime and endTime
                epoch_ms = original_time

            # Convert the epoch time to the expected format for comparison
            if time_format == 'epoch_ms_str':
                expected_time = str(epoch_ms)
            elif time_format == 'epoch_ms_int':
                expected_time = epoch_ms
            elif time_format == 'MM dd yyyy HH:mm:ss':
                expected_time = datetime.utcfromtimestamp(epoch_ms / 1000).strftime('%m %d %Y %H:%M:%S')
            elif time_format == 'ISO8601':
                expected_time = datetime.utcfromtimestamp(epoch_ms / 1000).isoformat(timespec='milliseconds') + 'Z'

            assert str(transformed_time) == str(expected_time), f"Time format mismatch for field {field} with format {time_format}"

