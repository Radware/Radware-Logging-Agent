# conftest.py
import pytest
from unittest.mock import patch, MagicMock
from logging_agent.data_loader import DataLoader
from logging_agent.transformer import Transformer
from logging_agent.sender import Sender
from logging_agent.data_processor import DataProcessor
from logging_agent.cloud_waap import CloudWAAPProcessor  # Make sure this import matches your project structure

from io import BytesIO
from logging_agent.downloader import S3Downloader


@pytest.fixture
def config():
    return {
        'type': 'sqs',
        'product': 'cloud_waap',
        'output': {
            'output_format': 'json',
            'type': 'tcp',
            'destination': 'http://example.com'
        },
        'aws_credentials': {
            'region': 'test-region',
            'access_key_id': 'test-access-key',
            'secret_access_key': 'test-secret-key'
        },
        'sqs_settings': {
            'queue_name': 'test-queue',
            'delete_on_failure': True
        },
        "logs": {
            "Access": True
        }
    }


@pytest.fixture
def input_info():
    return {
    "bucket": "cloudwaf-demo-event-bucket",
    "expected_size": 1559138,
    "key": "CWAAP-Logs-unprocessed/Access-Logs/805c88ac-aaf9-471a-9030-391c0393990d/rdwr_log_DEMO_New CWAF Automated Demo_20240131H070000_20240131H070500_79244803-9682-4d0f-924d-567268708991.json"
}
@pytest.fixture
def mock_s3_downloader(mocker):
    with patch('logging_agent.data_loader.S3Downloader') as MockDownloader:
        mock_instance = MockDownloader.return_value
        mock_instance.download.return_value = True  # Simulate successful download
        yield mock_instance
@pytest.fixture
def mock_filesystem(tmp_path):
    """
    Use pytest's tmp_path fixture to create a temporary directory for tests.
    This avoids the need for mocking os.path.exists and os.remove.
    """
    # Example file path within the temporary directory
    file_path = tmp_path / "example.json.gz"
    # Write example data to simulate a downloaded and processed file
    file_path.write_text('{"example": "data"}')
    return tmp_path  # This path can be used in DataLoader tests

@pytest.fixture
def data_loader_config(tmp_path):
    """
    Fixture to provide DataLoader with a configuration that uses the temporary directory.
    """
    return {
        'aws_credentials': {
            'region': 'us-test-1',
            'access_key_id': 'test',
            'secret_access_key': 'test'
        },
        'output_directory': str(tmp_path)  # Use pytest's tmp_path fixture directory
    }




@pytest.fixture
def mock_boto3_client():
    with patch('boto3.client') as MockClient:
        mock_s3_client = MockClient.return_value
        mock_s3_client.download_file = MagicMock(return_value=None)  # Simulate download
        yield mock_s3_client


@pytest.fixture
def mock_dependencies(monkeypatch):
    mock_data_loader = MagicMock(spec=DataLoader)
    mock_transformer = MagicMock(spec=Transformer)
    mock_sender_send_data = MagicMock(return_value=True)  # This mock is for the send_data method specifically

    # Correctly replace the instances where these would be instantiated
    monkeypatch.setattr("logging_agent.data_processor.DataLoader", lambda config: mock_data_loader)
    monkeypatch.setattr("logging_agent.data_processor.Transformer", lambda config: mock_transformer)
    monkeypatch.setattr("logging_agent.sender.Sender.send_data", mock_sender_send_data)  # Correctly mock the static method


    # Setup mock return values
    mock_data_loader.load_data.return_value = {'data': [{'sample': 'data'}], 'metadata': {}}
    mock_transformer.transform_content.return_value = [{'sample': 'data'}]

    return {
        'data_loader': mock_data_loader,
        'transformer': mock_transformer,
        'sender_send_data': mock_sender_send_data
    }

@pytest.fixture
def config_fixture():
    return {
        'type': 'sqs',
        'product': 'cloud_waap',
        'output': {
            'output_format': 'json',
            'type': 'tcp',
            'destination': '127.0.0.1',
            'port': "4444"
        },
        'aws_credentials': {
            'region': 'test-region',
            'access_key_id': 'test-access-key',
            'secret_access_key': 'test-secret-key'
        },
        'sqs_settings': {
            'queue_name': 'test-queue',
            'delete_on_failure': True
        },
        "logs": {
            "Access": True
        },
        "tcp": {
            "batch": False
        },
        "formats": {
            "json": {}
        }
    }

@pytest.fixture
def data_processor(config_fixture):
    # Directly return the DataProcessor instance using the config fixture
    return DataProcessor(config_fixture)



@pytest.fixture
def mock_cloud_waap_processor():
    with patch.object(CloudWAAPProcessor, 'identify_log_type', return_value='Access') as mock:
        yield mock


import pytest

@pytest.fixture
def field_mappings():
    return {
  "cloud_waap": {
    "Access": {
      "cef": {
        "prefix": "rdwrCld",
        "header": {
          "vendor": "Radware",
          "product": "Cloud WAAP",
          "version": "1.0",
          "log_type": "Access",
          "title": "Access Log",
          "severity": "Info"
        },
        "static_mapping": {
          "time": "rt",
          "action": "act",
          "host": "dhost",
          "source_ip": "src",
          "destination_ip": "dst",
          "source_port": "spt",
          "destination_port": "dpt",
          "protocol": "app",
          "request": "request",
          "uri": "uri",
          "http_method": "method",
          "http_bytes_in": "in",
          "http_bytes_out": "out",
          "user_agent": "requestClientApplication",
          "referrer": "requestContext",
          "cookie": "requestCookies"
        }
      },
      "leef": {
        "prefix": "rdwrCld",
        "header": {
          "vendor": "Radware",
          "product": "Cloud WAAP",
          "version": "1.0",
          "log_type": "Access"
        },
        "static_mapping": {
          "time": "eventTime",
          "action": "action",
          "host": "dhost",
          "source_ip": "src",
          "destination_ip": "dst",
          "source_port": "srcPort",
          "destination_port": "dstPort",
          "protocol": "proto",
          "request": "url",
          "uri": "uri",
          "http_method": "method",
          "http_bytes_in": "bytesIn",
          "http_bytes_out": "bytesOut",
          "user_agent": "userAgent",
          "referrer": "referrer",
          "cookie": "cookie",
          "response_code": "responseCode"
        }
      }
    },
    "WAF": {
      "cef": {
      "prefix": "rdwrCld",
        "header": {
          "vendor": "Radware",
          "product": "Cloud WAAP",
          "version": "1.0",
          "log_type": "WAF",
          "title": "fromlog",
          "severity": "fromlog"
      },
      "static_mapping": {
          "time": "rt",
          "action": "act",
          "host": "dhost",
          "source_ip": "src",
          "destination_ip": "dst",
          "source_port": "spt",
          "destination_port": "dpt",
          "protocol": "app",
          "http_method": "requestMethod",
          "request": "request",
          "uri": "uri",
          "reason": "reason",
          "category": "cat",
          "user_agent": "requestClientApplication",
          "referrer": "requestContext",
          "cookie": "requestCookies"
       }
      },
      "leef": {
      "prefix": "rdwrCld",
        "header": {
          "vendor": "Radware",
          "product": "Cloud WAAP",
          "version": "1.0",
          "log_type": "WAF"
      },
      "static_mapping": {
          "time": "eventTime",
          "action": "action",
          "host": "dhost",
          "source_ip": "src",
          "destination_ip": "dst",
          "source_port": "srcPort",
          "destination_port": "dstPort",
          "protocol": "proto",
          "http_method": "method",
          "request": "request",
          "uri": "uri",
          "name": "name",
          "reason": "reason",
          "category": "cat",
          "referrer": "referrer",
          "cookie": "cookie",
          "user_agent": "userAgent",
          "severity": "sev"
       }
      }
    },
    "Bot": {
      "cef": {
        "prefix": "rdwrCld",
        "header": {
          "vendor": "Radware",
          "product": "Cloud WAAP",
          "version": "1.0",
          "log_type": "Bot",
          "title": "fromlog",
          "severity": "Info"
        },
        "static_mapping": {
          "time": "rt",
          "action": "act",
          "host": "dhost",
          "source_ip": "src",
          "request": "request",
          "uri": "uri",
          "reason": "reason",
          "category": "cat",
          "user_agent": "requestClientApplication",
          "referrer": "requestContext"

        }
      },
      "leef": {
        "prefix": "rdwrCld",
        "header": {
          "vendor": "Radware",
          "product": "Cloud WAAP",
          "version": "1.0",
          "log_type": "Bot"
        },
        "static_mapping": {
          "time": "eventTime",
          "action": "action",
          "host": "dhost",
          "source_ip": "src",
          "request": "request",
          "uri": "uri",
          "name": "name",
          "reason": "reason",
          "category": "cat",
          "user_agent": "userAgent",
          "referrer": "referrer"
        }
      }
    },
    "DDoS": {
      "cef": {
      "prefix": "rdwrCld",
      "header": {
        "vendor": "Radware",
        "product": "CloudWAAP",
        "version": "1.0",
        "log_type": "DDoS",
        "title": "fromlog",
        "severity": "Info"
      },
      "static_mapping": {
        "time": "rt",
        "action": "act",
        "source_ip": "src",
        "destination_ip": "dst",
        "source_port": "spt",
        "destination_port": "dpt",
        "protocol": "app",
        "reason": "reason",
        "category": "cat"
      }
    },
      "leef": {
      "prefix": "rdwrCld",
      "header": {
        "vendor": "Radware",
        "product": "Cloud WAAP",
        "version": "1.0",
        "log_type": "DDoS"
      },
      "static_mapping": {
        "time": "eventTime",
        "action": "action",
        "source_ip": "src",
        "destination_ip": "dst",
        "source_port": "srcPort",
        "destination_port": "dstPort",
        "protocol": "proto",
        "name": "name",
        "reason":"reason",
        "category": "cat",
        "severity": "sev"
        }
      }
    },
    "WebDDoS": {
      "cef": {
        "prefix": "rdwrCld",
        "header": {
          "vendor": "Radware",
          "product": "Cloud WAAP",
          "version": "1.0",
          "log_type": "WebDDoS",
          "title": "fromlog",
          "severity": "Critical"
        },
        "static_mapping": {
          "time": "rt",
          "action": "act",
          "host": "dhost",
          "reason": "reason",
          "category": "category",
          "startTime": "start",
          "endTime": "end"
        }
      },
      "leef": {
        "prefix": "rdwrCld",
        "header": {
          "vendor": "Radware",
          "product": "Cloud WAAP",
          "version": "1.0",
          "log_type": "WebDDoS"
        },
        "static_mapping": {
          "time": "eventTime",
          "action": "action",
          "host": "dhost",
          "name": "name",
          "reason": "reason",
          "category": "cat",
          "severity": "sev",
          "startTime": "startTime",
          "endTime": "endTime"
        }
      }
    },
    "CSP": {
      "cef": {
        "prefix": "rdwrCld",
        "header": {
          "vendor": "Radware",
          "product": "Cloud WAAP",
          "version": "1.0",
          "log_type": "CSP",
          "title": "fromlog",
          "severity": "fromlog"
        },
        "static_mapping": {
          "time": "rt",
          "action": "act",
          "host": "dhost",
          "reason": "reason",
          "category": "category",
          "count": "cnt"
        }
      },
      "leef": {
        "prefix": "rdwrCld",
        "header": {
          "vendor": "Radware",
          "product": "Cloud WAAP",
          "version": "1.0",
          "log_type": "WebDDoS"
        },
        "static_mapping": {
          "time": "eventTime",
          "action": "action",
          "host": "dhost",
          "name": "name",
          "reason": "reason",
          "category": "category",
          "severity": "sev",
          "count": "cnt"
        }
      }
    }
  }
}


