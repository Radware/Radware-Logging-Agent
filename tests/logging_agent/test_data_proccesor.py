import pytest
from unittest.mock import patch, MagicMock
from logging_agent.data_processor import DataProcessor
from logging_agent.data_loader import DataLoader
from logging_agent.transformer import Transformer
from logging_agent.sender import Sender
from logging_agent.downloader import S3Downloader  # Ensure this is the correct path


@pytest.mark.parametrize("transformed_data", [
    # Example list of dictionaries based on your provided JSON transformed_data
    [{"time": "01 31 2024 13:14:51", "source_ip": "220.244.85.52", "source_port": 27855,
      "destination_ip": "10.202.0.159", "destination_port": 443,
      "protocol": "https", "http_method": "GET",
      "host": "autodemo.radware.net", "request": "https://autodemo.radware.net/product/view?id=129",
      "directory": "/product",
      "user_agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36 Edg/89.0.774.50",
      "accept_language": "-",
      "x-forwarded-for": "220.244.85.52",
      "cookie": "AWSALB=L9ebhHi5PuXyus0wbQ1FOaExKgaDq; AWSALBCORS=L9ebhHi5LDuhfsHzIFqj9zHGEQ1FOaExKgaDq; PHPSESSID=si2233mfq8a1gvl5adl06glvm1; visited_products=%2C4223%2C50%2C127%2C67%%2C70%2C102C",
      "request_time": "0.043", "response_code": 200, "http_bytes_in": 1445, "http_bytes_out": 10823,
      "country_code": "AU", "action": "Allowed", "application_id": "805c88ac-aaf9-471a-9030-391c0393990d",
      "application_name": "New CWAF Automated Demo", "tenant_name": "DEMO", "log_type": "Access",
      "http_version": "HTTP/1.1", "uri": "/product/view"},
     {"time": "01 31 2024 13:14:51", "source_ip": "95.21.225.67", "source_port": 24098,
      "destination_ip": "10.202.0.159", "destination_port": 443, "protocol": "https",
      "http_method": "GET", "host": "autodemo.radware.net", "request": "https://autodemo.radware.net/account",
      "directory": "/", "user_agent": "Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko",
      "accept_language": "en-US,en;q=0.9", "x-forwarded-for": "95.21.225.67",
      "cookie": "AWSALB=L9ebhHi5PuXyus0wbQ1FOaExKgaDq; AWSALBCORS=L9ebhHi5LDuhfsHzIFqj9zHGEQ1FOaExKgaDq; PHPSESSID=si2233mfq8a1gvl5adl06glvm1; visited_products=%2C4223%2C50%2C127%2C67%%2C70%2C102C",
      "request_time": "0.047", "response_code": 200, "http_bytes_in": 1723, "http_bytes_out": 7440,
      "country_code": "ES", "action": "Allowed", "application_id": "805c88ac-aaf9-471a-9030-391c0393990d",
      "application_name": "New CWAF Automated Demo", "tenant_name": "DEMO", "log_type": "Access",
      "http_version": "HTTP/1.1", "uri": "/account"}]
])



def test_data_processor_process_data_success(data_processor, mock_dependencies, config_fixture,transformed_data):
    input_fields = {
        'bucket': 'mock-bucket',
        'key': 'mock-key',
        'expected_size': 1234
    }

    # Mock identify_product_log_type within DataProcessor to return a supported log type
    with patch.object(DataProcessor, 'identify_product_log_type', return_value='Access'):
        success = data_processor.process_data(input_fields)

    assert success
    mock_dependencies['data_loader'].load_data.assert_called_once_with("sqs", input_fields)
    mock_dependencies['transformer'].transform_content.assert_called_once()  # Verifies transformation was invoked
    mock_dependencies['sender_send_data'].assert_called_once()



