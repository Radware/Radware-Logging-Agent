import pytest
import json
from logging_agent.data_loader import DataLoader
from io import StringIO
from logging_agent.downloader import S3Downloader
import json
import gzip
from unittest.mock import MagicMock

def test_load_data_unsupported_type(config):
    dataloader = DataLoader(config)
    result = dataloader.load_data("unsupported", {})
    assert result == {"data": None, "metadata": {}}


def test_load_from_s3_file_exists(mocker, mock_s3_downloader, config, input_info):
    # Mock data to be returned by the json file
    mock_data = {"test": "data"}

    # Mock open to return a StringIO object, simulating reading from a file
    mocker.patch("builtins.open", mocker.mock_open(read_data=json.dumps(mock_data)))

    # Mock os.path.exists to simulate the file existence
    mocker.patch('os.path.exists', return_value=True)

    # Mock os.path.getsize to simulate the file size check
    mocker.patch('os.path.getsize', return_value=100)

    # Mock os.makedirs in case the directory creation is triggered
    mocker.patch('os.makedirs', MagicMock())

    dataloader = DataLoader(config)
    result = dataloader.load_data("sqs", input_info)

    # Validate the result
    assert result['data'] == mock_data
    assert 'file_path' in result['metadata']

def test_load_from_s3_download_required(mocker, mock_s3_downloader, config, input_info):
    # Simulate file not existing locally
    mocker.patch('os.path.exists', side_effect=lambda path: False)
    mocker.patch('os.makedirs', MagicMock())  # Mock directory creation

    # Mock successful file download
    mock_s3_downloader.download.return_value = True

    # Mock file reading with sample data
    sample_data = {"sample": "data"}
    mocker.patch('builtins.open', mocker.mock_open(read_data=json.dumps(sample_data)))

    dataloader = DataLoader(config)
    result = dataloader.load_data("sqs", input_info)

    assert result['data'] == sample_data
    assert 'file_path' in result['metadata']

def test_load_from_s3_download_failure(mocker, mock_s3_downloader, config, input_info):
    # Simulate the file not existing locally
    mocker.patch('os.path.exists', side_effect=lambda path: False)
    mocker.patch('os.makedirs', MagicMock())  # Mock directory creation if it doesn't exist

    # Simulate the download attempt failing
    mock_s3_downloader.download.return_value = False

    dataloader = DataLoader(config)
    result = dataloader.load_data("sqs", input_info)

    # Verify that the method returns None upon download failure
    assert result is None

def test_load_from_s3_unsupported_format(mocker, mock_s3_downloader, config, input_info):
    # Mock the existence of the file to trigger the unsupported format path
    mocker.patch('os.path.exists', return_value=True)

    # Mock os.path.getsize to return a specific size, ensuring the file is considered existing and complete
    mocker.patch('os.path.getsize', return_value=1234)

    # Mock glob.glob to simulate no partial files exist, if your logic includes checking for these
    mocker.patch('glob.glob', return_value=[])

    # Mock os.makedirs in case your logic includes creating directories
    mocker.patch('os.makedirs', MagicMock())

    # Assume the download was successful, which should not be reached due to the unsupported format logic
    mock_s3_downloader.download.return_value = True

    # Mock opening of files to prevent actual file reads, adjust according to your logic inside the try-except block
    mocker.patch('builtins.open', mocker.mock_open())

    dataloader = DataLoader(config)
    input_info['key'] += ".unsupported"  # Ensure the key ends with an unsupported format
    result = dataloader.load_data("sqs", input_info)

    # Validate that the result indicates an unsupported file format
    assert result == {"data": None, "metadata": {}}, "Expected unsupported format to result in no data and metadata"


