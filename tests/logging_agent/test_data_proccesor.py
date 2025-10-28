import copy
from unittest.mock import patch

import pytest

from logging_agent.cloud_waap import CloudWAAPProcessor
from logging_agent.data_processor import DataProcessor


def test_data_processor_process_data_success(data_processor, mock_dependencies, config_fixture):
    input_fields = {
        'bucket': 'mock-bucket',
        'key': 'mock-key',
        'expected_size': 1234
    }

    metadata = {
        'file_path': '/tmp/mock-file',
        'relative_key': 'relative/mock-key',
        'cleanup': True
    }
    mock_dependencies['data_loader'].load_data.return_value = {
        'data': [{'sample': 'data'}],
        'metadata': metadata
    }

    with patch.object(DataProcessor, 'identify_product_log_type', return_value='Access') as identify_mock, \
            patch.object(DataProcessor, 'gather_data_fields', return_value={'key': 'relative/mock-key'}) as gather_mock:
        success = data_processor.process_data(input_fields)

    assert success
    mock_dependencies['data_loader'].load_data.assert_called_once_with("sqs", input_fields)
    identify_args = identify_mock.call_args[0]
    assert identify_args[1] == metadata
    gather_args = gather_mock.call_args[0]
    assert gather_args[1] == metadata
    mock_dependencies['transformer'].transform_content.assert_called_once()
    mock_dependencies['sender_send_data'].assert_called_once()
    mock_dependencies['utility_cleanup'].assert_called_once_with('/tmp/mock-file')


def test_data_processor_process_data_skips_cleanup_without_flag(mock_dependencies, config_fixture):
    config = copy.deepcopy(config_fixture)
    config['type'] = 'file'
    processor = DataProcessor(config)

    metadata = {
        'file_path': '/tmp/mock-file',
        'relative_key': 'relative/mock-key',
        'cleanup': False
    }
    mock_dependencies['data_loader'].load_data.return_value = {
        'data': [{'sample': 'data'}],
        'metadata': metadata
    }

    with patch.object(DataProcessor, 'identify_product_log_type', return_value='Access'), \
            patch.object(DataProcessor, 'gather_data_fields', return_value={'key': 'relative/mock-key'}):
        success = processor.process_data({'file_path': '/tmp/mock-file'})

    assert success
    mock_dependencies['utility_cleanup'].assert_not_called()


def test_data_processor_process_data_skips_cleanup_on_failure(mock_dependencies, config_fixture):
    config = copy.deepcopy(config_fixture)
    processor = DataProcessor(config)

    metadata = {
        'file_path': '/tmp/mock-file',
        'relative_key': 'relative/mock-key',
        'cleanup': True
    }
    mock_dependencies['data_loader'].load_data.return_value = {
        'data': [{'sample': 'data'}],
        'metadata': metadata
    }
    mock_dependencies['sender_send_data'].return_value = False

    with patch.object(DataProcessor, 'identify_product_log_type', return_value='Access'), \
            patch.object(DataProcessor, 'gather_data_fields', return_value={'key': 'relative/mock-key'}):
        success = processor.process_data({'key': 'mock-key'})

    assert not success
    mock_dependencies['utility_cleanup'].assert_not_called()


@pytest.mark.parametrize('input_type', ['sqs', 'file', 'sftp'])
def test_identify_product_log_type_uses_relative_key(config_fixture, input_type):
    processor = DataProcessor(config_fixture)
    metadata = {'relative_key': 'relative/path'}
    with patch.object(CloudWAAPProcessor, 'identify_log_type', return_value='Access') as identify_mock:
        sample_event = {'request': 'GET /index.html HTTP/1.1', 'protocol': 'https', 'http_method': 'GET'}
        log_type = processor.identify_product_log_type(
            {'key': 'fallback'},
            metadata,
            input_type,
            'cloud_waap',
            sample_event
        )

    assert log_type == 'Access'
    identify_mock.assert_called_once_with('relative/path', sample_event)


def test_identify_product_log_type_falls_back_to_input_fields(config_fixture):
    processor = DataProcessor(config_fixture)
    metadata = {}
    with patch.object(CloudWAAPProcessor, 'identify_log_type', return_value='Access') as identify_mock:
        sample_event = {'request': 'GET /home HTTP/1.1', 'protocol': 'http'}
        log_type = processor.identify_product_log_type(
            {'key': 'fallback'},
            metadata,
            'sqs',
            'cloud_waap',
            sample_event
        )

    assert log_type == 'Access'
    identify_mock.assert_called_once_with('fallback', sample_event)


def test_gather_data_fields_uses_relative_key(config_fixture):
    processor = DataProcessor(config_fixture)
    metadata = {'relative_key': 'relative/path'}
    with patch.object(CloudWAAPProcessor, 'extract_metadata', return_value={'meta': 'data'}) as extract_mock:
        data_fields = processor.gather_data_fields({}, metadata, 'file', 'Access', 'cloud_waap')

    assert data_fields['key'] == 'relative/path'
    assert data_fields['metadata'] == {'meta': 'data'}
    extract_mock.assert_called_once_with('relative/path', 'cloud_waap', 'Access')


def test_gather_data_fields_falls_back_to_input_fields(config_fixture):
    processor = DataProcessor(config_fixture)
    metadata = {}
    with patch.object(CloudWAAPProcessor, 'extract_metadata', return_value={'meta': 'data'}) as extract_mock:
        data_fields = processor.gather_data_fields({'key': 'fallback'}, metadata, 'sqs', 'Access', 'cloud_waap')

    assert data_fields['key'] == 'fallback'
    extract_mock.assert_called_once_with('fallback', 'cloud_waap', 'Access')


def test_gather_data_fields_non_cloud_product(config_fixture):
    processor = DataProcessor(config_fixture)
    result = processor.gather_data_fields({}, {}, 'sqs', 'Access', 'other_product')
    assert result == {}


def test_process_data_skips_unknown_type_when_flag_disabled(mock_dependencies, config_fixture):
    config = copy.deepcopy(config_fixture)
    config['logs']['unknown'] = False
    processor = DataProcessor(config)

    input_fields = {
        'bucket': 'mock-bucket',
        'key': 'mock-key',
        'expected_size': 512
    }
    metadata = {
        'file_path': '/tmp/mock-file',
        'relative_key': 'relative/mock-key',
        'cleanup': True
    }
    mock_dependencies['data_loader'].load_data.return_value = {
        'data': [{'sample': 'data'}],
        'metadata': metadata
    }

    with patch.object(DataProcessor, 'identify_product_log_type', return_value='NewType') as identify_mock, \
            patch.object(DataProcessor, 'gather_data_fields') as gather_mock:
        success = processor.process_data(input_fields)

    assert success
    identify_mock.assert_called_once()
    gather_mock.assert_not_called()
    mock_dependencies['transformer'].transform_content.assert_not_called()
    mock_dependencies['sender_send_data'].assert_not_called()


def test_process_data_processes_unknown_type_when_flag_enabled(mock_dependencies, config_fixture):
    config = copy.deepcopy(config_fixture)
    config['logs']['unknown'] = True
    processor = DataProcessor(config)

    input_fields = {
        'bucket': 'mock-bucket',
        'key': 'mock-key',
        'expected_size': 512
    }
    metadata = {
        'file_path': '/tmp/mock-file',
        'relative_key': 'relative/mock-key',
        'cleanup': True
    }
    mock_dependencies['data_loader'].load_data.return_value = {
        'data': [{'sample': 'data'}],
        'metadata': metadata
    }

    with patch.object(DataProcessor, 'identify_product_log_type', return_value='NewType') as identify_mock, \
            patch.object(DataProcessor, 'gather_data_fields', return_value={'key': 'relative/mock-key'}) as gather_mock:
        success = processor.process_data(input_fields)

    assert success
    identify_mock.assert_called_once()
    gather_mock.assert_called_once()
    mock_dependencies['transformer'].transform_content.assert_called_once()
    mock_dependencies['sender_send_data'].assert_called_once()
