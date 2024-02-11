from unittest.mock import patch, MagicMock
from unittest.mock import patch
from logging_agent.sqs_agent import SQSAgent
import pytest
import threading
import time
import json
from queue import Queue


@pytest.fixture
def agent_config():
    return {
        'name': 'TestAgent',
        'num_worker_threads': 2,
        'aws_credentials': {
            'region': 'test-region',
            'access_key_id': 'test-access-key',
            'secret_access_key': 'test-secret-key'
        },
        'sqs_settings': {
            'queue_name': 'test-queue',
            'delete_on_failure': True
        },
        'type': 'sqs'
    }


@pytest.fixture
def sqs_agent(agent_config):
    with patch('boto3.client') as mock_boto_client:
        mock_boto_client.return_value = MagicMock()
        agent = SQSAgent(agent_config)
    return agent

def test_sqs_agent_initialization(agent_config):
    with patch('boto3.client') as mock_boto_client:
        agent = SQSAgent(agent_config)
        assert agent.agent_config == agent_config
        mock_boto_client.assert_called_once_with(
            'sqs',
            region_name=agent_config['aws_credentials']['region'],
            aws_access_key_id=agent_config['aws_credentials']['access_key_id'],
            aws_secret_access_key=agent_config['aws_credentials']['secret_access_key']
        )

def test_fetch_messages(sqs_agent):
    mock_response = {'Messages': [{'Body': '{"test": "message"}', 'ReceiptHandle': 'mock_handle'}]}
    with patch.object(sqs_agent.sqs, 'receive_message', return_value=mock_response):
        response = sqs_agent.fetch_messages()
        assert response == mock_response


def test_delete_message_from_sqs(sqs_agent):
    receipt_handle = 'mock_receipt_handle'
    with patch.object(sqs_agent.sqs, 'delete_message') as mock_delete_message:
        sqs_agent.delete_message_from_sqs(receipt_handle)
        mock_delete_message.assert_called_once_with(
            QueueUrl=sqs_agent.agent_config['sqs_settings']['queue_name'],
            ReceiptHandle=receipt_handle
        )




def test_worker_process_message_success(sqs_agent, monkeypatch):
    # Prepare a realistic mock message structure
    mock_message = {
        'bucket': 'test-bucket',
        'key': 'test/key',
        'size': 123,
        'receipt_handle': 'mock_handle'
    }
    sqs_agent.processing_queue.put(mock_message)

    # Mock the DataProcessor's process_data method to simulate successful processing
    monkeypatch.setattr(sqs_agent.data_processor, 'process_data', lambda *args, **kwargs: True)

    # Simulate running the worker method
    threading.Thread(target=sqs_agent.worker, args=(sqs_agent.processing_queue, sqs_agent.stop_event)).start()
    time.sleep(1)  # Give some time for the thread to process the message
    sqs_agent.stop_event.set()  # Stop the worker thread

    # Ensure the processing queue is empty, indicating the message was processed
    assert sqs_agent.processing_queue.empty()


def test_poll_sqs_messages_queue_management(sqs_agent, monkeypatch):
    # Mock the fetch_messages method to return a controlled, realistic response
    mock_response = {
        'Messages': [{
            'Body': json.dumps({
                'Records': [{
                    's3': {
                        'bucket': {'name': 'test-bucket'},
                        'object': {'key': 'test/key', 'size': 123}
                    }
                }]
            }),
            'ReceiptHandle': 'mock_handle'
        }]
    }
    monkeypatch.setattr(sqs_agent, 'fetch_messages', lambda: mock_response)

    # Execute poll_sqs_messages with a controlled stop condition
    stop_event = threading.Event()
    threading.Thread(target=sqs_agent.poll_sqs_messages, args=(sqs_agent.processing_queue, stop_event)).start()
    time.sleep(1)  # Allow some time for messages to be fetched and processed
    stop_event.set()  # Signal to stop polling

    # Verify the message was correctly placed into the processing queue
    assert not sqs_agent.processing_queue.empty()
    message = sqs_agent.processing_queue.get_nowait()
    assert message['bucket'] == 'test-bucket'
    assert message['key'] == 'test/key'


def test_sqs_agent_stop(sqs_agent, monkeypatch):
    # Mock the threading event's set method to verify it gets called
    monkeypatch.setattr(sqs_agent.stop_event, 'set', MagicMock())

    # Mock join on the processing queue to simulate waiting for queue to empty
    monkeypatch.setattr(sqs_agent.processing_queue, 'join', MagicMock())

    # Call stop and verify stop_event.set() and processing_queue.join() are called
    sqs_agent.stop()
    sqs_agent.stop_event.set.assert_called_once()
    sqs_agent.processing_queue.join.assert_called_once()


