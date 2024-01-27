import boto3
import threading
import queue
import json
from .data_processor import DataProcessor
from .config_reader import Config
import urllib.parse
import time
from .logging_config import get_logger

# This module handles the interaction with AWS SQS, including message retrieval and processing.

# Create a logger for this module
logger = get_logger('local_agent')

# Load configuration
config = Config().config
if not config:
    logger.error("Failed to load configuration. Exiting.")
    exit(1)

# Instantiate DataProcessor
data_processor = DataProcessor(config)  # Create an instance of DataProcessor

def get_sqs_client(config):
    """
    Initialize and return an SQS client using the provided configuration.
    :param config: Configuration dictionary containing AWS credentials and region info.
    :return: An initialized SQS client.
    """
    return boto3.client(
        'sqs',
        region_name=config.get('sqs_region', 'us-east-1'),
        aws_access_key_id=config.get('sqs_access_key_id'),
        aws_secret_access_key=config.get('sqs_secret_access_key'))

def delete_message_from_sqs(sqs, config, receipt_handle):
    """
    Delete a message from the SQS queue.
    :param sqs: The SQS client.
    :param config: Configuration dictionary containing SQS settings.
    :param receipt_handle: The receipt handle of the message to delete.
    """
    try:
        sqs.delete_message(QueueUrl=config.get('sqs_name'), ReceiptHandle=receipt_handle)
        logger.info(f"Deleted message from SQS: {receipt_handle}")
    except Exception as e:
        logger.error(f"Error deleting message from SQS: {e}")

def fetch_messages(sqs, config):
    """
    Fetch messages from the SQS queue.
    :param sqs: The SQS client.
    :param config: Configuration dictionary containing SQS settings.
    :return: A response from SQS containing messages or None in case of an error.
    """
    try:
        return sqs.receive_message(
            QueueUrl=config.get('sqs_name'),
            MaxNumberOfMessages=10,
            WaitTimeSeconds=10)
    except Exception as e:
        logger.error(f"Error receiving messages: {e}")
        return None

def worker(processing_messages, stop_agent, config):
    """
    Worker thread function to process messages from the queue.
    :param processing_messages: Queue from which to retrieve and process messages.
    :param field_mappings: Field mappings for the log transformation process.
    :param stop_agent: A threading.Event to signal when to stop the worker.
    :param config: Configuration dictionary for the agent.
    """
    sqs = get_sqs_client(config)  # Initialize the SQS client using the helper function
    while not stop_agent.is_set():
        message_retrieved = False
        try:
            message_details = processing_messages.get(timeout=3)
            message_retrieved = True  # Flag set as a message has been successfully retrieved
            logger.debug(f"Worker picked up message: {message_details}")

            # Handle SQS-specific processing
            process_success = data_processor.process_data(
                input_fields={
                    'bucket': message_details['bucket'],
                    'key': message_details['key'],
                    'expected_size': message_details['size'],
                    'input_type': 'sqs'
                },
                product='cloud_waap'
            )

            # Handle message deletion based on processing success and config settings
            if process_success or (not process_success and config.get('delete_on_failure', True)):
                delete_message_from_sqs(sqs, config, message_details['receipt_handle'])

        except queue.Empty:
            logger.debug("No messages in queue.")

        if message_retrieved:
            processing_messages.task_done()


def poll_sqs_messages(processing_messages, stop_agent, config):
    """
    Continuously polls messages from the specified SQS queue and puts them into a processing queue.
    :param processing_messages: The queue to put the messages for processing.
    :param stop_agent: A threading.Event to signal when to stop polling.
    :param config: Configuration dictionary containing SQS settings.
    """
    sqs = get_sqs_client(config)  # Initialize the SQS client using the helper function

    while not stop_agent.is_set():
        if processing_messages.qsize() < 10:  # Check if the queue isn't overloaded
            response = fetch_messages(sqs, config)  # Fetch messages from SQS using the helper function
            if response and response.get('Messages'):
                logger.info(f"Received {len(response['Messages'])} messages from SQS.")
                for msg in response['Messages']:
                    try:
                        msg_body = json.loads(msg['Body'])
                        record = msg_body.get('Records', [])[0]  # Safely access the first record
                        processing_messages.put({
                            'input_type': 'sqs',
                            'bucket': record['s3']['bucket']['name'],
                            'key': urllib.parse.unquote_plus(record['s3']['object']['key']),
                            'size': record['s3']['object']['size'],
                            'receipt_handle': msg['ReceiptHandle']
                        })
                    except (IndexError, KeyError):
                        logger.error(f"Invalid message format: {msg}")
                        if config.get('delete_unrelated_messages', True):
                            delete_message_from_sqs(sqs, config, msg['ReceiptHandle'])
        else:
            logger.debug("Processing queue is full. Waiting before fetching more messages.")
            time.sleep(5)  # Wait for some time before trying to fetch messages again

