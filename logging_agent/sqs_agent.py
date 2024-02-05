import boto3
import threading
import queue
import json
from .data_processor import DataProcessor
from .logging_config import get_logger
import urllib.parse
import time

class SQSAgent:
    def __init__(self, agent_config):
        self.agent_config = agent_config
        self.logger = get_logger('SQSAgent')
        self.sqs = self.get_sqs_client(agent_config)
        self.data_processor = DataProcessor(agent_config)
        self.processing_queue = queue.Queue()
        self.stop_event = threading.Event()

    def get_sqs_client(self, config):
        """
        Initialize and return an SQS client using the provided configuration.

        Args:
            config (dict): Configuration dictionary for AWS credentials and region.

        Returns:
            boto3.client: An initialized SQS client.
        """
        return boto3.client(
            'sqs',
            region_name=config['aws_credentials']['region'],
            aws_access_key_id=config['aws_credentials']['access_key_id'],
            aws_secret_access_key=config['aws_credentials']['secret_access_key'])

    def delete_message_from_sqs(self, receipt_handle):
        """
        Delete a message from the SQS queue.

        Args:
            receipt_handle (str): The receipt handle of the message to delete.
        """
        try:
            self.sqs.delete_message(QueueUrl=self.agent_config['sqs_settings']['queue_name'],
                                    ReceiptHandle=receipt_handle)
            self.logger.info(f"Deleted message from SQS: {receipt_handle}")
        except Exception as e:
            self.logger.error(f"Error deleting message from SQS: {e}")

    def fetch_messages(self):
        """
        Fetch messages from the SQS queue.

        Returns:
            dict: A response from SQS containing messages or None in case of an error.
        """
        try:
            return self.sqs.receive_message(
                QueueUrl=self.agent_config['sqs_settings']['queue_name'],
                MaxNumberOfMessages=10,
                WaitTimeSeconds=10)
        except Exception as e:
            self.logger.error(f"Error receiving messages: {e}")
            return None

    def worker(self, processing_messages, stop_agent):
        """
        Worker thread function to process messages from the queue.

        Args:
            processing_messages (queue.Queue): Queue from which to retrieve and process messages.
            stop_agent (threading.Event): Event to signal when to stop the worker.
        """
        while not stop_agent.is_set():
            message_retrieved = False
            try:
                message_details = processing_messages.get(timeout=3)
                message_retrieved = True  # Flag set as a message has been successfully retrieved
                self.logger.debug(f"Worker picked up message: {message_details}")

                # Handle SQS-specific processing
                process_success = self.data_processor.process_data(
                    input_fields={
                        'bucket': message_details['bucket'],
                        'key': message_details['key'],
                        'expected_size': message_details['size'],
                    }
                )

                # Handle message deletion based on processing success and config settings
                if process_success or (not process_success and self.agent_config['sqs_settings']['delete_on_failure']):
                    self.delete_message_from_sqs(message_details['receipt_handle'])

            except queue.Empty:
                self.logger.debug("No messages in queue.")

            if message_retrieved:
                processing_messages.task_done()

    def poll_sqs_messages(self, processing_messages, stop_agent):
        """
        Continuously polls messages from the specified SQS queue and puts them into a processing queue.

        Args:
            processing_messages (queue.Queue): Queue to put the messages for processing.
            stop_agent (threading.Event): Event to signal when to stop polling.
        """
        while not stop_agent.is_set():
            if processing_messages.qsize() < 10:  # Check if the queue isn't overloaded
                response = self.fetch_messages()
                if response and response.get('Messages'):
                    self.logger.info(f"Received {len(response['Messages'])} messages from SQS.")
                    for msg in response['Messages']:
                        try:
                            msg_body = json.loads(msg['Body'])
                            record = msg_body.get('Records', [])[0]  # Safely access the first record
                            processing_messages.put({
                                'input_type': self.agent_config['type'],  # Using agent's input type
                                'bucket': record['s3']['bucket']['name'],
                                'key': urllib.parse.unquote_plus(record['s3']['object']['key']),
                                'size': record['s3']['object']['size'],
                                'receipt_handle': msg['ReceiptHandle']
                            })
                        except (IndexError, KeyError):
                            self.logger.error(f"Invalid message format: {msg}")
                            if self.agent_config.get('delete_unrelated_messages', True):
                                self.delete_message_from_sqs(msg['ReceiptHandle'])
            else:
                self.logger.debug("Processing queue is full. Waiting before fetching more messages.")
                time.sleep(5)  # Wait for some time before trying to fetch messages again

    def start(self):
        """Starts the SQS agent processing."""
        self.logger.debug(f"Starting SQS Agent: {self.agent_config['name']}")
        for _ in range(self.agent_config['num_worker_threads']):
            t = threading.Thread(target=self.worker, args=(self.processing_queue, self.stop_event))
            t.daemon = True
            t.start()

        self.poll_sqs_messages(self.processing_queue, self.stop_event)

    def stop(self):
        """Stops the SQS agent processing."""
        self.logger.debug(f"Stopping SQS Agent: {self.agent_config['name']}")

        # Signal the workers to stop after finishing their current message
        self.stop_event.set()

        # Wait until the processing queue is empty
        self.processing_queue.join()

        self.logger.debug(f"SQS Agent {self.agent_config['name']} stopped successfully.")
