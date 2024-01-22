import threading
import queue
from .sqs_agent import poll_sqs_messages, worker
from .config_reader import Config
from .logging_config import get_logger
from .app_info import supported_features
import pathlib
import json
import os

# Load configuration using the Config singleton
config = Config().config

# Initialize logger for this module
logger = get_logger('local_agent')


def load_field_mappings(product, output_format):
    field_mappings = {}
    if output_format in supported_features[product]['mapping']['required_for']:
        base_dir = pathlib.Path(__file__).parent.resolve()
        mapping_file_path = os.path.join(base_dir, supported_features[product]['mapping']['path'])
        try:
            with open(mapping_file_path, 'r') as file:
                field_mappings[product] = json.load(file)
        except FileNotFoundError:
            logger.error(f"Field mapping file not found for product {product}: {mapping_file_path}")
            raise
    return field_mappings

def initialize_worker_threads(num_threads, processing_queue, field_mappings, stop_event, config):
    for i in range(num_threads):
        t = threading.Thread(target=worker, args=(processing_queue, field_mappings, stop_event, config))
        t.daemon = True
        t.start()
def start_local_agent():
    logger.debug("Starting local agent.")
    product = "cloud_waap"
    # Load field mappings
    field_mappings = load_field_mappings(product, config.get('output_format', 'json'))

    num_worker_threads = config.get('num_worker_threads', 5)
    logger.debug(f"Worker threads: {num_worker_threads}, Product: {product}")

    processing_messages = queue.Queue()
    stop_agent = threading.Event()

    initialize_worker_threads(num_worker_threads, processing_messages, field_mappings, stop_agent, config)

    try:
        poll_sqs_messages(processing_messages, stop_agent, config)
    except KeyboardInterrupt:
        stop_agent.set()
        logger.info("Shutdown signal received. Exiting...")

    processing_messages.join()

# Entry point for the script
if __name__ == "__main__":
    start_local_agent()
