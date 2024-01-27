import threading
import queue
from .sqs_agent import poll_sqs_messages, worker
from .config_reader import Config
from .logging_config import get_logger
from .field_mappings import FieldMappings  # Import the FieldMappings singleton

# Load configuration using the Config singleton
config = Config().config

# Initialize logger for this module
logger = get_logger('local_agent')




def initialize_worker_threads(num_threads, processing_queue, stop_event, config):
    for i in range(num_threads):
        t = threading.Thread(target=worker, args=(processing_queue, stop_event, config))
        t.daemon = True
        t.start()
def start_local_agent():
    logger.debug("Starting local agent.")
    products = config.get('products')
    product = config.get('product')
    # Load field mappings
    output_format = config.get('output_format', 'json')
    FieldMappings.load_field_mappings(products, output_format)

    num_worker_threads = config.get('num_worker_threads', 5)
    logger.debug(f"Worker threads: {num_worker_threads}, Product: {product}")

    processing_messages = queue.Queue()
    stop_agent = threading.Event()

    initialize_worker_threads(num_worker_threads, processing_messages, stop_agent, config)

    try:
        poll_sqs_messages(processing_messages, stop_agent, config)
    except KeyboardInterrupt:
        stop_agent.set()
        logger.info("Shutdown signal received. Exiting...")

    processing_messages.join()

# Entry point for the script
if __name__ == "__main__":
    start_local_agent()
