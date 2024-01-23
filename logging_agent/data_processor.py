import os
from .downloader import Downloader
from .transformer import Transformer
from .sender import Sender
from .utility import Utility
from .logging_config import get_logger
from logging_agent.cloud_waap import CloudWAAPProcessor
import datetime


# Create a logger for this module
logger = get_logger('data_processor')




def process_data(input_fields, product, field_mappings, config):
    """
    Processes the input data based on the source type and product.

    Args:
        input_fields (dict): Contains fields specific to the input type.
        product (str): The product type being processed.
        field_mappings (dict): Field mappings for data transformation.
        config (dict): The configuration settings.

    Returns:
        bool: True if the processing is successful, False otherwise.
    """
    # General configuration fields
    input_type = input_fields.get('input_type', '')
    output_directory = config.get('output_directory', '/tmp')
    output_format = config.get('output_format', '').lower()
    format_options = config.get('output', {}).get(output_format, {})
    delimiter = format_options.get('delimiter', '\n')
    downloader = Downloader(config)

    # Batch mode configuration for HTTP/HTTPS
    output_config = config.get('output', {})
    http_config = output_config.get('http', {})
    https_config = output_config.get('https', {})
    batch_mode = http_config.get('batch', https_config.get('batch', False))

    # Record time for performance messurement
    start_time = datetime.datetime.now()  # Record the start time


    # Process data for SQS input type
    if input_type == "sqs":
        bucket = input_fields.get('bucket', '')
        key = input_fields.get('key', '')
        expected_size = input_fields.get('expected_size', '')
        logger.debug(f"Initiating processing for file: {key} from bucket: {bucket}")
        download_path = os.path.join(output_directory, os.path.basename(key))


    # Processing logic for Cloud WAAP product type with Input Type SQS
    if product == "cloud_waap" and input_type == "sqs" :
        log_type = CloudWAAPProcessor.identify_log_type(key)
        if not config['logs'][product][log_type]:
            return True

        # Check if file already exists and decide whether to download
        download_required = True
        if os.path.exists(download_path):
            actual_size = os.path.getsize(download_path)
            if actual_size >= expected_size:
                logger.info(f"File already exists and is complete: {key}")
                download_required = False
            else:
                # TODO partial might have different file extenstion and if partial is found it should be deleated and redownloaded
                logger.info(f"Partial file detected. Redownloading: {key}")

        # Download the file from S3 if required
        if download_required:
            logger.debug(f"Downloading file: {key}")
            if not downloader.download_from_s3(bucket, key, download_path):
                logger.error(f"Failed to download {key} from bucket {bucket}")
                return False
            logger.debug(f"File downloaded successfully: {key}")

        # Prepare data for transformation
        data_fields = {
            "file_path": download_path,
            "key": key,
            "log_type": log_type
        }

    # Transform the data
    transformed_data = Transformer.load_and_transform(
        input_type=input_type,
        data_fields=data_fields,
        output_format=config['output_format'],
        field_mappings=field_mappings,
        product=product,
        batch_mode=batch_mode,
        format_options=format_options
    )

    if transformed_data:
        logger.debug(f"Transformation successful for file: {key}")

        # Prepare destination configuration
        output_type = config['output']['type']
        destination = config['output']['destination']
        port = config['output'][output_type].get('port', None)
        batch_mode = config['output'].get('batch', False)
        delimiter = config['output'].get('delimiter', '\n')

        destination_config = {
            'destination': destination,
            'output_format': config['output_format'],
            'output_type': output_type,
            'port': port,
            'batch_mode': batch_mode,
            'delimiter': delimiter,
            'tls_config': config['output'].get('tls', {}) if output_type == 'tls' else {}
        }

        # Unify sending process
        try:
            success = Sender.send_data(transformed_data, destination_config)
            if success:
                logger.info(f"Data successfully sent to {destination_config['destination']}")
            else:
                logger.error("Failed to send transformed data")
        except Exception as e:
            logger.error(f"Error during data sending process: {e}")
            success = False

    else:
        logger.error(f"Failed to transform data from file: {download_path}")
        success = False

        # Cleanup and logging ...
    Utility.cleanup(download_path)
    logger.debug(f"Cleanup completed for file: {key}")
    end_time = datetime.datetime.now()
    time_taken = end_time - start_time
    logger.info(f"Task completed. Time taken: {time_taken}, File size: {expected_size} bytes")

    return success
