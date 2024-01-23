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

def process_sqs_input(input_fields, config, downloader):
    """
    Processes the input fields specific to the SQS input type.

    Args:
        input_fields (dict): Contains fields specific to the SQS input type.
        config (dict): The configuration settings.
        downloader (Downloader): Instance of the Downloader class.

    Returns:
        tuple: Returns bucket, key, expected_size, download_path.
    """
    bucket = input_fields.get('bucket', '')
    key = input_fields.get('key', '')
    expected_size = input_fields.get('expected_size', '')
    logger.debug(f"Initiating processing for file: {key} from bucket: {bucket}")

    download_path = os.path.join(config.get('output_directory', '/tmp'), os.path.basename(key))

    # Additional processing steps can be added here if needed

    return bucket, key, expected_size, download_path

def process_cloud_waap_sqs(key, config, download_path):
    """
    Processes the Cloud WAAP product type with SQS input.

    Args:
        key (str): The key of the file in the S3 bucket.
        config (dict): The configuration settings.
        download_path (str): The path where the file is downloaded.

    Returns:
        dict or None: Returns a dictionary with data fields for transformation or None if no processing is required.
    """
    log_type = CloudWAAPProcessor.identify_log_type(key)
    if not config['logs']['cloud_waap'].get(log_type, True):
        logger.info(f"No processing required for log type: {log_type}")
        return None

    # Here, include any logic specific to processing Cloud WAAP data
    # For example, checking file size, additional validations, etc.

    data_fields = {
        "file_path": download_path,
        "key": key,
        "log_type": log_type
    }

    return data_fields

def transform_data(input_type, data_fields, config, field_mappings, product):
    """
    Transforms the data based on the input type and configuration.

    Args:
        input_type (str): The type of the input (e.g., 'sqs').
        data_fields (dict): Data fields specific to the transformation.
        config (dict): The configuration settings.
        field_mappings (dict): Field mappings for data transformation.
        product (str): The product type being processed.

    Returns:
        object: The transformed data.
    """
    output_format = config['output_format']
    batch_mode = config.get('output', {}).get('batch', False)
    format_options = config.get('output', {}).get(output_format, {})

    transformed_data = Transformer.load_and_transform(
        input_type=input_type,
        data_fields=data_fields,
        output_format=output_format,
        field_mappings=field_mappings,
        product=product,
        batch_mode=batch_mode,
        format_options=format_options
    )

    return transformed_data


def finalize_and_send(transformed_data, config):
    """
    Finalizes the process by sending the transformed data.

    Args:
        transformed_data (object): The data after transformation.
        config (dict): The configuration settings.

    Returns:
        bool: True if the data was successfully sent, False otherwise.
    """
    output_type = config['output']['type']
    destination = config['output']['destination']
    port = config['output'][output_type].get('port', None)
    batch_mode = config['output'].get('batch', False)
    delimiter = config['output'].get('delimiter', '\n')
    tls_config = config['output'].get('tls', {}) if output_type == 'tls' else {}

    destination_config = {
        'destination': destination,
        'output_format': config['output_format'],
        'output_type': output_type,
        'port': port,
        'batch_mode': batch_mode,
        'delimiter': delimiter,
        'tls_config': tls_config
    }

    try:
        success = Sender.send_data(transformed_data, destination_config)
        if success:
            logger.info(f"Data successfully sent to {destination}")
        else:
            logger.error("Failed to send transformed data")
            return False
    except Exception as e:
        logger.error(f"Error during data sending process: {e}")
        return False

    return True

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
    # General configuration setup
    downloader = Downloader(config)
    start_time = datetime.datetime.now()

    # Extracting the input type
    input_type = input_fields.get('input_type', '')

    # Process data for SQS input type
    if input_type == "sqs":
        bucket, key, expected_size, download_path = process_sqs_input(input_fields, config, downloader)

        if product == "cloud_waap":
            data_fields = process_cloud_waap_sqs(key, config, download_path)
            if data_fields is None:
                return True

        transformed_data = transform_data(input_type, data_fields, config, field_mappings, product)
        if transformed_data:
            success = finalize_and_send(transformed_data, config)
        else:
            logger.error(f"Failed to transform data from file: {download_path}")
            success = False

    # Cleanup and logging
    Utility.cleanup(download_path)
    end_time = datetime.datetime.now()
    time_taken = end_time - start_time
    logger.info(f"Task completed. Time taken: {time_taken}")

    return success



"""
def process_data(input_fields, product, field_mappings, config):
    """"""
    Processes the input data based on the source type and product.

    Args:
        input_fields (dict): Contains fields specific to the input type.
        product (str): The product type being processed.
        field_mappings (dict): Field mappings for data transformation.
        config (dict): The configuration settings.

    Returns:
        bool: True if the processing is successful, False otherwise.
    """"""
    # Dependencies: config, input_fields
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
        if product == "cloud_waap":
            log_type = CloudWAAPProcessor.identify_log_type(key)
            if not config['logs'][product][log_type]:
                return True

        # --- more SQS/S3 Specific Processing ---
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

        # --- Data Transformation for sqs input type ---
        # Dependencies: input_type, data_fields, config, Transformer
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

    # --- Sending Process and Finalization ---
    # Dependencies: transformed_data, config, Sender
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
"""