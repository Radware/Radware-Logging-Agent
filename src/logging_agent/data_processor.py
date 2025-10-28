from logging_agent.app_info import supported_features
from logging_agent.data_loader import DataLoader
from logging_agent.transformer import Transformer
from logging_agent.sender import Sender
from logging_agent.utility import Utility
from logging_agent.logging_config import get_logger
from logging_agent.cloud_waap import CloudWAAPProcessor
import datetime


class DataProcessor:
    def __init__(self, config):
        """
        Initializes the DataProcessor with configuration settings.

        Args:
            config (dict): Configuration settings for the data processor.
        """
        self.config = config
        self.logger = get_logger('data_processor')

    def process_data(self, input_fields):
        """
        Processes the input data based on the source type and product.

        Args:
            input_fields (dict): Contains fields specific to the input type.

        Returns:
            bool: True if the processing is successful, False otherwise.
        """
        file_size = input_fields.get('expected_size', 'Unknown size')
        start_time = datetime.datetime.now()
        self.logger.info(f"Starting processing. File size: {file_size} bytes")

        input_type = self.config.get('type')  # Retrieve input type from config
        product = self.config.get('product')  # Retrieve product from config

        load_start_time = datetime.datetime.now()
        data_loader = DataLoader(self.config)
        loaded_data = data_loader.load_data(input_type, input_fields)
        load_end_time = datetime.datetime.now()
        self.logger.info(f"Loading completed. Time taken: {load_end_time - load_start_time}. File size: {file_size} bytes")

        data = None
        metadata = {}
        if loaded_data:
            data = loaded_data.get('data')
            metadata = loaded_data.get('metadata', {})
        if data is None:
            self.logger.error(f"Failed to load data for input type: {input_type}")
            return False

        sample_event = CloudWAAPProcessor.extract_sample_event(data)
        log_type = self.identify_product_log_type(
            input_fields,
            metadata,
            input_type,
            product,
            sample_event
        ) or "Unknown"
        supported_log_types = supported_features[product]["supported_log_types"]
        logs_config = self.config.get('logs', {}) or {}
        log_configuration = supported_features.get(product, {}).get('log_configuration', {})
        unknown_option = log_configuration.get('unknown_option')
        allow_unknown_logs = logs_config.get(unknown_option, False) if unknown_option else False

        # Check if the log type is supported for the product
        if log_type not in supported_log_types:
            if not allow_unknown_logs:
                self.logger.info(f"Skipping unsupported log type {log_type} for product {product}.")
                return True  # Successfully handled by skipping
            self.logger.info(
                f"Processing unsupported log type {log_type} for product {product} because unknown logs are enabled."
            )
        elif not logs_config.get(log_type, False):
            # Check if the log type should be processed based on configuration
            self.logger.info(f"Skipping log type {log_type} as per configuration.")
            return True  # Successfully handled by skipping

        data_fields = self.gather_data_fields(input_fields, metadata, input_type, log_type, product)
        transform_start_time = datetime.datetime.now()
        transformed_data = self.transform_data(data, data_fields)
        transform_end_time = datetime.datetime.now()
        self.logger.info(f"Transformation completed. Time taken: {transform_end_time - transform_start_time}. File size: {file_size} bytes")

        if not transformed_data:
            self.logger.error("Failed to transform data")
            return False
        send_start_time = datetime.datetime.now()

        success = self.finalize_and_send(transformed_data)
        send_end_time = datetime.datetime.now()
        self.logger.info(f"Sending completed. Time taken: {send_end_time - send_start_time}. File size: {file_size} bytes")


        # Cleanup
        file_path = metadata.get('file_path')
        cleanup_flag = metadata.get('cleanup')
        if success and cleanup_flag and file_path:
            Utility.cleanup(file_path)

        # Cleanup and final logging
        end_time = datetime.datetime.now()
        self.logger.info(f"Total processing time: {end_time - start_time}. File size: {file_size} bytes")

        #self.logger.info(f"Task completed. Time taken: {end_time - start_time}")
        return success

    def identify_product_log_type(self, log_info, metadata, input_type, product, sample_event=None):
        """
        Identifies the log type based on product and input type.

        Args:
            log_info (dict): Information about the log.
            input_type (str): Type of the input (e.g., 'sqs').
            product (str): The product type being processed.

        Returns:
            str: Identified log type.
        """
        log_type = ""
        if input_type in {"sqs", "file", "sftp"} and product == "cloud_waap":
            key = metadata.get('relative_key') or metadata.get('key') or log_info.get('key', '')
            log_type = CloudWAAPProcessor.identify_log_type(key, sample_event)
        return log_type

    def gather_data_fields(self, input_fields, metadata, input_type, log_type, product):
        """
        Gathers additional data fields required for transformation.

        Args:
            input_fields (dict): Input fields specific to the data source.
            input_type (str): Type of the input (e.g., 'sqs').
            log_type (str): Type of the log identified.
            product (str): The product type being processed.

        Returns:
            dict: Data fields collected for transformation.
        """
        data_fields = {}
        if input_type in {"sqs", "file", "sftp"} and product == "cloud_waap":
            key = metadata.get('relative_key') or metadata.get('key') or input_fields.get('key')
            waap_metadata = CloudWAAPProcessor.extract_metadata(key, product, log_type)
            data_fields = {
                'key': key,
                'input_type': input_type,
                'log_type': log_type,
                'product': product,
                'metadata': waap_metadata
            }
        return data_fields

    def transform_data(self, data, data_fields):
        """
        Transforms the data according to specified configurations and mappings.

        Args:
            data (dict): The data to be transformed.
            data_fields (dict): Additional data fields for transformation.
            product (str): Product name

        Returns:
            object: Transformed data.
        """
        output_type = self.config['output']['type']
        output_format = self.config['output']['output_format']
        format_options = self.config['formats'].get(output_format, {})


        # Instantiate Transformer with the specific product and output format
        transformer = Transformer(self.config)


        transformed_data = transformer.transform_content(
            data=data,
            data_fields=data_fields,
            format_options=format_options
        )

        return transformed_data


    def finalize_and_send(self, transformed_data):
        """
        Finalizes the process by sending the transformed data.

        Args:
            transformed_data (object): The data after transformation.

        Returns:
            bool: True if the data was successfully sent, False otherwise.
        """
        output_format = self.config['output']['output_format']
        output_type = self.config['output']['type']
        destination = self.config['output']['destination']
        port = self.config['output'].get('port', None)
        uri = self.config['output'].get('uri', None)
        batch_mode = self.config['output'].get('batch', False)
        authentication = self.config[output_type].get('authentication', {})
        custom_headers = self.config[output_type].get('custom_headers', {})
        delimiter = self.config['formats'][output_format].get('delimiter', '\n')
        tls_config = self.config[output_type] if output_type == 'tls' or output_type == 'https' else {}
        destination_config = {
            'destination': destination,
            'output_format': output_format,
            'output_type': output_type,
            'port': port,
            'uri': uri,
            'batch_mode': batch_mode,
            'authentication': authentication,
            'custom_headers': custom_headers,
            'delimiter': delimiter,
            'tls_config': tls_config
        }

        try:
            return Sender.send_data(transformed_data, destination_config)
        except Exception as e:
            self.logger.error(f"Error during data sending process: {e}")
            return False
