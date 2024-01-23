import gzip
import json
from logging_agent.cloud_waap import CloudWAAPProcessor
import logging_agent.cloud_waap.cloudwaap_enrich as cloud_waap_enrich
from .app_info import supported_features
from .logging_config import get_logger


# Create a logger for this module
logger = get_logger('transformer')

class Transformer:
    @staticmethod
    def load_and_transform(input_type, data_fields, output_format, field_mappings, product, batch_mode, format_options):

        try:
            metadata = {}
            log_type = ''
            data_source_type = ''

            if input_type == "sqs":
                key = data_fields.get('key', '')
                file_path = data_fields.get('file_path', '')
                log_type = data_fields.get('log_type', '')
                data_source_type = "file"
                data_info = file_path
                logger.debug(f"Loading file for transformation: {file_path}")
                with gzip.open(file_path, 'rt') as f:
                    data = json.load(f)


                # Extract metadata based on the product and log type

                if product == "cloud_waap":
                    metadata = CloudWAAPProcessor.extract_metadata(key, product, log_type)

            # Transform the content with all the extracted information
            transformed_content = Transformer.transform_content(
                data,
                output_format,
                log_type,
                field_mappings,
                product,
                batch_mode,
                format_options,
                **metadata
            )
            logger.info(f"Transformation completed for {data_source_type}: {data_info}")
            return transformed_content
        except Exception as e:
            logger.error(f"Error loading or transforming {data_source_type}: {data_info}: {e}")
            return None

    @staticmethod
    def transform_content(data, output_format, log_type, field_mappings, product, batch_mode, format_options, **metadata):
        product_field_mappings = field_mappings.get(product, {})
        transformed_logs = []
        logger.debug(f"Transforming data to {output_format}")
        requires_conversion = output_format in supported_features[product]["mapping"]["required_for"]
        is_supported_format = output_format in supported_features[product]["supported_conversions"]

        for event in data:
            enriched_event = Transformer.enrich_event(event, log_type, output_format, product, format_options, **metadata)
            if is_supported_format:
                if requires_conversion:
                    conversion_func = Transformer.get_conversion_function(output_format, product)
                    if conversion_func:
                        transformed_log = conversion_func(enriched_event,log_type, product, product_field_mappings, format_options)
                    else:
                        logger.error(
                            f"No conversion function found for output format: {output_format} and product {product}")
                        return None
                else:
                    transformed_log = json.dumps(enriched_event)
                transformed_logs.append(transformed_log)
            else:
                logger.error(f"Unsupported output format: {output_format} for product {product}")
                return None

        # Decide the return structure based on the batch mode
        return '\n'.join(transformed_logs) if batch_mode else transformed_logs

    @staticmethod
    def enrich_event(event, log_type, output_format, product, format_options, **metadata):
        # Add log type for 'json' and 'ndjson' formats
        # format_option = format_options.get('time_format', "epoch_ms_str")
        #print(format_option)

        # Check the product type from metadata

        # Use product-specific enrichment based on log type
        if product == "cloud_waap":
            tenant_name = metadata.get('tenant_name', '')
            application_name = metadata.get('application_name', '')
            if output_format in ["ndjson", "json"]:
                event['log_type'] = log_type
            if log_type != "Access":
                event['tenant_name'] = metadata.get('tenant_name', '')
            if log_type == "Access":
                return cloud_waap_enrich.enrich_access_log(event, format_options, output_format)
            elif log_type == "WAF":
                return cloud_waap_enrich.enrich_waf_log(event, format_options, output_format, application_name)
            elif log_type == "Bot":
                return cloud_waap_enrich.enrich_bot_log(event, format_options, output_format)
            elif log_type == "DDoS":

                return cloud_waap_enrich.enrich_ddos_log(event, format_options, output_format, application_name)
            elif log_type == "WebDDoS":
                return cloud_waap_enrich.enrich_webddos_log(event, format_options ,output_format, application_name)


            logger.debug(f"Event enriched with log type: {log_type}, tenant name: {tenant_name}, application name: {application_name}")

        return event

    @staticmethod
    def get_conversion_function(output_format, product):
        """
        Determine the appropriate conversion function based on the output format and product.

        Parameters:
        - output_format (str): The desired format of the output (e.g., 'cef', 'leef').
        - product (str): The product type (e.g., 'cloud_waap').

        Returns:
        - function: A reference to the conversion function or None if not found.
        """
        if product == "cloud_waap":
            if output_format == "cef":
                from .cloud_waap.cloudwaap_json_to_cef import json_to_cef as conversion_func
            elif output_format == "leef":
                from .cloud_waap.cloudwaap_json_to_leef import json_to_leef as conversion_func
            else:
                conversion_func = None
        else:
            # TODO add more product types in the future
            conversion_func = None

        return conversion_func