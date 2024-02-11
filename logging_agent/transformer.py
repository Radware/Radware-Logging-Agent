import gzip
import json
from logging_agent.cloud_waap import CloudWAAPProcessor
from logging_agent.field_mappings import FieldMappings
import logging_agent.cloud_waap.cloudwaap_enrich as cloud_waap_enrich
from logging_agent.app_info import supported_features
from logging_agent.logging_config import get_logger
from logging_agent.config_reader import Config


# Create a logger for this module
logger = get_logger('transformer')

class Transformer:

    # Mapping for cloud_waap enrichment functions
    cloud_waap_enrichment_functions = {
        "Access": cloud_waap_enrich.enrich_access_log,
        "WAF": cloud_waap_enrich.enrich_waf_log,
        "Bot": cloud_waap_enrich.enrich_bot_log,
        "DDoS": cloud_waap_enrich.enrich_ddos_log,
        "WebDDoS": cloud_waap_enrich.enrich_webddos_log,
        "CSP": cloud_waap_enrich.enrich_csp_log,
    }
    def __init__(self, config):
        self.logger = get_logger('Transformer')
        self.config = config  # Store the configuration in the instance
        # Retrieve the field mappings directly from the FieldMappings singleton
        product = self.config.get('product')
        self.field_mappings = FieldMappings.get_mapping_for_product(product)
        self.output_format = self.config['output']['output_format']
        self.product = product

    def transform_content(self, data, data_fields, batch_mode, format_options):
        log_type = data_fields.get('log_type', '')
        metadata = data_fields.get('metadata', {})

        transformed_logs = []
        self.logger.debug(f"Transforming data to {self.output_format}")

        requires_conversion = self.output_format in supported_features[self.product]["mapping"]["required_for"]
        is_supported_format = self.output_format in supported_features[self.product]["supported_conversions"]

        for event in data:
            enriched_event = self.enrich_event(event, log_type, format_options, metadata)
            if is_supported_format:
                if requires_conversion:
                    conversion_func = self.get_conversion_function()
                    if conversion_func:
                        transformed_log = conversion_func(enriched_event, log_type, self.product, self.field_mappings, format_options)
                    else:
                        self.logger.error(f"No conversion function found for output format: {self.output_format} and product {self.product}")
                        return None
                else:
                    transformed_log = json.dumps(enriched_event)

                transformed_logs.append(transformed_log)
            else:
                self.logger.error(f"Unsupported output format: {self.output_format} for product {self.product}")
                return None

        return '\n'.join(transformed_logs) if batch_mode else transformed_logs

    def enrich_event(self, event, log_type, format_options, metadata):
        """
        Enriches the event based on the log type and product-specific requirements.

        Args:
            event (dict): The event to be enriched.
            log_type (str): The type of log.
            metadata (dict): Additional metadata for enrichment.

        Returns:
            dict: The enriched event.
        """
        enrichment_functions = getattr(self, f"{self.product}_enrichment_functions", {})

        # Add log type for specific formats
        if self.output_format == 'json':
            event['log_type'] = log_type

        enrich_func = enrichment_functions.get(log_type)
        if enrich_func:
            enriched_event = enrich_func(event, format_options, self.output_format,
                                         metadata,
                                         log_type
                                         )
        else:
            # Default to the original event if no specific processing is required
            self.logger.debug(f"No specific enrichment for log type: {log_type} in product: {self.product}")
            enriched_event = event

        return enriched_event

    def get_conversion_function(self):
        """
        Determine the appropriate conversion function based on the output format and product.

        Returns:
            function: A reference to the conversion function or None if not found.
        """
        if self.product == "cloud_waap":
            if self.output_format == "cef":
                from logging_agent.cloud_waap.cloudwaap_json_to_cef import json_to_cef as conversion_func
            elif self.output_format == "leef":
                from logging_agent.cloud_waap.cloudwaap_json_to_leef import json_to_leef as conversion_func
            else:
                conversion_func = None
        else:
            # TODO: Add more product types in the future
            conversion_func = None

        return conversion_func


