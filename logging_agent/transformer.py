import gzip
import json
from logging_agent.cloud_waap import CloudWAAPProcessor
from .field_mappings import FieldMappings
import logging_agent.cloud_waap.cloudwaap_enrich as cloud_waap_enrich
from .app_info import supported_features
from .logging_config import get_logger


# Create a logger for this module
logger = get_logger('transformer')

class Transformer:
    def __init__(self, config, product, output_format):
        self.logger = get_logger('Transformer')
        self.config = config  # Store the configuration in the instance
        # Retrieve the field mappings directly from the FieldMappings singleton
        self.field_mappings = FieldMappings.get_mapping_for_product(product)
        self.output_format = output_format
        self.product = product

    def transform_content(self, data, data_fields, batch_mode, format_options):
        log_type = data_fields.get('log_type', '')
        metadata = data_fields.get('metadata', {})
        print(self.field_mappings)

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
        # Add log type for specific formats
        if self.output_format in ["ndjson", "json"]:
            event['log_type'] = log_type

        # Use product-specific enrichment based on log type
        if self.product == "cloud_waap":
            tenant_name = metadata.get('tenant_name', '')
            application_name = metadata.get('application_name', '')

            if log_type == "Access":
                enriched_event = cloud_waap_enrich.enrich_access_log(event,format_options, self.output_format, application_name)
            elif log_type == "WAF":
                enriched_event = cloud_waap_enrich.enrich_waf_log(event,format_options, self.output_format, application_name)
            elif log_type == "Bot":
                enriched_event = cloud_waap_enrich.enrich_bot_log(event,format_options, self.output_format, application_name)
            elif log_type == "DDoS":
                enriched_event = cloud_waap_enrich.enrich_ddos_log(event,format_options, self.output_format, application_name)
            elif log_type == "WebDDoS":
                enriched_event = cloud_waap_enrich.enrich_webddos_log(event,format_options, self.output_format, application_name)
            else:
                # Handle other cases or unhandled log types
                enriched_event = event

            self.logger.debug(f"Event enriched with log type: {log_type}, tenant name: {tenant_name}, application name: {application_name}")
            return enriched_event

        # Default: return the event as is if no specific processing is required
        return event

    def get_conversion_function(self):
        """
        Determine the appropriate conversion function based on the output format and product.

        Returns:
            function: A reference to the conversion function or None if not found.
        """
        if self.product == "cloud_waap":
            if self.output_format == "cef":
                from .cloud_waap.cloudwaap_json_to_cef import json_to_cef as conversion_func
            elif self.output_format == "leef":
                from .cloud_waap.cloudwaap_json_to_leef import json_to_leef as conversion_func
            else:
                conversion_func = None
        else:
            # TODO: Add more product types in the future
            conversion_func = None

        return conversion_func
#