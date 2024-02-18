import re
from logging_agent.logging_config import get_logger
import datetime
import time


# Create a logger for this module
logger = get_logger('cloud_waap_json_to_splunk_hec')




def json_to_splunk_hec(log, log_type, product, field_mappings, format_options):
    """
    Transform a CloudWAAP log to LEEF format based on the product and log type.

    Args:
        log (dict): The log entry to be transformed.
        log_type (str): The type of the log.
        product (str): The product name.
        field_mappings (dict): Mappings for fields based on product and log type.
        format_options (dict): Format options including severity format and syslog header.

    Returns:
        str: The transformed log in LEEF format or None in case of an error.
    """
    splunk_log = {}
    # Convert current time to epoch seconds. The int() conversion truncates the microseconds.
    splunk_log['time'] = int(time.time())
    splunk_log['source'] = product
    splunk_log['sourcetype'] = log_type
    splunk_log['event'] = log

    return splunk_log



