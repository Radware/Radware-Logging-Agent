import re
from logging_agent.logging_config import get_logger
import datetime
import time


# Create a logger for this module
logger = get_logger('cloud_waap_json_to_splunk_hec')




def json_to_splunk_hec(log, log_type, product, field_mappings, format_options):
    """
    Formats a given log entry for submission to Splunk's HTTP Event Collector (HEC).

    This function prepares a dictionary with keys suitable for Splunk HEC ingestion,
    including the log's timestamp, source, sourcetype, and the event data itself. It
    uses the current time as the event timestamp, and incorporates the provided
    `log`, `log_type`, and `product` into the formatted output.

    Args:
        log (dict): The log entry to be formatted. Expected to be a dictionary.
        log_type (str): A string indicating the type of the log (used as `sourcetype` in Splunk).
        product (str): The name of the product generating the log (used as `source` in Splunk).
        field_mappings (dict): This argument is not used in the function but included for future enhancements.
                                Mappings for fields based on product and log type.
        format_options (dict): This argument is not used in the function but included for future enhancements.
                                Format options including severity format and syslog header.

    Returns:
        dict: A dictionary formatted for Splunk HEC ingestion. Includes keys for `time`,
              `source`, `sourcetype`, and `event`. Returns None in case of an error.
    """
    splunk_log = {}
    # Convert current time to Unix epoch seconds (integer format)
    splunk_log['time'] = int(time.time())
    # Set the product name as the source of the log
    splunk_log['source'] = product
    # Set the log type as the sourcetype of the log
    splunk_log['sourcetype'] = log_type
    # Include the original log event data
    splunk_log['event'] = log

    return splunk_log



