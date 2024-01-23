import re
from logging_agent.logging_config import get_logger
import datetime

# Create a logger for this module
logger = get_logger('cloud_waap_json_to_leef')

def map_severity_format(severity, severity_format):
    """
    Map a given severity to a different format.

    Parameters:
    - severity (str): The original severity level.
    - severity_format (int): The target format option (2 or 3).

    Returns:
    - str: Mapped severity level in the new format.
    """

    # Mapping for format option 2
    format_2 = {"info": "Unknown", "low": "Low", "warning": "Medium", "high": "High", "critical": "Very-High"}

    # Mapping for format option 3 (assuming severity levels are 'info', 'low', ..., 'critical')
    format_3 = {"info": 1, "low": 2, "warning": 5, "high": 7, "critical": 10}


    if severity_format == 2:
        return format_2.get(severity.lower(), "Unknown")  # Default to "Unknown" if not found
    elif severity_format == 3:
        return str(format_3.get(severity.lower(), 1))  # Default to 1 if not found
    else:
        return severity  # Return the original severity if the format option is not recognized

def construct_leef_syslog_header(format_options, log):
    syslog_header = ""
    syslog_headers = format_options.get('syslog_header', {})

    # Use the current system time in a LEEF acceptable format
    if not syslog_headers or 'time' not in syslog_headers or syslog_headers['time'] == "agent":
        syslog_header += datetime.datetime.now().strftime("%b %d %H:%M:%S") + " "


    # Handle the host part of the syslog header
    host = "Radware-CloudWAAP"  # Default host
    if syslog_headers and 'host' in syslog_headers:
        if syslog_headers['host'] == "product":
            host = "Radware-CloudWAAP"
        elif syslog_headers['host'] == "tenant":
            host = log.get('tenant_name', 'UnknownTenant')
        elif syslog_headers['host'] == "application":
            host = log.get('application_name', 'UnknownApplication')
    syslog_header += host + " "

    return syslog_header

def sanitize_leef_value(value):
    """Sanitize values for LEEF format by escaping reserved characters."""
    if not isinstance(value, str):
        value = str(value)  # Ensure the value is a string

    # List of characters to escape: \, |, =, and \n (commonly escaped in LEEF)
    value = (value.replace('\\', '\\\\')  # Escape backslashes first
                  .replace('\n', '\\n')   # Newline
                  .replace('|', '\\|')    # Pipe
                  .replace('=', '\\='))   # Equal sign

    return value


def get_leef_header(product, log_type, field_mappings):
    """Generate the LEEF header based on the product and log type."""
    try:
        header_info = field_mappings.get(product, {}).get(log_type, {}).get("leef", {}).get("header", {})
        leef_header = f"LEEF:2.0|{header_info.get('vendor', 'Unknown')}|{header_info.get('product', 'Unknown')}|{header_info.get('version', 'Unknown')}|{header_info.get('log_type', 'Unknown')}|"
        return leef_header
    except Exception as e:
        logger.error(f"Error generating LEEF header: {e}")
        return "LEEF:2.0|Unknown|Unknown|Unknown|Unknown|"


def format_extension_key(key, prefix):
    """Format the key name for the leef extension."""

    # Check if the key contains a space, hyphen, or underscore
    if any(char in key for char in [' ', '-', '_']):
        # If it does, format it to TitleCase and remove special characters
        formatted_key = prefix + re.sub(r"[-_\s]", "", key.title())
    else:
        # If it doesn't, maintain its original case but capitalize the first letter
        formatted_key = prefix + key[0].upper() + key[1:]

    return formatted_key


def is_value_valid(value):
    """Check if the value is valid and not in the list of unwanted values."""
    unwanted_values = {"", "-", " - ", "--", None}
    return value not in unwanted_values


def json_to_leef(log, log_type, product, field_mappings, format_options):
    """Transform a CloudWAAP log to LEEF format based on the product and log type."""
    try:
        severity_format = format_options.get('severity_format', 1 )
        if severity_format != 1:
            severity = log.get('severity', "no_severity")
            if severity != "no_severity":
                log['severity'] = map_severity_format(severity, severity_format)
        leef_header = get_leef_header(product, log_type, field_mappings)
        leef_mappings = field_mappings.get(product, {}).get(log_type, {}).get("leef", {})
        static_mapping = leef_mappings.get("static_mapping", {})
        prefix = leef_mappings.get("prefix", "")

        generate_header = format_options.get('syslog_header', {}).get('generate_header', False)
        syslog_header = ""
        if generate_header:
            syslog_header = construct_leef_syslog_header(format_options, log)

        extensions = []
        # Process static mappings first
        for json_key, leef_key in static_mapping.items():
            value = log.pop(json_key, None)
            if is_value_valid(value):
                sanitized_value = sanitize_leef_value(value)
                extensions.append(f"{leef_key}={sanitized_value}")

        # Process remaining fields for dynamic mapping
        for json_key, value in log.items():
            if is_value_valid(value):
                formatted_key = format_extension_key(json_key, prefix)
                sanitized_value = sanitize_leef_value(value)  # Sanitize the value
                extensions.append(f"{formatted_key}={sanitized_value}")


        leef_log = syslog_header + leef_header + "\t".join(extensions)
        return leef_log
    except Exception as e:
        logger.error(f"Error transforming log to LEEF: {e}")
        return None


