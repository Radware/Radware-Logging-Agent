import re
from logging_agent.logging_config import get_logger
import datetime


# Create a logger for this module
logger = get_logger('cloudwaap_json_to_cef')


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

def construct_cef_syslog_header(format_options, log):
    syslog_header = ""
    syslog_headers = format_options.get('syslog_header', {})

    # Handle the time part of the syslog header
    # Use the current system time in a CEF acceptable format
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

def sanitize_cef_value(value):
    """Sanitize values for CEF format by escaping reserved characters."""
    if not isinstance(value, str):
        value = str(value)  # Ensure the value is a string
    value = (value.replace('\\', '\\\\')
             .replace('\r', '\\r')
             .replace('\n', '\\n')
             .replace('=', '\\=')
             .replace('|', '\\|')
             .replace(',', '\\,')
             .replace(';', '\\;')
             .replace('"', '\\"'))

    return value

def get_cef_header(product, log_type, log, field_mappings, format_options, severity_format):
    """Generate the CEF header based on the product, log type, and log content."""
    try:
        header_info = field_mappings.get(product, {}).get(log_type, {}).get("cef", {}).get("header", {})
        # Determine if severity is dynamic and extract from log if so
        if severity_format == 2:
            unknown_severity = "Unknown"
        elif severity_format == 3:
            unknown_severity = "0"
        else:
            unknown_severity = "info"
        if header_info.get('severity', '').lower() == 'fromlog':
            severity = log.get('severity', unknown_severity)  # Attempt to get severity from log
        else:
            severity = header_info.get('severity', unknown_severity)  # Use static severity from mapping
            if severity_format != 1:
                if severity != unknown_severity:
                    severity = map_severity_format(severity, severity_format)




        cef_header = (f"CEF:0|{header_info.get('vendor', 'Unknown')}|{header_info.get('product', 'Unknown')}"
                      f"|{header_info.get('version', 'Unknown')}|{header_info.get('log_type', 'Unknown')}"
                      f"|{header_info.get('title', 'Unknown')}|{severity}|")
        return cef_header
    except Exception as e:
        logger.error(f"Error generating CEF header: {e}")
        logger.error(f"Original Log: {log}")
        return "CEF:0|Unknown|Unknown|Unknown|Unknown|Unknown|Unknown|"


def format_extension_key(key, prefix):
    """Format the key name for the CEF extension."""

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


def json_to_cef(log, log_type, product, field_mappings, format_options):
    """Transform a CloudWAAP log to CEF format based on the product and log type."""
    try:
        severity_format = format_options.get('severity_format', 1 )
        if severity_format != 1:
            severity = log.get('severity', "no_severity")
            if severity != "no_severity":
                log['severity'] = map_severity_format(severity, severity_format)
        cef_header = get_cef_header(product, log_type, log, field_mappings, severity_format)
        cef_mappings = field_mappings.get(product, {}).get(log_type, {}).get("cef", {})
        static_mapping = cef_mappings.get("static_mapping", {})
        prefix = cef_mappings.get("prefix", "")

        generate_header = format_options.get('syslog_header', {}).get('generate_header', False)
        syslog_header = ""
        if generate_header:
            syslog_header = construct_cef_syslog_header(format_options, log)

        extensions = []
        # Process static mappings first
        for json_key, cef_key in static_mapping.items():
            value = log.pop(json_key, None)
            if is_value_valid(value):
                sanitized_value = sanitize_cef_value(value)
                extensions.append(f"{cef_key}={sanitized_value}")

        # Process remaining fields for dynamic mapping
        for json_key, value in log.items():
            if is_value_valid(value):
                formatted_key = format_extension_key(json_key, prefix)
                sanitized_value = sanitize_cef_value(value)  # Sanitize the value
                extensions.append(f"{formatted_key}={sanitized_value}")

        cef_log = syslog_header + cef_header + " " + " ".join(extensions)
        return cef_log
    except Exception as e:
        logger.error(f"Error transforming log to CEF: {e}")
        return None



