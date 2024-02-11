import re
from logging_agent.logging_config import get_logger
import datetime


# Create a logger for this module
logger = get_logger('cloud_waap_json_to_cef')


def map_severity_format(severity, severity_format):
    """
    Map a given severity to a specified format.

    Parameters:
    - severity (str): The original severity level as a string.
    - severity_format (int): The target format option. Accepted values:
      - 1: Original severity (no mapping)
      - 2: Descriptive textual representations
      - 3: Numeric severity levels

    Returns:
    - str: Mapped severity level in the new format. If the format option is unrecognized,
      the original severity is returned.
    """

    format_2 = {"info": "Unknown", "low": "Low", "warning": "Medium", "high": "High", "critical": "Very-High"}
    format_3 = {"info": 1, "low": 2, "warning": 5, "high": 7, "critical": 10}

    severity = severity.lower()  # Normalize severity to lower case
    if severity_format == 2:
        return format_2.get(severity, "Unknown")
    elif severity_format == 3:
        return str(format_3.get(severity, 1))
    else:
        return severity



def construct_cef_syslog_header(format_options, log):
    """
    Constructs the syslog header for a CEF log based on provided format options and log content.

    Args:
        format_options (dict): Configuration options for syslog header and time format.
        log (dict): The log entry for extracting tenant or application name if configured.

    Returns:
        str: A syslog header string for CEF logs.
    """
    syslog_header = ""
    syslog_headers = format_options.get('syslog_header', {})
    time_format_option = format_options.get('time_format', '%Y-%m-%dT%H:%M:%S%z')

    try:
        # Determine the time format for the syslog header
        if time_format_option == 'epoch_ms_str':
            # Epoch time in milliseconds as a string
            time_format = '%s%f'
        elif time_format_option == 'epoch_ms_int':
            # Epoch time in milliseconds as an integer
            time_format = '%s'
        elif time_format_option == 'MM dd yyyy HH:mm:ss':
            # Custom format
            time_format = '%m %d %Y %H:%M:%S'
        else:
            # ISO 8601 format or any other custom format specified
            time_format = '%Y-%m-%dT%H:%M:%S%z'

        current_time = datetime.datetime.now()
        syslog_header += current_time.strftime(time_format) + " "

        # Handle the host part of the syslog header
        host = "CloudWAAP"  # Default host
        if syslog_headers and 'host' in syslog_headers:
            if syslog_headers['host'] == "product":
                host = "CloudWAAP"
            elif syslog_headers['host'] == "tenant":
                host = log.get('tenant_name', 'UnknownTenant')
            elif syslog_headers['host'] == "application":
                host = log.get('application_name', 'UnknownApplication')

        syslog_header += host + " "
    except Exception as e:
        logger.error(f"Error constructing syslog header for CEF: {e}")
        syslog_header = "ErrorGeneratingSyslogHeader "

    return syslog_header



# escape_pattern = re.compile(r'([\\=\r\n|,;"\'])')
#
# def sanitize_cef_value(value):
#     """
#     Sanitize values for CEF format by escaping reserved characters.
#
#     Args:
#         value (any): The value to be sanitized for CEF format.
#
#     Returns:
#         str: A sanitized string safe for CEF formatting.
#     """
#     try:
#         if not isinstance(value, str):
#             value = str(value)  # Convert non-string values to string
#
#         # Mapping of characters to their escaped versions
#         escape_chars = {
#             '\\': '\\\\',
#             '\r': '\\r',
#             '\n': '\\n',
#             '=': '\\=',
#             '|': '\\|',
#             ',': '\\,',
#             ';': '\\;',
#             '"': '\\"'
#         }
#
#         for char, escaped_char in escape_chars.items():
#             value = value.replace(char, escaped_char)
#
#         return value
#     except Exception as e:
#         logger.error(f"Error sanitizing value for CEF format: {e}")
#         return str(value)

def sanitize_header_value(value):
    """
    Sanitize values for CEF header by escaping backslashes, carriage returns, and new lines.

    Args:
        value (str): The header value to be sanitized.

    Returns:
        str: A sanitized string safe for CEF header.
    """
    if not isinstance(value, str):
        value = str(value)  # Ensure the value is a string
    sanitized_value = value.replace('\\', '\\\\').replace('\r', '\\r').replace('\n', '\\n')
    return sanitized_value

def sanitize_extended_field_value(value):
    """
    Sanitize values for CEF extended fields by escaping backslashes, equals signs, carriage returns, and new lines.

    Args:
        value (str): The extended field value to be sanitized.

    Returns:
        str: A sanitized string safe for CEF extended fields.
    """
    sanitized_value = sanitize_header_value(value)  # Use the same base sanitization as header
    sanitized_value = sanitized_value.replace('=', '\\=')  # Additional escape for equals sign
    return sanitized_value


def construct_cef_header(product, log_type, log, field_mappings, severity_format):
    """
    Generate the CEF header based on the product, log type, and log content.

    Args:
        product (str): The product name.
        log_type (str): The type of the log.
        log (dict): The actual log data.
        field_mappings (dict): Mappings for fields based on product and log type.
        severity_format (int): The format option for severity.

    Returns:
        str: A string representing the CEF header.
    """
    try:
        header_info = field_mappings.get(product, {}).get(log_type, {}).get("cef", {}).get("header", {})

        # Determine default unknown severity based on the format
        if severity_format == 2:
            unknown_severity = "Unknown"
        elif severity_format == 3:
            unknown_severity = "0"
        else:
            unknown_severity = "info"

        # Determine if severity is dynamic and extract from log if so
        if header_info.get('severity', '').lower() == 'fromlog':
            severity = log.get('severity', unknown_severity)
        else:
            severity = header_info.get('severity', unknown_severity)
            if severity_format != 1 and severity != unknown_severity:
                severity = map_severity_format(severity, severity_format)

        # Determine title based on configuration
        if header_info.get('title', '').lower() == "fromlog":
            title = log.get('name', header_info.get('log_type', 'Unknown'))
            title = sanitize_header_value(title)  # Sanitize title if it comes from the log
        else:
            title = header_info.get('title', 'Unknown')

        cef_header = (f"CEF:0|{header_info.get('vendor', 'Unknown')}|{header_info.get('product', 'Unknown')}"
                      f"|{header_info.get('version', 'Unknown')}|{header_info.get('log_type', 'Unknown')}"
                      f"|{title}|{severity}|")
        return cef_header
    except Exception as e:
        logger.error(f"Error generating CEF header: {e}")
        logger.error(f"Original Log: {log}")
        return "CEF:0|Unknown|Unknown|Unknown|Unknown|Unknown|Unknown|"


def format_extension_key(key, prefix):
    """
    Format the key name for the CEF extension by ensuring it adheres to CEF key naming conventions.

    Args:
        key (str): The original key from the JSON log.
        prefix (str): The prefix to be added to the key for CEF format.

    Returns:
        str: Formatted key name suitable for use in CEF extension.
    """
    try:
        if any(char in key for char in [' ', '-', '_']):
            return prefix + re.sub(r"[-_\s]", "", key.title())
        return prefix + key[0].upper() + key[1:]
    except Exception as e:
        logger.error(f"Error formatting extension key: {e}")
        return prefix + "UnknownKey"


def is_value_valid(value):
    """
    Check if the given value is valid for inclusion in the CEF log.

    Args:
        value: The value to check.

    Returns:
        bool: True if the value is valid, False otherwise.
    """
    try:
        unwanted_values = {"", "-", " - ", "--", None}
        return value not in unwanted_values
    except Exception as e:
        logger.error(f"Error checking value validity: {e}")
        return False




def json_to_cef(log, log_type, product, field_mappings, format_options):
    """
    Transform a CloudWAAP log entry to the CEF format based on product, log type, and configuration.

    Args:
        log (dict): The log entry in JSON format.
        log_type (str): The type of the log.
        product (str): The product name.
        field_mappings (dict): Mappings for CEF field names.
        format_options (dict): Additional format options like severity format and syslog header.

    Returns:
        str: The transformed log entry in CEF format, or None if an error occurs.
    """
    try:
        severity_format = format_options.get('severity_format', 1)
        # Set default severity if not present, with specific logic for WebDDoS
        if 'severity' not in log:
            if log_type == "WebDDoS":
                log['severity'] = "Critical"  # Default severity for WebDDoS
            else:
                log['severity'] = "Info"  # Default severity for other types

        # Update severity based on the format options
        if severity_format != 1:
            severity = log['severity']  # Directly use the severity as it is now guaranteed to exist
            log['severity'] = map_severity_format(severity, severity_format)


        cef_header = construct_cef_header(product, log_type, log, field_mappings, severity_format)
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
                sanitized_value = sanitize_extended_field_value(value)
                extensions.append(f"{cef_key}={sanitized_value}")

        # Process remaining fields for dynamic mapping
        for json_key, value in log.items():
            if is_value_valid(value):
                formatted_key = format_extension_key(json_key, prefix)
                sanitized_value = sanitize_extended_field_value(value)  # Sanitize the value
                extensions.append(f"{formatted_key}={sanitized_value}")

        cef_log = syslog_header + cef_header + " " + " ".join(extensions)
        return cef_log
    except Exception as e:
        logger.error(f"Error transforming log to CEF: {e}")
        return None



