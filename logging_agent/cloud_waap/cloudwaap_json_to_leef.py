import re
from logging_agent.logging_config import get_logger
import datetime

# Create a logger for this module
logger = get_logger('cloud_waap_json_to_leef')

def map_severity_format(severity, severity_format):
    """
    Map a given severity to a different format for LEEF logs.

    Args:
        severity (str): The original severity level.
        severity_format (int): The target format option (2 or 3).

    Returns:
        str: Mapped severity level in the new format.
    """
    try:
        format_2 = {"info": "Unknown", "low": "Low", "warning": "Medium", "high": "High", "critical": "Very-High"}
        format_3 = {"info": 1, "low": 2, "warning": 5, "high": 7, "critical": 10}

        if severity_format == 2:
            return format_2.get(severity.lower(), "Unknown")
        elif severity_format == 3:
            return str(format_3.get(severity.lower(), 1))
        else:
            return severity
    except Exception as e:
        logger.error(f"Error in mapping severity format: {e}")
        return severity  # Return the original severity in case of an error


def construct_leef_syslog_header(format_options, log):
    """
    Construct the syslog header for LEEF logs.

    Args:
        format_options (dict): Configuration options for log format.
        log (dict): The log data to potentially extract values from.

    Returns:
        str: Constructed syslog header.
    """
    try:
        syslog_header = ""
        syslog_headers = format_options.get('syslog_header', {})
        time_format_option = format_options.get('time_format', '%Y-%m-%dT%H:%M:%S%z')

        if time_format_option == 'epoch_ms_str':
            time_format = '%s%f'
        elif time_format_option == 'epoch_ms_int':
            time_format = '%s'
        elif time_format_option == 'MM dd yyyy HH:mm:ss':
            time_format = '%m %d %Y %H:%M:%S'
        else:
            time_format = '%Y-%m-%dT%H:%M:%S%z'

        current_time = datetime.datetime.now()
        syslog_header += current_time.strftime(time_format) + " "

        host = "Radware-CloudWAAP"
        if syslog_headers and 'host' in syslog_headers:
            host_mapping = {
                "product": "Radware-CloudWAAP",
                "tenant": log.get('tenant_name', 'UnknownTenant'),
                "application": log.get('application_name', 'UnknownApplication')
            }
            host = host_mapping.get(syslog_headers['host'], "Radware-CloudWAAP")

        syslog_header += host + " "
        return syslog_header
    except Exception as e:
        logger.error(f"Error constructing LEEF syslog header: {e}")
        return ""  # Return an empty string in case of an error


def sanitize_leef_value(value):
    """
    Sanitize values for LEEF format by escaping reserved characters.

    Args:
        value: The value to be sanitized.

    Returns:
        str: The sanitized value.
    """
    try:
        if not isinstance(value, str):
            value = str(value)  # Convert to string if not already

        # Escape characters that are reserved in LEEF
        value = (value.replace('\\', '\\\\')  # Escape backslashes first
                      .replace('\n', '\\n')   # Escape newlines
                      .replace('|', '\\|')    # Escape pipes
                      .replace('=', '\\='))   # Escape equals signs

        return value
    except Exception as e:
        logger.error(f"Error in sanitizing LEEF value: {e}")
        return str(value)  # Return the original value as string in case of an error



def get_leef_header(product, log_type, field_mappings):
    """
    Generate the LEEF header based on the product and log type.

    Args:
        product (str): The product name.
        log_type (str): The type of the log.
        field_mappings (dict): Mappings for fields based on product and log type.

    Returns:
        str: A string representing the LEEF header.
    """
    try:
        header_info = field_mappings.get(product, {}).get(log_type, {}).get("leef", {}).get("header", {})
        leef_header = (f"LEEF:2.0|{header_info.get('vendor', 'Unknown')}|"
                       f"{header_info.get('product', 'Unknown')}|"
                       f"{header_info.get('version', 'Unknown')}|"
                       f"{header_info.get('log_type', 'Unknown')}|")
        return leef_header
    except Exception as e:
        logger.error(f"Error generating LEEF header: {e}")
        return "LEEF:2.0|Unknown|Unknown|Unknown|Unknown|"  # Default header in case of an error



def format_extension_key(key, prefix):
    """
    Format the key name for the LEEF extension.

    Args:
        key (str): The key to be formatted.
        prefix (str): The prefix to be added to the key.

    Returns:
        str: The formatted key name.
    """
    try:
        if any(char in key for char in [' ', '-', '_']):
            # Format key to TitleCase and remove special characters
            formatted_key = prefix + re.sub(r"[-_\s]", "", key.title())
        else:
            # Maintain original case but capitalize the first letter
            formatted_key = prefix + key[0].upper() + key[1:]
        return formatted_key
    except Exception as e:
        logger.error(f"Error in formatting extension key: {e}")
        return prefix + key  # Return the key with prefix as fallback



def is_value_valid(value):
    """
    Check if the value is valid and not in the list of unwanted values.

    Args:
        value: The value to be checked.

    Returns:
        bool: True if the value is valid, False otherwise.
    """
    try:
        unwanted_values = {"", "-", " - ", "--", None}
        return value not in unwanted_values
    except Exception as e:
        logger.error(f"Error checking value validity for LEEF: {e}")
        return False




def json_to_leef(log, log_type, product, field_mappings, format_options):
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
    try:
        severity_format = format_options.get('severity_format', 1)
        # Update severity if required by the format options
        if severity_format != 1:
            severity = log.get('severity', "no_severity")
            if severity != "no_severity":
                log['severity'] = map_severity_format(severity, severity_format)

        leef_header = get_leef_header(product, log_type, field_mappings)
        leef_mappings = field_mappings.get(product, {}).get(log_type, {}).get("leef", {})
        static_mapping = leef_mappings.get("static_mapping", {})
        prefix = leef_mappings.get("prefix", "")

        # Construct syslog header if required
        generate_header = format_options.get('syslog_header', {}).get('generate_header', False)
        syslog_header = construct_leef_syslog_header(format_options, log) if generate_header else ""

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
                sanitized_value = sanitize_leef_value(value)
                extensions.append(f"{formatted_key}={sanitized_value}")

        leef_log = syslog_header + leef_header + "\t".join(extensions)
        return leef_log
    except Exception as e:
        logger.error(f"Error transforming log to LEEF: {e}")
        return None



