import re
from logging_agent.logging_config import get_logger
from urllib.parse import urlparse
from user_agents import parse
import copy
import ipaddress

# Create a logger for this module
logger = get_logger('cloud_waap_json_to_json')


def validate_and_process_ips(log):
    """
    Validates and processes IP addresses in specified log dictionary fields.

    This function checks for IP addresses in 'destinationIp', 'sourceIp', and 'xForwardedFor'
    fields of a log dictionary, validates them, and categorizes them into valid and invalid IPs.
    Valid IPs are stored in their respective fields as lists, and invalid IPs are moved to a
    nested 'invalidData' dictionary within the log.

    Parameters:
    - log (dict): The log dictionary containing IP fields to be validated and processed.

    Returns:
    - dict: The modified log dictionary.
    """
    fields_to_check = ['destinationIp', 'sourceIp', 'xForwardedFor']

    for field in fields_to_check:
        if field in log:
            try:
                raw_ips = log[field].split(',')
                valid_ips, invalid_ips = [], []

                for ip in raw_ips:
                    ip = ip.strip()
                    try:
                        ipaddress.ip_address(ip)
                        valid_ips.append(ip)
                    except ValueError:
                        invalid_ips.append(ip)

                # Update the log based on validation results
                if valid_ips:
                    log[field] = valid_ips  # Assign list of valid IPs directly
                else:
                    del log[field]  # Remove the key if no valid IPs are left

                if invalid_ips:
                    if 'invalidData' not in log:
                        log['invalidData'] = {}
                    log['invalidData'][field] = invalid_ips
            except Exception as e:
                logger.error(f"Error processing field {field}: {e}")

    return log

def extract_user_agent_details(user_agent_string):
    """
    Extracts details from a user agent string.

    Args:
        user_agent_string (str): The user agent string to parse.

    Returns:
        dict: A dictionary containing the extracted user agent details.
    """
    try:
        ua = parse(user_agent_string)
        return {
            'device_type': 'Mobile' if ua.is_mobile else 'Desktop' if ua.is_pc else 'Other',
            'user_agent_name': ua.browser.family,
            'user_agent_version': ua.browser.version_string,
            'device_name': ua.device.family  # Added device name extraction
        }
    except Exception as e:
        logger.error(f"Error extracting user agent details: {e}")
        return {}

def map_log_to_ecs(log, ecs_fields_mapping, ecs_log):
    try:
        for original_field, ecs_field_path in ecs_fields_mapping.items():
            if original_field not in log:
                continue
            ecs_field_hierarchy = ecs_field_path.split('.')
            current_level = ecs_log
            for i, field in enumerate(ecs_field_hierarchy):
                if i == len(ecs_field_hierarchy) - 1:
                    current_level[field] = log[original_field]
                else:
                    if field not in current_level:
                        current_level[field] = {}
                    current_level = current_level[field]
        return ecs_log
    except Exception as e:
        logger.error(f"Error mapping log to ECS: {e}")
        return ecs_log




def extract_url_components(log):
    result = {
        'domain': None,
        'path': None,
        'query': None,
        'extension': None
    }

    try:
        request_url = log.get('request', '')
        if request_url.startswith('http://') or request_url.startswith('https://'):
            parsed_url = urlparse(request_url)
            result['domain'] = parsed_url.netloc
            result['path'] = parsed_url.path
            result['query'] = parsed_url.query
            if '.' in parsed_url.path:
                result['extension'] = parsed_url.path.split('.')[-1]
    except Exception as e:
        logger.error(f"Error extracting URL components: {e}")

    return result


def map_severity_format(severity, severity_format):
    try:
        format_2 = {"info": "Unknown", "low": "Low", "warning": "Medium", "high": "High", "critical": "Very-High"}
        format_3 = {"info": 1, "low": 2, "warning": 5, "high": 7, "critical": 10}

        severity = severity.lower()  # Normalize severity to lower case
        if severity_format == 2:
            return format_2.get(severity, "Unknown")
        elif severity_format == 3:
            return str(format_3.get(severity, 1))
        else:
            return severity
    except Exception as e:
        logger.error(f"Error mapping severity format: {e}")
        return severity  # Return the original severity in case of an error


def process_http_request_headers(log, ecs_log):
    """
    Attempts to parse HTTP request headers from the log based on the log type ('WAF' or 'Bot') and assigns them
    to individual fields under ecs_log['http']['request']['headers']. If the process fails, ecs_log remains unchanged.

    Args:
        log (dict): The original log entry.
        ecs_log (dict): The ECS log entry being constructed.

    Modifies:
        ecs_log: Conditionally adds parsed headers to the 'http.request.headers' field if processing succeeds.
    """
    try:
        # Make a deep copy of the ecs_log's http.request.headers part to work on
        temp_ecs_log = copy.deepcopy(ecs_log)
        headers_str = log.get('headers', '')
        log_type = log.get('logType')

        if headers_str:

            # Ensure the nested structure for headers exists in ecs_log
            if 'http' not in temp_ecs_log:
                temp_ecs_log['http'] = {}
            if 'request' not in temp_ecs_log['http']:
                temp_ecs_log['http']['request'] = {}
            if 'headers' not in temp_ecs_log['http']['request']:
                temp_ecs_log['http']['request']['headers'] = {}

            http_headers = temp_ecs_log['http']['request']['headers']

            parsed_headers = []
            if log_type == 'WAF':
                # For 'WAF' logs, headers are split by '\r\n'
                parsed_headers = [header.split(": ", 1) for header in headers_str.split('\r\n') if ": " in header]
            elif log_type == 'Bot':
                # For 'Bot' logs, headers are split by ', ' and then by ': '
                parsed_headers = [header.strip().split(" : ", 1) for header in headers_str.split(', ') if
                                  " : " in header]

            # Process each parsed header
            for header in parsed_headers:
                if len(header) == 2:
                    header_name, header_value = header
                    # Normalize header names to lowercase and replace '-' with '_'
                    normalized_header_name = header_name.lower().replace('-', '_')
                    # Assign the header value to the appropriate field in temp_ecs_log
                    http_headers[normalized_header_name] = header_value

            # Update the original ecs_log only after successful processing
            if 'http' not in ecs_log:
                ecs_log['http'] = {}
            if 'request' not in ecs_log['http']:
                ecs_log['http']['request'] = {}
            if 'headers' not in ecs_log['http']['request']:
                ecs_log['http']['request']['headers'] = {}

            ecs_log['http']['request']['headers'] = http_headers

    except Exception as e:
        # Log any exceptions and leave ecs_log unchanged
        logger.error(f"Error processing HTTP request headers, leaving ecs_log unchanged: {e}")
        print(log.get('headers', ''))


def seconds_to_nanoseconds(seconds):
    """
    Converts seconds (with decimals) to nanoseconds. If conversion fails, returns the original input.

    Parameters:
    - seconds (str or float): Duration in seconds with decimal precision.

    Returns:
    - int or original input: Duration in nanoseconds, or the original input if conversion fails.
    """
    try:
        seconds_float = float(seconds)
        nanoseconds = int(seconds_float * 1_000_000_000)
        return nanoseconds
    except (ValueError, TypeError):
        return seconds

def hhmmss_to_nanoseconds(duration):
    """
    Converts a duration in "HH:MM:SS" format to nanoseconds. If conversion fails, returns the original input.

    Parameters:
    - duration (str): Duration in "HH:MM:SS" format.

    Returns:
    - int or original input: Duration in nanoseconds, or the original input if conversion fails.
    """
    try:
        hours, minutes, seconds = map(int, duration.split(":"))
        total_seconds = (hours * 3600) + (minutes * 60) + seconds
        nanoseconds = total_seconds * 1_000_000_000
        return nanoseconds
    except (ValueError, TypeError):
        return duration


def transform_latest_real_time_signature(pattern_dict):
    """
    Transforms a dictionary containing a 'Pattern' key with an array of patterns into a more structured format.
    Each pattern's 'Name' is converted into a key in the resulting dictionary, and its 'Values' are assigned as the value.
    If 'Values' contains more than one item, it is kept as a list; otherwise, it is a single value.
    In case of any exception during transformation, the original value is returned unchanged.

    :param pattern_dict: A dictionary with a 'Pattern' key containing an array of pattern objects.
    :return: A transformed dictionary with structured key-value pairs or the original dictionary if an error occurs.
    """
    try:
        transformed = {}

        for pattern in pattern_dict["Pattern"]:
            name = pattern["Name"]

            # Convert name to lowercase, remove "header " prefix, '*' characters, and trailing '-'
            formatted_name = name.replace('header ', '').lower().replace(' ', '_').replace('*', '').rstrip('-')

            # Use list if multiple values, otherwise just the single value
            transformed_value = pattern["Values"] if len(pattern["Values"]) > 1 else pattern["Values"][0]

            transformed[formatted_name] = transformed_value

        return transformed
    except Exception:
        # Return the original dictionary if any exception occurs
        return pattern_dict

def json_to_ecs(log, log_type, product, field_mappings, format_options):
    """
    Transform a log entry to ECS (Elastic Common Schema) format based on the product, log type,
    and provided field mappings. This function enriches the log with ECS-compliant fields
    and custom transformations such as URL and user agent parsing.

    Args:
        log (dict): The log entry to be transformed.
        log_type (str): The type of the log.
        product (str): The product name.
        field_mappings (dict): Mappings for fields based on product and log type, including ECS mappings.
        format_options (dict): Format options that may include additional processing flags or preferences.

    Returns:
        dict: The transformed log in ECS format or None in case of an error.
    """
    try:
        ecs_fields = field_mappings.get(product, {}).get(log_type, {}).get("ecs", {})
        if log['logType'] == "WebDDoS":
            if 'duration' in log:
                log['duration'] = hhmmss_to_nanoseconds(log['duration'])
            if 'latestRealTimeSignature' in log:
                log['latestRealTimeSignature'] = transform_latest_real_time_signature(log['latestRealTimeSignature'])

        if 'requestTime' in log:
            log['requestTime'] = seconds_to_nanoseconds(log['requestTime'])
        log = validate_and_process_ips(log)
        ecs_log = {}
        ecs_log['radware'] = {}
        ecs_log['radware']['cloud_waap'] = log
        ecs_log['event'] = {}
        ecs_log['event'] = {'category': ['web'], 'type': ['info']}
        if 'action' in log:
            ecs_log['event']['action'] = log['action']
        if 'reason' in log:
            ecs_log['event']['reason'] = log['reason']
        if 'transId' in log:
            ecs_log['event']['id'] = log['transId']
        if 'severity' in log:
            ecs_log['event']['severity'] = map_severity_format(log['severity'], 3)
        ecs_log['observer'] = {}  # Initialize observer as a dictionary
        ecs_log['observer'] = {
            'product': 'Cloud WAAP',
            'vendor': 'Radware',
            'type': log.get('logType', '')
        }



        ecs_log['rule'] = {}
        if 'reason' in log:
            ecs_log['rule']['description'] = log['reason']
        if 'category' in log:
            ecs_log['rule']['category'] = log['category']
        if 'name' in log:
            ecs_log['rule']['name'] = log['name']
        if 'targetModule' in log:
            ecs_log['rule']['ruleset'] = log['targetModule']
        if 'ruleId' in log:
            ecs_log['rule']['id'] = log['ruleId']
        if 'policyId' in log:
            ecs_log['rule']['id'] = log['policyId']

        # Extract URL components if the request field exists
        if 'request' in log:
            ecs_log['url'] = {}
            url_components = extract_url_components(log)
            if url_components['path']:
                ecs_log.setdefault('url', {})['path'] = url_components['path']
            if url_components['query']:
                ecs_log.setdefault('url', {})['query'] = url_components['query']
            if url_components['extension']:
                ecs_log.setdefault('url', {})['extension'] = url_components['extension']
            if url_components['domain']:
                ecs_log.setdefault('url', {})['domain'] = url_components['domain']

        if 'headers' in log:
            process_http_request_headers(log, ecs_log)

        # Extract user agent details if userAgent field exists and populate subfields conditionally
        user_agent_string = log.get('userAgent')
        if user_agent_string:
            ecs_log['user_agent'] = {}
            ua_details = extract_user_agent_details(user_agent_string)

            # Add checks to ensure each detail is only added if present
            if 'user_agent_name' in ua_details and ua_details['user_agent_name']:
                ecs_log['user_agent']['name'] = ua_details['user_agent_name']
            if 'user_agent_version' in ua_details and ua_details['user_agent_version']:
                ecs_log['user_agent']['version'] = ua_details['user_agent_version']
            if 'device_type' in ua_details and ua_details['device_type']:
                ecs_log['user_agent']['device'] = {'type': ua_details['device_type']}
            if 'device_name' in ua_details and ua_details['device_name']:
                ecs_log['user_agent']['device']['name'] = ua_details['device_name']

        ecs_log = map_log_to_ecs(log, ecs_fields, ecs_log)


        return ecs_log
    except Exception as e:
        print(f"Error transforming log to ECS: {e}")
        return None