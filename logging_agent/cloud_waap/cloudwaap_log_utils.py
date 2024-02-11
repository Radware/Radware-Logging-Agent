import re
from urllib.parse import urlparse
from logging_agent.logging_config import get_logger
from datetime import datetime

# Create a logger for this module
logger = get_logger('cloudwaap_log_utils')

class CloudWAAPProcessor:
    """
    CloudWAAPProcessor provides a collection of static methods designed to process
    and analyze Cloud WAAP logs. It includes functionalities for identifying log types,
    parsing various components of the logs, and extracting detailed information from log entries.
    """

    @staticmethod
    def identify_log_type(key):
        """
        Identify the type of Cloud WAAP log based on the key or file name.

        Args:
            key (str): The S3 key or file name of the log.

        Returns:
            str: The identified type of log ('Access', a specific log type, or 'Unknown').
        """
        try:
            log_type = "Unknown"
            parts = key.split("/")

            if parts:
                last_part = parts[-1]
                if last_part.startswith("rdwr_log"):
                    log_type = "Access"
                elif last_part.startswith("rdwr_event"):
                    log_type = parts[-2]

            return log_type
        except Exception as e:
            logger.error(f"Error identifying log type for key '{key}': {e}")
            return "Unknown"

    @staticmethod
    def identify_application_id(key, log_type):
        """
        Identify and return specific parts of a Cloud WAAP log key based on the log type.

        Args:
            key (str): The S3 key or file name of the log.
            log_type (str): The type of log, e.g., "Bot" or other specified types.

        Returns:
            str: The identified part of the log key (e.g., application ID if log_type is "Bot", or 'Unknown').
        """
        try:
            # Default value in case of failure to identify
            result = "Unknown"

            # Split the key into parts
            parts = key.split("/")

            if parts and log_type == "Bot":
                result = parts[-3]
            else:
                # For other types of logs, implement the logic as needed
                pass

            return result
        except Exception as e:
            logger.error(f"Error processing key '{key}' with log_type '{log_type}': {e}")
            return "Unknown"

    @staticmethod
    def parse_tenant_name(key):
        """
        Extract the tenant name from the S3 key.

        Args:
            key (str): The S3 key of the log file.

        Returns:
            str: The extracted tenant name.
        """
        try:
            parts = key.split("/")
            if len(parts) >= 4:
                tenant_name = parts[-4]
                return tenant_name
            logger.error(f"Unable to extract tenant name from key: {key}")
            return ""
        except Exception as e:
            logger.error(f"Error extracting tenant name from key '{key}': {e}")
            return ""

    @staticmethod
    def parse_application_name(key):
        """
        Extract the application name from the S3 key based on a regular expression pattern.

        Args:
            key (str): The S3 key of the log file.

        Returns:
            str or None: The extracted application name, or None if not found.
        """
        try:
            tenant_name = CloudWAAPProcessor.parse_tenant_name(key)
            pattern = r"rdwr_event_{}_([^_]+)_(\d{{8}}H\d{{6}})".format(tenant_name)
            match = re.search(pattern, key)

            if match:
                application_name = match.group(1)
                return application_name
            else:
                logger.error(f"No application name found in key: {key}")
                return None
        except Exception as e:
            logger.error(f"Error parsing application name from key '{key}': {e}")
            return None



    @staticmethod
    def parse_access_request(request, protocol, host, http_method):
        """
        Parses the HTTP request line from access logs.

        Args:
            request (str): The full HTTP request line.
            protocol (str): The protocol used in the request (e.g., 'http').
            host (str): The host part of the request.
            http_method (str): The HTTP method of the request.

        Returns:
            tuple: A tuple containing the parsed method, full URL, HTTP version, and URI path.
        """

        # Known HTTP versions in lowercase for case-insensitive comparison
        known_versions = ['http/1.0', 'http/1.1','http/1.2', 'http/2', 'http/2.0' 'http/3', 'http/0.9']

        # Initialize default values
        method, http_version, uri_only, uri = "-", "-", "-", request

        # Split the request and check for a valid HTTP version
        try:
            if http_method != "-":
                parts = request.split(' ')
                if parts[-1].lower() in known_versions:
                    http_version = parts[-1]  # Valid HTTP version found
                    if len(parts) == 3:
                        method = http_method if http_method and http_method != "-" else parts[0]
                        uri = parts[1]

                    else:
                        # Combine all parts except the last into the URI
                        uri = ' '.join(parts[:-1])

                else:
                    # No valid HTTP version found, entire request is the URI
                    logger.debug(
                        f"No Valid HTTP version found, defaulting values: method={method}, full_url={request}, http_version={http_version}")
                    return http_method, request, http_version, uri_only

            else:
                # No valid HTTP method found, entire request is the URI
                logger.debug(
                    f"No valid HTTP method found, defaulting values: method={method}, full_url={request}, http_version={http_version}")
                return http_method, request, http_version, uri_only

            # Parse the URI using urllib.parse
            parsed_uri = urlparse(uri)
            uri_only = parsed_uri.path  # The path component of the URI

            # Reconstruct the full URL
            full_url = f"{protocol}://{host}{uri}"

        except Exception as e:
            logger.error(f"Error parsing URL: {e}")


        return method, full_url, http_version, uri_only


    @staticmethod
    def parse_waf_request(request, protocol, host):
        """
        Parse a WAF request to extract the method, full URL, HTTP version, and specified headers.
        Converts all headers into a single string.

        Parameters:
        - request (str): The raw request string.
        - protocol (str): The protocol used ('http' or 'https').
        - host (str): The host to which the request was made.

        Returns:
        - tuple: A tuple containing the method, full URL, HTTP version, cookie, user-agent, referrer, and all headers as a string.
                 Returns an empty string for each element if not found or if the request doesn't match the expected format.
        """
        try:
            # Split the request line from the headers
            lines = request.split('\r\n')
            request_line = lines[0]
            headers = lines[1:]

            # Extract method, URI, and HTTP version from the request line
            parts = request_line.split(' ')
            method = parts[0] if len(parts) > 0 else ""
            uri = parts[1] if len(parts) > 1 else ""
            http_version = parts[2] if len(parts) > 2 else ""
            full_url = f"{protocol}://{host}{uri}"

            # Initialize header variables
            cookie = ""
            user_agent = ""
            referrer = ""
            headers_str = ""

            # Compile all headers into a single string and extract specific headers
            for line in headers:
                if line.startswith('Cookie:'):
                    cookie = line.split('Cookie: ')[1]
                elif line.startswith('User-Agent:'):
                    user_agent = line.split('User-Agent: ')[1]
                elif line.startswith('Referer:'):
                    referrer = line.split('Referer: ')[1]

                headers_str += line + '; '

            return method, full_url, http_version, cookie, user_agent, referrer, headers_str.strip('; ')
        except Exception as e:
            logger.error(f"Error parsing WAF request: {e}")
            return "", "", "", "", "", "", ""

    @staticmethod
    def enrich_waf_log(log, method, full_url, http_version, cookie, user_agent, referrer, headers):
        """
        Enriches a WAF log entry with additional fields parsed from the request.

        Args:
            log (dict): The WAF log entry to be enriched.
            method (str): HTTP method from the request.
            full_url (str): Full URL from the request.
            http_version (str): HTTP version from the request.
            cookie (str): Extracted cookie from the request.
            user_agent (str): User agent from the request.
            referrer (str): Referrer from the request.
            headers (str): All headers from the request as a single string.

        Returns:
            dict: The enriched log entry.
        """
        try:
            # Update the log with parsed information
            log.update({
                'http_method': method,
                'request': full_url,
                'http_version': http_version,
                'cookie': cookie,
                'user_agent': user_agent,
                'referrer': referrer,
                'headers': headers
            })

            # Remove original 'method' field, if exists
            log.pop('method', None)

            return log
        except Exception as e:
            logger.error(f"Error enriching WAF log: {e}")
            return log  # Return the original log in case of an error

    @staticmethod
    def process_enrichment_container(log):
        """
        Process the 'enrichmentContainer' field in the log, if it exists.
        Extracts specific sub-fields and moves them to the top level of the log.

        Parameters:
        - log (dict): The log entry as a dictionary.

        Returns:
        - dict: The updated log entry with processed 'enrichmentContainer' data.
        """
        try:
            enrichment = log.get('enrichmentContainer')
            if enrichment:
                mappings = {
                    "geoLocation.countryCode": "country_code",
                    "applicationId": "application_id",
                    "contractId": "contract_id",
                    "tenant": "tenant_id",
                    "owaspCategory2021": "owasp_category"
                }

                for original_key, new_key in mappings.items():
                    value = enrichment.get(original_key)
                    if value is not None:
                        log[new_key] = value

                del log['enrichmentContainer']

            return log
        except Exception as e:
            logger.error(f"Error processing enrichment container: {e}")
            return log

    @staticmethod
    def transform_time(time_string, input_format='epoch_ms', output_format='epoch_ms_str'):
        """
        Transforms a time string from one format to another.

        Args:
            time_string (str): The time string to be transformed.
            input_format (str): The format of the input time string. Supported formats include
                                'epoch_ms', '%d/%b/%Y:%H:%M:%S %z', '%d-%m-%Y %H:%M:%S',
                                '%b %d %Y %H:%M:%S', 'ISO8601', and 'ISO8601_NS'.
            output_format (str): The desired format for the output time string. Supported formats include
                                 'epoch_ms_str', 'epoch_ms_int', 'MM dd yyyy HH:mm:ss', and 'ISO8601'.

        Returns:
            str or int: The transformed time in the desired output format. Returns None in case of errors.
        """
        try:
            # Initialize variables for the epoch time in milliseconds
            epoch_time_ms = 0
            # TODO if output in epoch_ms_str or epoch_ms_int is short then 13 char then add 0 so output like 1706598020 would become 1706598020000 and if it was 17065980 turn to 1706598000000
            # Handle input time based on the input format
            if input_format in ['epoch_ms', 'epoch_ms_str']:
                epoch_time_ms = int(time_string)
            elif input_format in ['%d/%b/%Y:%H:%M:%S %z', "%d-%m-%Y %H:%M:%S", '%b %d %Y %H:%M:%S', 'ISO8601',
                                  'ISO8601_NS']:
                if input_format == 'ISO8601_NS':
                    base_time, ns = time_string[:-1].split('.')
                    parsed_time = datetime.strptime(base_time, '%Y-%m-%dT%H:%M:%S')
                    epoch_time_ms = int(parsed_time.timestamp() * 1000) + int(ns[:3])
                else:
                    parsed_time = datetime.strptime(time_string, input_format)
                    epoch_time_ms = int(parsed_time.timestamp() * 1000)
            else:
                raise ValueError(f"Unsupported input format: {input_format}")

            # Transform to the output format
            if output_format == 'epoch_ms_str':
                return str(epoch_time_ms)
            elif output_format == 'epoch_ms_int':
                return epoch_time_ms
            elif output_format == 'MM dd yyyy HH:mm:ss':
                return datetime.utcfromtimestamp(epoch_time_ms / 1000.0).strftime('%m %d %Y %H:%M:%S')
            elif output_format == 'ISO8601':
                return datetime.utcfromtimestamp(epoch_time_ms / 1000.0).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
            else:
                return datetime.utcfromtimestamp(epoch_time_ms / 1000.0).strftime(output_format)
        except Exception as e:
            logger.error(f"Error transforming time: {e}")
            return None

    @staticmethod
    def extract_metadata(key, product, log_type):
        """
        Extracts metadata from the S3 key based on the product and log type.

        Parameters:
        - key (str): The S3 key of the log file.
        - product (str): The product type (e.g., 'cloud_waap').
        - log_type (str): The type of the log.

        Returns:
        - dict: A dictionary containing extracted metadata.
        """
        try:
            if not key:
                key = None
            tenant_name = application_name = None
            if product == "cloud_waap" and log_type != "Access":
                tenant_name = CloudWAAPProcessor.parse_tenant_name(key)
                application_name = CloudWAAPProcessor.parse_application_name(key)

            return {"tenant_name": tenant_name, "application_name": application_name, "key": key}
        except Exception as e:
            logger.error(f"Error extracting metadata: {e}")
            return {"tenant_name": None, "application_name": None, "key": key}

    @staticmethod
    def flatten_latest_realtime_signature(log_data):
        """
        Flatten the 'latestRealTimeSignature' section of a WebDDOS log into a single field.

        Parameters:
        - log_data (dict): The log data containing 'latestRealTimeSignature'.

        Returns:
        - str: A flattened string of the 'latestRealTimeSignature' section.
        """
        try:
            latest_realtime = log_data.get('latestRealTimeSignature', {})
            flattened_parts = []

            for entry in latest_realtime.get('Pattern', []):
                name = entry.get('Name', '')
                values = entry.get('Values', [])
                value_str = ','.join(values)
                flattened_parts.append(f"{name}: {value_str}")

            return '; '.join(flattened_parts)
        except Exception as e:
            logger.error(f"Error in flattening latestRealTimeSignature: {e}")
            return ""

    @staticmethod
    def flatten_nested_fields(nested_dict, parent_key=''):
        """
        Flatten a nested dictionary into a single-level dictionary with concatenated keys.

        Parameters:
        - nested_dict (dict): The nested dictionary to flatten.
        - parent_key (str): The base key for flattened fields (used in recursion).

        Returns:
        - dict: A flattened dictionary with keys combined using underscores.
        """
        try:
            items = []
            for key, value in nested_dict.items():
                new_key = f"{parent_key}.{key}" if parent_key else key
                if isinstance(value, dict):
                    items.extend(CloudWAAPProcessor.flatten_nested_fields(value, new_key).items())
                else:
                    items.append((new_key, value))
            return dict(items)
        except Exception as e:
            logger.error(f"Error flattening nested fields: {e}")
            return {}

    @staticmethod
    def update_log_with_flattened_fields(log_data, fields_to_flatten):
        """
        Update the log data by flattening specified fields and integrating them into the main log data.

        Parameters:
        - log_data (dict): The log data to update.
        - fields_to_flatten (list): List of fields to flatten and integrate.

        Returns:
        - dict: The updated log data with flattened fields.
        """
        try:
            for field in fields_to_flatten:
                if field in log_data:
                    flattened_field = CloudWAAPProcessor.flatten_nested_fields(log_data[field],field.rstrip('.'))
                    log_data.update(flattened_field)
                    del log_data[field]
                else:
                    logger.warning(f"Field '{field}' not found in log data")
            return log_data
        except Exception as e:
            logger.error(f"Error updating log with flattened fields: {e}")
            return log_data

    @staticmethod
    def flatten_csp_fields(log, fields_to_flatten):
        """
        Flattens specified fields in the log into semicolon-separated strings.

        Parameters:
        - log (dict): The log entry as a dictionary.
        - fields_to_flatten (list): List of field names to flatten.

        Returns:
        - dict: The log entry with flattened fields.
        """
        try:
            for field in fields_to_flatten:
                if field in log and isinstance(log[field], list):
                    log[field] = ';'.join(log[field])
            return log
        except Exception as e:
            logger.error(f"Error flattening fields: {e}")
            return log

    @staticmethod
    def map_webddos_field_names(event):
        """
        Maps specific field names in the event to new names, verifying their existence before making any changes.

        Parameters:
        - event (dict): The event data to update.

        Returns:
        - dict: The event data with updated field names.
        """
        # Define the mapping of old field names to new field names
        field_map = {
            "detection.ApplicationBehavior.attackThreshold": "detection_attack_threshold",
            "mitigation.totalRequests.received": "total_requests_received",
            "mitigation.totalRequests.dropped": "total_requests_dropped",
            "mitigation.averageValues": "average_values",
            "mitigation.maximumValues": "maximum_values",
            "rps.inbound": "rps_inbound",
            "rps.blocked": "rps_blocked",
            "rps.clean": "rps_clean",
            "rps.attackThreshold": "rps_attack_threshold"
        }

        # Iterate over the mapping and update the event if the field exists
        for old_key, new_key in field_map.items():
            if old_key in event:
                event[new_key] = event.pop(old_key)
            else:
                logger.error(f"Warning: Field '{old_key}' not found in event data")

        return event
