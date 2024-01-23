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
        Identify the type of log based on the key naming convention.

        Parameters:
        - key (str): The S3 key or file name of the log.

        Returns:
        - str: The identified type of the log ("Access" or a specific key part).
        """
        logger.debug(f"Identifying log type for key: {key}")
        if key.split("/")[-1].startswith("rdwr_log"):
            log_type = "Access"
        elif key.split("/")[-1].startswith("rdwr_event"):
            log_type = key.split("/")[-2]
        else:
            log_type = "Unknown"
        logger.info(f"Identified log type: {log_type}")
        return log_type

    @staticmethod
    def parse_tenant_name(key):
        """
        Extract the tenant name from the S3 key.

        Parameters:
        - key (str): The S3 key of the log file.

        Returns:
        - str: The extracted tenant name.
        """
        logger.debug(f"Extracting tenant name from key: {key}")
        tenant_name = key.split("/")[-4]
        logger.debug(f"Extracted tenant name: {tenant_name}")
        return tenant_name

    @staticmethod
    def parse_application_name(key):
        """
        Parse the application name from the S3 key using a regular expression.

        Parameters:
        - key (str): The S3 key of the log file.

        Returns:
        - str or None: The application name if found, otherwise None.
        """
        try:
            logger.debug(f"Parsing application name from key: {key}")
            tenant_name = CloudWAAPProcessor.parse_tenant_name(key)
            pattern = r"rdwr_event_{}_([^_]+)_(\d{{8}}H\d{{6}})".format(tenant_name)
            match = re.search(pattern, key)
            if match:
                application_name = match.group(1)
                logger.debug(f"Extracted application name: {application_name}")
                return application_name
            logger.warning(f"No application name found in key: {key}")
            return None
        except Exception as e:
            logger.error(f"Error parsing application name from key: {key}: {e}")
            raise


    @staticmethod
    def parse_access_request(request, protocol, host, http_method):
        logger.debug("Parsing access request")

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
            logger.debug(
                f"Parsed access request: method={method}, full_url={full_url}, http_version={http_version}")

        except Exception as e:
            logger.error(f"Error parsing URL: {e}")


        return method, full_url, http_version, uri_only

    # @staticmethod
    # def parse_access_request(request, protocol, host, http_method):
    #     """
    #     Parse an HTTP access request to extract the method, full URL, and HTTP version.
    #
    #     Parameters:
    #     - request (str): The raw request string.
    #     - protocol (str): The protocol used ('http' or 'https').
    #     - host (str): The host to which the request was made.
    #
    #     Returns:
    #     - tuple: A tuple containing the method, full URL, and HTTP version.
    #              Returns the original request and empty strings if the format doesn't match.
    #     """
    #     logger.debug("Parsing access request")
    #     parts = request.split(' ')
    #     if len(parts) != 3:
    #         logger.warning(f"Access request format does not match expected format: {request}")
    #
    #         return request, "", ""  # Return the original request if it doesn't match the expected format
    #
    #     method, uri, http_version = parts
    #     full_url = "{}://{}{}".format(protocol, host, uri)
    #     logger.debug(f"Parsed access request: method={method}, full_url={full_url}, http_version={http_version}")
    #     return method, full_url, http_version, uri

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
        Enrich the WAF log with parsed values and remove the original request field.

        Parameters:
        - log (dict): The original log entry.
        - method (str): The HTTP method extracted from the request.
        - full_url (str): The full URL extracted from the request.
        - http_version (str): The HTTP version extracted from the request.
        - cookie (str): The cookies extracted from the request.
        - user_agent (str): The user-agent extracted from the request.
        - referrer (str): The referer extracted from the request.
        - headers (str): All headers compiled into a single string.

        Returns:
        - dict: The enriched log entry.
        """
        # Enrich the log with new fields
        log['http_method'] = method
        log['request'] = full_url
        log['http_version'] = http_version  # Adding HTTP version to the log
        log['cookie'] = cookie
        log['user_agent'] = user_agent
        log['referrer'] = referrer
        log['headers'] = headers
        del log['method']


        return log

    @staticmethod
    def process_enrichment_container(log):
        """
        Process the 'enrichmentContainer' field in the log, if it exists.
        It extracts certain sub-fields and promotes them to the top level of the log.

        Parameters:
        - log (dict): The log entry as a dictionary.

        Returns:
        - dict: The updated log entry with processed 'enrichmentContainer' data.
        """
        # Check if 'enrichmentContainer' exists in the log
        enrichment = log.get('enrichmentContainer')
        if enrichment:
            # Map the sub-fields from enrichmentContainer to the top level
            mappings = {
                "geoLocation.countryCode": "country_code",
                "applicationId": "application_id",
                "contractId": "contract_id",
                "tenant": "tenant_id"
            }

            for original_key, new_key in mappings.items():
                # Copy the value to the new key at the root level
                value = enrichment.get(original_key)
                if value is not None:
                    log[new_key] = value

            # Remove the original 'enrichmentContainer' field
            del log['enrichmentContainer']

        return log

    @staticmethod
    def transform_time(time_string, input_format='epoch_ms', output_format='epoch_ms_str'):
        try:
            # Handle input time based on the input format
            if input_format == 'epoch_ms':
                epoch_time = int(time_string)
                length = len(str(time_string))

                if length == 13:  # Milliseconds format
                    epoch_time_ms = epoch_time
                elif length == 10:  # Seconds format
                    epoch_time_ms = epoch_time * 1000
                elif length < 10:  # Seconds with less precision
                    epoch_time_ms = epoch_time * (10 ** (13 - length))
                else:
                    raise ValueError(f"Invalid length for epoch time: {time_string}")

            elif input_format in ['%d/%b/%Y:%H:%M:%S %z', "%d-%m-%Y %H:%M:%S", '%b %d %Y %H:%M:%S', 'ISO8601',
                                  'ISO8601_NS']:
                # Handle common date string formats including custom 'MM dd yyyy HH:mm:ss' and ISO 8601
                if input_format == 'ISO8601':
                    parsed_time = datetime.strptime(time_string[:-1], '%Y-%m-%dT%H:%M:%S.%f')
                    epoch_time_ms = int(parsed_time.timestamp() * 1000)
                elif input_format == 'ISO8601_NS':
                    base_time, ns = time_string[:-1].split('.')
                    parsed_time = datetime.strptime(base_time, '%Y-%m-%dT%H:%M:%S')
                    epoch_time_ms = int(
                        parsed_time.timestamp() * 1000 + int(ns[:3]))  # Convert nanoseconds to milliseconds
                else:
                    parsed_time = datetime.strptime(time_string, input_format)
                    epoch_time_ms = int(parsed_time.timestamp() * 1000)
            else:
                raise ValueError(f"Unsupported input format: {input_format}")

            # Handle output time based on the output format
            if output_format == 'epoch_ms_str':
                return str(epoch_time_ms)
            elif output_format == 'epoch_ms_int':
                return epoch_time_ms
            elif output_format == 'MM dd yyyy HH:mm:ss':
                return datetime.utcfromtimestamp(epoch_time_ms / 1000.0).strftime('%b %d %Y %H:%M:%S')
            elif output_format == 'ISO8601':
                return datetime.utcfromtimestamp(epoch_time_ms / 1000.0).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
            else:
                # Custom strftime format or any other specified format
                return datetime.utcfromtimestamp(epoch_time_ms / 1000.0).strftime(output_format)
        except Exception as e:
            # Consider logging the error
            logger.error(f"Error transforming time: {e}")
            return None

    @staticmethod
    def extract_metadata(key, product, log_type):
        """Extracts metadata from the key and product for Cloud WAAP logs."""
        tenant_name = None
        application_name = None
        if product == "cloud_waap" and log_type != "Access":
            tenant_name = CloudWAAPProcessor.parse_tenant_name(key)
            application_name = CloudWAAPProcessor.parse_application_name(key)

        return {
            "tenant_name": tenant_name,
            "application_name": application_name
        }

    @staticmethod
    def flatten_latest_realtime_signature(log_data):
        """
        Flatten the 'latestRealTimeSignature' section of a WebDDOS log into a single field.

        Args:
        log_data (dict): The log data containing 'latestRealTimeSignature'.

        Returns:
        str: A flattened string of the 'latestRealTimeSignature' section.
        """
        try:
            latest_realtime = log_data['latestRealTimeSignature']
            pattern = latest_realtime['Pattern']
            flattened_parts = []

            for entry in pattern:
                try:
                    name = entry.get('Name', '')
                    values = entry.get('Values', [])

                    # Concatenating values with comma and appending to name with colon
                    value_str = ','.join(values)
                    flattened_parts.append(f"{name}: {value_str}")
                except Exception as e:
                    logger.error(f"Error processing entry {entry}: {e}")

            # Joining all parts with semicolon
            flattened_string = '; '.join(flattened_parts)
            return flattened_string
        except KeyError as ke:
            logger.error(f"'latestRealTimeSignature' key not found in log data: {ke}")
            return "KeyError: 'latestRealTimeSignature' not found"
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            return f"Unexpected error: {e}"

    @staticmethod
    def flatten_nested_fields(nested_dict, parent_key=''):
        """
        Flatten a nested dictionary into a single-level dictionary with concatenated keys using underscores,
        including the parent key name.
        """
        items = []
        for key, value in nested_dict.items():
            new_key = f"{parent_key}_{key}" if parent_key else key
            if isinstance(value, dict):
                items.extend(CloudWAAPProcessor.flatten_nested_fields(value, new_key).items())
            else:
                items.append((new_key, value))
        return dict(items)

    @staticmethod
    def update_log_with_flattened_fields(log_data, fields_to_flatten):
        """
        Update the log data by flattening specified fields and replacing the original nested structures.
        """
        for field in fields_to_flatten:
            if field in log_data:
                # Flatten the field
                flattened_field = CloudWAAPProcessor.flatten_nested_fields(log_data[field], field)

                # Remove the original nested field
                del log_data[field]

                # Update the log data with flattened key-value pairs
                log_data.update(flattened_field)
            else:
                print(f"Warning: Field '{field}' not found in log data")
        return log_data
