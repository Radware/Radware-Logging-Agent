import re
from collections.abc import Sequence
from urllib.parse import urlparse

from logging_agent.logging_config import get_logger
from datetime import datetime

# Create a logger for this module
logger = get_logger('cloudwaap_log_utils')

DEFAULT_PREFIX = "rdwrCld"

class CloudWAAPProcessor:
    """
    CloudWAAPProcessor provides a collection of static methods designed to process
    and analyze Cloud WAAP logs. It includes functionalities for identifying log types,
    parsing various components of the logs, and extracting detailed information from log entries.
    """

    LOG_TYPE_MARKERS = {
        "Access": {
            "httpmethod",
            "responsecode",
            "httpbytesin",
            "httpbytesout",
            "httpversion",
            "requesttime",
        },
        "WAF": {
            "receivedtimestamp",
            "violationcategory",
            "violationdetails",
            "ruleid",
            "policyid",
            "request",
            "protocol",
        },
        "Bot": {
            "botcategory",
            "sessioncookie",
            "signaturepattern",
            "violationreason",
            "tid",
            "site",
            "url",
            "policyid",
        },
        "DDoS": {
            "sourceip",
            "destinationip",
            "category",
            "name",
            "id",
            "transid",
        },
        "WebDDoS": {
            "attackvector",
            "currenttimestamp",
            "starttime",
            "endtime",
            "latestrealtimesignature",
            "mitigation",
            "detection",
            "rps",
            "attackid",
        },
        "CSP": {
            "receivedtimestamp",
            "violationtype",
            "details",
            "targetmodule",
            "aggregateduseragent",
            "urls",
            "transid",
        },
    }
    MARKER_THRESHOLD = 2
    _ALL_MARKER_KEYS = {marker for markers in LOG_TYPE_MARKERS.values() for marker in markers}

    @classmethod
    def identify_log_type(cls, key, payload_sample=None):
        """
        Identify the type of Cloud WAAP log using the key or file name, optionally
        confirming with payload markers when a sample event is available.

        Args:
            key (str): The S3 key or file name of the log.
            payload_sample (dict | None): Representative payload event used to confirm the log type.

        Returns:
            str: The identified type of log ('Access', a specific log type, or 'Unknown').
        """
        try:
            key = key or ""
            guess = cls._identify_log_type_from_key(key)
            if payload_sample is None:
                return guess

            marker_scores = cls._score_payload_markers(payload_sample)
            if not marker_scores:
                return guess

            matching_types = {log_type: hits for log_type, hits in marker_scores.items() if hits >= cls.MARKER_THRESHOLD}

            if matching_types:
                if guess in matching_types:
                    if len(matching_types) > 1:
                        logger.debug(
                            f"Multiple marker matches for key '{key}'; keeping key-derived log type '{guess}'. Matches: {matching_types}"
                        )
                    return guess

                best_log_type, best_score = max(
                    matching_types.items(),
                    key=lambda item: (item[1], item[0] == guess)
                )
                if guess != "Unknown":
                    logger.debug(
                        f"Key-derived log type '{guess}' for key '{key}' not confirmed by markers; "
                        f"selected '{best_log_type}' based on payload markers ({best_score} matches)."
                    )
                else:
                    logger.debug(
                        f"Identified log type '{best_log_type}' for key '{key}' using payload markers ({best_score} matches)."
                    )
                return best_log_type

            if guess != "Unknown":
                logger.debug(
                    f"Markers did not confirm key-derived log type '{guess}' for key '{key}'. Falling back to 'Unknown'."
                )
            else:
                logger.debug(f"No marker matches found for key '{key}'. Returning 'Unknown'.")
            return "Unknown"
        except Exception as e:
            logger.error(f"Error identifying log type for key '{key}': {e}")
            return "Unknown"

    @staticmethod
    def _identify_log_type_from_key(key):
        log_type = "Unknown"
        parts = key.split("/") if isinstance(key, str) else []

        if parts:
            last_part = parts[-1]
            if isinstance(last_part, str) and last_part.startswith("rdwr_log"):
                log_type = "Access"
            elif isinstance(last_part, str) and last_part.startswith("rdwr_event") and len(parts) >= 2:
                log_type = parts[-2]

        return log_type

    @classmethod
    def extract_sample_event(cls, payload):
        """
        Traverse a payload structure to obtain a representative event dictionary.

        Args:
            payload (object): Loaded payload content (list, dict, etc.).

        Returns:
            dict | None: A dictionary representing a single event, or None if not found.
        """
        try:
            sample = cls._find_first_event(payload, depth=0)
            return sample if isinstance(sample, dict) else None
        except Exception as e:
            logger.debug(f"Failed to extract sample event from payload: {e}")
            return None

    @classmethod
    def _find_first_event(cls, payload, depth):
        if depth > 6:
            return None

        if isinstance(payload, dict):
            if cls._looks_like_event_dict(payload):
                return payload
            for value in payload.values():
                sample = cls._find_first_event(value, depth + 1)
                if sample is not None:
                    return sample
        elif isinstance(payload, list):
            for item in payload:
                sample = cls._find_first_event(item, depth + 1)
                if sample is not None:
                    return sample
        return None

    @classmethod
    def _looks_like_event_dict(cls, candidate):
        if not isinstance(candidate, dict) or not candidate:
            return False

        normalized_keys = cls._collect_normalized_keys(candidate)
        if normalized_keys & cls._ALL_MARKER_KEYS:
            return True

        return any(not isinstance(value, (dict, list)) for value in candidate.values())

    @classmethod
    def _score_payload_markers(cls, sample_event):
        if not isinstance(sample_event, dict):
            return {}

        normalized_keys = cls._collect_normalized_keys(sample_event)
        scores = {}
        for log_type, markers in cls.LOG_TYPE_MARKERS.items():
            hits = len(normalized_keys & markers)
            if hits:
                scores[log_type] = hits
        return scores

    @classmethod
    def _collect_normalized_keys(cls, payload):
        keys = set()
        for key in payload.keys():
            normalized = cls._normalize_field_name(key)
            if normalized:
                keys.add(normalized)
        return keys

    @staticmethod
    def _normalize_field_name(field_name):
        if not isinstance(field_name, str):
            return ""
        return ''.join(ch for ch in field_name if ch.isalnum()).lower()

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
        Converts all headers into a single string, excluding cookies which are handled separately.

        Parameters:
        - request (str): The raw request string.
        - protocol (str): The protocol used ('http' or 'https'), converted to lowercase.
        - host (str): The host to which the request was made.

        Returns:
        - tuple: A tuple containing the method, full URL, HTTP version, cookie, user-agent, referrer, and all headers as a string.
                 Returns an empty string for each element if not found or if the request doesn't match the expected format.
        """
        try:
            protocol = protocol.lower()  # Ensure protocol is lowercase
            lines = request.split('\r\n')
            request_line = lines[0]
            headers = lines[1:]

            parts = request_line.split(' ')
            method = parts[0] if len(parts) > 0 else ""
            uri = parts[1] if len(parts) > 1 else ""
            http_version = parts[2] if len(parts) > 2 else ""

            # Initialize header variables and placeholders for extracted headers
            cookie = ""
            user_agent = ""
            referrer = ""
            headers_dict = {}

            # Process each header line
            for line in headers:
                if ": " in line:
                    key, value = line.split(": ", 1)
                    headers_dict[key] = value
                    if key.lower() == 'cookie':
                        cookie = value
                    elif key.lower() == 'user-agent':
                        user_agent = value
                    elif key.lower() == 'referer':
                        referrer = value

            # Use host header if available
            host_header = headers_dict.get('Host', host)
            full_url = f"{protocol}://{host_header}{uri}"

            # Remove cookie from headers_dict to avoid duplication
            headers_dict.pop('Cookie', None)

            # Compile all headers except cookies into a single string
            headers_str = "\r\n".join([f"{key}: {value}" for key, value in headers_dict.items()])

            return method, full_url, http_version, cookie, user_agent, referrer, headers_str
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
                    "geoLocation.countryCode": "countryCode",
                    "applicationId": "applicationId",
                    "contractId": "contractId",
                    "tenant": "tenantId",
                    "owaspCategory2021": "owaspCategory"
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
    def _convert_to_epoch_ms(time_data, input_format):
        """Convert the provided time data to epoch milliseconds based on the input format."""
        if input_format in ['epoch_ms', 'epoch_ms_str', 'epoch_ms_int']:
            time_string = str(time_data)
            while len(time_string) < 13:
                time_string += '0'
            return int(time_string)
        if input_format == 'ISO8601':
            iso_string = str(time_data)
            if iso_string.endswith('Z'):
                iso_string = iso_string[:-1] + '+00:00'
            return int(datetime.fromisoformat(iso_string).timestamp() * 1000)
        if input_format == 'ISO8601_NS':
            time_string = str(time_data)
            base_time, ns = time_string[:-1].split('.')
            parsed_time = datetime.strptime(base_time, '%Y-%m-%dT%H:%M:%S')
            return int(parsed_time.timestamp() * 1000) + int(ns[:3])

        parsed_time = datetime.strptime(str(time_data), input_format)
        return int(parsed_time.timestamp() * 1000)

    @staticmethod
    def _format_epoch_ms(epoch_time_ms, output_format):
        """Format epoch milliseconds into the requested output representation."""
        if output_format in ['epoch_ms_str', 'epoch_ms_int']:
            output = str(epoch_time_ms)
            while len(output) < 13:
                output += '0'
            return output if output_format == 'epoch_ms_str' else int(output)
        if output_format == 'MM dd yyyy HH:mm:ss':
            return datetime.utcfromtimestamp(epoch_time_ms / 1000.0).strftime('%m %d %Y %H:%M:%S')
        if output_format == 'ISO8601':
            return datetime.utcfromtimestamp(epoch_time_ms / 1000.0).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
        return datetime.utcfromtimestamp(epoch_time_ms / 1000.0).strftime(output_format)

    @staticmethod
    def transform_time(time_data, input_format='epoch_ms', output_format='epoch_ms_str'):
        """
        Transforms a time string from one format to another.

        Args:
            time_data (str or int): The time data to be transformed.
            input_format (str): The format of the input time string. Supported formats include
                                'epoch_ms', '%d/%b/%Y:%H:%M:%S %z', '%d/%b/%Y:%H:%M:%S.%f %z',
                                '%d-%m-%Y %H:%M:%S', '%b %d %Y %H:%M:%S', 'ISO8601', and 'ISO8601_NS'.
            output_format (str): The desired format for the output time string. Supported formats include
                                 'epoch_ms_str', 'epoch_ms_int', 'MM dd yyyy HH:mm:ss', and 'ISO8601'.

        Returns:
            str or int: The transformed time in the desired output format. Returns None in case of errors.
        """
        original_value = str(time_data)
        formats_to_try = []
        if isinstance(input_format, Sequence) and not isinstance(input_format, (str, bytes)):
            formats_to_try.extend(list(input_format))
        else:
            formats_to_try.append(input_format)

        last_exception = None
        for fmt in formats_to_try:
            try:
                epoch_time_ms = CloudWAAPProcessor._convert_to_epoch_ms(time_data, fmt)
                return CloudWAAPProcessor._format_epoch_ms(epoch_time_ms, output_format)
            except Exception as e:
                last_exception = e
                logger.debug(f"Failed to transform time '{time_data}' using input format '{fmt}': {e}")
                continue

        if last_exception:
            logger.error(f"Error transforming time '{time_data}' with formats {formats_to_try}: {last_exception}")
        return original_value

    @staticmethod
    def get_candidate_time_formats(default_formats, format_options, product, log_type):
        """Combine default time formats with additional operator-configured formats."""
        if isinstance(default_formats, Sequence) and not isinstance(default_formats, (str, bytes)):
            combined = list(default_formats)
        else:
            combined = [default_formats]

        additional_formats = []
        if isinstance(format_options, dict):
            product_formats = format_options.get('input_time_formats', {}).get(product, {})
            candidate_formats = product_formats.get(log_type)
            if candidate_formats is None and isinstance(log_type, str):
                for key, value in product_formats.items():
                    if isinstance(key, str) and key.lower() == log_type.lower():
                        candidate_formats = value
                        break
            if candidate_formats is None:
                candidate_formats = []
            if isinstance(candidate_formats, str):
                additional_formats = [candidate_formats]
            elif isinstance(candidate_formats, Sequence) and not isinstance(candidate_formats, (str, bytes)):
                additional_formats = list(candidate_formats)
            elif candidate_formats:
                logger.error(
                    f"Invalid additional time formats type for product '{product}', log type '{log_type}': {type(candidate_formats)}"
                )

        for fmt in additional_formats:
            if fmt not in combined:
                combined.append(fmt)

        return combined
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
            tenant_name = application_name = product_name = None
            if product == "cloud_waap" and log_type != "Access":
                tenant_name = CloudWAAPProcessor.parse_tenant_name(key)
                application_name = CloudWAAPProcessor.parse_application_name(key)
                product_name = "Cloud WAAP"

            return {"tenant_name": tenant_name, "application_name": application_name, "key": key,  "product": product_name}
        except Exception as e:
            logger.error(f"Error extracting metadata: {e}")
            return {"tenant_name": None, "application_name": None, "key": key, "product": product_name}

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
            "detection.applicationBehavior.attackThreshold": "detection_attack_threshold",
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
    @staticmethod
    def _to_camel_case(key):
        if not key:
            return key
        if not isinstance(key, str):
            return key

        if not re.search(r"[-_\s]", key):
            return key

        parts = [part for part in re.split(r"[^0-9A-Za-z]+", key) if part]
        if not parts:
            return key

        first, *rest = parts
        camel_key = first.lower() + ''.join(word.capitalize() for word in rest)
        return camel_key

    @staticmethod
    def _to_prefixed_title_case(key, prefix):
        if not key:
            return key
        if not isinstance(key, str):
            return key

        prefix = prefix or ""

        if prefix and key.startswith(prefix):
            remainder = key[len(prefix):]
            if remainder and remainder[0].isupper():
                return key

        parts = [part for part in re.split(r"[^0-9A-Za-z]+", key) if part]
        if not parts:
            return prefix + key if prefix else key

        title_key = ''.join(part.capitalize() for part in parts)
        if not title_key and prefix:
            return prefix
        if not title_key:
            return key

        return f"{prefix}{title_key}" if prefix else title_key

    @staticmethod
    def _normalize_structure(value, style, prefix):
        if isinstance(value, dict):
            normalized = {}
            for key, sub_value in value.items():
                normalized_key = CloudWAAPProcessor._normalize_key(key, style, prefix)
                normalized[normalized_key] = CloudWAAPProcessor._normalize_structure(sub_value, style, prefix)
            return normalized
        if isinstance(value, list):
            return [CloudWAAPProcessor._normalize_structure(item, style, prefix) for item in value]
        if isinstance(value, tuple):
            return tuple(CloudWAAPProcessor._normalize_structure(item, style, prefix) for item in value)
        return value

    @staticmethod
    def _normalize_key(key, style, prefix):
        if not isinstance(key, str):
            return key

        key = key.strip()
        if not key:
            return key

        if style == 'camel':
            return CloudWAAPProcessor._to_camel_case(key)
        if style == 'prefixed_title':
            return CloudWAAPProcessor._to_prefixed_title_case(key, prefix)
        return key

    @staticmethod
    def _resolve_prefix(field_mappings, product, log_type, output_format):
        try:
            product_mappings = field_mappings.get(product, {}) if isinstance(field_mappings, dict) else {}
            prefix = product_mappings.get(log_type, {}).get(output_format, {}).get('prefix', '')
            if prefix:
                return prefix
            for mapping in product_mappings.values():
                candidate = mapping.get(output_format, {}).get('prefix')
                if candidate:
                    return candidate
        except Exception as exc:
            logger.debug(f"Unable to resolve prefix for {product}/{log_type}: {exc}")
        return DEFAULT_PREFIX

    @staticmethod
    def normalize_event_fields(event, output_format, field_mappings, log_type, product, compatibility_mode=None):
        try:
            if not isinstance(event, dict):
                return event

            style = 'camel'
            prefix = ''
            if output_format in {'cef', 'leef'}:
                style = 'prefixed_title'
                prefix = CloudWAAPProcessor._resolve_prefix(field_mappings, product, log_type, output_format)

            normalized_event = CloudWAAPProcessor._normalize_structure(event, style, prefix)

            normalized_event.setdefault('logType', log_type or 'Unknown')
            if product == 'cloud_waap' and output_format == 'json':
                normalized_event.setdefault('product', 'Cloud WAAP')

            return normalized_event
        except Exception as exc:
            logger.error(f"Error normalizing event fields for {product}/{log_type}: {exc}")
            return event
