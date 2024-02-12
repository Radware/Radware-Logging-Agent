from .cloudwaap_log_utils import CloudWAAPProcessor
from urllib.parse import urlparse
from logging_agent.logging_config import get_logger

logger = get_logger('cloud_waap_enrich')


def enrich_access_log(event, format_options, output_format, metadata, log_type):
    """
    Enriches access log entries for output in JSON, CEF, or LEEF formats.

    Args:
        event (dict): The access log event to be enriched.
        format_options (dict): Options to control the enrichment format and fields.
        output_format (str): The desired output format ('json', 'cef', 'leef').
        metadata (dict): Additional metadata for log enrichment.
        log_type (str): The type of log being processed.

    Returns:
        dict: The enriched access log event.
    """
    try:
        format_option = format_options.get('unify_fields', True)
        if output_format == ['json']:
            event['log_type'] = log_type
            event['product'] = metadata.get('product', "Cloud WAAP")

        if format_option or output_format in ['cef', 'leef']:
            if event.get('cookie') == "-":
                event.pop('cookie', None)

            if event.get('referrer') == "-":
                event.pop('referrer', None)

            if 'destinationPort' in event:
                event['destination_port'] = event.pop('destinationPort')

            output_time_format = format_options.get('time_format', "epoch_ms_str")
            access_input_format = '%d/%b/%Y:%H:%M:%S %z'
            if 'time' in event:
                event['time'] = CloudWAAPProcessor.transform_time(
                    event['time'],
                    input_format=access_input_format,
                    output_format=output_time_format
                )

            if event.get('country_code') in {"", "--"}:
                event.pop('country_code', None)

            if all(key in event for key in ['request', 'protocol', 'host', 'http_method']):
                method, full_url, http_version, uri = CloudWAAPProcessor.parse_access_request(
                    event['request'],
                    event['protocol'],
                    event['host'],
                    event['http_method']
                )
                event.update({'http_method': method, 'request': full_url, 'http_version': http_version, 'uri': uri})

        return event

    except Exception as e:
        logger.error(f"Error in enriching access log: {e}")
        return {}




def enrich_waf_log(event, format_options, output_format, metadata, log_type):
    """
    Enriches WAF log entries for output in JSON, CEF, or LEEF formats.

    Args:
        event (dict): The WAF log event to be enriched.
        format_options (dict): Options to control the enrichment format and fields.
        output_format (str): The desired output format ('json', 'cef', 'leef').
        metadata (dict): Additional metadata for log enrichment.
        log_type (str): The type of log being processed.

    Returns:
        dict: The enriched WAF log event.
    """
    try:
        tenant_name = metadata.get('tenant_name', '')
        if tenant_name:
            event['tenant_name'] = tenant_name
        format_option = format_options.get('unify_fields', True)
        if output_format == "json":
            event['log_type'] = log_type
            event['product'] = metadata.get('product', "Cloud WAAP")

        if format_option or output_format in ['cef', 'leef']:
            application_name = metadata.get('application_name', '')
            event["time"] = event.pop("receivedTimeStamp", "")
            event["application_name"] = event.pop("applicationName", application_name)

            # Homogenize IP and port fields
            if 'sourceIp' in event:
                event['source_ip'] = event.pop('sourceIp')
            if 'externalIp' in event:
                event['destination_ip'] = event.pop('externalIp')
            if 'sourcePort' in event:
                event['source_port'] = event.pop('sourcePort')
            if 'destinationPort' in event:
                event['destination_port'] = event.pop('destinationPort')
            if 'destinationIp' in event:
                del event['destinationIp']

            # Homogenize other fields
            for key, new_key in {'RuleID': 'ruleId', 'URI': 'uri', 'title': 'name', 'violationCategory': 'category',
                                 'violationDetails': 'reason', 'transId': 'trans_id'}.items():
                if key in event:
                    event[new_key] = event.pop(key)

            # Time transformation
            waf_output_format = format_options.get('time_format', "epoch_ms_str")
            waf_input_format = 'epoch_ms'
            if 'time' in event:
                event['time'] = CloudWAAPProcessor.transform_time(
                    event['time'],
                    input_format=waf_input_format,
                    output_format=waf_output_format
                )

            # Process enrichment container
            if 'enrichmentContainer' in event:
                event = CloudWAAPProcessor.process_enrichment_container(event)

            # Parse and update request-related fields
            if all(key in event for key in ['request', 'protocol', 'host']):
                parsed_values = CloudWAAPProcessor.parse_waf_request(event['request'], event['protocol'], event['host'])
                enriched_log = CloudWAAPProcessor.enrich_waf_log(event, *parsed_values)
                event.update(enriched_log)

        return event

    except Exception as e:
        logger.error(f"Error in enriching WAF log: {e}")
        return {}


def enrich_bot_log(event, format_options, output_format, metadata, log_type):
    """
    Enriches Bot log entries for output in JSON, CEF, or LEEF formats.

    Args:
        event (dict): The Bot log event to be enriched.
        format_options (dict): Options to control the enrichment format and fields.
        output_format (str): The desired output format ('json', 'cef', 'leef').
        metadata (dict): Additional metadata for log enrichment.
        log_type (str): The type of log being processed.

    Returns:
        dict: The enriched Bot log event.
    """
    try:
        key = metadata.get('key', '')
        application_id = CloudWAAPProcessor.identify_application_id(key, "Bot")
        event['application_id'] = application_id
        tenant_name = metadata.get('tenant_name', '')
        if tenant_name:
            event['tenant_name'] = tenant_name
        format_option = format_options.get('unify_fields', True)
        if output_format == 'json':
            event['log_type'] = log_type
            event['product'] = metadata.get('product', "Cloud WAAP")

        if format_option or output_format in ['cef', 'leef']:
            # Time transformation
            bot_output_format = format_options.get('time_format', "epoch_ms_str")
            bot_input_format = 'epoch_ms'
            if 'time' in event:
                event['time'] = CloudWAAPProcessor.transform_time(
                    event['time'],
                    input_format=bot_input_format,
                    output_format=bot_output_format
                )

            # Homogenize IP and port fields
            for key, new_key in {'destinationIP': 'destination_ip', 'ip': 'source_ip',
                                 'destinationPort': 'destination_port', 'ua': 'user_agent'}.items():
                if key in event:
                    event[new_key] = event.pop(key)

            # Combine 'violation_reason' and 'bot_category' into 'reason'
            if 'violation_reason' in event and 'bot_category' in event:
                event['reason'] = f"{event['violation_reason']}, {event['bot_category']}"

            if 'violation_reason' in event:
                event['name'] = event.pop('violation_reason')
            if 'bot_category' in event:
                event['category'] = event.pop('bot_category')

            # Rename 'site' to 'host' and 'tid' to 'trans_id'
            if 'site' in event:
                event['host'] = event.pop('site')
            if 'tid' in event:
                event['trans_id'] = event.pop('tid')

            # Parse and update URL-related fields
            if 'url' in event:
                parsed_url = urlparse(event['url'])
                event['request'] = event.pop('url')
                event['uri'] = parsed_url.path  # Store the path as 'uri' in the event

        return event

    except Exception as e:
        logger.error(f"Error in enriching Bot log: {e}")

def enrich_ddos_log(event, format_options, output_format, metadata, log_type):
    """
    Enriches DDoS log entries for output in JSON, CEF, or LEEF formats.

    Args:
        event (dict): The DDoS log event to be enriched.
        format_options (dict): Options to control the enrichment format and fields.
        output_format (str): The desired output format ('json', 'cef', 'leef').
        metadata (dict): Additional metadata for log enrichment.
        log_type (str): The type of log being processed.

    Returns:
        dict: The enriched DDoS log event.
    """
    try:
        tenant_name = metadata.get('tenant_name', '')
        if tenant_name:
            event['tenant_name'] = tenant_name
        format_option = format_options.get('unify_fields', True)
        if output_format == 'json':
            event['log_type'] = log_type
            event['product'] = metadata.get('product', "Cloud WAAP")

        if format_option or output_format in ['cef', 'leef']:
            # Homogenize IP and port fields
            for key, new_key in {'sourceIP': 'source_ip', 'destinationIP': 'destination_ip',
                                 'sourcePort': 'source_port', 'destinationPort': 'destination_port'}.items():
                if key in event:
                    event[new_key] = event.pop(key)

            # Combine 'category' and 'name' into 'reason'
            if 'category' in event and 'name' in event:
                event['reason'] = f"{event['category']}, {event['name']}"

            # Rename 'ID' to 'trans_id'
            if 'ID' in event:
                event['trans_id'] = event.pop('ID')

            # Update 'applicationName' from metadata if available
            event["application_name"] = event.pop("applicationName", metadata.get('application_name', ''))

            # Transform time field based on format options
            output_time_format = format_options.get('time_format', "epoch_ms_str")
            ddos_input_format = "%d-%m-%Y %H:%M:%S"
            if 'time' in event:
                event['time'] = CloudWAAPProcessor.transform_time(
                    event['time'],
                    input_format=ddos_input_format,
                    output_format=output_time_format
                )

            # Process 'enrichmentContainer' if present
            if 'enrichmentContainer' in event:
                event = CloudWAAPProcessor.process_enrichment_container(event)

            # Remove unwanted fields
            event.pop('country', None)

        return event

    except Exception as e:
        logger.error(f"Error in enriching DDoS log: {e}")
        return {}



def enrich_webddos_log(event, format_options, output_format, metadata, log_type):
    """
    Enriches WebDDoS log entries for output in JSON, CEF, or LEEF formats.

    Args:
        event (dict): The WebDDoS log event to be enriched.
        format_options (dict): Options to control the enrichment format and fields.
        output_format (str): The desired output format ('json', 'cef', 'leef').
        metadata (dict): Additional metadata for log enrichment.
        log_type (str): The type of log being processed.

    Returns:
        dict: The enriched WebDDoS log event.
    """
    try:
        tenant_name = metadata.get('tenant_name', '')
        if tenant_name:
            event['tenant_name'] = tenant_name
        format_option = format_options.get('unify_fields', True)
        if output_format == 'json':
            event['log_type'] = log_type
            event['product'] = metadata.get('product', "Cloud WAAP")

        if format_option or output_format in ['cef', 'leef']:
            # Update application name from metadata if available
            event["application_name"] = event.pop("applicationName", metadata.get('application_name', ''))

            # Transform various time fields based on format options
            time_fields = {'startTime': 'startTime', 'endTime': 'endTime'}
            for original_field, new_field in time_fields.items():
                if original_field in event:
                    input_format = 'epoch_ms'
                    event[new_field] = CloudWAAPProcessor.transform_time(
                        event[original_field],
                        input_format=input_format,
                        output_format=format_options.get('time_format', "epoch_ms_str")
                    )

            # Transform and remove 'currentTimestamp' after processing
            if 'currentTimestamp' in event:
                event['time'] = CloudWAAPProcessor.transform_time(
                    event['currentTimestamp'],
                    input_format='ISO8601_NS',
                    output_format=format_options.get('time_format', "epoch_ms_str")
                )
                del event['currentTimestamp']  # Explicitly remove 'currentTimestamp' after it's processed

            # Rename 'attackID' to 'trans_id'
            if 'attackID' in event:
                event['trans_id'] = event.pop('attackID')

            # Combine 'attackVector' into 'reason', 'name', and 'category'
            if 'attackVector' in event:
                attack_vector = event.pop('attackVector')
                parsed_attack_vector = attack_vector.replace("_", " ") if "_" in attack_vector else attack_vector
                event.update({'reason': f"WebDDoS module has detected a {parsed_attack_vector}",
                              'name': attack_vector, 'category': f"WebDDoS {parsed_attack_vector}"})
            else:
                event['name'] = "WebDDoS Attack Detected"

            # Process 'enrichmentContainer' if present
            if 'enrichmentContainer' in event:
                event = CloudWAAPProcessor.process_enrichment_container(event)

            if output_format in ['cef', 'leef']:
                # Flatten latest real time signature if it exists
                if 'latestRealTimeSignature' in event:
                    event['latestRealTimeSignature'] = CloudWAAPProcessor.flatten_latest_realtime_signature(event)

                # Flatten the rest of the nested fields
                fields_to_flatten = ['detection', 'mitigation', 'rps']  # Add other fields as needed
                event = CloudWAAPProcessor.update_log_with_flattened_fields(event, fields_to_flatten)
                event = CloudWAAPProcessor.map_webddos_field_names(event)

        return event

    except Exception as e:
        logger.error(f"Error in enriching WebDDoS log: {e}")
        return {}



def enrich_csp_log(event, format_options, output_format, metadata, log_type):
    """
    Enriches Client-Side Protection (CSP) log entries for output in JSON, CEF, or LEEF formats.

    Args:
        event (dict): The CSP log event to be enriched.
        format_options (dict): Options to control the enrichment format and fields.
        output_format (str): The desired output format ('json', 'cef', 'leef').
        metadata (dict): Additional metadata for log enrichment.
        log_type (str): The type of log being processed.

    Returns:
        dict: The enriched CSP log event.
    """
    try:
        tenant_name = metadata.get('tenant_name', '')
        if tenant_name:
            event['tenant_name'] = tenant_name
        format_option = format_options.get('unify_fields', True)
        if output_format == 'json':
            event['log_type'] = log_type
            event['product'] = metadata.get('product', "Cloud WAAP")

        if format_option or output_format in ['cef', 'leef']:
            application_name = metadata.get('application_name', '')
            event["time"] = event.pop("receivedTimeStamp", "")

            event["application_name"] = event.pop("applicationName", application_name)

            if "applicationId" in event:
                del event['applicationId']

            if 'violationType' in event:
                event['name'] = event.pop('violationType')

            if 'details' in event:
                event['reason'] = event.pop('details')

            if 'transId' in event:
                event['trans_id'] = event.pop('transId')

            if 'externalIp' in event:
                del event['externalIp']

            output_time_format = format_options.get('time_format', "epoch_ms_str")
            if 'time' in event:
                if event['time']:
                    event['time'] = CloudWAAPProcessor.transform_time(
                        event['time'],
                        input_format="epoch_ms_str",
                        output_format=output_time_format
                    )
                else:
                    del event['time']

            if 'enrichmentContainer' in event:
                event = CloudWAAPProcessor.process_enrichment_container(event)

            if output_format in ['cef', 'leef']:
                fields_to_flatten = ['aggregatedUserAgent', 'urls']
                event = CloudWAAPProcessor.flatten_csp_fields(event, fields_to_flatten)

        return event

    except Exception as e:
        logger.error(f"Error in enriching CSP log: {e}")
        return event  # Return the original event in case of an error

