from .cloudwaap_log_utils import CloudWAAPProcessor
from urllib.parse import urlparse


def enrich_access_log(event, format_options, output_format):
    format_option = format_options.get('unify_fields', True)
    if format_option or output_format in ['cef', 'leef']:
        cookie = event.get('cookie', '')
        if cookie == "-":
            del event['cookie']

        referrer = event.get('referrer', '')
        if referrer == "-":
            del event['referrer']

        destination_port = event.get('destinationPort', '')
        if destination_port:
            event['destination_port'] = destination_port
            del event['destinationPort']
        output_time_format = format_options.get('time_format', "epoch_ms_str")  # Milliseconds since epoch as a string
        access_input_format = '%d/%b/%Y:%H:%M:%S %z'
        event['time'] = CloudWAAPProcessor.transform_time(
            event['time'],
            input_format=access_input_format,
            output_format=output_time_format
        )
        country_code = event.get('country_code', '')
        if country_code or country_code == "--":
            del event['country_code']
        if 'request' in event and 'protocol' in event and 'host' in event:
            method, full_url, http_version, uri = CloudWAAPProcessor.parse_access_request(
                event['request'],
                event['protocol'],
                event['host'],
                event['http_method']
            )
            event['http_method'] = method
            event['request'] = full_url
            event['http_version'] = http_version
            event['uri'] = uri
    return event

def enrich_waf_log(event, format_options, output_format, application_name):

    format_option = format_options.get('unify_fields', True)
    if format_option or output_format in ['cef', 'leef']:
        event["time"] = event.pop("receivedTimeStamp")
        event["application_name"] = event.pop("applicationName", application_name)
        source_ip = event.get('sourceIp', '')
        if source_ip:
            event['source_ip'] = source_ip
            del event['sourceIp']

        destination_ip = event.get('externalIp', '')
        if destination_ip:
            event['destination_ip'] = destination_ip
            del event['externalIp']

        destinationip = event.get('destinationIp', '')
        if destinationip:
            del event['destinationIp']

        source_port = event.get('sourcePort', '')
        if source_port:
            event['source_port'] = source_port
            del event['sourcePort']

        destination_port = event.get('destinationPort', '')
        if destination_port:
            event['destination_port'] = destination_port
            del event['destinationPort']

        uri = event.get('URI', '')
        if uri:
            event['uri'] = uri
            del event['URI']

        reason = event.get('title', '')
        if reason:
            event['reason'] = reason
            del event['title']


        waf_output_format = format_options.get('time_format', "epoch_ms_str")
        waf_input_format = 'epoch_ms'
        if 'time' in event:
            event['time'] = CloudWAAPProcessor.transform_time(
                event['time'],
                input_format=waf_input_format,
                output_format=waf_output_format
            )
        if 'enrichmentContainer' in event:
            event = CloudWAAPProcessor.process_enrichment_container(event)
        if 'request' in event and 'protocol' in event and 'host' in event:
            parsed_values = CloudWAAPProcessor.parse_waf_request(event['request'], event['protocol'], event['host'])
            enriched_log = CloudWAAPProcessor.enrich_waf_log(event, *parsed_values)
            event.update(enriched_log)
    return event

def enrich_bot_log(event, format_options, output_format):

    format_option = format_options.get('unify_fields', True)
    if format_option or output_format in ['cef', 'leef']:
        bot_output_format = format_options.get('time_format', "epoch_ms_str")
        bot_input_format = 'epoch_ms'
        if 'time' in event:
            event['time'] = CloudWAAPProcessor.transform_time(
                event['time'],
                input_format=bot_input_format,
                output_format=bot_output_format
            )
        destination_ip = event.get('destinationIP', '')
        if destination_ip:
            event['destination_ip'] = destination_ip
            del event['destinationIP']

        source_ip = event.get('ip', '')
        if source_ip:
            event['source_ip'] = source_ip
            del event['ip']

        destination_port = event.get('destinationPort', '')
        if destination_port:
            event['destination_port'] = destination_port
            del event['destinationPort']

        user_agent = event.get('ua', '')
        if user_agent:
            event['user_agent'] = user_agent
            del event['ua']

        category = event.get('bot_category', '')
        if category:
            event['category'] = category
            del event['bot_category']

        host = event.get('site', '')
        if host:
            event['host'] = host
            del event['site']

        reason = event.get('violation_reason', '')
        if reason:
            event['reason'] = reason
            del event['violation_reason']

        request = event.get('url', '')
        if request:
            event['request'] = request
            # Parse the URL and extract the path
            parsed_url = urlparse(request)
            uri = parsed_url.path
            event['uri'] = uri  # Store the path as 'uri' in the event
            del event['url']

    return event

def enrich_ddos_log(event, format_options, output_format, application_name):
    format_option = format_options.get('unify_fields', True)
    if format_option or output_format in ['cef', 'leef']:
        source_ip = event.get('sourceIP', '')
        if source_ip:
            event['source_ip'] = source_ip
            del event['sourceIP']

        destination_ip = event.get('destinationIP', '')
        if destination_ip:
            event['destination_ip'] = destination_ip
            del event['destinationIP']

        source_port = event.get('sourcePort', '')
        if source_port:
            event['source_port'] = source_port
            del event['sourcePort']

        destination_port = event.get('destinationPort', '')
        if destination_port:
            event['destination_port'] = destination_port
            del event['destinationPort']

        reason = event.get('name', '')
        if reason:
            event['reason'] = reason
            del event['name']

        event["application_name"] = event.pop("applicationName", application_name)
        output_time_format = format_options.get('time_format', "epoch_ms_str")
        ddos_input_format = "%d-%m-%Y %H:%M:%S"
        del event['country']
        if 'time' in event:
            event['time'] = CloudWAAPProcessor.transform_time(
                event['time'],
                input_format=ddos_input_format,
                output_format=output_time_format
            )
        if 'enrichmentContainer' in event:
            event = CloudWAAPProcessor.process_enrichment_container(event)
    return event

def enrich_webddos_log(event, format_options, output_format,application_name):
    format_option = format_options.get('unify_fields', True)
    if format_option or output_format in ['cef', 'leef']:
        event["time"] = event.pop("currentTimestamp", "")
        event["application_name"] = event.pop("applicationName", application_name)
        output_time_format = format_options.get('time_format', "epoch_ms_str")
        webddos_input_format_time = "ISO8601_NS"
        webddos_input_format_start = 'epoch_ms'
        webddos_input_format_end = 'epoch_ms'
        if 'time' in event:
            event['time'] = CloudWAAPProcessor.transform_time(
                event['time'],
                input_format=webddos_input_format_time,
                output_format=output_time_format
            )
        if 'startTime' in event:
            event['startTime'] = CloudWAAPProcessor.transform_time(
                event['startTime'],
                input_format=webddos_input_format_start,
                output_format=output_time_format
            )
        if 'endTime' in event:
            event['endTime'] = CloudWAAPProcessor.transform_time(
                event['endTime'],
                input_format=webddos_input_format_end,
                output_format=output_time_format
            )
        if 'enrichmentContainer' in event:
            event = CloudWAAPProcessor.process_enrichment_container(event)
        if output_format in ['cef', 'leef']:
            # Flatten latest real time signature if it exists
            if 'latestRealTimeSignature' in event:
                event['latestRealTimeSignature'] = CloudWAAPProcessor.flatten_latest_realtime_signature(event)

            # Flatten the rest of the nested fields
            fields_to_flatten = ['detection', 'mitigation', 'rps']  # Add other fields as needed
            event = CloudWAAPProcessor.update_log_with_flattened_fields(event, fields_to_flatten)

    return event

# Add more functions for other log types as needed
