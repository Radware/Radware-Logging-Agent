import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import json
import socket
import ssl
from .logging_config import get_logger

# Create a logger for this module
logger = get_logger('sender')
class Sender:

    @staticmethod
    def send_data(data, destination_config):
        output_type = destination_config['output_type']
        if output_type in ["http", "https"]:
            return Sender.send_http(data, destination_config)
        elif output_type == "tcp":
            return Sender.send_tcp(data, destination_config)
        elif output_type == "udp":
            return Sender.send_udp(data, destination_config)
        elif output_type == "tls":
            return Sender.send_tls_tcp(data, destination_config)
        else:
            logger.error(f"Unsupported output type: {output_type}")
            return False

    @staticmethod
    def send_http(data, destination_config):
        """
        Send data to the specified HTTP destination.
        Enhanced to include retry logic.

        :param data: The data to send. Could be a list of transformed events or a single event.
        :param destination_config: Configuration containing destination, output_format, and batch mode.
        """
        destination = destination_config['destination']
        port = destination_config.get('port')
        output_format = destination_config.get('output_format', 'json')
        batch_mode = destination_config.get('batch_mode', False)

        # Append port to the destination URL if not already present
        if ':' not in destination.split('//')[-1]:
            destination = f"{destination}:{port}"

        # Determine the appropriate header based on the output format
        headers = {'Content-Type': 'application/json'}
        if output_format == 'ndjson':
            headers['Content-Type'] = 'application/x-ndjson'

        # Define retry strategy for HTTP/HTTPS requests
        retries = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retries)
        session = requests.Session()
        session.mount('http://', adapter)
        session.mount('https://', adapter)

        if batch_mode:
            try:
                batch_data = '\n'.join(data) if output_format == 'ndjson' else json.dumps(data)
                response = session.post(destination, data=batch_data, headers=headers)
                response.raise_for_status()  # Raise an error for bad status
                logger.info(f"Batch data sent successfully to {destination}")
                return True
            except Exception as e:
                logger.error(f"Failed to send batch data to {destination}: {e}")
                return False
        else:
            for event in data:
                try:
                    response = session.post(destination, data=json.dumps(event), headers=headers)
                    response.raise_for_status()  # Raise an error for bad status
                except Exception as e:
                    logger.error(f"Failed to send event to {destination}: {e}")
                    return False
            logger.info(f"All events sent successfully to {destination}")
            return True

    @staticmethod
    def send_tcp(data, destination_config):
        """
        Send data to the specified TCP destination.

        :param data: The data to send. Should be a list of transformed events.
        :param destination_config: Configuration containing destination, port, and output format.
        """
        destination = destination_config['destination']
        port = destination_config['port']
        output_format = destination_config.get('output_format', 'json')
        delimiter = destination_config.get('delimiter', '\n')

        try:
            # Establish a socket connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((destination, port))
            logger.debug(f"Connected to {destination}:{port}")

            for event in data:
                # Check the format and prepare the event for sending
                if output_format.lower() in ["ndjson", "json", "cef", "leef"]:
                    event_str = event + delimiter
                else:
                    logger.error(f"Unsupported output format: {output_format}")
                    sock.close()
                    return False

                # Send the event as bytes
                sock.sendall(event_str.encode('utf-8'))
                logger.debug(f"Sent event to {destination}:{port}")

            # Close the socket connection after sending all events
            sock.close()
            logger.info(f"All events sent successfully to {destination}:{port}")
            return True

        except Exception as e:
            logger.error(f"Failed to send data to {destination}:{port}: {e}")
            return False

    @staticmethod
    def send_udp(data, destination_config):
        """
        Send data to the specified UDP destination.

        :param data: The data to send. Should be a list of transformed events.
        :param destination_config: Configuration containing destination, port, and output format.
        """
        destination = destination_config['destination']
        port = destination_config['port']
        output_format = destination_config.get('output_format', 'json')
        delimiter = destination_config.get('delimiter', '\n')

        try:
            # Create a UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            logger.debug(f"UDP socket created for {destination}:{port}")

            for event in data:
                # Check the format and prepare the event for sending
                if output_format.lower() in ["ndjson", "json", "cef", "leef"]:
                    event_str = event + delimiter
                else:
                    logger.error(f"Unsupported output format: {output_format}")
                    return False

                # Send the event as bytes
                sock.sendto(event_str.encode('utf-8'), (destination, port))
                logger.debug(f"Sent event to {destination}:{port}")

            # Close the socket
            sock.close()
            logger.info(f"All events sent successfully to {destination}:{port}")
            return True

        except Exception as e:
            logger.error(f"Failed to send data to {destination}:{port}: {e}")
            return False

    @staticmethod
    def send_tls_tcp(data, destination_config):
        """
        Send data to the specified TLS TCP destination.

        :param data: The data to send. Should be a list of transformed events.
        :param destination_config: Configuration containing destination, port, output format, and TLS configuration.
        """
        destination = destination_config['destination']
        port = destination_config['port']
        output_format = destination_config.get('output_format', 'json')
        delimiter = destination_config.get('delimiter', '\n')
        tls_config = destination_config.get('tls_config', {})

        try:
            # Establish a raw socket connection
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_sock.connect((destination, port))

            # Wrap the socket with SSL for TLS
            if tls_config.get('verify', False) and 'ca_cert' in tls_config:
                context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=tls_config['ca_cert'])
            else:
                context = ssl._create_unverified_context()

            tls_sock = context.wrap_socket(raw_sock, server_hostname=destination)
            logger.debug(f"Connected to {destination}:{port} over TLS")

            for event in data:
                # Prepare the event for sending
                if output_format.lower() in ["ndjson", "json", "cef", "leef"]:
                    event_str = event + delimiter
                else:
                    logger.error(f"Unsupported output format: {output_format}")
                    tls_sock.close()
                    return False

                # Send the event as bytes over TLS
                tls_sock.sendall(event_str.encode('utf-8'))
                logger.debug(f"Sent event to {destination}:{port} over TLS")

            # Close the TLS socket connection after sending all events
            tls_sock.close()
            logger.info(f"All events sent successfully to {destination}:{port} over TLS")
            return True

        except Exception as e:
            logger.error(f"Failed to send data to {destination}:{port} over TLS: {e}")
            return False