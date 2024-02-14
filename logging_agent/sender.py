import requests
from requests.adapters import HTTPAdapter
from requests.auth import HTTPBasicAuth
from urllib3.util.retry import Retry
import json
import socket
import ssl
from .logging_config import get_logger
from requests.exceptions import SSLError


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
        destination = destination_config['destination']
        port = destination_config.get('port')
        uri = destination_config.get('uri')
        output_format = destination_config.get('output_format', 'json')
        batch_mode = destination_config.get('batch_mode', False)
        output_type = destination_config['output_type']  # 'http' or 'https'
        authentication = destination_config.get('authentication', {})
        custom_headers = destination_config.get('custom_headers', {})
        tls_config = destination_config.get('tls_config', {})

        # Ensure destination URL starts with http:// or https://
        if not destination.startswith("http://") and not destination.startswith("https://"):
            destination = f"{output_type}://{destination}"  # Prepend with output_type
            if port:
                destination += f":{port}"
            if uri:  # Append uri if it exists
                destination += uri

        if output_format == 'json':
            headers = {'Content-Type': 'application/json'}
        headers.update(custom_headers)


        session = requests.Session()
        # Setup SSL/TLS for HTTPS if specified in destination_config
        if destination.startswith("https://"):
            if tls_config.get('verify', False):
                session.verify = tls_config.get('ca_cert')  # Path to CA cert
                logger.info("Verifying against CA Cert", session.verify)
            else:
                session.verify = False  # Disable SSL verification

            # Load client certificate and key if provided
            if 'client_cert' in tls_config and 'client_key' in tls_config:
                session.cert = (tls_config['client_cert'], tls_config['client_key'])
                logger.info("Client Cert and Key Loaded:", session.cert)

        retries = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retries)
        session.mount('https://', adapter) if destination.startswith("https://") else session.mount('http://', adapter)


        auth = None
        if authentication:
            if authentication.get('auth_type') == 'basic':
                auth = HTTPBasicAuth(authentication.get('username'), authentication.get('password'))
            elif authentication.get('auth_type') == 'bearer':
                headers['Authorization'] = f"Bearer {authentication.get('token')}"

        try:
            if batch_mode:
                response = session.post(destination, data=data, headers=headers, auth=auth)
                response.raise_for_status()
                logger.info(f"Batch data sent successfully to {destination}")
            else:
                for event in data:
                    response = session.post(destination, data=event, headers=headers, auth=auth)
                    response.raise_for_status()
                logger.info(f"All events sent successfully to {destination}")
            return True
        except SSLError as ssl_error:
            logger.error(f"SSL Error encountered: {ssl_error}")
        except Exception as e:
            logger.error(f"Failed to send data to {destination}: {e}")
            return False
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
        batch_mode = destination_config.get('batch_mode', False)


        try:
            # Establish a socket connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((destination, port))
            logger.debug(f"Connected to {destination}:{port}")

            if batch_mode:
                # Combine all events into a single string separated by the delimiter
                sock.sendall(data.encode('utf-8'))
            else:
                for event in data:
                    event_str = event + delimiter
                    sock.sendall(event_str.encode('utf-8'))

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
                if output_format.lower() in ["json", "cef", "leef"]:
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
        batch_mode = destination_config.get('batch_mode', False)


        try:
            # Establish a raw socket connection
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_sock.connect((destination, port))

            # Initialize SSL context
            if tls_config.get('verify', False):
                context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
                if 'ca_cert' in tls_config:
                    context.load_verify_locations(cafile=tls_config['ca_cert'])
            else:
                context = ssl._create_unverified_context()

            # Load client certificate and key if provided
            if 'client_cert' in tls_config and 'client_key' in tls_config and tls_config['client_cert'] and tls_config['client_key']:
                context.load_cert_chain(certfile=tls_config['client_cert'], keyfile=tls_config['client_key'])

            # Wrap the socket with SSL for TLS
            tls_sock = context.wrap_socket(raw_sock, server_hostname=destination)
            logger.debug(f"Connected to {destination}:{port} over TLS")

            if batch_mode:
                # If batch mode, send all data as one concatenated string
                batch_data = delimiter.join(data)
                tls_sock.sendall(batch_data.encode('utf-8'))
            else:
                # If not batch mode, iterate through each event and send individually
                for event in data:
                    event_str = event + delimiter
                    tls_sock.sendall(event_str.encode('utf-8'))

            # Close the TLS socket connection after sending all events
            tls_sock.close()
            logger.info(f"All events sent successfully to {destination}:{port} over TLS")
            return True

        except Exception as e:
            logger.error(f"Failed to send data to {destination}:{port} over TLS: {e}")
            return False
