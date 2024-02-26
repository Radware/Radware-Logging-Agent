import os
import boto3
from .logging_config import get_logger
from .config_reader import Config
from .app_info import supported_features
import socket
import ssl
import requests

logger = get_logger('config_verification')



def test_tcp_connection(host, port, timeout=5, compatibility=None):
    """
    Tests TCP connectivity to a given host and port.

    Args:
        host (str): The hostname or IP address of the server.
        port (int): The port number.
        timeout (int): Timeout in seconds for the connection attempt.

    Returns:
        bool: True if the connection was successful, False otherwise.
    """
    if not host or not isinstance(port, int):
        logger.error("Invalid host or port for TCP connection test.")
        return False

    try:
        with socket.create_connection((host, port), timeout=timeout):
            logger.info(f"TCP connection to {host}:{port} successful.")
            return True
    except OSError as e:
        logger.error(f"TCP connection to {host}:{port} failed: {e}")
        return False


def test_udp_connection(host, port, timeout=5, compatibility=None):
    """
    Tests UDP connectivity by attempting to send a dummy packet.

    Args:
        host (str): The hostname or IP address of the server.
        port (int): The port number.
        timeout (int): Timeout in seconds for sending the packet.

    Returns:
        bool: True if the dummy packet was sent successfully, False otherwise.
    """
    if not host or not isinstance(port, int):
        logger.error("Invalid host or port for UDP connection test.")
        return False

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(b'', (host, port))  # Sending a dummy packet
            logger.info(f"UDP dummy packet sent to {host}:{port} successfully.")
            return True
    except OSError as e:
        logger.error(f"UDP dummy packet to {host}:{port} failed: {e}")
        return False



def test_tls_connection(host, port, verify=False, ca_cert=None, client_cert=None, client_key=None, timeout=5, compatibility=None):
    """
    Tests TLS connectivity with optional client and CA certificates and verification control.

    Args:
        host (str): The hostname or IP address of the server.
        port (int): The port number.
        verify (bool): Whether to verify the server's TLS certificate against the provided CA certificate.
        ca_cert (str, optional): Path to the CA certificate to verify against if verify is True.
        client_cert (str, optional): Path to the client certificate for mutual TLS authentication.
        client_key (str, optional): Path to the client key for mutual TLS authentication.
        timeout (int): Timeout in seconds for the connection attempt.
        compatibility (str, optional): Special compatibility mode for the connectivity test.

    Returns:
        bool: True if the TLS connection was successful, False otherwise.
    """
    if not host or not isinstance(port, int):
        logger.error("Invalid host or port for TLS connection test.")
        return False

    try:
        # Create a default context with or without certificate verification
        if verify:
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca_cert)
        else:
            # Verification disabled
            context = ssl._create_unverified_context()

        # Load client certificate and key for mutual TLS authentication, if provided
        if client_cert and client_key:
            context.load_cert_chain(certfile=client_cert, keyfile=client_key)

        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host):
                # Log success and return True
                logger.info(f"TLS connection to {host}:{port} successful.")
                return True
    except OSError as e:
        # Log failure and return False
        logger.error(f"TLS connection to {host}:{port} failed: {e}")
        return False


def test_http_connection(url, headers=None, auth=None, compatibility=None):
    """
    Tests HTTP connectivity with optional headers and authentication, and special compatibility modes.

    Args:
        url (str): The full URL to test connectivity with.
        headers (dict, optional): Custom headers for the request.
        auth (tuple, optional): A tuple containing the username and password for Basic authentication.
        compatibility (str, optional): Special compatibility mode for the connectivity test.

    Returns:
        bool: True if the connectivity test is successful, False otherwise.
    """
    try:
        if compatibility == 'splunk hec':
            # For Splunk HEC compatibility, perform a POST request with an empty body
            response = requests.post(url, headers=headers, auth=auth, data='', timeout=5)
            # Valid response is a 400 with a specific error message
            return response.status_code == 400 and "No data" in response.json().get("text", "")
        else:
            # Default behavior with a GET request
            response = requests.get(url, headers=headers, auth=auth, timeout=5)
            return response.status_code == 200
    except requests.RequestException as e:
        logger.error(f"HTTP connectivity test failed: {e}")
        return False


def test_https_connection(url, headers=None, auth=None, verify=True, cert=None, compatibility=None):
    """
    Tests HTTPS connectivity with optional headers, authentication, SSL/TLS verification, and client certificates,
    and special compatibility modes.

    Args:
        url (str): The full URL to test connectivity with.
        headers (dict, optional): Custom headers for the request.
        auth (tuple, optional): A tuple containing the username and password for Basic authentication.
        verify (bool or str, optional): Either a boolean, in which case it controls whether to verify the server's TLS certificate,
                                        or a string, in which case it must be a path to a CA bundle to use. Defaults to True.
        cert (str or tuple, optional): If String, the path to an SSL client cert file (.pem).
                                       If Tuple, ('cert', 'key') pair.
        compatibility (str, optional): Special compatibility mode for the connectivity test.

    Returns:
        bool: True if the connectivity test is successful, False otherwise.
    """
    # Create a Session object to persist certain parameters across requests
    session = requests.Session()

    # Apply the optional parameters to the session
    if headers:
        session.headers.update(headers)
    if auth:
        session.auth = auth
    if verify:
        session.verify = verify  # CA bundle for server verification
    if cert:
        session.cert = cert  # Client certificate and optionally a key for client authentication

    try:
        if compatibility == 'splunk hec':
            # For Splunk HEC compatibility, perform a POST request with an empty body
            response = session.post(url, data='', timeout=5)
            # Valid response is a 400 with a specific error message
            return response.status_code == 400 and "No data" in response.json().get("text", "")
        else:
            # Default behavior with a GET request
            response = session.get(url, timeout=5)
            return response.status_code == 200
    except requests.RequestException as e:
        # Log any exception that occurs during the request
        logger.error(f"HTTPS connectivity test failed: {e}")
        return False

def verify_output_connectivity(config):
    """
    Verifies the connectivity based on the output configuration.

    Args:
        config (dict): Configuration from the user, including output and protocol details.

    Returns:
        bool: True if the connectivity test is successful, False otherwise.
    """
    # Mapping output types to their respective test functions
    protocol_test_functions = {
        'tcp': test_tcp_connection,
        'udp': test_udp_connection,
        'tls': test_tls_connection,
        'http': test_http_connection,
        'https': test_https_connection,
    }

    output = config.get('output')
    output_type = output.get('type', '').lower()
    protocol_config = config.get(output_type, {})
    compatibility = output.get('compatibility_mode', None)

    # Authentication and Headers Setup
    auth_config = protocol_config.get('authentication', {})
    auth = None
    if auth_config.get('auth_type', '').lower() == 'basic':
        auth = (auth_config.get('username', ''), auth_config.get('password', ''))
    elif auth_config.get('auth_type', '').lower() == 'bearer':
        token = auth_config.get('token', '')
        protocol_config['custom_headers'] = {'Authorization': f'Bearer {token}'}
    headers = protocol_config.get('custom_headers', {})

    # SSL/TLS Verification and Client Certificates
    verify = protocol_config.get('verify', True)
    ca_cert = protocol_config.get('ca_cert', None)
    client_cert = protocol_config.get('client_cert', None)
    client_key = protocol_config.get('client_key', None)
    cert = (client_cert, client_key) if client_cert and client_key else None

    # Full Destination URL or Address
    destination = output.get('destination')
    port = output.get('port')
    uri = output.get('uri', '')
    full_dest = None
    if output_type in ['http', 'https']:
        protocol_prefix = 'https' if output_type == 'https' else 'http'
        full_dest = f"{protocol_prefix}://{destination}:{port}{uri}"

    test_function = protocol_test_functions.get(output_type)
    if not test_function:
        logger.error(f"Unsupported output type: {output_type}")
        return False

    # Execute the test function based on output type
    try:
        if output_type == 'http':
            # HTTPS and HTTP with potential SSL/TLS verification and client certificates
            return test_function(full_dest, headers=headers, auth=auth, compatibility=compatibility)
        elif output_type == 'https':
            return test_function(full_dest, headers=headers, auth=auth,
                                 verify=verify, cert=cert, compatibility=compatibility)
        elif output_type == 'tls':
            # TLS with SSL/TLS verification and client certificates
            return test_function(destination, port, verify=verify, ca_cert=ca_cert, client_cert=client_cert, client_key=client_key, compatibility=compatibility)
        elif output_type in ['tcp', 'udp']:
            # TCP and UDP might simply require destination and port
            return test_function(destination, port, compatibility=compatibility)
    except Exception as e:
        logger.error(f"Error testing connectivity for {output_type}: {e}")
        return False

    return True
def verify_aws_credentials(config, agents_config):
    """
    Verifies AWS credentials by checking if specified SQS queues exist and are accessible.

    Args:
        config (dict): Global configuration that includes AWS credentials.
        agents_config (list): List of agent configurations.

    Returns:
        bool: True if AWS credentials are verified successfully, or if no SQS agents require verification. False otherwise.
    """
    require_verification = False
    sqs_names = []

    # Collect SQS queue names from the agents_config
    for agent in agents_config:
        if agent.get('type', '').lower() == 'sqs':
            require_verification = True
            if 'sqs_settings' in agent and 'queue_name' in agent['sqs_settings']:
                sqs_names.append(agent['sqs_settings']['queue_name'])

    if require_verification:
        try:
            # Initialize SQS client with provided AWS credentials
            sqs = boto3.client('sqs', region_name=config['aws_credentials']['region'],
                               aws_access_key_id=config['aws_credentials']['access_key_id'],
                               aws_secret_access_key=config['aws_credentials']['secret_access_key'])

            # Fetch list of queues and extract queue names from the URLs
            response = sqs.list_queues()
            existing_queues_urls = response.get('QueueUrls', [])
            existing_queue_names = [url.split('/')[-1] for url in existing_queues_urls]

            # Check if each required queue name exists in the list of existing queues
            for queue_name in sqs_names:
                if queue_name not in existing_queue_names:
                    logger.error(f"SQS queue '{queue_name}' does not exist or is not accessible.")
                    return False

            logger.info("AWS credentials verified successfully. All specified SQS queues exist and are accessible.")
            return True
        except Exception as e:
            logger.error(f"AWS credentials verification failed: {e}")
            return False
    else:
        logger.info("No SQS agents configured. Skipping AWS credentials verification.")
        return True
def verify_agent_config(agent_config):
    product = agent_config.get('product')
    if product not in supported_features['products']:
        logger.error(f"Unsupported product: {product} in agent {agent_config['name']}")
        return False

    if agent_config['type'] not in supported_features[product]['supported_input_type']:
        logger.error(f"Unsupported input type: {agent_config['type']} for product: {product} in agent {agent_config['name']}")
        return False

    # Verify log types for the agent
    supported_log_types = supported_features[product]['supported_log_types']
    for log_type, enabled in agent_config.get('logs', {}).items():
        if not isinstance(enabled, bool):
            logger.error(f"Invalid value for log type '{log_type}' in agent {agent_config['name']}. Should be a boolean.")
            return False
        if log_type not in supported_log_types:
            logger.error(f"Unsupported log type: {log_type} for product: {product} in agent {agent_config['name']}")
            return False
    # Dynamically check compatibility mode requirements
    compatibility_mode = agent_config.get('output', {}).get('compatibility_mode')
    if compatibility_mode is not None:
        # Check if the compatibility mode is supported for the product
        if compatibility_mode.lower() not in supported_features[product].get('compatibility_mode', []):
            logger.error(
                f"The product '{product}' in agent {agent_config['name']} does not support {compatibility_mode} compatibility mode.")
            return False

        # Verify the requirements for the specified compatibility mode
        requirements = supported_features[product].get('compatibility_mode_requirements', {}).get(compatibility_mode,
                                                                                                  {}).get('output', {})
        output_type = agent_config.get('output', {}).get('type')
        output_format = agent_config.get('output', {}).get('output_format')

        # Check output type and format against requirements
        if output_type not in requirements.get('type', []) or output_format not in requirements.get('output_format',
                                                                                                    []):
            logger.error(
                f"The agent {agent_config['name']} with product '{product}' does not meet  {compatibility_mode}"
                f" requirements: output type must be one of {requirements.get('type', [])}"
                f" and output format must be one of {requirements.get('output_format', [])}."
            )
            return False

    return True

def verify_output_config(output_config):
    supported_formats = ['cef', 'json', 'leef']
    if output_config['output_format'] not in supported_formats:
        logger.error(f"Unsupported output format: {output_config['output_format']}")
        return False
    return True

def verify_tls_config(tls_config):
    if tls_config.get('verify', False):
        # Check for CA certificate if verification is enabled
        if 'ca_cert' in tls_config and not os.path.exists(tls_config['ca_cert']):
            logger.error(f"CA certificate file not found: {tls_config['ca_cert']}")
            return False

    # Check for client certificate and key only if they are specified
    if 'client_cert' in tls_config and tls_config['client_cert'] != "" and not os.path.exists(tls_config['client_cert']):
        logger.error(f"Client certificate file not found: {tls_config['client_cert']}")
        return False
    if 'client_key' in tls_config and tls_config['client_key'] != "" and not os.path.exists(tls_config['client_key']):
        logger.error(f"Client key file not found: {tls_config['client_key']}")
        return False

    return True


def verify_general_config(general_config):
    for key in ['output_directory', 'log_directory']:
        if not os.path.exists(general_config[key]):
            logger.error(f"Path does not exist: {general_config[key]}")
            return False
    valid_log_levels = ["INFO", "WARNING", "DEBUG", "ERROR"]
    if general_config['logging_levels'] not in valid_log_levels:
        logger.error(f"Invalid logging level: {general_config['logging_levels']}")
        return False
    return True

def verify_selected_output_config(output_config, formats_config):
    """
    Verify the selected output configuration for CEF or LEEF formats.

    Args:
        output_config (dict): Output configuration from the user.
        formats_config (dict): Format-specific configurations.

    Returns:
        bool: True if the selected output configuration is valid, False otherwise.
    """
    output_format = output_config.get('output_format')
    format_options = formats_config.get(output_format, {})
    allowed_time_formats = ['epoch_ms_str', 'epoch_ms_int', 'MM dd yyyy HH:mm:ss', 'ISO8601', '']
    allowed_severity_formats = [1, 2, 3]

    # Verify unify_fields for CEF and LEEF
    if output_format in ['cef', 'leef']:
        if not format_options.get('unify_fields', True):
            logger.error(f"'unify_fields' must be True for {output_format} format.")
            return False

    # Verify time_format
    time_format = format_options.get('time_format', '')
    if time_format not in allowed_time_formats:
        logger.error(f"Invalid 'time_format' for {output_format} format: {time_format}. Allowed options are {allowed_time_formats}.")
        return False

    # Verify severity_format for CEF and LEEF
    if output_format in ['cef', 'leef']:
        severity_format = format_options.get('severity_format')
        if severity_format not in allowed_severity_formats:
            logger.error(f"Invalid 'severity_format' for {output_format} format: {severity_format}. Allowed options are {allowed_severity_formats}.")
            return False

    return True




def verify_configuration(config, agents_config):
    logger.info("Starting configuration verification...")
    # Verify general configuration
    if not verify_general_config(config['general']):
        return False

    # Verify AWS credentials
    if not verify_aws_credentials(config, agents_config):
        return False

    # Verify each agent configuration
    if agents_config:
        for agent in agents_config:
            if not verify_agent_config(agent):
                return False

    # Verify output configuration
    if not verify_output_config(config['output']):
        return False

    # Verify TLS configuration
    if 'tls' in config and not verify_tls_config(config['tls']):
        return False


    if not verify_selected_output_config(config['output'], config['formats']):
        return False

    verify_mode = config['debug'].get('verify_destination_connectivity', True)
    # Verify connectivity based on the output configuration
    if verify_mode:
        if not verify_output_connectivity(config):
            logger.error("Output connectivity test failed.")
            return False

    logger.info("Configuration verification completed successfully.")
    return True

# Example usage
if __name__ == "__main__":
    # Assume 'config' is the loaded configuration dictionary
    config = Config().config
    if verify_configuration(config):
        logger.info("All configuration checks passed.")
    else:
        logger.error("Configuration checks failed.")