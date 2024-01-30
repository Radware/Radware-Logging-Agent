import os
import boto3
from .logging_config import get_logger
from urllib.parse import urlparse
from .config_reader import Config
from .app_info import supported_features

logger = get_logger('config_verification')


def verify_aws_credentials(config, agents):
    # Check if any agent is using SQS, if not, skip AWS credentials verification
    if not any(agent['type'] == 'sqs' for agent in agents):
        logger.info("No SQS agents configured. Skipping AWS credentials verification.")
        return True

    try:
        sqs = boto3.client('sqs', region_name=config['aws_credentials']['region'],
                           aws_access_key_id=config['aws_credentials']['access_key_id'],
                           aws_secret_access_key=config['aws_credentials']['secret_access_key'])
        sqs.list_queues()
        logger.info("AWS credentials verified successfully.")
        return True
    except Exception as e:
        logger.error(f"AWS credentials verification failed: {e}")
        return False
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
    return True

def verify_output_config(output_config):
    supported_formats = ['cef', 'json', 'ndjson', 'leef']
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
    if 'client_cert' in tls_config and not os.path.exists(tls_config['client_cert']):
        logger.error(f"Client certificate file not found: {tls_config['client_cert']}")
        return False
    if 'client_key' in tls_config and not os.path.exists(tls_config['client_key']):
        logger.error(f"Client key file not found: {tls_config['client_key']}")
        return False

    return True

def verify_http_https_config(http_config):
    if not isinstance(http_config.get('batch', False), bool):
        logger.error("Invalid batch configuration in HTTP/HTTPS settings.")
        return False
    return True

def verify_general_config(general_config):
    for key in ['log_file', 'output_directory', 'log_directory']:
        if not os.path.exists(general_config[key]):
            logger.error(f"Path does not exist: {general_config[key]}")
            return False
    valid_log_levels = ["INFO", "WARNING", "DEBUG", "ERROR"]
    if general_config['logging_levels'] not in valid_log_levels:
        logger.error(f"Invalid logging level: {general_config['logging_levels']}")
        return False
    return True

def verify_configuration(config):
    logger.info("Starting configuration verification...")

    # Verify general configuration
    if not verify_general_config(config['general']):
        return False

    # Verify AWS credentials
    if not verify_aws_credentials(config, config.get('agents', [])):
        return False

    # Verify each agent configuration
    for agent_config in config.get('agents', []):
        if not verify_agent_config(agent_config):
            return False

    # Verify output configuration
    if not verify_output_config(config['output']):
        return False

    # Verify TLS configuration
    if 'tls' in config and not verify_tls_config(config['tls']):
        return False

    # Verify HTTP/HTTPS configuration
    for protocol in ['http', 'https']:
        if protocol in config and not verify_http_https_config(config[protocol]):
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