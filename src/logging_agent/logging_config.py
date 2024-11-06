import logging
import os
from .config_reader import Config  # Adjust import path based on your project structure

# Check if we are in verification mode
verify_mode = os.getenv('RLA_VERIFY_MODE', '0') == '1'
rla_environment = os.getenv('RLA_ENVIRONMENT', '')
print("rla_environment: " + rla_environment)
# Default logging level
log_level = logging.INFO

if verify_mode:
    # If in verification mode, use console logging only
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    console_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
    logging.basicConfig(handlers=[console_handler], level=log_level)
else:
    # Normal operation mode, use configuration from Config class
    config = Config().config

    if not config:
        logging.error("Failed to load configuration. Exiting.")
        exit(1)

    # Determine the logging level based on the configuration
    logging_levels = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR
    }
    log_level = logging_levels.get(config.get('general', {}).get('logging_levels', 'INFO'), logging.INFO)

    # Set up logging
    logger = logging.getLogger()
    logger.setLevel(log_level)

    # Create console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    console_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
    logger.addHandler(console_handler)

    # Only add file handler if not in Docker environment
    if rla_environment != 'docker':
        # Fetch log directory and file from the configuration, or use defaults
        log_directory = config.get('general', {}).get('log_directory', '/tmp')
        log_file = config.get('general', {}).get('log_file', 'rla.log')
        log_path = os.path.join(log_directory, log_file)

        # Ensure the directory exists
        os.makedirs(log_directory, exist_ok=True)

        # Create file handler which logs even debug messages
        file_handler = logging.FileHandler(log_path)
        file_handler.setLevel(log_level)
        file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))

        # Add file handler to the logger
        logger.addHandler(file_handler)

def get_logger(module_name):
    """
    Returns a logger with the given module name, adjusting for verification mode if necessary.
    """
    return logging.getLogger(module_name)