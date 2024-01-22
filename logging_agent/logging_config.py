import logging
import os
from .config_reader import Config  # Import the Config class

# Access configuration
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
log_level = logging_levels.get(config.get('logging_level', 'INFO'), logging.INFO)

# Fetch log directory and file from the configuration, or use defaults
log_directory = config.get('log_directory', '/tmp/')
log_file = config.get('log_file', 'rcwla.log')
log_path = os.path.join(log_directory, log_file)

# Ensure the directory exists
os.makedirs(log_directory, exist_ok=True)

# Set up the basic configuration for logging
logging.basicConfig(filename=log_path,
                    level=log_level,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

def get_logger(module_name):
    """
    Returns a logger with the given module name.
    """
    return logging.getLogger(module_name)
