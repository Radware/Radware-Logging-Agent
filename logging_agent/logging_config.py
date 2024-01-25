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
log_level = logging_levels.get(config.get('logging_levels', 'INFO'), logging.INFO)

# Fetch log directory and file from the configuration, or use defaults
log_directory = config.get('log_directory', '/tmp/')
log_file = config.get('log_file', 'rcwla.log')
log_path = os.path.join(log_directory, log_file)

# Ensure the directory exists
os.makedirs(log_directory, exist_ok=True)

# # Set up the basic configuration for logging
# logging.basicConfig(filename=log_path,
#                     level=log_level,
#                     format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# Set up logging
logger = logging.getLogger()
logger.setLevel(log_level)

# Create file handler which logs even debug messages
file_handler = logging.FileHandler(log_path)
file_handler.setLevel(log_level)
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))

# Create console handler with a higher log level
console_handler = logging.StreamHandler()
console_handler.setLevel(log_level)
console_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))

# Add the handlers to the logger
logger.addHandler(file_handler)
logger.addHandler(console_handler)

def get_logger(module_name):
    """
    Returns a logger with the given module name.
    """
    return logging.getLogger(module_name)
