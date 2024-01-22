__version__ = '1.0.0'

# Importing core functionalities from sub-packages for easier access
from logging_agent.cloud_waap.cloudwaap_log_utils import CloudWAAPProcessor

# Define what should be accessible when importing * from this package
__all__ = ['CloudWAAPProcessor']