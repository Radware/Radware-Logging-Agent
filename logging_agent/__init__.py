__version__ = '1.0.0'

# Importing core functionalities from sub-packages for easier access
from logging_agent.cloud_waap.cloudwaap_log_utils import CloudWAAPProcessor

"""
Initialization module for the logging_agent package.

Defines the version and exposes core functionalities for convenient access.
"""
# Define what should be accessible when importing * from this package
__all__ = ['CloudWAAPProcessor']