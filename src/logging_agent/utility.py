import os
from .logging_config import get_logger

# Create a logger for this module
logger = get_logger('utility')

class Utility:
    @staticmethod
    def cleanup(file_path):
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
                logger.info(f"Deleted local file: {file_path}")
        except Exception as e:
            logger.error(f"Error deleting local file: {file_path}: {e}")
