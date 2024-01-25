import boto3
import os
from .logging_config import get_logger

# Create a logger for this module
logger = get_logger('downloader')

class Downloader:
    def __init__(self, config):
        self.config = config
        logger.debug("Downloader initialized.")

    def download(self, source, destination):
        raise NotImplementedError("This method should be implemented by subclasses.")


class S3Downloader(Downloader):
    def __init__(self, config):
        super().__init__(config)
        self.s3_client = boto3.client(
            's3',
            aws_access_key_id=config.get('sqs_access_key_id'),
            aws_secret_access_key=config.get('sqs_secret_access_key'),
            region_name=config.get('sqs_region', 'us-east-1')
        )
        logger.debug("AWS S3 client initialized for S3Downloader.")

    def download(self, bucket, key, download_path):
        # Ensure the directory exists
        directory = os.path.dirname(download_path)
        if not os.path.exists(directory):
            os.makedirs(directory, exist_ok=True)
            logger.debug(f"Created directories for path: {directory}")

        try:
            logger.info(f"Attempting to download {key} from {bucket} to {download_path}")
            self.s3_client.download_file(bucket, key, download_path)
            logger.info(f"Downloaded {key} to {download_path}")
            return True
        except Exception as e:
            logger.error(f"Error downloading {key} from S3: {e}")
            return False
