import gzip
import os
import json
import glob
from .downloader import S3Downloader
from .logging_config import get_logger


class DataLoader:
    def __init__(self, config):
        self.config = config
        self.logger = get_logger('data_loader')  # Initialize logger as an instance attribute

    def load_data(self, input_type, input_info):
        if input_type == "sqs":
            return self.load_from_s3(input_info)
        else:
            self.logger.error(f"Unsupported input type: {input_type}")
            return {"data": None, "metadata": {}}

    def load_from_s3(self, input_info):
        """
        Loads data from S3. Checks if the file already exists, handles partial files,
        and downloads the file if required.

        Args:
            input_info (dict): Contains fields specific to the S3 input type.

        Returns:
            dict: Loaded data from S3, or None if an error occurred.
        """
        bucket = input_info.get('bucket', '')
        key = input_info.get('key', '')
        expected_size = input_info.get('expected_size', '')
        download_path = os.path.join(self.config.get('output_directory', '/tmp'), os.path.basename(key))

        # Check if file already exists and decide whether to download
        download_required = True
        if os.path.exists(download_path):
            actual_size = os.path.getsize(download_path)
            if actual_size >= expected_size:
                self.logger.info(f"File already exists and is complete: {key}")
                download_required = False
            else:
                # Handle partial file - Detect, Delete and Redownload
                for partial_file in glob.glob(download_path + '*'):
                    if partial_file != download_path:
                        self.logger.info(f"Partial file detected and will be deleted: {partial_file}")
                        os.remove(partial_file)

        # Download the file from S3 if required
        if download_required:
            downloader = S3Downloader(self.config)
            if not downloader.download(bucket, key, download_path):
                self.logger.error(f"Failed to download {key} from bucket {bucket}")
                return None

        # Determine the file type and process accordingly
        file_extension = os.path.splitext(download_path)[1]
        try:
            if file_extension == '.gz':
                # Decompress and load JSON data
                with gzip.open(download_path, 'rt') as f:
                    data = json.load(f)
            elif file_extension == '.json':
                # Load JSON data
                with open(download_path, 'r') as f:
                    data = json.load(f)
            elif file_extension == '.ndjson':
                # Load NDJSON data
                with open(download_path, 'r') as f:
                    data = [json.loads(line) for line in f]
            else:
                self.logger.error(f"Unsupported file format: {file_extension}")
                return {"data": None, "metadata": {}}
            return {"data": data, "metadata": {"file_path": download_path}}
        except Exception as e:
            self.logger.error(f"Error processing file: {download_path}: {e}")
            return {"data": None, "metadata": {"file_path": download_path}}
