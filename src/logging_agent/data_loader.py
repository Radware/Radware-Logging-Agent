import gzip
import os
import json
import glob
from logging_agent.downloader import S3Downloader
from logging_agent.logging_config import get_logger


class DataLoader:
    def __init__(self, config):
        self.config = config
        self.logger = get_logger('data_loader')  # Initialize logger as an instance attribute

    def load_data(self, input_type, input_info):
        loaders = {
            "sqs": self.load_from_s3,
            "file": self.load_from_file_system,
            "sftp": self.load_from_file_system,
        }

        loader = loaders.get(input_type)
        if not loader:
            self.logger.error(f"Unsupported input type: {input_type}")
            return {"data": None, "metadata": {}}

        return loader(input_info, input_type)

    def load_from_s3(self, input_info, input_type="sqs"):
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
        output_directory = self.config.get('output_directory', '/tmp')
        download_path = os.path.join(output_directory, os.path.basename(key))
        metadata = {
            "file_path": download_path,
            "key": key,
            "relative_key": key,
            "cleanup": True,
        }

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
            s3_config = self.config.get('aws_credentials', {})  # Extract AWS specific configuration
            downloader = S3Downloader(s3_config)
            if not downloader.download(bucket, key, download_path):
                self.logger.error(f"Failed to download {key} from bucket {bucket}")
                return {"data": None, "metadata": metadata}

        try:
            data = self._load_local_file(download_path)
            if data is None:
                return {"data": None, "metadata": metadata}
            return {"data": data, "metadata": metadata}
        except Exception as e:
            self.logger.error(f"Error processing file: {download_path}: {e}")
            return {"data": None, "metadata": metadata}

    def load_from_file_system(self, input_info, input_type):
        root_path = None
        if input_type == "file":
            root_path = self.config.get('file_settings', {}).get('root_path')
        elif input_type == "sftp":
            root_path = self.config.get('sftp_settings', {}).get('drop_directory')

        provided_path = input_info.get('file_path') or input_info.get('path')
        if not provided_path:
            self.logger.error(f"No file path provided for input type: {input_type}")
            return {"data": None, "metadata": {}}

        absolute_path = provided_path
        if not os.path.isabs(absolute_path):
            if root_path:
                absolute_path = os.path.join(root_path, absolute_path)
            absolute_path = os.path.abspath(absolute_path)
        else:
            absolute_path = os.path.abspath(absolute_path)

        if not os.path.exists(absolute_path):
            self.logger.error(f"File does not exist: {absolute_path}")
            return {"data": None, "metadata": {}}

        relative_key = self._compute_relative_key(absolute_path, root_path)
        metadata = {
            "file_path": absolute_path,
            "key": relative_key,
            "relative_key": relative_key,
            "cleanup": False,
        }

        try:
            data = self._load_local_file(absolute_path)
            if data is None:
                return {"data": None, "metadata": metadata}
            return {"data": data, "metadata": metadata}
        except Exception as e:
            self.logger.error(f"Error processing file: {absolute_path}: {e}")
            return {"data": None, "metadata": metadata}

    def _load_local_file(self, path):
        file_extension = os.path.splitext(path)[1].lower()
        if file_extension == '.gz':
            with gzip.open(path, 'rt') as f:
                return json.load(f)
        if file_extension == '.json':
            with open(path, 'r') as f:
                return json.load(f)
        if file_extension == '.ndjson':
            with open(path, 'r') as f:
                return [json.loads(line) for line in f]

        self.logger.error(f"Unsupported file format: {file_extension}")
        return None

    @staticmethod
    def _compute_relative_key(absolute_path, root_path):
        if root_path:
            try:
                return os.path.relpath(absolute_path, root_path)
            except ValueError:
                pass
        return os.path.basename(absolute_path)
