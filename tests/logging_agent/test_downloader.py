
# test_downloader.py
import tempfile

from logging_agent.downloader import S3Downloader

def test_s3_downloader_download_success(mock_boto3_client):
    config = {
        'access_key_id': 'fake_access_key',
        'secret_access_key': 'fake_secret_key',
        'region': 'us-east-1'
    }
    downloader = S3Downloader(config)

    bucket = "test-bucket"
    key = "test-key"
    with tempfile.TemporaryDirectory() as tmpdir:
        download_path = f"{tmpdir}/test-key"

        result = downloader.download(bucket, key, download_path)

        assert result is True
        mock_boto3_client.download_file.assert_called_once_with(bucket, key, download_path)

def test_s3_downloader_download_failure(mock_boto3_client):
    mock_boto3_client.download_file.side_effect = Exception("Failed to download")

    config = {
        'access_key_id': 'fake_access_key',
        'secret_access_key': 'fake_secret_key',
        'region': 'us-east-1'
    }
    downloader = S3Downloader(config)

    bucket = "test-bucket"
    key = "test-key"
    with tempfile.TemporaryDirectory() as tmpdir:
        download_path = f"{tmpdir}/test-key"

        result = downloader.download(bucket, key, download_path)

        assert result is False
        mock_boto3_client.download_file.assert_called_once_with(bucket, key, download_path)

