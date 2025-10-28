import os
import json
import gzip

import pytest

from logging_agent.data_loader import DataLoader


def test_load_data_unsupported_type(config):
    dataloader = DataLoader(config)
    result = dataloader.load_data("unsupported", {})
    assert result == {"data": None, "metadata": {}}


def test_load_from_s3_file_exists(monkeypatch, mock_s3_downloader, config, input_info):
    mock_data = {"test": "data"}

    monkeypatch.setattr('os.path.exists', lambda path: True)
    monkeypatch.setattr('os.path.getsize', lambda path: 100)
    monkeypatch.setattr('os.makedirs', lambda *args, **kwargs: None)
    monkeypatch.setattr('glob.glob', lambda pattern: [])
    monkeypatch.setattr(DataLoader, '_load_local_file', lambda self, path: mock_data)

    dataloader = DataLoader(config)
    result = dataloader.load_data("sqs", input_info)

    assert result['data'] == mock_data
    metadata = result['metadata']
    assert metadata['key'] == input_info['key']
    assert metadata['relative_key'] == input_info['key']
    assert metadata['cleanup'] is True


def test_load_from_s3_download_required(monkeypatch, mock_s3_downloader, config, input_info):
    monkeypatch.setattr('os.path.exists', lambda path: False)
    monkeypatch.setattr('os.makedirs', lambda *args, **kwargs: None)

    mock_s3_downloader.download.return_value = True
    sample_data = {"sample": "data"}
    monkeypatch.setattr(DataLoader, '_load_local_file', lambda self, path: sample_data)

    dataloader = DataLoader(config)
    result = dataloader.load_data("sqs", input_info)

    assert result['data'] == sample_data
    metadata = result['metadata']
    assert metadata['cleanup'] is True
    assert metadata['key'] == input_info['key']


def test_load_from_s3_download_failure(monkeypatch, mock_s3_downloader, config, input_info):
    monkeypatch.setattr('os.path.exists', lambda path: False)
    monkeypatch.setattr('os.makedirs', lambda *args, **kwargs: None)

    mock_s3_downloader.download.return_value = False

    dataloader = DataLoader(config)
    result = dataloader.load_data("sqs", input_info)

    assert result['data'] is None
    metadata = result['metadata']
    assert metadata['cleanup'] is True
    assert metadata['key'] == input_info['key']


def test_load_from_s3_unsupported_format(monkeypatch, mock_s3_downloader, config, input_info):
    monkeypatch.setattr('os.path.exists', lambda path: True)
    monkeypatch.setattr('os.path.getsize', lambda path: 1234)
    monkeypatch.setattr('glob.glob', lambda pattern: [])
    monkeypatch.setattr('os.makedirs', lambda *args, **kwargs: None)

    mock_s3_downloader.download.return_value = True
    monkeypatch.setattr(DataLoader, '_load_local_file', lambda self, path: None)

    dataloader = DataLoader(config)
    input_info['key'] += ".unsupported"
    result = dataloader.load_data("sqs", input_info)

    assert result['data'] is None
    metadata = result['metadata']
    assert metadata['key'] == input_info['key']
    assert metadata['relative_key'] == input_info['key']


def test_load_from_file_reads_local_json(tmp_path):
    root_path = tmp_path / "root"
    root_path.mkdir()
    nested_dir = root_path / "logs"
    nested_dir.mkdir()
    file_path = nested_dir / "sample.json"
    sample_data = {"message": "hello"}
    file_path.write_text(json.dumps(sample_data))

    config = {
        'file_settings': {
            'root_path': str(root_path)
        }
    }

    dataloader = DataLoader(config)
    result = dataloader.load_data("file", {'file_path': str(file_path)})

    assert result['data'] == sample_data
    metadata = result['metadata']
    assert metadata['file_path'] == str(file_path)
    assert metadata['relative_key'] == os.path.relpath(file_path, root_path)
    assert metadata['cleanup'] is False


def test_load_from_sftp_reads_gzip(tmp_path):
    root_path = tmp_path / "drop"
    root_path.mkdir()
    partner_dir = root_path / "partner"
    partner_dir.mkdir()
    file_path = partner_dir / "log.json.gz"
    payload = {"status": "ok"}
    with gzip.open(file_path, 'wt') as f:
        json.dump(payload, f)

    config = {
        'sftp_settings': {
            'drop_directory': str(root_path)
        }
    }

    dataloader = DataLoader(config)
    result = dataloader.load_data("sftp", {'file_path': str(file_path)})

    assert result['data'] == payload
    metadata = result['metadata']
    assert metadata['file_path'] == str(file_path)
    assert metadata['relative_key'] == os.path.relpath(file_path, root_path)
    assert metadata['cleanup'] is False
