from pathlib import Path
from unittest.mock import MagicMock

import pytest

from logging_agent.file_agent import FileAgent
from logging_agent.sftp_agent import SFTPAgent


@pytest.fixture
def file_agent_config(tmp_path: Path) -> dict:
    root = tmp_path / "logs"
    root.mkdir()
    return {
        'name': 'file-agent',
        'type': 'file',
        'num_worker_threads': 1,
        'file_settings': {
            'root_path': str(root),
            'polling_interval_seconds': 0,
            'completion_strategy': {'mode': 'delete'},
        },
    }


def test_file_agent_enqueues_completed_file(tmp_path: Path, file_agent_config: dict) -> None:
    agent = FileAgent(file_agent_config)
    agent.data_processor.process_data = MagicMock(return_value=True)

    target_file = Path(file_agent_config['file_settings']['root_path']) / 'sample.json'
    target_file.write_text('{"example": true}')

    # First scan records the file, second scan confirms it is stable
    agent._scan_for_files()
    agent._scan_for_files()

    entry = agent.processing_queue.get_nowait()
    assert entry['input_type'] == 'file'
    assert entry['relative_key'] == 'sample.json'
    assert Path(entry['file_path']).resolve() == target_file.resolve()

    agent._process_queue_entry(entry)
    agent.data_processor.process_data.assert_called_once()
    assert not target_file.exists()


@pytest.fixture
def sftp_agent_config(tmp_path: Path) -> dict:
    drop_dir = tmp_path / "drop"
    drop_dir.mkdir()
    host_key = tmp_path / "ssh_host_key"
    host_key.write_text("dummy")
    return {
        'name': 'sftp-agent',
        'type': 'sftp',
        'num_worker_threads': 1,
        'sftp_settings': {
            'listen': {'host': '127.0.0.1', 'port': 0},
            'host_keys': [str(host_key)],
            'drop_directory': str(drop_dir),
            'polling_interval_seconds': 0,
            'completion_strategy': {'mode': 'delete'},
            'credential_policy': {
                'mode': 'static',
                'users': [{'username': 'upload', 'password': 'secret'}],
            },
        },
    }


def test_sftp_agent_upload_callback(tmp_path: Path, sftp_agent_config: dict) -> None:
    agent = SFTPAgent(sftp_agent_config)
    agent.data_processor.process_data = MagicMock(return_value=True)

    target_file = Path(sftp_agent_config['sftp_settings']['drop_directory']) / 'folder' / 'event.json'
    target_file.parent.mkdir()
    target_file.write_text('{"value": 1}')

    agent._handle_upload_complete('folder/event.json')

    entry = agent.processing_queue.get_nowait()
    assert entry['input_type'] == 'sftp'
    assert entry['relative_key'] == 'folder/event.json'

    agent._process_queue_entry(entry)
    agent.data_processor.process_data.assert_called_once()
    assert not target_file.exists()
