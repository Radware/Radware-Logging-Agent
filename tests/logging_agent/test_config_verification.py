import os

import pytest

os.environ.setdefault("RLA_VERIFY_MODE", "1")

from logging_agent import config_verification


class DummyResponse:
    def __init__(self, status_code, json_data=None, text='', ok=None, json_exc=False):
        self.status_code = status_code
        self._json_data = json_data
        self.text = text
        self._json_exc = json_exc
        self.ok = ok if ok is not None else 200 <= status_code < 300

    def json(self):
        if self._json_exc:
            raise ValueError("Invalid JSON")
        if self._json_data is None:
            raise ValueError("Invalid JSON")
        return self._json_data


class DummySession:
    def __init__(self, response):
        self._response = response
        self.headers = {}
        self.auth = None
        self.cert = None
        self.verify = True

    def post(self, url, data='', timeout=5):
        return self._response

    def get(self, url, timeout=5):
        return self._response


def patch_session(monkeypatch, response):
    monkeypatch.setattr(
        config_verification.requests,
        "Session",
        lambda: DummySession(response),
    )


def _base_output():
    return {
        'type': 'http',
        'output_format': 'json',
        'compatibility_mode': None,
    }


def test_verify_agent_config_accepts_file_agent(tmp_path):
    root_path = tmp_path / "incoming"
    archive_path = tmp_path / "archive"
    root_path.mkdir()
    archive_path.mkdir()

    agent_config = {
        'name': 'file-agent',
        'type': 'file',
        'product': 'cloud_waap',
        'logs': {'Access': True},
        'output': _base_output(),
        'file_settings': {
            'root_path': str(root_path),
            'polling_interval_seconds': 30,
            'completion_strategy': {
                'mode': 'archive',
                'archive_directory': str(archive_path),
            }
        }
    }

    assert config_verification.verify_agent_config(agent_config)


def test_verify_agent_config_rejects_file_agent_with_missing_archive(tmp_path):
    root_path = tmp_path / "incoming"
    root_path.mkdir()

    agent_config = {
        'name': 'file-agent-invalid',
        'type': 'file',
        'product': 'cloud_waap',
        'logs': {'Access': True},
        'output': _base_output(),
        'file_settings': {
            'root_path': str(root_path),
            'polling_interval_seconds': 30,
            'completion_strategy': {
                'mode': 'archive',
                'archive_directory': str(root_path / "archive"),
            }
        }
    }

    assert not config_verification.verify_agent_config(agent_config)


def test_verify_agent_config_accepts_sftp_agent_public_key(tmp_path):
    drop_directory = tmp_path / "drop"
    host_key = tmp_path / "ssh_host_ed25519_key"
    authorized_key = tmp_path / "partner.pub"
    user_home = drop_directory / "partner"

    drop_directory.mkdir()
    user_home.mkdir()
    host_key.write_text("dummy")
    authorized_key.write_text("ssh-ed25519 AAAA test")

    agent_config = {
        'name': 'sftp-agent',
        'type': 'sftp',
        'product': 'cloud_waap',
        'logs': {'Access': True},
        'output': _base_output(),
        'sftp_settings': {
            'listen': {'host': '0.0.0.0', 'port': 2222},
            'host_keys': [str(host_key)],
            'drop_directory': str(drop_directory),
            'credential_policy': {
                'mode': 'public_key',
                'users': [
                    {
                        'username': 'partner',
                        'authorized_keys': [str(authorized_key)],
                        'home_directory': str(user_home),
                    }
                ],
            },
        }
    }

    assert config_verification.verify_agent_config(agent_config)


def test_verify_agent_config_accepts_inline_authorized_key(tmp_path):
    pytest.importorskip("asyncssh")
    import asyncssh  # type: ignore

    drop_directory = tmp_path / "drop"
    host_key = tmp_path / "ssh_host_ed25519_key"
    user_home = drop_directory / "partner"

    drop_directory.mkdir()
    user_home.mkdir()
    host_key.write_text("dummy")

    inline_key = asyncssh.generate_private_key("ssh-ed25519").export_public_key().decode().strip()

    agent_config = {
        'name': 'sftp-agent-inline',
        'type': 'sftp',
        'product': 'cloud_waap',
        'logs': {'Access': True},
        'output': _base_output(),
        'sftp_settings': {
            'listen': {'host': '0.0.0.0', 'port': 2222},
            'host_keys': [str(host_key)],
            'drop_directory': str(drop_directory),
            'credential_policy': {
                'mode': 'public_key',
                'users': [
                    {
                        'username': 'partner',
                        'authorized_keys': [inline_key],
                        'home_directory': str(user_home),
                    }
                ],
            },
        }
    }

    assert config_verification.verify_agent_config(agent_config)


def test_verify_agent_config_rejects_sftp_agent_missing_password(tmp_path):
    drop_directory = tmp_path / "drop"
    host_key = tmp_path / "ssh_host_ed25519_key"

    drop_directory.mkdir()
    host_key.write_text("dummy")

    agent_config = {
        'name': 'sftp-agent-invalid',
        'type': 'sftp',
        'product': 'cloud_waap',
        'logs': {'Access': True},
        'output': _base_output(),
        'sftp_settings': {
            'listen': {'host': '0.0.0.0', 'port': 2222},
            'host_keys': [str(host_key)],
            'drop_directory': str(drop_directory),
            'credential_policy': {
                'mode': 'static',
                'users': [
                    {
                        'username': 'partner',
                    }
                ],
            },
        }
    }

    assert not config_verification.verify_agent_config(agent_config)


def test_splunk_hec_http_accepts_no_data(monkeypatch):
    response = DummyResponse(400, json_data={"text": "No data"})
    monkeypatch.setattr(
        config_verification.requests,
        "post",
        lambda *args, **kwargs: response,
    )

    assert config_verification.test_http_connection("http://example", compatibility="splunk hec")


def test_splunk_hec_https_accepts_no_data(monkeypatch):
    response = DummyResponse(400, json_data={"text": "No data"})
    patch_session(monkeypatch, response)

    assert config_verification.test_https_connection("https://example", compatibility="splunk hec")


def test_splunk_hec_accepts_cribl_success(monkeypatch):
    http_response = DummyResponse(200, json_data={"code": 0})
    monkeypatch.setattr(
        config_verification.requests,
        "post",
        lambda *args, **kwargs: http_response,
    )

    https_response = DummyResponse(200, json_data={"text": "Success"})
    patch_session(monkeypatch, https_response)

    assert config_verification.test_http_connection("http://example", compatibility="splunk hec")
    assert config_verification.test_https_connection("https://example", compatibility="splunk hec")


def test_splunk_hec_accepts_non_json_success(monkeypatch):
    response = DummyResponse(200, text="OK", json_exc=True)
    monkeypatch.setattr(
        config_verification.requests,
        "post",
        lambda *args, **kwargs: response,
    )
    patch_session(monkeypatch, response)

    assert config_verification.test_http_connection("http://example", compatibility="splunk hec")
    assert config_verification.test_https_connection("https://example", compatibility="splunk hec")


@pytest.mark.parametrize(
    "response",
    [
        DummyResponse(500, json_data={"text": "error"}),
        DummyResponse(200, json_data={"text": "Unexpected"}),
    ],
)
def test_splunk_hec_rejects_unexpected_responses(monkeypatch, response):
    monkeypatch.setattr(
        config_verification.requests,
        "post",
        lambda *args, **kwargs: response,
    )
    patch_session(monkeypatch, response)

    assert not config_verification.test_http_connection("http://example", compatibility="splunk hec")
    assert not config_verification.test_https_connection("https://example", compatibility="splunk hec")
