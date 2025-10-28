import os
from pathlib import Path

import pytest

from logging_agent.config_reader import Config


@pytest.fixture
def config_instance():
    """Provide a fresh Config instance without triggering the singleton loader."""
    original_instance = Config._instance
    Config._instance = None
    config = object.__new__(Config)
    Config._instance = config
    try:
        yield config
    finally:
        Config._instance = original_instance


def write_config(tmp_path, content):
    config_file = tmp_path / "config.yaml"
    config_file.write_text(content)
    return config_file


def test_load_config_normalizes_and_applies_defaults(tmp_path, monkeypatch, config_instance):
    output_dir = tmp_path / "output"
    host_key = tmp_path / "ssh_host_ed25519_key"
    authorized_key = tmp_path / "partner.pub"
    host_key.write_text("key")
    authorized_key.write_text("ssh-ed25519 AAAA")

    monkeypatch.setenv("OUTPUT_DIR", str(output_dir))

    config_template = """
        general:
          output_directory: ${OUTPUT_DIR}
          log_directory: logs
          log_file:
          logging_levels: DEBUG
        aws_credentials: {}
        output:
          type: https
          destination: example.com:8443/api
          output_format: cef
          compatibility_mode: NONE
        formats: {}
        agents:
          - name: file-agent
            type: file
            product: cloud_waap
            logs:
              Access: true
            file_settings:
              root_path: relative/path
              polling_interval_seconds: "15"
              completion_strategy:
                mode: archive
                archive_directory: relative/archive
          - name: sftp-agent
            type: sftp
            product: cloud_waap
            logs: {}
            sftp_settings:
              listen:
                host: 10.0.0.1
              host_keys:
                - {HOST_KEY}
              drop_directory: sftp/drop
              credential_policy:
                users:
                  - username: partner
                    home_directory: partners/home
                    authorized_keys: {AUTHORIZED_KEY}
        """
    config_text = (
        config_template
        .replace("{HOST_KEY}", str(host_key))
        .replace("{AUTHORIZED_KEY}", str(authorized_key))
    )
    config_file = write_config(tmp_path, config_text)

    config_instance.load_config(str(config_file))
    config_data = config_instance.config

    assert config_data["output"]["destination"] == "example.com"
    assert config_data["output"]["port"] == 8443
    assert config_data["output"]["uri"] == "/api"
    assert config_data["output"]["compatibility_mode"] is None

    assert config_data["general"]["output_directory"] == str(output_dir)
    assert config_data["general"]["log_directory"] == str(Path(os.getcwd()) / "logs")
    assert config_data["general"]["log_file"] == "agent.log"

    file_agent = config_data["agents"]["file-agent"]
    assert file_agent["logs"]["Access"] is True
    # Unknown options should be injected and default to False
    assert file_agent["logs"]["unknown"] is False
    assert file_agent["file_settings"]["root_path"] == str(Path(os.getcwd()) / "relative/path")
    assert file_agent["file_settings"]["polling_interval_seconds"] == 15
    assert file_agent["file_settings"]["completion_strategy"] == {
        "mode": "archive",
        "archive_directory": str(Path(os.getcwd()) / "relative/archive")
    }

    sftp_agent = config_data["agents"]["sftp-agent"]
    assert sftp_agent["sftp_settings"]["listen"] == {"host": "10.0.0.1", "port": 2222}
    assert sftp_agent["sftp_settings"]["host_keys"] == [str(host_key)]
    assert sftp_agent["sftp_settings"]["drop_directory"] == str(Path(os.getcwd()) / "sftp/drop")

    user = sftp_agent["sftp_settings"]["credential_policy"]["users"][0]
    assert user["home_directory"] == str(Path(os.getcwd()) / "partners/home")
    assert user["authorized_keys"] == [str(authorized_key)]

    assert sorted(config_instance.get_all_agent_names()) == ["file-agent", "sftp-agent"]
    assert config_instance.get_all_products() == ["cloud_waap"]


def test_get_agent_config_merges_defaults(tmp_path, config_instance):
    config_file = write_config(
        tmp_path,
        """
        general:
          output_directory: /tmp/out
        aws_credentials: {}
        output:
          type: https
          destination: example.com
          output_format: cef
        formats: {}
        agents:
          - name: file-agent
            type: file
            product: cloud_waap
            logs: {}
            file_settings:
              root_path: /tmp/source
        """
    )

    config_instance.load_config(str(config_file))
    agent_config = config_instance.get_agent_config("file-agent")

    assert agent_config["output"]["output_format"] == "cef"
    format_defaults = agent_config["formats"]["cef"]
    assert format_defaults["delimiter"] == "\n"
    assert format_defaults["syslog_header"]["generate_header"] is True
    assert format_defaults["syslog_header"]["host"] == "product"

    https_config = agent_config["https"]
    assert "authentication" in https_config
    assert https_config["authentication"]["auth_type"] is None
    assert https_config["verify"] is False

    assert agent_config["file_settings"]["root_path"] == "/tmp/source"


def test_transform_single_agent_structure(tmp_path, config_instance):
    config_file = write_config(
        tmp_path,
        """
        agent:
          sqs_name: queue-name
          logs:
            Access: true
        output:
          type: tcp
          destination: localhost
          output_format: json
        formats: {}
        """
    )

    config_instance.load_config(str(config_file))
    agents = config_instance.config["agents"]

    assert list(agents) == ["cloud_waap"]
    transformed = agents["cloud_waap"]
    assert transformed["type"] == "sqs"
    assert transformed["product"] == "cloud_waap"
    assert transformed["logs"]["Access"] is True
    assert transformed["sqs_settings"]["queue_name"] == "queue-name"
    assert transformed["sqs_settings"]["delete_on_failure"] is False
