import importlib
import logging
import sys

import pytest

import logging_agent.config_reader as config_reader


@pytest.fixture(autouse=True)
def reset_logging_root():
    """Ensure the root logger is clean before each test."""
    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)
        handler.close()
    root.setLevel(logging.NOTSET)
    yield
    for handler in list(root.handlers):
        root.removeHandler(handler)
        handler.close()
    root.setLevel(logging.NOTSET)


def reload_logging_config():
    module_name = "logging_agent.logging_config"
    if module_name in sys.modules:
        del sys.modules[module_name]
    return importlib.import_module(module_name)


def test_verify_mode_uses_stream_handler(monkeypatch):
    monkeypatch.setenv("RLA_VERIFY_MODE", "1")
    monkeypatch.delenv("RLA_ENVIRONMENT", raising=False)

    module = reload_logging_config()
    logger = module.get_logger("test")

    handlers = logging.getLogger().handlers
    assert any(isinstance(h, logging.StreamHandler) for h in handlers)
    assert not any(isinstance(h, logging.FileHandler) for h in handlers)
    assert logger is logging.getLogger("test")


def test_normal_mode_adds_file_handler(monkeypatch, tmp_path):
    class DummyConfig:
        def __init__(self):
            self.config = {
                "general": {
                    "log_directory": str(tmp_path),
                    "log_file": "agent.log",
                    "logging_levels": "WARNING",
                },
                "output": {"type": "tcp", "destination": "localhost", "output_format": "json"},
                "formats": {},
                "agents": {},
            }

    monkeypatch.setattr(config_reader, "Config", DummyConfig)
    monkeypatch.setenv("RLA_VERIFY_MODE", "0")
    monkeypatch.setenv("RLA_ENVIRONMENT", "")

    module = reload_logging_config()
    logger = module.get_logger("test")

    handlers = logging.getLogger().handlers
    assert any(isinstance(h, logging.StreamHandler) for h in handlers)

    file_handlers = [h for h in handlers if isinstance(h, logging.FileHandler)]
    assert file_handlers, "Expected a file handler to be configured"
    assert file_handlers[0].baseFilename == str(tmp_path / "agent.log")
    assert logging.getLogger().level == logging.WARNING

    logger.warning("message")
    assert (tmp_path / "agent.log").exists()


def test_docker_environment_skips_file_handler(monkeypatch, tmp_path):
    class DummyConfig:
        def __init__(self):
            self.config = {
                "general": {
                    "log_directory": str(tmp_path),
                    "log_file": "agent.log",
                    "logging_levels": "INFO",
                },
                "output": {"type": "tcp", "destination": "localhost", "output_format": "json"},
                "formats": {},
                "agents": {},
            }

    monkeypatch.setattr(config_reader, "Config", DummyConfig)
    monkeypatch.setenv("RLA_VERIFY_MODE", "0")
    monkeypatch.setenv("RLA_ENVIRONMENT", "docker")

    module = reload_logging_config()
    reload_logger = module.get_logger("test")

    handlers = logging.getLogger().handlers
    assert any(isinstance(h, logging.StreamHandler) for h in handlers)
    assert not any(isinstance(h, logging.FileHandler) for h in handlers)
    assert reload_logger is logging.getLogger("test")
