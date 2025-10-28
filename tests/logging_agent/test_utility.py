import importlib
import sys

import pytest


@pytest.fixture
def utility_module(monkeypatch):
    monkeypatch.setenv("RLA_VERIFY_MODE", "1")
    for module_name in ["logging_agent.logging_config", "logging_agent.utility"]:
        if module_name in sys.modules:
            del sys.modules[module_name]
    return importlib.import_module("logging_agent.utility")


class StubLogger:
    def __init__(self):
        self.messages = []

    def info(self, message):
        self.messages.append(("info", message))

    def error(self, message):
        self.messages.append(("error", message))


def test_cleanup_removes_file_and_logs_info(tmp_path, monkeypatch, utility_module):
    temp_file = tmp_path / "test.log"
    temp_file.write_text("data")

    logger = StubLogger()
    monkeypatch.setattr(utility_module, "logger", logger)

    utility_module.Utility.cleanup(str(temp_file))

    assert not temp_file.exists()
    assert ("info", f"Deleted local file: {temp_file}") in logger.messages


def test_cleanup_logs_error_on_failure(tmp_path, monkeypatch, utility_module):
    temp_file = tmp_path / "test.log"
    temp_file.write_text("data")

    logger = StubLogger()
    monkeypatch.setattr(utility_module, "logger", logger)

    def raise_error(path):  # pragma: no cover - invoked to simulate failure
        raise OSError("boom")

    monkeypatch.setattr(utility_module.os, "remove", raise_error)

    utility_module.Utility.cleanup(str(temp_file))

    assert temp_file.exists()
    assert logger.messages[-1][0] == "error"
    assert f"Error deleting local file: {temp_file}" in logger.messages[-1][1]
