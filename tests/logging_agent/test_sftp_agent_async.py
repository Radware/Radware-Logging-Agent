from __future__ import annotations

import asyncio
import contextlib
import copy
import json
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Optional

import pytest

asyncssh = pytest.importorskip("asyncssh")

from logging_agent.sftp_agent import SFTPAgent


pytestmark = pytest.mark.asyncio


def _wait_for(predicate: Callable[[], Any], timeout: float = 5.0) -> Any:
    """Poll *predicate* until it returns a truthy value or *timeout* expires."""

    deadline = time.monotonic() + timeout
    result: Any = None
    while time.monotonic() < deadline:
        result = predicate()
        if result:
            return result
        time.sleep(0.05)
    raise TimeoutError("predicate did not become true before timeout")


def _deep_update(target: Dict[str, Any], updates: Dict[str, Any]) -> Dict[str, Any]:
    for key, value in updates.items():
        if isinstance(value, dict) and isinstance(target.get(key), dict):
            _deep_update(target[key], value)
        else:
            target[key] = value
    return target


def _generate_host_key(destination: Path) -> Path:
    key = asyncssh.generate_private_key("ssh-rsa")
    key.write_private_key(destination)
    return destination


async def _sftp_upload(port: int, remote_path: str, payload: bytes) -> None:
    async with asyncssh.connect(
        "127.0.0.1",
        port=port,
        username="upload",
        password="secret",
        known_hosts=None,
    ) as conn:
        async with conn.start_sftp_client() as client:
            directory = Path(remote_path).parent
            if str(directory) not in {".", "/"}:
                with contextlib.suppress(asyncssh.SFTPError):
                    await client.makedirs(str(directory))
            async with client.open(remote_path, "w", encoding=None) as remote_file:
                await remote_file.write(payload)


@dataclass
class AgentRuntime:
    agent: SFTPAgent
    thread: threading.Thread
    port: int
    drop_directory: Path
    cleanup: Callable[[], None]

    def stop(self) -> None:
        self.cleanup()


@pytest.fixture
def sftp_harness(tmp_path: Path):
    host_key_path = _generate_host_key(tmp_path / "ssh_host_key")
    base_config: Dict[str, Any] = {
        "name": "sftp-agent",
        "type": "sftp",
        "product": "cloud_waap",
        "logs": {"Access": True, "unknown": False},
        "output": {
            "type": "tcp",
            "destination": "127.0.0.1",
            "port": 9000,
            "output_format": "json",
            "batch": False,
        },
        "tcp": {"batch": False},
        "formats": {"json": {}},
        "num_worker_threads": 2,
        "sftp_settings": {
            "listen": {"host": "127.0.0.1", "port": 0},
            "host_keys": [str(host_key_path)],
            "drop_directory": "",  # populated per runtime
            "polling_interval_seconds": 0,
            "completion_strategy": {"mode": "delete"},
            "credential_policy": {
                "mode": "static",
                "users": [{"username": "upload", "password": "secret"}],
            },
        },
    }

    runtimes: list[AgentRuntime] = []

    def start_agent(
        *,
        process_data: Optional[Callable[[Dict[str, Any]], bool]] = None,
        extra_config: Optional[Dict[str, Any]] = None,
    ) -> AgentRuntime:
        drop_directory = tmp_path / f"drop_{len(runtimes)}"
        drop_directory.mkdir()

        config = copy.deepcopy(base_config)
        _deep_update(config, extra_config or {})
        config["sftp_settings"] = config["sftp_settings"].copy()
        config["sftp_settings"]["drop_directory"] = str(drop_directory)

        agent = SFTPAgent(config)
        if process_data is not None:
            agent.data_processor.process_data = process_data  # type: ignore[assignment]

        thread = threading.Thread(target=agent.start, daemon=True)
        thread.start()

        def cleanup() -> None:
            if thread.is_alive():
                agent.stop()
                thread.join(timeout=10)

        try:
            port = int(_wait_for(lambda: agent._server and agent._server.get_port(), timeout=10))
        except Exception:
            cleanup()
            raise

        runtime = AgentRuntime(
            agent=agent,
            thread=thread,
            port=port,
            drop_directory=drop_directory,
            cleanup=cleanup,
        )
        runtimes.append(runtime)
        return runtime

    yield start_agent

    for runtime in runtimes:
        runtime.stop()


def _assert_queue_drained(agent: SFTPAgent) -> None:
    _wait_for(lambda: agent.processing_queue.unfinished_tasks == 0, timeout=10)
    _wait_for(lambda: agent.processing_queue.empty(), timeout=5)
    _wait_for(lambda: not agent._inflight_files, timeout=5)


async def test_sftp_agent_concurrent_uploads(sftp_harness) -> None:
    processed: list[tuple[str, bool]] = []

    def process_payload(fields: Dict[str, Any]) -> bool:
        key = fields["key"]
        success = not key.endswith("/fail.json")
        processed.append((key, success))
        if not success:
            Path(fields["file_path"]).unlink(missing_ok=True)
        return success

    runtime = sftp_harness(process_data=process_payload)

    payloads = {
        "alpha/event.json": json.dumps({"value": 1}).encode(),
        "beta/event.json": json.dumps({"value": 2}).encode(),
        "gamma/fail.json": json.dumps({"value": 3}).encode(),
    }

    await asyncio.gather(
        *[
            asyncio.create_task(_sftp_upload(runtime.port, path, data))
            for path, data in payloads.items()
        ]
    )

    _wait_for(lambda: len(processed) == len(payloads), timeout=10)
    _assert_queue_drained(runtime.agent)

    keys = {entry[0] for entry in processed}
    assert keys == set(payloads.keys())
    assert sum(1 for _key, success in processed if success) == 2
    assert not (runtime.drop_directory / "alpha/event.json").exists()
    assert not (runtime.drop_directory / "beta/event.json").exists()


async def test_sftp_agent_rejects_invalid_credentials(sftp_harness) -> None:
    runtime = sftp_harness(process_data=lambda _: True)

    with pytest.raises(asyncssh.PermissionDenied):
        async with asyncssh.connect(
            "127.0.0.1",
            port=runtime.port,
            username="upload",
            password="wrong",  # noqa: S106 - test credential
            known_hosts=None,
        ):
            pass


async def test_sftp_agent_rejects_path_traversal_attempts(sftp_harness) -> None:
    recorded: list[str] = []

    def process_payload(fields: Dict[str, Any]) -> bool:
        recorded.append(fields["key"])
        return True

    runtime = sftp_harness(process_data=process_payload)

    async with asyncssh.connect(
        "127.0.0.1",
        port=runtime.port,
        username="upload",
        password="secret",
        known_hosts=None,
    ) as conn:
        async with conn.start_sftp_client() as client:
            async with client.open("../escape.txt", "w", encoding=None) as handle:  # noqa: SIM117
                await handle.write(b"forbidden")

    _wait_for(lambda: recorded, timeout=5)
    assert recorded == ["escape.txt"]
    assert not (runtime.drop_directory.parent / "escape.txt").exists()


async def test_sftp_agent_handles_large_file_upload(sftp_harness) -> None:
    seen: list[str] = []

    def process_payload(fields: Dict[str, Any]) -> bool:
        seen.append(fields["key"])
        return True

    runtime = sftp_harness(process_data=process_payload)

    large_payload = json.dumps({"blob": "x" * (2 * 1024 * 1024)}).encode()
    await _sftp_upload(runtime.port, "bulk/data.json", large_payload)

    _wait_for(lambda: seen, timeout=10)
    _assert_queue_drained(runtime.agent)
    assert seen == ["bulk/data.json"]
    assert not (runtime.drop_directory / "bulk/data.json").exists()


async def test_sftp_agent_shutdown_during_active_transfer(sftp_harness) -> None:
    processing_started = threading.Event()

    def slow_processor(_fields: Dict[str, Any]) -> bool:
        processing_started.set()
        time.sleep(0.5)
        return True

    runtime = sftp_harness(process_data=slow_processor)

    await _sftp_upload(runtime.port, "slow/transfer.bin", b"payload")

    assert processing_started.wait(timeout=5)
    runtime.stop()

    assert not runtime.thread.is_alive()


@pytest.fixture
def e2e_pipeline(monkeypatch):
    loader_calls: list[tuple[str, Dict[str, Any]]] = []
    transformer_calls: list[tuple[Iterable[Dict[str, Any]], Dict[str, Any], Dict[str, Any]]] = []
    send_calls: list[tuple[Any, Dict[str, Any]]] = []
    send_result = {"value": True}

    class StubDataLoader:
        def __init__(self, config: Dict[str, Any]) -> None:
            self.config = config

        def load_data(self, input_type: str, input_fields: Dict[str, Any]) -> Dict[str, Any]:
            loader_calls.append((input_type, dict(input_fields)))
            file_path = Path(input_fields["file_path"])
            data = json.loads(file_path.read_text())
            metadata = {
                "file_path": str(file_path),
                "relative_key": input_fields["key"],
                "cleanup": False,
            }
            return {"data": [data], "metadata": metadata}

    class StubTransformer:
        def __init__(self, config: Dict[str, Any]) -> None:
            self.config = config

        def transform_content(
            self,
            data: Iterable[Dict[str, Any]],
            data_fields: Dict[str, Any],
            format_options: Dict[str, Any],
        ) -> Iterable[Dict[str, Any]]:
            transformer_calls.append((list(data), dict(data_fields), dict(format_options)))
            return [{"key": data_fields["key"], "payload": list(data)}]

    def fake_send_data(transformed_data: Any, destination_config: Dict[str, Any]) -> bool:
        send_calls.append((transformed_data, dict(destination_config)))
        return bool(send_result["value"])

    monkeypatch.setattr("logging_agent.data_processor.DataLoader", StubDataLoader)
    monkeypatch.setattr("logging_agent.data_processor.Transformer", StubTransformer)
    monkeypatch.setattr("logging_agent.sender.Sender.send_data", fake_send_data)
    monkeypatch.setattr(
        "logging_agent.data_processor.CloudWAAPProcessor.identify_log_type",
        lambda *_args, **_kwargs: "Access",
    )
    monkeypatch.setattr(
        "logging_agent.data_processor.CloudWAAPProcessor.extract_metadata",
        lambda key, product, log_type: {"key": key, "product": product, "log_type": log_type},
    )
    monkeypatch.setattr("logging_agent.data_processor.Utility.cleanup", lambda _path: None)

    return {
        "loader_calls": loader_calls,
        "transformer_calls": transformer_calls,
        "send_calls": send_calls,
        "set_send_result": lambda value: send_result.update({"value": value}),
    }


async def test_sftp_end_to_end_success(sftp_harness, e2e_pipeline) -> None:
    e2e_pipeline["set_send_result"](True)
    runtime = sftp_harness(extra_config={"num_worker_threads": 1})

    payload = {"event": "success"}
    await _sftp_upload(runtime.port, "ingest/success.json", json.dumps(payload).encode())

    _wait_for(lambda: e2e_pipeline["send_calls"], timeout=10)
    _assert_queue_drained(runtime.agent)

    assert e2e_pipeline["loader_calls"]
    assert e2e_pipeline["transformer_calls"]
    transformed_data, destination = e2e_pipeline["send_calls"][0]
    assert transformed_data[0]["payload"][0] == payload
    assert destination["output_type"] == runtime.agent.agent_config["output"]["type"]
    assert not (runtime.drop_directory / "ingest/success.json").exists()


async def test_sftp_end_to_end_failure(sftp_harness, e2e_pipeline) -> None:
    e2e_pipeline["set_send_result"](False)
    runtime = sftp_harness(extra_config={"num_worker_threads": 1})

    outcomes: list[bool] = []
    original_process = runtime.agent.data_processor.process_data

    def wrapped_process(fields: Dict[str, Any]) -> bool:
        result = original_process(fields)
        outcomes.append(result)
        if not result:
            Path(fields["file_path"]).unlink(missing_ok=True)
        return result

    runtime.agent.data_processor.process_data = wrapped_process  # type: ignore[assignment]

    payload = {"event": "failure"}
    await _sftp_upload(runtime.port, "ingest/failure.json", json.dumps(payload).encode())

    _wait_for(lambda: outcomes, timeout=10)
    assert outcomes == [False]
    assert e2e_pipeline["send_calls"]
    _assert_queue_drained(runtime.agent)
    assert not (runtime.drop_directory / "ingest/failure.json").exists()

