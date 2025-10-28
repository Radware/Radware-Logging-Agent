from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Tuple

from logging_agent.sender import Sender
from logging_agent import sender as sender_module


@dataclass
class _DummyTLSSocket:
    sent: List[bytes] = field(default_factory=list)

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)

    def close(self) -> None:  # pragma: no cover - no-op
        return None


@dataclass
class _DummyContext:
    socket: _DummyTLSSocket = field(default_factory=_DummyTLSSocket)

    def wrap_socket(self, sock, server_hostname: str) -> _DummyTLSSocket:
        return self.socket


@dataclass
class _DummySocket:
    connected_to: Tuple[str, int] | None = None

    def connect(self, address: Tuple[str, int]) -> None:
        self.connected_to = address

    def close(self) -> None:  # pragma: no cover - no-op
        return None


def test_send_tls_tcp_batch_uses_single_payload(monkeypatch):
    dummy_socket = _DummySocket()
    dummy_context = _DummyContext()

    monkeypatch.setattr(sender_module.socket, "socket", lambda *args, **kwargs: dummy_socket)
    monkeypatch.setattr(sender_module.ssl, "_create_unverified_context", lambda: dummy_context)

    data = "event-one\nevent-two"
    config = {
        "destination": "127.0.0.1",
        "port": 6514,
        "output_format": "json",
        "delimiter": "\n",
        "tls_config": {"verify": False},
        "batch_mode": True,
    }

    assert Sender.send_tls_tcp(data, config)

    assert dummy_socket.connected_to == ("127.0.0.1", 6514)
    assert dummy_context.socket.sent == [data.encode("utf-8")]


def test_send_tls_tcp_batch_with_list(monkeypatch):
    dummy_socket = _DummySocket()
    dummy_context = _DummyContext()

    monkeypatch.setattr(sender_module.socket, "socket", lambda *args, **kwargs: dummy_socket)
    monkeypatch.setattr(sender_module.ssl, "_create_unverified_context", lambda: dummy_context)

    payload = ["event-one", "event-two"]
    config = {
        "destination": "127.0.0.1",
        "port": 6514,
        "output_format": "json",
        "delimiter": "\n",
        "tls_config": {"verify": False},
        "batch_mode": True,
    }

    assert Sender.send_tls_tcp(payload, config)

    expected = "event-one\nevent-two".encode("utf-8")
    assert dummy_context.socket.sent == [expected]
