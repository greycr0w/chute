"""Socket helper behavior that must stay shared across relay endpoints."""

from __future__ import annotations

import chute._sockets as sockets


class _FakeSocket:
    def __init__(self) -> None:
        self.calls: list[tuple[int, int, int]] = []

    def setsockopt(self, level: int, opt: int, value: int) -> None:
        self.calls.append((level, opt, value))


class _FakeWriter:
    def __init__(self, sock: _FakeSocket | None) -> None:
        self.sock = sock

    def get_extra_info(self, name: str) -> object:
        if name == "socket":
            return self.sock
        return None


def test_enable_tcp_keepalive_sets_socket_options(monkeypatch) -> None:
    monkeypatch.setattr(sockets.socket, "TCP_KEEPIDLE", 9001, raising=False)
    monkeypatch.setattr(sockets.socket, "TCP_KEEPINTVL", 9002, raising=False)
    monkeypatch.setattr(sockets.socket, "TCP_KEEPCNT", 9003, raising=False)

    sock = _FakeSocket()

    sockets.enable_tcp_keepalive(_FakeWriter(sock))

    assert sock.calls == [
        (sockets.socket.SOL_SOCKET, sockets.socket.SO_KEEPALIVE, 1),
        (sockets.socket.IPPROTO_TCP, sockets.socket.TCP_KEEPIDLE, sockets._KEEPALIVE_IDLE),
        (
            sockets.socket.IPPROTO_TCP,
            sockets.socket.TCP_KEEPINTVL,
            sockets._KEEPALIVE_INTERVAL,
        ),
        (sockets.socket.IPPROTO_TCP, sockets.socket.TCP_KEEPCNT, sockets._KEEPALIVE_COUNT),
    ]


def test_enable_tcp_keepalive_ignores_streams_without_socket() -> None:
    sockets.enable_tcp_keepalive(_FakeWriter(None))
