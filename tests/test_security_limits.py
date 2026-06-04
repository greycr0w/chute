"""Behavioral regression tests for the audit hardening that test_security.py
didn't cover: connection caps actually reject, the per-stream queue resets a
stalled consumer, the pinned cert can't sign trusted children (CA:FALSE), and
the control channel negotiates no permessage-deflate.
"""

from __future__ import annotations

import asyncio
import contextlib
import datetime as dt
import http.client
import json
import logging
import os
import signal
import socket
import ssl
from pathlib import Path
from typing import cast

import pytest
import websockets
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

import chute.mux
import chute.server
from chute import certs, protocol
from chute.auth import Budget
from chute.mux import Mux, Stream
from chute.server import Server


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


async def _quiet_cancel(*tasks: asyncio.Future) -> None:
    for t in tasks:
        t.cancel()
    for t in tasks:
        try:
            await t
        except (asyncio.CancelledError, Exception):
            pass


def _http_get(port: int, path: str = "/") -> tuple[int, bytes]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        conn.request("GET", path)
        r = conn.getresponse()
        return r.status, r.read()
    finally:
        conn.close()


def _tls_handshake(port: int, ctx: ssl.SSLContext) -> tuple[str, tuple[str, str, int]]:
    with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
        with ctx.wrap_socket(raw, server_hostname="127.0.0.1") as ssock:
            version = ssock.version()
            cipher = ssock.cipher()
            assert version is not None
            assert cipher is not None
            return version, cipher


class _FakeListener:
    def __init__(self) -> None:
        self.close_calls: list[tuple[tuple[object, ...], dict[str, object]]] = []
        self.wait_closed_called = False

    def close(self, *args: object, **kwargs: object) -> None:
        self.close_calls.append((args, kwargs))

    async def wait_closed(self) -> None:
        self.wait_closed_called = True


class _FakeDrainMux:
    def __init__(self) -> None:
        self.drain_timeouts: list[float] = []

    async def drain(self, timeout: float) -> None:
        self.drain_timeouts.append(timeout)


class _FakeVisitorWriter:
    def __init__(self, peer: tuple[str, int] = ("198.51.100.9", 50000)) -> None:
        self.peer = peer
        self.data = bytearray()
        self.closed = False
        self.eof_written = False

    def get_extra_info(self, name: str) -> object:
        if name == "peername":
            return self.peer
        if name == "socket":
            return None
        return None

    def write(self, data: bytes) -> None:
        self.data.extend(data)

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True

    def can_write_eof(self) -> bool:
        return True

    def write_eof(self) -> None:
        self.eof_written = True


class _NeverReader:
    async def read(self, _limit: int = -1) -> bytes:
        await asyncio.Future()
        raise AssertionError("unreachable")


class _SequencedAgentWS:
    remote_address = ("127.0.0.1", 51000)

    def __init__(self) -> None:
        self.recv_done = False
        self.sent: list[str] = []
        self.closed: list[tuple[int, str]] = []

    async def recv(self) -> str:
        self.recv_done = True
        return json.dumps(
            {
                "type": "auth",
                "token": "secret",
                "scheme": "http",
                "v": protocol.VERSION,
            }
        )

    async def send(self, data: str) -> None:
        self.sent.append(data)

    async def close(self, code: int = 1000, reason: str = "") -> None:
        self.closed.append((code, reason))


class _IdleRelayStream:
    id = 1
    reset_by_peer = False

    def __init__(self) -> None:
        self.sent: list[bytes] = []
        self.sent_eof = False
        self.reset_called = False
        self.closed = False
        self.acked: list[int] = []

    async def send(self, data: bytes) -> None:
        self.sent.append(data)

    async def send_eof(self) -> None:
        self.sent_eof = True

    async def read(self) -> bytes | None:
        await asyncio.Future()
        raise AssertionError("unreachable")

    async def ack(self, n: int) -> None:
        self.acked.append(n)

    async def reset(self) -> None:
        self.reset_called = True

    def close(self) -> None:
        self.closed = True


class _ResponseRelayStream(_IdleRelayStream):
    def __init__(self, chunks: list[bytes], *, delay: float) -> None:
        super().__init__()
        self._chunks = chunks
        self._delay = delay

    async def read(self) -> bytes | None:
        if not self._chunks:
            return None
        await asyncio.sleep(self._delay)
        return self._chunks.pop(0)


def _fake_registration() -> chute.server.TunnelRegistration:
    return chute.server.TunnelRegistration(
        mux=cast(Mux, object()),
        account_id="acct",
        budget=Budget(),
        connection_id="conn",
        credential_id=None,
        scheme="http",
        public_url="http://example.test/",
        agent_ip=None,
        requested_subdomain=None,
        accepting_visitors=True,
    )


def test_websockets_top_level_uses_new_asyncio_implementation() -> None:
    assert websockets.serve.__module__ == "websockets.asyncio.server"
    assert websockets.connect.__module__ == "websockets.asyncio.client"


def test_systemd_notify_sends_datagram(monkeypatch) -> None:
    notify_socket = Path("/tmp") / f"chute-notify-{os.getpid()}-{id(monkeypatch)}.sock"
    notify_socket.unlink(missing_ok=True)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        sock.bind(str(notify_socket))
        sock.settimeout(1)
        monkeypatch.setenv("NOTIFY_SOCKET", str(notify_socket))

        assert chute.server._systemd_notify("READY=1")

        assert sock.recv(1024) == b"READY=1"
    finally:
        sock.close()
        notify_socket.unlink(missing_ok=True)


def test_systemd_watchdog_interval_uses_half_systemd_deadline(monkeypatch) -> None:
    monkeypatch.setenv("WATCHDOG_USEC", "30000000")
    monkeypatch.delenv("WATCHDOG_PID", raising=False)
    assert chute.server._systemd_watchdog_interval() == 15.0

    monkeypatch.setenv("WATCHDOG_PID", str(os.getpid()))
    assert chute.server._systemd_watchdog_interval() == 15.0

    monkeypatch.setenv("WATCHDOG_PID", str(os.getpid() + 1))
    assert chute.server._systemd_watchdog_interval() is None

    monkeypatch.setenv("WATCHDOG_PID", "not-a-pid")
    assert chute.server._systemd_watchdog_interval() is None


async def test_server_sigterm_stops_accepting_and_drains_live_muxes(monkeypatch) -> None:
    signal_handlers: dict[signal.Signals, object] = {}
    removed_handlers: list[signal.Signals] = []
    notifications: list[str] = []
    control = _FakeListener()
    public = _FakeListener()
    mux = _FakeDrainMux()

    class _FakeLoop:
        def add_signal_handler(self, sig: signal.Signals, callback: object) -> None:
            signal_handlers[sig] = callback

        def remove_signal_handler(self, sig: signal.Signals) -> bool:
            removed_handlers.append(sig)
            return True

    async def _fake_serve(*_args: object, **_kwargs: object) -> _FakeListener:
        return control

    async def _fake_start_server(*_args: object, **_kwargs: object) -> _FakeListener:
        return public

    monkeypatch.setattr(chute.server.websockets, "serve", _fake_serve)
    monkeypatch.setattr(chute.server.asyncio, "start_server", _fake_start_server)
    monkeypatch.setattr(chute.server.asyncio, "get_running_loop", lambda: _FakeLoop())
    monkeypatch.setattr(chute.server, "_systemd_watchdog_interval", lambda: None)
    monkeypatch.setattr(
        chute.server, "_systemd_notify", lambda message, **_kwargs: notifications.append(message)
    )

    srv = Server(token="secret", public_host="127.0.0.1", control_host="127.0.0.1")
    monkeypatch.setattr(srv, "_live_muxes", lambda: [mux])

    task = asyncio.ensure_future(srv.serve())
    try:
        for _ in range(100):
            if signal.SIGTERM in signal_handlers:
                break
            await asyncio.sleep(0.01)
        assert signal.SIGINT in signal_handlers
        assert signal.SIGTERM in signal_handlers
        callback = signal_handlers[signal.SIGTERM]
        assert callable(callback)
        callback()
        await asyncio.wait_for(task, timeout=1)
    finally:
        if not task.done():
            await _quiet_cancel(task)

    assert control.close_calls == [((), {"close_connections": False})]
    assert public.close_calls == [((), {})]
    assert control.wait_closed_called
    assert public.wait_closed_called
    assert mux.drain_timeouts == [chute.server._GRACEFUL_DRAIN_TIMEOUT]
    assert signal.SIGINT in removed_handlers
    assert signal.SIGTERM in removed_handlers
    assert "READY=1\nSTATUS=chute accepting tunnels" in notifications
    assert "STOPPING=1\nSTATUS=chute draining tunnels" in notifications


async def test_server_startup_failure_closes_partial_listeners(monkeypatch) -> None:
    notifications: list[str] = []
    control = _FakeListener()
    public = _FakeListener()
    start_calls = 0

    async def _fake_serve(*_args: object, **_kwargs: object) -> _FakeListener:
        return control

    async def _fake_start_server(*_args: object, **_kwargs: object) -> _FakeListener:
        nonlocal start_calls
        start_calls += 1
        if start_calls == 1:
            return public
        raise OSError("edge tls bind failed")

    monkeypatch.setattr(chute.server.websockets, "serve", _fake_serve)
    monkeypatch.setattr(chute.server.asyncio, "start_server", _fake_start_server)
    monkeypatch.setattr(
        chute.server, "_systemd_notify", lambda message, **_kwargs: notifications.append(message)
    )

    srv = Server(token="secret", public_host="127.0.0.1", control_host="127.0.0.1")
    srv._public_tls_context = cast(ssl.SSLContext, object())

    with pytest.raises(OSError, match="edge tls bind failed"):
        await srv.serve()

    assert control.close_calls == [((), {})]
    assert public.close_calls == [((), {})]
    assert control.wait_closed_called
    assert public.wait_closed_called
    assert notifications == []


def test_data_path_logs_are_metadata_only_and_rate_limited(monkeypatch, caplog) -> None:
    srv = Server(token="secret")
    ticks = iter([100.0, 101.0, 161.0])
    monkeypatch.setattr(chute.server.time, "monotonic", lambda: next(ticks))
    caplog.set_level(logging.WARNING, logger="chute.server")

    for _ in range(3):
        srv._log_data_path(
            logging.WARNING,
            "visitor_ip_limit",
            visitor_ip="198.51.100.9",
            detail="cap",
        )

    messages = [record.getMessage() for record in caplog.records]
    assert len(messages) == 2
    assert "reason=visitor_ip_limit" in messages[0]
    assert "visitor_ip='198.51.100.9'" in messages[0]
    assert "suppressed=1" in messages[1]
    assert "GET /" not in caplog.text
    assert "Cookie:" not in caplog.text


async def test_server_runtime_buffer_limits_are_explicit(monkeypatch) -> None:
    serve_calls: list[dict[str, object]] = []
    start_server_calls: list[dict[str, object]] = []
    notifications: list[str] = []

    class _FakeServer:
        def close(self, **_kwargs: object) -> None:
            return None

        async def wait_closed(self) -> None:
            return None

    async def _fake_serve(*_args: object, **kwargs: object) -> _FakeServer:
        serve_calls.append(kwargs)
        return _FakeServer()

    async def _fake_start_server(*_args: object, **kwargs: object) -> _FakeServer:
        start_server_calls.append(kwargs)
        return _FakeServer()

    monkeypatch.setattr(chute.server.websockets, "serve", _fake_serve)
    monkeypatch.setattr(chute.server.asyncio, "start_server", _fake_start_server)
    monkeypatch.setattr(
        chute.server, "_systemd_notify", lambda message, **_kwargs: notifications.append(message)
    )
    monkeypatch.setattr(chute.server, "_systemd_watchdog_interval", lambda: None)

    srv = Server(token="secret", public_host="127.0.0.1", control_host="127.0.0.1")
    task = asyncio.ensure_future(srv.serve())
    try:
        await asyncio.sleep(0.05)
        assert serve_calls
        assert start_server_calls
        control_kwargs = serve_calls[0]
        public_kwargs = start_server_calls[0]
        assert control_kwargs["max_size"] == chute.server._MAX_WS_MESSAGE
        assert control_kwargs["max_queue"] == chute.server._WS_MAX_QUEUE
        assert control_kwargs["write_limit"] == chute.server._WS_WRITE_LIMIT
        assert control_kwargs["compression"] is None
        assert public_kwargs["limit"] == chute.server._MAX_REQUEST_HEAD
        assert chute.server._STREAM_READER_LIMIT == chute.server._MAX_REQUEST_HEAD
        assert "READY=1\nSTATUS=chute accepting tunnels" in notifications
    finally:
        await _quiet_cancel(task)


def test_metrics_listener_is_loopback_only_when_enabled() -> None:
    Server(token="secret", metrics_host="127.0.0.1", metrics_port=0)
    with pytest.raises(ValueError, match="loopback-only"):
        Server(token="secret", metrics_host="0.0.0.0", metrics_port=9100)


async def test_metrics_endpoint_serves_healthz_and_prometheus_text() -> None:
    srv = Server(
        token="secret",
        max_control_conns=3,
        max_auth_conns=2,
        max_visitors=4,
        max_visitors_per_ip=None,
    )
    srv._relay_bytes_to_agent = 123
    srv._relay_bytes_to_visitor = 456
    srv._control_in_flight = 1
    srv._auth_in_flight = 2
    srv._visitors_in_flight = 3
    srv._control_busy = 5
    srv._auth_busy = 6
    srv._visitor_pool_busy = 7
    srv._visitor_ip_limited = 8
    srv._event_generated["auth_rejected"] = 2
    srv._policy_update_poll_failures = 9
    srv._policy_updates_applied = 10
    srv._policy_updates_rejected = 11
    srv._lease_renewals_succeeded = 12
    srv._lease_renewals_failed = 13
    srv._lease_renewals_invalid = 14
    srv._lease_renewals_revoked = 15
    srv._lease_revocations = 16
    srv._lease_expirations = 17
    listener = await asyncio.start_server(
        srv._handle_metrics,
        "127.0.0.1",
        0,
        limit=chute.server._METRICS_REQUEST_HEAD_LIMIT,
    )
    assert listener.sockets is not None
    port = listener.sockets[0].getsockname()[1]
    try:
        status, body = await asyncio.to_thread(_http_get, port, "/healthz")
        assert status == 200
        assert body == b"ok\n"

        def _get_metrics() -> tuple[int, str | None, str]:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            try:
                conn.request("GET", "/metrics")
                response = conn.getresponse()
                return response.status, response.getheader("Content-Type"), response.read().decode()
            finally:
                conn.close()

        response_status, content_type, body = await asyncio.to_thread(_get_metrics)
        assert response_status == 200
        assert content_type == "text/plain; version=0.0.4; charset=utf-8"
        assert "# TYPE chute_active_tunnels gauge\nchute_active_tunnels 0\n" in body
        assert "# TYPE chute_control_capacity gauge\nchute_control_capacity 3\n" in body
        assert "# TYPE chute_control_in_flight gauge\nchute_control_in_flight 1\n" in body
        assert "# TYPE chute_auth_capacity gauge\nchute_auth_capacity 2\n" in body
        assert "# TYPE chute_auth_in_flight gauge\nchute_auth_in_flight 2\n" in body
        assert "# TYPE chute_visitor_capacity gauge\nchute_visitor_capacity 4\n" in body
        assert "# TYPE chute_visitors_in_flight gauge\nchute_visitors_in_flight 3\n" in body
        assert "# TYPE chute_visitor_ip_capacity gauge\nchute_visitor_ip_capacity -1\n" in body
        assert "# TYPE chute_control_busy_total counter\nchute_control_busy_total 5\n" in body
        assert "# TYPE chute_auth_busy_total counter\nchute_auth_busy_total 6\n" in body
        assert (
            "# TYPE chute_visitor_pool_busy_total counter\nchute_visitor_pool_busy_total 7\n"
            in body
        )
        assert (
            "# TYPE chute_visitor_ip_limited_total counter\nchute_visitor_ip_limited_total 8\n"
            in body
        )
        assert "# TYPE chute_bytes_to_agent_total counter\nchute_bytes_to_agent_total 123\n" in body
        assert (
            "# TYPE chute_bytes_to_visitor_total counter\nchute_bytes_to_visitor_total 456\n"
            in body
        )
        assert (
            "# TYPE chute_policy_update_poll_failures_total counter\n"
            "chute_policy_update_poll_failures_total 9\n" in body
        )
        assert (
            "# TYPE chute_policy_updates_applied_total counter\n"
            "chute_policy_updates_applied_total 10\n" in body
        )
        assert (
            "# TYPE chute_policy_updates_rejected_total counter\n"
            "chute_policy_updates_rejected_total 11\n" in body
        )
        assert (
            "# TYPE chute_lease_renewals_succeeded_total counter\n"
            "chute_lease_renewals_succeeded_total 12\n" in body
        )
        assert (
            "# TYPE chute_lease_renewals_failed_total counter\n"
            "chute_lease_renewals_failed_total 13\n" in body
        )
        assert (
            "# TYPE chute_lease_renewals_invalid_total counter\n"
            "chute_lease_renewals_invalid_total 14\n" in body
        )
        assert (
            "# TYPE chute_lease_renewals_revoked_total counter\n"
            "chute_lease_renewals_revoked_total 15\n" in body
        )
        assert (
            "# TYPE chute_lease_revocations_total counter\nchute_lease_revocations_total 16\n"
            in body
        )
        assert (
            "# TYPE chute_lease_expirations_total counter\nchute_lease_expirations_total 17\n"
            in body
        )
        assert (
            "# TYPE chute_event_auth_rejected_generated_total counter\n"
            "chute_event_auth_rejected_generated_total 2\n" in body
        )
        assert "# TYPE chute_event_queue_depth gauge\nchute_event_queue_depth 0\n" in body
        assert (
            "# TYPE chute_event_queue_dropped_total counter\n"
            "chute_event_queue_dropped_total 0\n" in body
        )
        assert "account_id" not in body
        assert "label" not in body

        status, body = await asyncio.to_thread(_http_get, port, "/missing")
        assert status == 404
        assert body == b"not found\n"
    finally:
        listener.close()
        await listener.wait_closed()


async def test_server_metrics_listener_starts_and_closes_with_daemon(monkeypatch) -> None:
    listeners = [_FakeListener(), _FakeListener(), _FakeListener()]
    start_calls: list[tuple[tuple[object, ...], dict[str, object]]] = []

    async def _fake_serve(*_args: object, **_kwargs: object) -> _FakeListener:
        return listeners[0]

    async def _fake_start_server(*args: object, **kwargs: object) -> _FakeListener:
        start_calls.append((args, kwargs))
        return listeners[len(start_calls)]

    monkeypatch.setattr(chute.server.websockets, "serve", _fake_serve)
    monkeypatch.setattr(chute.server.asyncio, "start_server", _fake_start_server)
    monkeypatch.setattr(chute.server, "_systemd_watchdog_interval", lambda: None)

    srv = Server(
        token="secret",
        public_host="127.0.0.1",
        control_host="127.0.0.1",
        metrics_port=9100,
    )
    task = asyncio.ensure_future(srv.serve())
    try:
        await asyncio.sleep(0.05)
        assert len(start_calls) == 2
        metrics_args, metrics_kwargs = start_calls[1]
        assert metrics_args[0] == srv._handle_metrics
        assert metrics_args[1] == "127.0.0.1"
        assert metrics_args[2] == 9100
        assert metrics_kwargs["limit"] == chute.server._METRICS_REQUEST_HEAD_LIMIT
    finally:
        await _quiet_cancel(task)

    assert listeners[2].close_calls == [((), {})]
    assert listeners[2].wait_closed_called


def test_source_avoids_deprecated_websocket_exception_close_attrs() -> None:
    offenders: list[str] = []
    for path in (Path(__file__).resolve().parents[1] / "src" / "chute").glob("*.py"):
        for lineno, line in enumerate(path.read_text().splitlines(), start=1):
            if "exc.code" in line or "exc.reason" in line:
                offenders.append(
                    f"{path.relative_to(Path(__file__).resolve().parents[1])}:{lineno}"
                )

    assert offenders == []


async def test_agent_hello_recv_completes_before_mux_run(monkeypatch) -> None:
    ran = False

    class _FakeMux:
        def __init__(self, ws: _SequencedAgentWS, **_kwargs: object) -> None:
            assert ws.recv_done
            self.ws = ws

        async def run(self) -> None:
            nonlocal ran
            assert self.ws.recv_done
            ran = True

    monkeypatch.setattr(chute.server, "Mux", _FakeMux)

    ws = _SequencedAgentWS()
    srv = Server(token="secret", public_host="127.0.0.1", control_host="127.0.0.1")

    await srv._handle_agent(ws)

    assert ran
    assert ws.closed == []
    assert json.loads(ws.sent[0])["type"] == "ready"


async def test_request_head_cap_is_explicit_before_routing() -> None:
    reader = asyncio.StreamReader(limit=chute.server._MAX_REQUEST_HEAD)
    reader.feed_data(b"GET / HTTP/1.1\r\nX-Bloat: " + b"a" * chute.server._MAX_REQUEST_HEAD)

    srv = Server(token="secret")
    with pytest.raises(asyncio.LimitOverrunError):
        await srv._read_request_head(reader)


async def test_oversized_request_head_returns_400_before_routing(tmp_path: Path, caplog) -> None:
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    certs.generate("127.0.0.1", cert, key)
    pp, cp = _free_port(), _free_port()
    server = Server(
        token="secret",
        public_host="127.0.0.1",
        public_port=pp,
        control_host="127.0.0.1",
        control_port=cp,
        public_url=f"http://127.0.0.1:{pp}/",
        ssl_context=certs.server_ssl_context(cert, key),
    )
    task = asyncio.ensure_future(server.serve())
    caplog.set_level(logging.WARNING, logger="chute.server")
    await asyncio.sleep(0.3)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", pp)
        try:
            oversized_head = (
                b"GET / HTTP/1.1\r\n"
                b"Host: example.test\r\n"
                b"X-Bloat: " + b"a" * chute.server._MAX_REQUEST_HEAD + b"\r\n\r\n"
            )
            writer.write(oversized_head)
            await writer.drain()

            response = await asyncio.wait_for(reader.read(1024), timeout=5)
            assert response.startswith(b"HTTP/1.1 400 Bad Request"), response[:64]
            assert "request_head_too_large" in caplog.text
            assert "X-Bloat" not in caplog.text
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
    finally:
        await _quiet_cancel(task)


async def test_relay_idle_timeout_resets_stream_and_closes_visitor() -> None:
    srv = Server(token="secret", relay_idle_timeout=0.05)
    stream = _IdleRelayStream()
    writer = _FakeVisitorWriter()
    registration = _fake_registration()

    await asyncio.wait_for(
        srv._relay(
            _NeverReader(),
            writer,
            stream,
            b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n",
            registration,
            "default",
            "example.test",
            "198.51.100.9",
        ),
        timeout=1,
    )

    assert stream.sent == [b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"]
    assert stream.reset_called
    assert stream.closed
    assert writer.closed


async def test_relay_idle_timeout_counts_bytes_in_either_direction() -> None:
    srv = Server(token="secret", relay_idle_timeout=0.05)
    stream = _ResponseRelayStream([b"hello", b" world"], delay=0.02)
    writer = _FakeVisitorWriter()
    registration = _fake_registration()

    await asyncio.wait_for(
        srv._relay(
            _NeverReader(),
            writer,
            stream,
            b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n",
            registration,
            "default",
            "example.test",
            "198.51.100.9",
        ),
        timeout=1,
    )

    assert writer.data == b"hello world"
    assert writer.eof_written
    assert not stream.reset_called
    assert stream.acked == [5, 6]
    assert stream.closed
    assert writer.closed


async def test_request_eof_does_not_cancel_delayed_response_body() -> None:
    srv = Server(token="secret")
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
    stream = _ResponseRelayStream([response[:38], response[38:]], delay=0.02)
    writer = _FakeVisitorWriter()
    registration = _fake_registration()
    reader = asyncio.StreamReader()
    reader.feed_eof()
    initial = b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"

    await asyncio.wait_for(
        srv._relay(
            reader,
            writer,
            stream,
            initial,
            registration,
            "default",
            "example.test",
            "198.51.100.9",
        ),
        timeout=1,
    )

    assert stream.sent == [initial]
    assert stream.sent_eof
    assert writer.data == response
    assert writer.eof_written
    assert writer.closed
    assert stream.acked == [38, len(response) - 38]
    assert stream.closed


# -- 1. control-channel connection cap actually rejects -----------------------
async def test_control_connection_cap_rejects(tmp_path: Path) -> None:
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    certs.generate("127.0.0.1", cert, key)
    cp = _free_port()
    # cap 0 => no pre-auth handshake slot is ever free => every dial is rejected
    # (fast, via the wait_for(acquire) timeout) with 1013, NOT the 4000 hello path.
    server = Server(
        token="secret",
        public_host="127.0.0.1",
        public_port=_free_port(),
        control_host="127.0.0.1",
        control_port=cp,
        ssl_context=certs.server_ssl_context(cert, key),
        max_control_conns=0,
        hello_timeout=0.3,
    )
    task = asyncio.ensure_future(server.serve())
    await asyncio.sleep(0.3)
    try:
        ctx = certs.client_ssl_context(cert)
        async with websockets.connect(f"wss://127.0.0.1:{cp}", ssl=ctx, open_timeout=5) as ws:
            with pytest.raises(websockets.exceptions.ConnectionClosed):
                await asyncio.wait_for(ws.recv(), timeout=5)
            assert ws.close_code == 1013  # "server busy" — the cap rejected it
        assert server._control_busy == 1
    finally:
        await _quiet_cancel(task)


# -- 2. visitor connection cap returns 503 ------------------------------------
async def test_visitor_cap_returns_503(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(chute.server, "_VISITOR_ACQUIRE_TIMEOUT", 0.3)
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    certs.generate("127.0.0.1", cert, key)
    pp, cp = _free_port(), _free_port()
    server = Server(
        token="secret",
        public_host="127.0.0.1",
        public_port=pp,
        control_host="127.0.0.1",
        control_port=cp,
        public_url=f"http://127.0.0.1:{pp}/",
        ssl_context=certs.server_ssl_context(cert, key),
        max_visitors=0,  # no visitor slots => every request is shed
    )
    task = asyncio.ensure_future(server.serve())
    await asyncio.sleep(0.3)
    try:
        status, body = await asyncio.to_thread(_http_get, pp, "/")
        assert status == 503
        assert b"server busy" in body
        assert server._visitor_pool_busy == 1
    finally:
        await _quiet_cancel(task)


def test_visitor_ip_budget_counts_non_loopback_and_exempts_loopback() -> None:
    srv = Server(token="secret", max_visitors_per_ip=2)

    first_ok, first_key = srv._try_acquire_visitor_ip("198.51.100.9")
    second_ok, second_key = srv._try_acquire_visitor_ip("198.51.100.9")
    third_ok, third_key = srv._try_acquire_visitor_ip("198.51.100.9")

    assert (first_ok, first_key) == (True, "198.51.100.9")
    assert (second_ok, second_key) == (True, "198.51.100.9")
    assert (third_ok, third_key) == (False, "198.51.100.9")
    assert srv._visitor_ips == {"198.51.100.9": 2}

    srv._release_visitor_ip(first_key)
    assert srv._visitor_ips == {"198.51.100.9": 1}
    srv._release_visitor_ip(second_key)
    assert srv._visitor_ips == {}

    assert srv._try_acquire_visitor_ip("127.0.0.1") == (True, None)
    assert srv._try_acquire_visitor_ip("::1") == (True, None)
    assert srv._try_acquire_visitor_ip("::ffff:127.0.0.1") == (True, None)
    assert srv._visitor_ips == {}

    mapped_ok, mapped_key = srv._try_acquire_visitor_ip("::ffff:198.51.100.9")
    assert (mapped_ok, mapped_key) == (True, "198.51.100.9")
    assert srv._visitor_ips == {"198.51.100.9": 1}
    srv._release_visitor_ip(mapped_key)
    assert srv._visitor_ips == {}

    assert srv._visitor_ip_key("2001:db8:abcd:1234::1") == "2001:db8:abcd:1234::/64"
    v6_first_ok, v6_first_key = srv._try_acquire_visitor_ip("2001:db8:abcd:1234::1")
    v6_second_ok, v6_second_key = srv._try_acquire_visitor_ip("2001:db8:abcd:1234::2")
    v6_third_ok, v6_third_key = srv._try_acquire_visitor_ip("2001:db8:abcd:1234::3")
    other_prefix_ok, other_prefix_key = srv._try_acquire_visitor_ip("2001:db8:abcd:1235::1")

    assert (v6_first_ok, v6_first_key) == (True, "2001:db8:abcd:1234::/64")
    assert (v6_second_ok, v6_second_key) == (True, "2001:db8:abcd:1234::/64")
    assert (v6_third_ok, v6_third_key) == (False, "2001:db8:abcd:1234::/64")
    assert (other_prefix_ok, other_prefix_key) == (True, "2001:db8:abcd:1235::/64")
    srv._release_visitor_ip(v6_first_key)
    srv._release_visitor_ip(v6_second_key)
    srv._release_visitor_ip(other_prefix_key)
    assert srv._visitor_ips == {}


def test_visitor_ip_budget_can_be_disabled() -> None:
    srv = Server(token="secret", max_visitors_per_ip=None)

    for _ in range(10):
        assert srv._try_acquire_visitor_ip("198.51.100.9") == (True, None)
    assert srv._visitor_ips == {}


def test_auth_concurrency_cap_distinguishes_zero_from_default() -> None:
    defaulted = Server(token="secret", max_control_conns=5, max_auth_conns=None)
    shed_all = Server(token="secret", max_control_conns=5, max_auth_conns=0)

    assert defaulted._auth_sem.locked() is False
    assert shed_all._auth_sem.locked() is True


def test_visitor_ip_budget_map_is_hard_capped(monkeypatch) -> None:
    monkeypatch.setattr(chute.server, "_VISITOR_IP_MAX_KEYS", 2)
    srv = Server(token="secret", max_visitors_per_ip=10)

    assert srv._try_acquire_visitor_ip("198.51.100.1") == (True, "198.51.100.1")
    assert srv._try_acquire_visitor_ip("198.51.100.2") == (True, "198.51.100.2")
    assert srv._try_acquire_visitor_ip("198.51.100.3") == (False, "198.51.100.3")
    assert srv._visitor_ips == {"198.51.100.1": 1, "198.51.100.2": 1}


async def test_visitor_per_ip_cap_returns_503_before_global_pool() -> None:
    srv = Server(token="secret", max_visitors=0, max_visitors_per_ip=1)
    ok, key = srv._try_acquire_visitor_ip("198.51.100.9")
    assert (ok, key) == (True, "198.51.100.9")
    writer = _FakeVisitorWriter()

    await srv._handle_visitor(asyncio.StreamReader(), cast(asyncio.StreamWriter, writer))

    assert bytes(writer.data).startswith(b"HTTP/1.1 503 Service Unavailable")
    assert b"server busy" in writer.data
    assert writer.closed is True
    assert srv._visitor_ip_limited == 1
    assert srv._visitor_ips == {"198.51.100.9": 1}
    srv._release_visitor_ip(key)
    assert srv._visitor_ips == {}


# -- 3. a peer that floods past the hard backstop is reset (flow-control net) --
async def test_stream_flood_past_backstop_resets(monkeypatch, caplog) -> None:
    # With credit-window flow control a compliant peer never overflows; this is the
    # backstop for a peer that IGNORES its window and floods us -- a protocol
    # violation -> RESET, with the consumer woken (not buffered without bound).
    monkeypatch.setattr(chute.mux, "_STREAM_HARD_MAX", 10)
    caplog.set_level(logging.WARNING, logger="chute.mux")

    class _FakeWS:
        def __init__(self) -> None:
            self.sent: list[bytes] = []

        async def send(self, data: bytes) -> None:
            self.sent.append(data)

    ws = _FakeWS()
    mux = Mux(ws)
    s = Stream(mux, 5)
    mux._streams[5] = s

    s._feed(b"12345")
    s._feed(b"67890")  # buffered == 10, still within the backstop
    s._feed(b"over")  # 14 > 10 -> overflow -> schedules a RESET, drops the stream
    await asyncio.sleep(0.05)  # let the scheduled reset() task run

    sent_types = [protocol.decode(m)[0] for m in ws.sent]
    assert protocol.RESET in sent_types, "a peer flooding past the backstop must be RESET"
    assert 5 not in mux._streams, "overflowing stream must be removed"
    assert "reason=stream_buffer_limit" in caplog.text
    assert "detail='stream_bytes'" in caplog.text
    assert s.reset_by_peer is True
    assert await s.read() == b"12345"
    assert await s.read() == b"67890"
    assert await s.read() is None


# -- 4. CA:FALSE — a leaf minted FROM the pinned cert is rejected -------------
def _mint_child(ca_cert: Path, ca_key: Path) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    """Attacker move: with the (leaked) pinned key, forge a NEW leaf 'signed by'
    the pinned cert. This must NOT be trusted now that the pinned cert is CA:FALSE."""
    issuer = x509.load_pem_x509_certificate(ca_cert.read_bytes())
    signing_key = serialization.load_pem_private_key(ca_key.read_bytes(), password=None)
    child_key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.UTC)
    child = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "evil.example")]))
        .issuer_name(issuer.subject)
        .public_key(child_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("127.0.0.1")]), critical=False)
        .sign(signing_key, hashes.SHA256())
    )
    return child, child_key


def _mint_replacement_self_signed(cert_path: Path, key_path: Path) -> x509.Certificate:
    """Attacker move: with the leaked pinned key, mint a new self-signed leaf.

    The client pins the certificate, not just the key, so this replacement must not
    verify even though the attacker can prove possession of the original private key.
    """
    original = x509.load_pem_x509_certificate(cert_path.read_bytes())
    key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    now = dt.datetime.now(dt.UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(original.subject)
        .issuer_name(original.subject)
        .public_key(original.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(
            original.extensions.get_extension_for_class(x509.SubjectAlternativeName).value,
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(key, hashes.SHA256())
    )


async def test_pinned_cert_cannot_sign_trusted_children(tmp_path: Path) -> None:
    cert, key = tmp_path / "pin.pem", tmp_path / "pin-key.pem"
    certs.generate("127.0.0.1", cert, key)  # self-signed LEAF, CA:FALSE
    child, child_key = _mint_child(cert, key)

    cc, ck = tmp_path / "child.pem", tmp_path / "child-key.pem"
    cc.write_bytes(child.public_bytes(serialization.Encoding.PEM))
    ck.write_bytes(
        child_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )

    port = _free_port()

    async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.close()

    server = await asyncio.start_server(
        _handle, "127.0.0.1", port, ssl=certs.server_ssl_context(cc, ck)
    )
    try:
        client_ctx = certs.client_ssl_context(cert)  # trusts ONLY the pinned leaf
        with pytest.raises(ssl.SSLError):  # forged child must fail to verify
            await asyncio.open_connection(
                "127.0.0.1", port, ssl=client_ctx, server_hostname="127.0.0.1"
            )
    finally:
        server.close()
        await server.wait_closed()


async def test_pinned_cert_rejects_replacement_leaf_with_same_key(tmp_path: Path) -> None:
    cert, key = tmp_path / "pin.pem", tmp_path / "pin-key.pem"
    certs.generate("127.0.0.1", cert, key)
    replacement = _mint_replacement_self_signed(cert, key)

    replacement_cert = tmp_path / "replacement.pem"
    replacement_cert.write_bytes(replacement.public_bytes(serialization.Encoding.PEM))

    port = _free_port()

    async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.close()

    server = await asyncio.start_server(
        _handle, "127.0.0.1", port, ssl=certs.server_ssl_context(replacement_cert, key)
    )
    try:
        client_ctx = certs.client_ssl_context(cert)
        with pytest.raises(ssl.SSLError):
            await asyncio.open_connection(
                "127.0.0.1", port, ssl=client_ctx, server_hostname="127.0.0.1"
            )
    finally:
        server.close()
        await server.wait_closed()


# -- 6. a deeply-nested hello closes cleanly (4000), not an uncaught 1011 -------
async def test_nested_json_hello_closes_cleanly(tmp_path: Path) -> None:
    # json.loads on a deeply-nested payload raises RecursionError (a RuntimeError,
    # not ValueError/TypeError). Before the fix it escaped the hello except -> an
    # uncaught 1011 (retryable, so real clients reconnect-loop) that also skipped
    # the failed-auth limiter. It must be the benign close-4000 path instead (F36).
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    certs.generate("127.0.0.1", cert, key)
    cp = _free_port()
    server = Server(
        token="secret",
        public_host="127.0.0.1",
        public_port=_free_port(),
        control_host="127.0.0.1",
        control_port=cp,
        ssl_context=certs.server_ssl_context(cert, key),
    )
    task = asyncio.ensure_future(server.serve())
    await asyncio.sleep(0.3)
    try:
        ctx = certs.client_ssl_context(cert)
        async with websockets.connect(f"wss://127.0.0.1:{cp}", ssl=ctx, open_timeout=5) as ws:
            await ws.send("[" * 100_000)  # sub-max_size, but blows json's recursion
            with pytest.raises(websockets.exceptions.ConnectionClosed):
                await asyncio.wait_for(ws.recv(), timeout=5)
            assert ws.close_code == 4000  # clean "bad handshake", not 1011
    finally:
        await _quiet_cancel(task)


# -- 7. server TLS context disables session-ticket resumption (forward secrecy)-
def test_server_ssl_context_disables_session_tickets_and_renegotiation(
    tmp_path: Path,
) -> None:
    # OpenSSL otherwise mints one session-ticket key at context creation and never
    # rotates it for the process lifetime; a later leak retroactively breaks the
    # forward secrecy of every resumed session. Both the control channel and the
    # edge-TLS listener use this context, so both must refuse resumption (F45).
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    certs.generate("127.0.0.1", cert, key)
    ctx = certs.server_ssl_context(cert, key)
    assert ctx.options & ssl.OP_NO_TICKET  # TLS 1.2 STEK off
    if hasattr(ssl, "OP_NO_RENEGOTIATION"):
        assert ctx.options & ssl.OP_NO_RENEGOTIATION  # TLS 1.2 renegotiation off
    assert ctx.num_tickets == 0  # TLS 1.3 tickets off


async def test_server_ssl_context_negotiates_modern_tls_and_pfs_cipher(
    tmp_path: Path,
) -> None:
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    certs.generate("127.0.0.1", cert, key)

    async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()

    async def _probe(
        server_ctx: ssl.SSLContext, client_ctx: ssl.SSLContext
    ) -> tuple[str, tuple[str, str, int]]:
        server = await asyncio.start_server(_handle, "127.0.0.1", 0, ssl=server_ctx)
        assert server.sockets is not None
        port = server.sockets[0].getsockname()[1]
        try:
            return await asyncio.to_thread(_tls_handshake, port, client_ctx)
        finally:
            server.close()
            await server.wait_closed()

    version, cipher = await _probe(
        certs.server_ssl_context(cert, key), certs.client_ssl_context(cert)
    )

    assert version in {"TLSv1.2", "TLSv1.3"}
    assert cipher[1] == version
    if version == "TLSv1.2":
        assert cipher[0].startswith(("ECDHE-", "DHE-"))

    server_ctx = certs.server_ssl_context(cert, key)
    server_ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    client_ctx = certs.client_ssl_context(cert)
    client_ctx.maximum_version = ssl.TLSVersion.TLSv1_2

    version, cipher = await _probe(server_ctx, client_ctx)

    assert version == "TLSv1.2"
    assert cipher[1] == version
    assert cipher[0].startswith(("ECDHE-", "DHE-"))


def test_generated_control_key_is_0600_even_with_permissive_umask(tmp_path: Path) -> None:
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"

    old_umask = os.umask(0)
    try:
        certs.generate("127.0.0.1", cert, key)
    finally:
        os.umask(old_umask)

    assert key.stat().st_mode & 0o777 == 0o600


def test_regenerated_control_key_reasserts_0600_before_write(tmp_path: Path) -> None:
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    certs.generate("127.0.0.1", cert, key)
    key.chmod(0o644)

    certs.generate("127.0.0.1", cert, key)

    assert key.stat().st_mode & 0o777 == 0o600


def test_warns_when_control_cert_is_near_expiry(tmp_path: Path, caplog) -> None:
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    certs.generate("127.0.0.1", cert, key, days=30)

    caplog.set_level(logging.WARNING, logger="chute.certs")
    certs.warn_if_control_cert_expiring(cert)

    assert "control certificate" in caplog.text
    assert "expires in" in caplog.text
    assert "--server-cert" in caplog.text


def test_control_cert_expiry_warning_stays_quiet_before_threshold(tmp_path: Path, caplog) -> None:
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    certs.generate("127.0.0.1", cert, key, days=365)

    caplog.set_level(logging.WARNING, logger="chute.certs")
    certs.warn_if_control_cert_expiring(cert)

    assert caplog.text == ""


def test_warns_when_control_cert_is_already_expired(tmp_path: Path, caplog) -> None:
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    certs.generate("127.0.0.1", cert, key, days=1)
    observed_at = certs.certificate_expires_at(cert) + dt.timedelta(seconds=1)

    caplog.set_level(logging.WARNING, logger="chute.certs")
    certs.warn_if_control_cert_expiring(cert, now=observed_at)

    assert "control certificate" in caplog.text
    assert "expired" in caplog.text
    assert "--server-cert" in caplog.text


# -- 5. control channel negotiates no permessage-deflate (no zip-bomb surface)-
async def test_control_channel_disables_compression(tmp_path: Path) -> None:
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    certs.generate("127.0.0.1", cert, key)
    cp = _free_port()
    server = Server(
        token="secret",
        public_host="127.0.0.1",
        public_port=_free_port(),
        control_host="127.0.0.1",
        control_port=cp,
        ssl_context=certs.server_ssl_context(cert, key),
    )
    task = asyncio.ensure_future(server.serve())
    await asyncio.sleep(0.3)
    try:
        ctx = certs.client_ssl_context(cert)
        # the client offers permessage-deflate by default; the server must refuse it
        async with websockets.connect(f"wss://127.0.0.1:{cp}", ssl=ctx, open_timeout=5) as ws:
            resp = getattr(ws, "response", None)
            assert resp is not None, "cannot introspect the handshake response"
            exts = resp.headers.get("Sec-WebSocket-Extensions", "") or ""
            assert "permessage-deflate" not in exts.lower()
    finally:
        await _quiet_cancel(task)


def test_auth_fail_map_is_hard_capped(monkeypatch) -> None:
    # A flood of FRESH distinct IPs sweeps no stale buckets, so the per-IP failure map
    # must be hard-capped (oldest-inserted evicted), not grow without bound.
    monkeypatch.setattr(chute.server, "_AUTH_FAIL_SWEEP_AT", 8)
    monkeypatch.setattr(chute.server, "_AUTH_FAIL_MAX_IPS", 16)
    srv = Server(token="x")
    for i in range(200):
        srv._record_auth_fail(f"2001:db8:{i:x}::1")  # distinct /64s, fresh window
    assert len(srv._auth_fails) <= 16


def test_auth_fail_limiter_groups_ipv6_privacy_addresses_by_64(monkeypatch) -> None:
    monkeypatch.setattr(chute.server, "_AUTH_FAIL_MAX", 2)
    srv = Server(token="x")

    assert srv._auth_fail_key("2001:db8:abcd:1234::1") == "2001:db8:abcd:1234::/64"
    srv._record_auth_fail("2001:db8:abcd:1234::1")
    assert srv._auth_rate_ok("2001:db8:abcd:1234::2")
    srv._record_auth_fail("2001:db8:abcd:1234::2")

    assert not srv._auth_rate_ok("2001:db8:abcd:1234::9999")
    assert srv._auth_rate_ok("2001:db8:abcd:1235::1")


def test_auth_fail_limiter_maps_ipv4_mapped_ipv6_to_ipv4(monkeypatch) -> None:
    monkeypatch.setattr(chute.server, "_AUTH_FAIL_MAX", 1)
    srv = Server(token="x")

    assert srv._auth_fail_key("::ffff:192.0.2.9") == "192.0.2.9"
    srv._record_auth_fail("::ffff:192.0.2.9")

    assert not srv._auth_rate_ok("192.0.2.9")
