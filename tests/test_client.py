"""Agent-side robustness: bounded local-app dial and reconnect state hygiene.
These drive Tunnel internals directly (no server needed)."""

from __future__ import annotations

import asyncio
import json
import logging
import ssl
from pathlib import Path

import pytest

import chute.client
from chute import protocol
from chute.client import Tunnel


# -- F24: an unreachable local app must RESET within the connect timeout -------
async def test_local_connect_timeout_resets(monkeypatch) -> None:
    monkeypatch.setattr(chute.client, "_LOCAL_CONNECT_TIMEOUT", 0.2)
    seen_kwargs: dict[str, object] = {}

    async def _hang(*_args, **kwargs):
        seen_kwargs.update(kwargs)
        await asyncio.sleep(30)  # simulate a blackholed port (SYN dropped)

    monkeypatch.setattr(chute.client.asyncio, "open_connection", _hang)

    t = Tunnel(server="x", token="y", local_port=9)
    reset = asyncio.Event()

    class _FakeStream:
        id = 1
        reset_by_peer = False

        async def reset(self) -> None:
            reset.set()

        def close(self) -> None:
            pass

    # Bound well above the 0.2s connect timeout but far below the 30s hang.
    await asyncio.wait_for(t._handle_stream(_FakeStream()), timeout=3)
    assert seen_kwargs["limit"] == chute.client._STREAM_READER_LIMIT
    assert reset.is_set(), "a timed-out local connect must reset the stream"


async def test_local_connect_cancellation_closes_stream(monkeypatch) -> None:
    started = asyncio.Event()

    async def _hang(*_args, **_kwargs):
        started.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(chute.client.asyncio, "open_connection", _hang)

    t = Tunnel(server="x", token="y", local_port=9)
    stream = _ClosableFakeStream()
    task = asyncio.create_task(t._handle_stream(stream))
    await asyncio.wait_for(started.wait(), timeout=1)

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert stream.closed, "cancellation before local connect succeeds must close the stream"
    assert not stream.reset_called


async def test_stream_handler_cancellation_after_connect_closes_writer_and_stream(
    monkeypatch,
) -> None:
    connected = asyncio.Event()
    writer = _FakeLocalWriter()

    class _BlockingReader:
        async def read(self, _limit: int = -1) -> bytes:
            await asyncio.Event().wait()
            raise AssertionError("unreachable")

    class _BlockingStream:
        id = 1
        reset_by_peer = False

        def __init__(self) -> None:
            self.closed = False

        async def read(self) -> bytes | None:
            await asyncio.Event().wait()
            raise AssertionError("unreachable")

        async def send(self, _data: bytes) -> None:
            return None

        async def send_eof(self) -> None:
            return None

        async def ack(self, _n: int) -> None:
            return None

        async def reset(self) -> None:
            return None

        def close(self) -> None:
            self.closed = True

    async def _open_connection(
        _host: str, _port: int, *, limit: int
    ) -> tuple[_BlockingReader, _FakeLocalWriter]:
        assert limit == chute.client._STREAM_READER_LIMIT
        connected.set()
        return _BlockingReader(), writer

    monkeypatch.setattr(chute.client.asyncio, "open_connection", _open_connection)
    monkeypatch.setattr(chute.client, "enable_tcp_keepalive", lambda _writer: None)

    t = Tunnel(server="x", token="y", local_port=8080)
    stream = _BlockingStream()
    task = asyncio.create_task(t._handle_stream(stream))
    await asyncio.wait_for(connected.wait(), timeout=1)

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert writer.closed
    assert stream.closed


async def test_local_app_socket_keepalive_is_enabled(monkeypatch) -> None:
    seen_open: dict[str, object] = {}
    keepalive_writers: list[_FakeLocalWriter] = []
    reader = _FakeLocalReader()
    writer = _FakeLocalWriter()
    stream = _ConnectedFakeStream()

    async def _open_connection(host: str, port: int, *, limit: int) -> tuple[object, object]:
        seen_open["host"] = host
        seen_open["port"] = port
        seen_open["limit"] = limit
        return reader, writer

    def _record_keepalive(candidate: _FakeLocalWriter) -> None:
        keepalive_writers.append(candidate)

    monkeypatch.setattr(chute.client.asyncio, "open_connection", _open_connection)
    monkeypatch.setattr(chute.client, "enable_tcp_keepalive", _record_keepalive)

    t = Tunnel(server="x", token="y", local_port=8080)

    await asyncio.wait_for(t._handle_stream(stream), timeout=3)

    assert seen_open == {
        "host": "127.0.0.1",
        "port": 8080,
        "limit": chute.client._STREAM_READER_LIMIT,
    }
    assert keepalive_writers == [writer]
    assert stream.sent_eof
    assert stream.closed
    assert not stream.reset
    assert writer.eof_written
    assert writer.closed


async def test_local_unreachable_warnings_are_rate_limited(monkeypatch, caplog) -> None:
    monkeypatch.setattr(chute.client, "_LOCAL_UNREACHABLE_LOG_INTERVAL", 0.01)
    caplog.set_level(logging.WARNING, logger="chute.client")
    t = Tunnel(server="x", token="y", local_port=9)

    t._record_local_unreachable(OSError("refused-1"))
    t._record_local_unreachable(OSError("refused-2"))
    t._record_local_unreachable(OSError("refused-3"))
    await asyncio.sleep(0.02)
    t._record_local_unreachable(OSError("refused-4"))

    warnings = [
        record.getMessage() for record in caplog.records if record.levelno == logging.WARNING
    ]
    assert len(warnings) == 2
    assert "refused-1" in warnings[0]
    assert "refused-2" not in "\n".join(warnings)
    assert "refused-3" not in "\n".join(warnings)
    assert "refused-4" in warnings[1]
    assert "suppressed 2 similar failures" in warnings[1]


async def test_local_recovery_resets_unreachable_log_window(monkeypatch, caplog) -> None:
    monkeypatch.setattr(chute.client, "_LOCAL_UNREACHABLE_LOG_INTERVAL", 60.0)
    caplog.set_level(logging.INFO, logger="chute.client")
    t = Tunnel(server="x", token="y", local_port=9)

    t._record_local_unreachable(OSError("refused-1"))
    t._record_local_unreachable(OSError("refused-2"))
    t._record_local_reachable()
    t._record_local_unreachable(OSError("refused-after-recovery"))

    messages = [record.getMessage() for record in caplog.records]
    assert any("local app reachable again" in message for message in messages)
    assert any("suppressed 1 unreachable warnings" in message for message in messages)
    assert any("refused-after-recovery" in message for message in messages)


async def test_agent_control_channel_runtime_limits_are_explicit(monkeypatch) -> None:
    captured: dict[str, object] = {}

    class _FakeWS:
        async def send(self, data: str) -> None:
            captured["hello"] = data

        async def recv(self) -> str:
            return json.dumps(
                {
                    "type": "ready",
                    "public_url": "https://example.test/",
                    "flow_window": 131072,
                    "v": protocol.VERSION,
                }
            )

        def __aiter__(self) -> _FakeWS:
            return self

        async def __anext__(self) -> bytes:
            raise StopAsyncIteration

    class _FakeConnect:
        def __init__(self, uri: str, **kwargs: object) -> None:
            captured["uri"] = uri
            captured["kwargs"] = kwargs
            self.ws = _FakeWS()

        async def __aenter__(self) -> _FakeWS:
            return self.ws

        async def __aexit__(self, *_exc: object) -> None:
            return None

    def _fake_connect(uri: str, **kwargs: object) -> _FakeConnect:
        return _FakeConnect(uri, **kwargs)

    monkeypatch.setattr(chute.client.websockets, "connect", _fake_connect)

    t = Tunnel(server="relay.example", token="secret", local_port=8080)
    assert t.negotiated_mux_flow_window is None
    await asyncio.wait_for(t._run_once(), timeout=3)
    assert t.negotiated_mux_flow_window == 131072

    hello = json.loads(captured["hello"])
    assert hello["flow_window"] == chute.client._FLOW_WINDOW
    kwargs = captured["kwargs"]
    assert isinstance(kwargs, dict)
    assert kwargs["max_size"] == chute.client._MAX_WS_MESSAGE
    assert kwargs["max_queue"] == chute.client._WS_MAX_QUEUE
    assert kwargs["write_limit"] == chute.client._WS_WRITE_LIMIT
    assert kwargs["compression"] is None
    assert kwargs["open_timeout"] == 15


@pytest.mark.parametrize(
    ("reply", "match"),
    [
        ("not-json", "malformed handshake reply"),
        (json.dumps(["ready"]), "handshake rejected"),
        (
            json.dumps({"type": "ready", "v": protocol.VERSION}),
            "handshake reply missing public_url",
        ),
        (
            json.dumps(
                {
                    "type": "ready",
                    "public_url": "https://example.test/",
                    "v": protocol.VERSION,
                }
            ),
            "invalid flow_window",
        ),
        (
            json.dumps(
                {
                    "type": "ready",
                    "public_url": "https://example.test/",
                    "flow_window": True,
                    "v": protocol.VERSION,
                }
            ),
            "invalid flow_window",
        ),
        (
            json.dumps(
                {
                    "type": "ready",
                    "public_url": "https://example.test/",
                    "flow_window": chute.client._FLOW_WINDOW + 1,
                    "v": protocol.VERSION,
                }
            ),
            "exceeds requested",
        ),
        (
            json.dumps(
                {
                    "type": "ready",
                    "public_url": "https://example.test/",
                    "flow_window": chute.client._FLOW_WINDOW,
                    "v": protocol.VERSION + 1,
                }
            ),
            "server protocol",
        ),
    ],
)
async def test_malformed_ready_replies_are_fatal(monkeypatch, reply: str, match: str) -> None:
    def _fake_connect(_uri: str, **_kwargs: object) -> _HandshakeReplyConnect:
        return _HandshakeReplyConnect(reply)

    monkeypatch.setattr(chute.client.websockets, "connect", _fake_connect)

    t = Tunnel(server="relay.example", token="secret", local_port=8080)
    with pytest.raises(chute.client._FatalError, match=match):
        await asyncio.wait_for(t._run_once(), timeout=3)


def test_build_ssl_logs_pinned_trust_mode(monkeypatch, tmp_path: Path, caplog) -> None:
    cert = tmp_path / "server.pem"
    cert.write_text("cert")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    seen: list[Path] = []

    def _fake_client_ssl_context(path: Path) -> ssl.SSLContext:
        seen.append(path)
        return ctx

    monkeypatch.setattr(chute.client.certs, "client_ssl_context", _fake_client_ssl_context)
    caplog.set_level(logging.INFO, logger="chute.client")

    t = Tunnel(server="relay.example", token="secret", local_port=8080, server_cert=cert)

    assert t._build_ssl() is ctx
    assert seen == [cert]
    assert "control TLS: pinned server cert" in caplog.text
    assert str(cert) in caplog.text


def test_build_ssl_logs_system_trust_mode(monkeypatch, caplog) -> None:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    monkeypatch.setattr(chute.client.ssl, "create_default_context", lambda: ctx)
    caplog.set_level(logging.INFO, logger="chute.client")

    t = Tunnel(server="relay.example", token="secret", local_port=8080)

    assert t._build_ssl() is ctx
    assert "control TLS: system trust store" in caplog.text
    assert "--server-cert" in caplog.text


# -- F30: _connected is cleared at the top of EVERY attempt, incl. clean ones --
async def test_connected_cleared_before_each_attempt(monkeypatch) -> None:
    t = Tunnel(server="x", token="y", local_port=1)
    seen: list[bool] = []
    calls = 0

    async def _fake_run_once() -> None:
        nonlocal calls
        seen.append(t._connected.is_set())  # observed at the start of each attempt
        t._connected.set()  # simulate "connected"
        calls += 1
        if calls >= 2:
            t._stop.set()
        # returns cleanly -> exercises the clean-disconnect path (no except branch)

    monkeypatch.setattr(t, "_run_once", _fake_run_once)
    await asyncio.wait_for(t.serve_forever(), timeout=3)
    # Pre-fix the clean path never cleared _connected, so attempt 2 would see True
    # (a stale, still-"connected" state). Post-fix both attempts start cleared.
    assert seen == [False, False]


# -- F13/F52: stop() after the loop has closed (post-fatal) must not raise -----
def test_stop_is_idempotent_after_loop_closed() -> None:
    t = Tunnel(server="x", token="y", local_port=1)
    loop = asyncio.new_event_loop()
    loop.close()
    t._loop = loop  # simulate the background thread having exited (fatal auth)
    t.stop()  # pre-fix: RuntimeError("Event loop is closed"); post-fix: clean no-op
    t.stop()  # and genuinely idempotent


class _FakeLocalReader:
    async def read(self, _limit: int) -> bytes:
        return b""


class _FakeTransport:
    def __init__(self) -> None:
        self.aborted = False

    def abort(self) -> None:
        self.aborted = True


class _FakeLocalWriter:
    def __init__(self) -> None:
        self.closed = False
        self.eof_written = False
        self.transport = _FakeTransport()

    def write(self, _data: bytes) -> None:
        return None

    async def drain(self) -> None:
        return None

    def can_write_eof(self) -> bool:
        return True

    def write_eof(self) -> None:
        self.eof_written = True

    def close(self) -> None:
        self.closed = True


class _ConnectedFakeStream:
    id = 1
    reset_by_peer = False

    def __init__(self) -> None:
        self.closed = False
        self.reset = False
        self.sent: list[bytes] = []
        self.sent_eof = False
        self.acked: list[int] = []

    async def read(self) -> bytes | None:
        return None

    async def send(self, data: bytes) -> None:
        self.sent.append(data)

    async def send_eof(self) -> None:
        self.sent_eof = True

    async def ack(self, n: int) -> None:
        self.acked.append(n)

    async def reset(self) -> None:
        self.reset = True

    def close(self) -> None:
        self.closed = True


class _ClosableFakeStream:
    id = 1
    reset_by_peer = False

    def __init__(self) -> None:
        self.closed = False
        self.reset_called = False

    async def reset(self) -> None:
        self.reset_called = True

    def close(self) -> None:
        self.closed = True


class _HandshakeReplyWS:
    def __init__(self, reply: str) -> None:
        self.reply = reply
        self.sent: list[str] = []

    async def send(self, data: str) -> None:
        self.sent.append(data)

    async def recv(self) -> str:
        return self.reply


class _HandshakeReplyConnect:
    def __init__(self, reply: str) -> None:
        self.ws = _HandshakeReplyWS(reply)

    async def __aenter__(self) -> _HandshakeReplyWS:
        return self.ws

    async def __aexit__(self, *_exc: object) -> None:
        return None
