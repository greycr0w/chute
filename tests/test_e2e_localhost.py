"""End-to-end tests on loopback: real server + real agent + a real local app.

These exercise the whole path -- TLS handshake with the pinned cert, token
auth, stream multiplexing, bidirectional relay, concurrency isolation and
auto-reconnect -- without needing the VPS. This is the suite you run on every
change; the on-server smoke test (scripts/smoke_test.sh) is the final gate.
"""

from __future__ import annotations

import asyncio
import http.client
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from chute import certs
from chute.client import Tunnel
from chute.server import Server


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


async def _quiet_cancel(*tasks: asyncio.Future) -> None:
    """Cancel tasks and await them, swallowing the resulting CancelledError.

    NB: asyncio.CancelledError is a BaseException, so contextlib.suppress(Exception)
    does NOT catch it -- hence this helper.
    """
    for task in tasks:
        task.cancel()
    for task in tasks:
        try:
            await task
        except (asyncio.CancelledError, Exception):
            pass


class _Echo(BaseHTTPRequestHandler):
    """Local app under test: echoes path + body so we can detect cross-talk."""

    protocol_version = "HTTP/1.1"

    def log_message(self, *args: object) -> None:  # silence test output
        pass

    def _handle(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else b""
        payload = b"echo:" + self.path.encode() + b":" + body
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = _handle
    do_POST = _handle


def _request(port: int, path: str, body: bytes | None = None) -> tuple[int, bytes]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        method = "POST" if body is not None else "GET"
        conn.request(method, path, body=body)
        resp = conn.getresponse()
        return resp.status, resp.read()
    finally:
        conn.close()


def _start_local_app() -> tuple[int, ThreadingHTTPServer]:
    port = _free_port()
    httpd = ThreadingHTTPServer(("127.0.0.1", port), _Echo)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return port, httpd


def _start_server(
    token: str, cert: Path, key: Path, public_port: int, control_port: int
) -> tuple[Server, asyncio.Task]:
    server = Server(
        token=token,
        public_host="127.0.0.1",
        public_port=public_port,
        control_host="127.0.0.1",
        control_port=control_port,
        public_url=f"http://127.0.0.1:{public_port}/",
        ssl_context=certs.server_ssl_context(cert, key),
    )
    return server, asyncio.ensure_future(server.serve())


class _Harness:
    """Holds everything a test spins up so teardown is one call."""

    def __init__(self) -> None:
        self.public_port = 0
        self.control_port = 0
        self.tunnel: Tunnel | None = None
        self._tasks: list[asyncio.Task] = []
        self._httpd: ThreadingHTTPServer | None = None

    async def aclose(self) -> None:
        if self.tunnel is not None:
            await self.tunnel.aclose()
        await _quiet_cancel(*self._tasks)
        if self._httpd is not None:
            self._httpd.shutdown()


async def _bring_up(tmp_path: Path, *, with_agent: bool = True) -> _Harness:
    h = _Harness()
    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    certs.generate("127.0.0.1", cert, key)

    local_port, h._httpd = _start_local_app()
    h.public_port, h.control_port = _free_port(), _free_port()
    _, server_task = _start_server("secret", cert, key, h.public_port, h.control_port)
    h._tasks.append(server_task)
    await asyncio.sleep(0.3)  # let the listeners bind

    if with_agent:
        h.tunnel = Tunnel(
            server="127.0.0.1",
            token="secret",
            local_port=local_port,
            control_port=h.control_port,
            server_cert=str(cert),
        )
        h._tasks.append(asyncio.ensure_future(h.tunnel.serve_forever()))
        await h.tunnel.wait_until_ready(timeout=5)
    return h


async def test_basic_get(tmp_path: Path) -> None:
    h = await _bring_up(tmp_path)
    try:
        status, body = await asyncio.to_thread(_request, h.public_port, "/hello")
        assert status == 200
        assert body == b"echo:/hello:"
    finally:
        await h.aclose()


async def test_post_body_round_trips(tmp_path: Path) -> None:
    h = await _bring_up(tmp_path)
    try:
        status, body = await asyncio.to_thread(_request, h.public_port, "/submit", b"payload-123")
        assert status == 200
        assert body == b"echo:/submit:payload-123"
    finally:
        await h.aclose()


async def test_public_url_is_reported(tmp_path: Path) -> None:
    h = await _bring_up(tmp_path)
    try:
        assert h.tunnel is not None
        assert h.tunnel.public_url == f"http://127.0.0.1:{h.public_port}/"
    finally:
        await h.aclose()


async def test_concurrent_streams_do_not_cross_talk(tmp_path: Path) -> None:
    h = await _bring_up(tmp_path)
    try:
        paths = [f"/req-{i}" for i in range(25)]
        results = await asyncio.gather(
            *[asyncio.to_thread(_request, h.public_port, p) for p in paths]
        )
        for path, (status, body) in zip(paths, results, strict=True):
            assert status == 200, path
            assert body == f"echo:{path}:".encode(), path
    finally:
        await h.aclose()


async def test_bad_token_is_rejected(tmp_path: Path) -> None:
    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    certs.generate("127.0.0.1", cert, key)
    control_port, public_port = _free_port(), _free_port()
    _, server_task = _start_server("right-secret", cert, key, public_port, control_port)
    await asyncio.sleep(0.3)
    tunnel = Tunnel(
        server="127.0.0.1",
        token="WRONG",
        local_port=_free_port(),
        control_port=control_port,
        server_cert=str(cert),
    )
    try:
        with pytest.raises(Exception):
            await asyncio.wait_for(tunnel.serve_forever(), timeout=5)
    finally:
        await _quiet_cancel(server_task)


async def test_offline_returns_503(tmp_path: Path) -> None:
    h = await _bring_up(tmp_path, with_agent=False)
    try:
        status, _ = await asyncio.to_thread(_request, h.public_port, "/")
        assert status == 503
    finally:
        await h.aclose()


async def test_agent_reconnects_after_server_restart(tmp_path: Path) -> None:
    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    certs.generate("127.0.0.1", cert, key)
    local_port, httpd = _start_local_app()
    public_port, control_port = _free_port(), _free_port()

    _, server_task = _start_server("secret", cert, key, public_port, control_port)
    await asyncio.sleep(0.3)
    tunnel = Tunnel(
        server="127.0.0.1",
        token="secret",
        local_port=local_port,
        control_port=control_port,
        server_cert=str(cert),
        max_backoff=1.0,
    )
    tunnel_task = asyncio.ensure_future(tunnel.serve_forever())
    await tunnel.wait_until_ready(timeout=5)

    status, _ = await asyncio.to_thread(_request, public_port, "/before")
    assert status == 200

    # kill the server hard
    await _quiet_cancel(server_task)
    await asyncio.sleep(0.3)

    # fresh server on the SAME ports (retry through TIME_WAIT)
    server_task = None
    for _ in range(20):
        try:
            _, server_task = _start_server("secret", cert, key, public_port, control_port)
            break
        except OSError:
            await asyncio.sleep(0.25)
    assert server_task is not None
    await asyncio.sleep(0.25)

    # the agent should self-heal; poll until it serves again
    ok = False
    for _ in range(20):
        try:
            status, body = await asyncio.to_thread(_request, public_port, "/after")
            if status == 200 and body == b"echo:/after:":
                ok = True
                break
        except Exception:
            pass
        await asyncio.sleep(0.5)
    assert ok, "agent did not reconnect after server restart"

    await tunnel.aclose()
    await _quiet_cancel(tunnel_task, server_task)
    httpd.shutdown()
