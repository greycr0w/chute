"""chute is a transparent byte pipe: it must NOT inspect or alter HTTP.

This is a guard-test. The whole point of chute is to serve plain HTTP exactly
as the local app emits it -- including headers some proxies would "helpfully"
strip (HSTS, CSP, etc.). If anyone reintroduces response/request rewriting,
these tests fail.
"""

from __future__ import annotations

import asyncio
import contextlib
import http.client
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

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
    for t in tasks:
        t.cancel()
    for t in tasks:
        try:
            await t
        except (asyncio.CancelledError, Exception):
            pass


class _App(BaseHTTPRequestHandler):
    """Emits headers a sanitising proxy would mangle. We assert they survive."""

    protocol_version = "HTTP/1.1"

    def log_message(self, *args: object) -> None:
        pass

    def do_GET(self) -> None:
        body = b"<h1>plain http</h1>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
        self.send_header("Content-Security-Policy", "upgrade-insecure-requests; default-src 'self'")
        self.send_header("X-Custom-Header", "verbatim-value-123")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _get_full(port: int, path: str) -> tuple[int, dict[str, str], bytes]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        conn.request("GET", path)
        resp = conn.getresponse()
        headers = {k.lower(): v for k, v in resp.getheaders()}
        return resp.status, headers, resp.read()
    finally:
        conn.close()


@contextlib.asynccontextmanager
async def _tunnel(tmp_path: Path, handler: type[BaseHTTPRequestHandler] = _App):
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    certs.generate("127.0.0.1", cert, key)
    local_port = _free_port()
    httpd = ThreadingHTTPServer(("127.0.0.1", local_port), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    public_port, control_port = _free_port(), _free_port()
    server = Server(
        token="secret",
        public_host="127.0.0.1",
        public_port=public_port,
        control_host="127.0.0.1",
        control_port=control_port,
        public_url=f"http://127.0.0.1:{public_port}/",
        ssl_context=certs.server_ssl_context(cert, key),
    )
    server_task = asyncio.ensure_future(server.serve())
    await asyncio.sleep(0.3)
    tunnel = Tunnel(
        server="127.0.0.1",
        token="secret",
        local_port=local_port,
        control_port=control_port,
        server_cert=str(cert),
        scheme="http",
    )
    tunnel_task = asyncio.ensure_future(tunnel.serve_forever())
    await tunnel.wait_until_ready(timeout=5)
    try:
        yield public_port
    finally:
        await tunnel.aclose()
        await _quiet_cancel(tunnel_task, server_task)
        httpd.shutdown()


async def test_response_headers_pass_through_verbatim(tmp_path: Path) -> None:
    async with _tunnel(tmp_path) as port:
        status, headers, body = await asyncio.to_thread(_get_full, port, "/")
        assert status == 200
        assert body == b"<h1>plain http</h1>"
        # nothing dropped, nothing rewritten:
        assert headers.get("strict-transport-security") == "max-age=63072000; includeSubDomains"
        assert (
            headers.get("content-security-policy")
            == "upgrade-insecure-requests; default-src 'self'"
        )
        assert headers.get("x-custom-header") == "verbatim-value-123"


async def test_we_do_not_force_connection_close(tmp_path: Path) -> None:
    # The app didn't send `Connection: close`, so chute must not inject it.
    async with _tunnel(tmp_path) as port:
        _, headers, _ = await asyncio.to_thread(_get_full, port, "/")
        assert headers.get("connection", "").lower() != "close"


# A 20 MiB deterministic body: well past the old 16 MiB (256 x 64 KiB) ceiling,
# with a repeating 0..255 pattern so truncation OR reordering is caught.
_BIG = (bytes(range(256)) * (20 * 1024 * 1024 // 256 + 1))[: 20 * 1024 * 1024]


class _BigApp(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args: object) -> None:
        pass

    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(_BIG)))
        self.end_headers()
        self.wfile.write(_BIG)


def _get_body(port: int) -> bytes:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=60)
    try:
        conn.request("GET", "/")
        return conn.getresponse().read()
    finally:
        conn.close()


def _get_body_slow(port: int) -> bytes:
    # Read in small chunks with a brief pause, so the consumer is slower than the
    # producer and the credit window actually engages (backpressure, not reset).
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=60)
    try:
        conn.request("GET", "/")
        resp = conn.getresponse()
        out = bytearray()
        while True:
            part = resp.read(32 * 1024)
            if not part:
                break
            out.extend(part)
            time.sleep(0.001)
        return bytes(out)
    finally:
        conn.close()


async def test_large_body_is_byte_exact_through_the_mux(tmp_path: Path) -> None:
    # F6: the most serious bug was completely uncovered (existing bodies ~19-30 B).
    # A 20 MiB transfer must arrive byte-for-byte -- flow control paces it, the old
    # chunk-count cap would have RESET it mid-stream.
    async with _tunnel(tmp_path, handler=_BigApp) as port:
        body = await asyncio.wait_for(asyncio.to_thread(_get_body, port), timeout=60)
        assert len(body) == len(_BIG)
        assert body == _BIG


async def test_slow_consumer_is_throttled_not_reset(tmp_path: Path) -> None:
    # F6 (small-frame / slow-but-progressing reader): a consumer slower than the
    # producer must be backpressured to completion, never falsely RESET below the
    # advertised limit. Asserts the full body still arrives intact.
    async with _tunnel(tmp_path, handler=_BigApp) as port:
        body = await asyncio.wait_for(asyncio.to_thread(_get_body_slow, port), timeout=90)
        assert len(body) == len(_BIG)
        assert body == _BIG
