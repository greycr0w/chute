"""HTTPS workflow: TLS terminates at the server edge; the agent stays plaintext.

Covers the second supported workflow (normal web apps over https) without
disturbing the transparent http path (see test_transparency.py). A locally
generated cert stands in for the browser-trusted production cert; the
"is it trusted by a real browser" question is a deployment concern, not testable
on loopback.
"""

from __future__ import annotations

import asyncio
import contextlib
import http.client
import json
import socket
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
import websockets

from chute import certs, protocol
from chute.client import Tunnel, _FatalError
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


class _Echo(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args: object) -> None:
        pass

    def do_GET(self) -> None:
        body = b"echo:" + self.path.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _https_get(port: int, path: str, ca_cert: Path) -> tuple[int, bytes]:
    ctx = ssl.create_default_context(cafile=str(ca_cert))
    ctx.check_hostname = False  # self-signed CA-of-one; we trust the cert itself
    conn = http.client.HTTPSConnection("127.0.0.1", port, timeout=10, context=ctx)
    try:
        conn.request("GET", path)
        resp = conn.getresponse()
        return resp.status, resp.read()
    finally:
        conn.close()


def _peer_cert_der(port: int) -> bytes:
    """TLS-handshake against the edge and return the server cert (DER), unverified."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection(("127.0.0.1", port), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname="127.0.0.1") as ssock:
            return ssock.getpeercert(binary_form=True)


@contextlib.asynccontextmanager
async def _https_tunnel(tmp_path: Path):
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    certs.generate("127.0.0.1", cert, key)
    local_port = _free_port()
    httpd = ThreadingHTTPServer(("127.0.0.1", local_port), _Echo)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()

    http_port, tls_port, control_port = _free_port(), _free_port(), _free_port()
    server = Server(
        token="secret",
        public_host="127.0.0.1",
        public_port=http_port,
        control_host="127.0.0.1",
        control_port=control_port,
        public_url=f"http://127.0.0.1:{http_port}/",
        ssl_context=certs.server_ssl_context(cert, key),  # control channel
        tls_cert=cert,
        tls_key=key,  # public TLS (edge)
        public_tls_port=tls_port,
        public_https_url=f"https://127.0.0.1:{tls_port}/",
    )
    server_task = asyncio.ensure_future(server.serve())
    await asyncio.sleep(0.3)
    tunnel = Tunnel(
        server="127.0.0.1",
        token="secret",
        local_port=local_port,
        control_port=control_port,
        server_cert=str(cert),
        scheme="https",
    )
    tunnel_task = asyncio.ensure_future(tunnel.serve_forever())
    await tunnel.wait_until_ready(timeout=5)
    try:
        yield tunnel, tls_port, cert
    finally:
        await tunnel.aclose()
        await _quiet_cancel(tunnel_task, server_task)
        httpd.shutdown()


async def test_https_terminates_at_edge_and_relays(tmp_path: Path) -> None:
    async with _https_tunnel(tmp_path) as (_tunnel, tls_port, cert):
        status, body = await asyncio.to_thread(_https_get, tls_port, "/hello", cert)
        assert status == 200
        assert body == b"echo:/hello"


async def test_public_url_is_https(tmp_path: Path) -> None:
    async with _https_tunnel(tmp_path) as (tunnel, tls_port, _cert):
        assert tunnel.public_url == f"https://127.0.0.1:{tls_port}/"


def test_explicit_http_normalizes_single_tunnel_url_scheme() -> None:
    server = Server(token="secret", public_url="https://example.test/")
    assert server._public_url_for("default", "http") == "http://example.test/"


async def test_https_requested_without_cert_fails_closed(tmp_path: Path) -> None:
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    certs.generate("127.0.0.1", cert, key)
    http_port, control_port = _free_port(), _free_port()
    server = Server(
        token="secret",
        public_host="127.0.0.1",
        public_port=http_port,
        control_host="127.0.0.1",
        control_port=control_port,
        public_url=f"http://127.0.0.1:{http_port}/",
        ssl_context=certs.server_ssl_context(cert, key),
        # no tls_cert/tls_key -> https not available
    )
    server_task = asyncio.ensure_future(server.serve())
    await asyncio.sleep(0.3)
    tunnel = Tunnel(
        server="127.0.0.1",
        token="secret",
        local_port=_free_port(),
        control_port=control_port,
        server_cert=str(cert),
        scheme="https",
    )
    tunnel_task = asyncio.ensure_future(tunnel.serve_forever())
    try:
        with pytest.raises(_FatalError, match="https_unavailable"):
            await tunnel.wait_until_ready(timeout=5)
    finally:
        await tunnel.aclose()
        await _quiet_cancel(tunnel_task, server_task)


async def test_agent_without_scheme_gets_http(tmp_path: Path) -> None:
    # The "scheme" field is optional (defaults to http); a v2 agent that omits it
    # still gets a working http URL.
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    certs.generate("127.0.0.1", cert, key)
    http_port, tls_port, control_port = _free_port(), _free_port(), _free_port()
    server = Server(
        token="secret",
        public_host="127.0.0.1",
        public_port=http_port,
        control_host="127.0.0.1",
        control_port=control_port,
        public_url=f"http://127.0.0.1:{http_port}/",
        ssl_context=certs.server_ssl_context(cert, key),
        tls_cert=cert,
        tls_key=key,
        public_tls_port=tls_port,
        public_https_url=f"https://127.0.0.1:{tls_port}/",
    )
    server_task = asyncio.ensure_future(server.serve())
    await asyncio.sleep(0.3)
    client_ctx = certs.client_ssl_context(cert)
    try:
        async with websockets.connect(
            f"wss://127.0.0.1:{control_port}", ssl=client_ctx, open_timeout=5
        ) as ws:
            await ws.send(json.dumps({"type": "auth", "token": "secret", "v": protocol.VERSION}))
            reply = json.loads(await asyncio.wait_for(ws.recv(), timeout=5))
            assert reply["type"] == "ready"
            assert reply["public_url"].startswith("http://")
            assert reply["v"] == protocol.VERSION
    finally:
        await _quiet_cancel(server_task)


async def test_pre_v2_agent_is_rejected(tmp_path: Path) -> None:
    # F27: an agent that doesn't advertise the flow-control protocol version is
    # refused with a clear, fatal reason -- not silently served into a stall.
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    certs.generate("127.0.0.1", cert, key)
    control_port = _free_port()
    server = Server(
        token="secret",
        public_host="127.0.0.1",
        public_port=_free_port(),
        control_host="127.0.0.1",
        control_port=control_port,
        ssl_context=certs.server_ssl_context(cert, key),
    )
    server_task = asyncio.ensure_future(server.serve())
    await asyncio.sleep(0.3)
    client_ctx = certs.client_ssl_context(cert)
    try:
        async with websockets.connect(
            f"wss://127.0.0.1:{control_port}", ssl=client_ctx, open_timeout=5
        ) as ws:
            await ws.send(json.dumps({"type": "auth", "token": "secret"}))  # no "v"
            reply = json.loads(await asyncio.wait_for(ws.recv(), timeout=5))
            assert reply["type"] == "error"
            assert "protocol" in reply["reason"].lower()
            with pytest.raises(websockets.exceptions.ConnectionClosed):
                await asyncio.wait_for(ws.recv(), timeout=5)
            assert ws.close_code == 4004
    finally:
        await _quiet_cancel(server_task)


class _CloseDelimited(BaseHTTPRequestHandler):
    """HTTP/1.0, no Content-Length: the response body is delimited by the
    connection closing. The local app closes after writing, so the agent sees EOF
    and the edge must turn that into a FIN the visitor can observe."""

    protocol_version = "HTTP/1.0"

    def log_message(self, *args: object) -> None:
        pass

    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()  # deliberately NO Content-Length
        self.wfile.write(b"close-delimited-body-no-length")


def _https_get_read_to_eof(port: int, ca_cert: Path) -> bytes:
    ctx = ssl.create_default_context(cafile=str(ca_cert))
    ctx.check_hostname = False
    conn = http.client.HTTPSConnection("127.0.0.1", port, timeout=10, context=ctx)
    try:
        conn.request("GET", "/")
        resp = conn.getresponse()
        return resp.read()  # close-delimited: blocks until the edge sends FIN
    finally:
        conn.close()


async def test_edge_tls_close_delimited_response_does_not_hang(tmp_path: Path) -> None:
    # Regression for F20: over the SSL edge, can_write_eof() is False, so the old
    # code took neither branch on the peer's half-close and never closed the visitor
    # -- a no-Content-Length response hung until the client timed out. The fix falls
    # back to a full close. We bound the whole fetch and assert it completes.
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    certs.generate("127.0.0.1", cert, key)
    local_port = _free_port()
    httpd = ThreadingHTTPServer(("127.0.0.1", local_port), _CloseDelimited)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()

    http_port, tls_port, control_port = _free_port(), _free_port(), _free_port()
    server = Server(
        token="secret",
        public_host="127.0.0.1",
        public_port=http_port,
        control_host="127.0.0.1",
        control_port=control_port,
        public_url=f"http://127.0.0.1:{http_port}/",
        ssl_context=certs.server_ssl_context(cert, key),
        tls_cert=cert,
        tls_key=key,
        public_tls_port=tls_port,
        public_https_url=f"https://127.0.0.1:{tls_port}/",
    )
    server_task = asyncio.ensure_future(server.serve())
    await asyncio.sleep(0.3)
    tunnel = Tunnel(
        server="127.0.0.1",
        token="secret",
        local_port=local_port,
        control_port=control_port,
        server_cert=str(cert),
        scheme="https",
    )
    tunnel_task = asyncio.ensure_future(tunnel.serve_forever())
    await tunnel.wait_until_ready(timeout=5)
    try:
        # If the edge never sends FIN, resp.read() blocks forever and wait_for trips.
        body = await asyncio.wait_for(
            asyncio.to_thread(_https_get_read_to_eof, tls_port, cert), timeout=8
        )
        assert body == b"close-delimited-body-no-length"
    finally:
        await tunnel.aclose()
        await _quiet_cancel(tunnel_task, server_task)
        httpd.shutdown()


async def test_public_cert_hot_reload(tmp_path: Path) -> None:
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    certs.generate("127.0.0.1", cert, key)
    http_port, tls_port, control_port = _free_port(), _free_port(), _free_port()
    server = Server(
        token="secret",
        public_host="127.0.0.1",
        public_port=http_port,
        control_host="127.0.0.1",
        control_port=control_port,
        ssl_context=certs.server_ssl_context(cert, key),
        tls_cert=cert,
        tls_key=key,
        public_tls_port=tls_port,
        public_https_url=f"https://127.0.0.1:{tls_port}/",
        cert_reload_interval=0.4,  # poll fast for the test
    )
    server_task = asyncio.ensure_future(server.serve())
    await asyncio.sleep(0.3)
    try:
        der_before = await asyncio.to_thread(_peer_cert_der, tls_port)
        # rewrite the cert files in place (simulates an external ACME renewal)
        certs.generate("127.0.0.1", cert, key)
        await asyncio.sleep(1.2)  # let the watcher pick up the mtime change
        der_after = await asyncio.to_thread(_peer_cert_der, tls_port)
        assert der_before != der_after, "server did not hot-reload the new cert"
    finally:
        await _quiet_cancel(server_task)
