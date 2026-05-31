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

import websockets

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


async def test_https_requested_without_cert_falls_back_to_http(tmp_path: Path) -> None:
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
    url = await tunnel.wait_until_ready(timeout=5)
    try:
        assert url.startswith("http://")  # graceful fallback, not a crash
    finally:
        await tunnel.aclose()
        await _quiet_cancel(tunnel_task, server_task)


async def test_legacy_agent_without_scheme_gets_http(tmp_path: Path) -> None:
    # An agent that predates the scheme field sends no "scheme" key.
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
            await ws.send(json.dumps({"type": "auth", "token": "secret"}))  # no scheme
            reply = json.loads(await asyncio.wait_for(ws.recv(), timeout=5))
            assert reply["type"] == "ready"
            assert reply["public_url"].startswith("http://")
    finally:
        await _quiet_cancel(server_task)


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
