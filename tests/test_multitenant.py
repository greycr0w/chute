"""Host-label routing: many agents, each owning a subdomain label.

When the server is given a ``base_domain`` it routes each public request by its
Host header to the agent that owns that label, and hands every agent a
``<label>.<base_domain>`` URL. Without a base domain, the same registry/relay
path is used under the reserved internal ``default`` label.

There's no nginx here: we drive the server's plain-HTTP public port directly
with a hand-built request carrying a chosen Host, exactly as nginx would after
terminating TLS.
"""

from __future__ import annotations

import asyncio
import contextlib
import http.client
import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
import websockets

from chute import certs, names, protocol
from chute.client import Tunnel
from chute.server import Server

BASE = "tun.test"


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


def _make_handler(marker: str) -> type[BaseHTTPRequestHandler]:
    """A local app whose responses are tagged with *marker* so we can prove
    a request reached the right agent (and carries app headers verbatim)."""

    class _H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args: object) -> None:
            pass

        def do_GET(self) -> None:
            body = marker.encode() + b":" + self.path.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("X-Custom-Header", "verbatim-value-123")
            self.send_header("Strict-Transport-Security", "max-age=63072000")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return _H


def _start_app(marker: str) -> tuple[int, ThreadingHTTPServer]:
    port = _free_port()
    httpd = ThreadingHTTPServer(("127.0.0.1", port), _make_handler(marker))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return port, httpd


def _raw_get(port: int, host_header: str, path: str = "/") -> tuple[int, dict[str, str], bytes]:
    """GET the public port carrying an explicit Host -- exactly what nginx
    forwards after terminating TLS. Passing our own Host header suppresses the
    one http.client would otherwise derive from the connection target."""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        conn.request("GET", path, headers={"Host": host_header})
        resp = conn.getresponse()
        headers = {k.lower(): v for k, v in resp.getheaders()}
        return resp.status, headers, resp.read()
    finally:
        conn.close()


def _raw_send(port: int, raw: bytes) -> bytes:
    """Send hand-crafted request bytes (the malformed shapes http.client would
    refuse to form) and return the whole raw response. Used to assert that an
    ambiguous head gets a 400 on the wire and never reaches an agent."""
    with socket.create_connection(("127.0.0.1", port), timeout=10) as s:
        s.sendall(raw)
        chunks: list[bytes] = []
        while True:
            buf = s.recv(4096)
            if not buf:
                break
            chunks.append(buf)
    return b"".join(chunks)


@contextlib.asynccontextmanager
async def _multi(
    tmp_path: Path,
    agents: list[tuple[str | None, str]],
    *,
    scheme: str = "http",
    include_server: bool = False,
):
    """Spin up a multi-tenant server + one agent per (requested_subdomain, marker)."""
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    certs.generate("127.0.0.1", cert, key)
    public_port, control_port = _free_port(), _free_port()
    server = Server(
        token="secret",
        public_host="127.0.0.1",
        public_port=public_port,
        control_host="127.0.0.1",
        control_port=control_port,
        ssl_context=certs.server_ssl_context(cert, key),
        base_domain=BASE,
        upstream_tls=True,
    )
    tasks: list[asyncio.Future] = [asyncio.ensure_future(server.serve())]
    httpds: list[ThreadingHTTPServer] = []
    tunnels: list[Tunnel] = []
    await asyncio.sleep(0.3)
    try:
        for sub, marker in agents:
            lp, httpd = _start_app(marker)
            httpds.append(httpd)
            t = Tunnel(
                server="127.0.0.1",
                token="secret",
                local_port=lp,
                control_port=control_port,
                server_cert=str(cert),
                subdomain=sub,
                scheme=scheme,
            )
            tasks.append(asyncio.ensure_future(t.serve_forever()))
            await t.wait_until_ready(timeout=5)
            tunnels.append(t)
        if include_server:
            yield public_port, tunnels, server
        else:
            yield public_port, tunnels
    finally:
        for t in tunnels:
            await t.aclose()
        await _quiet_cancel(*tasks)
        for h in httpds:
            h.shutdown()


async def test_routes_by_host_to_correct_agent(tmp_path: Path) -> None:
    async with _multi(tmp_path, [("alpha", "A"), ("beta", "B")]) as (port, _tunnels):
        s, _, body = await asyncio.to_thread(_raw_get, port, f"alpha.{BASE}", "/x")
        assert s == 200 and body == b"A:/x"
        s, _, body = await asyncio.to_thread(_raw_get, port, f"beta.{BASE}", "/y")
        assert s == 200 and body == b"B:/y"


async def test_requested_subdomain_is_honored(tmp_path: Path) -> None:
    async with _multi(tmp_path, [("myapp", "M")]) as (_port, tunnels):
        assert tunnels[0].subdomain == "myapp"
        assert tunnels[0].public_url == f"http://myapp.{BASE}/"


async def test_explicit_http_stays_http_when_https_is_available(tmp_path: Path) -> None:
    async with _multi(tmp_path, [("plain", "P")], scheme="http") as (_port, tunnels):
        assert tunnels[0].subdomain == "plain"
        assert tunnels[0].public_url == f"http://plain.{BASE}/"


async def test_auto_subdomain_assigned_and_routes(tmp_path: Path) -> None:
    async with _multi(tmp_path, [(None, "Z")]) as (port, tunnels):
        label = tunnels[0].subdomain
        assert label and names.valid_label(label)
        assert tunnels[0].public_url == f"http://{label}.{BASE}/"
        s, _, body = await asyncio.to_thread(_raw_get, port, f"{label}.{BASE}")
        assert s == 200 and body == b"Z:/"


async def test_unknown_subdomain_returns_503(tmp_path: Path) -> None:
    async with _multi(tmp_path, [("alpha", "A")]) as (port, _tunnels):
        s, _, _ = await asyncio.to_thread(_raw_get, port, f"nobody.{BASE}")
        assert s == 503


async def test_ambiguous_head_gets_400_and_is_not_routed(tmp_path: Path) -> None:
    # A request a downstream hop could parse differently must be refused (400) and
    # must never reach the agent -- otherwise it's a routing/smuggling primitive.
    # The body marker "A:" only appears if the request actually hit agent alpha.
    malformed = [
        # malformed request-line shapes must fail before Host routing.
        f"GET\r\nHost: alpha.{BASE}\r\n\r\n".encode(),
        f"GET / HTTP/1.1 extra\r\nHost: alpha.{BASE}\r\n\r\n".encode(),
        f"GET *garbage HTTP/1.1\r\nHost: alpha.{BASE}\r\n\r\n".encode(),
        # duplicate Host: the old parser picked the first; a smuggler put the
        # victim second so the app behind saw a different host than we routed on.
        f"GET / HTTP/1.1\r\nHost: alpha.{BASE}\r\nHost: alpha.{BASE}\r\n\r\n".encode(),
        # whitespace before the colon (the CVE-2019-16276 shape).
        f"GET / HTTP/1.1\r\nHost : alpha.{BASE}\r\n\r\n".encode(),
        # obs-fold: an indented continuation masquerading as the Host line.
        f"GET / HTTP/1.1\r\nX-Pad: y\r\n\tHost: alpha.{BASE}\r\n\r\n".encode(),
    ]
    async with _multi(tmp_path, [("alpha", "A")], include_server=True) as (
        port,
        _tunnels,
        server,
    ):
        for raw in malformed:
            before = server._agents["alpha"].mux.stats()["opened"]
            resp = await asyncio.to_thread(_raw_send, port, raw)
            assert resp.startswith(b"HTTP/1.1 400"), resp[:64]
            assert b"A:" not in resp  # never routed to alpha's app
            assert server._agents["alpha"].mux.stats()["opened"] == before


async def test_direct_host_routing_commits_connection_to_first_request(tmp_path: Path) -> None:
    # This is the cloud deployment invariant in executable form: chute routes once
    # per TCP connection, so nginx must not reuse one upstream connection for
    # requests targeting different labels.
    raw = (
        f"GET /one HTTP/1.1\r\nHost: alpha.{BASE}\r\nConnection: keep-alive\r\n\r\n"
        f"GET /two HTTP/1.1\r\nHost: beta.{BASE}\r\nConnection: close\r\n\r\n"
    ).encode()
    async with _multi(tmp_path, [("alpha", "A"), ("beta", "B")]) as (port, _tunnels):
        resp = await asyncio.to_thread(_raw_send, port, raw)
        assert b"A:/one" in resp
        assert b"A:/two" in resp
        assert b"B:/two" not in resp


def test_multitenant_is_loopback_only() -> None:
    # Multi-tenant routes per connection, so a routable bind is a cross-tenant
    # request-bleed: the ctor must fail closed, not warn-and-run.
    with pytest.raises(ValueError, match="loopback-only"):
        Server(token="x", base_domain=BASE, public_host="0.0.0.0")
    with pytest.raises(ValueError, match="loopback-only"):
        Server(token="x", base_domain=BASE, public_host="203.0.113.7")
    # Loopback multi-tenant is fine; single-tenant never routes, so any bind is fine.
    Server(token="x", base_domain=BASE, public_host="127.0.0.1")
    Server(token="x", public_host="0.0.0.0")


async def test_routed_path_is_transparent(tmp_path: Path) -> None:
    # Routing must not cost us transparency: app headers still pass verbatim.
    async with _multi(tmp_path, [("alpha", "A")]) as (port, _tunnels):
        s, headers, _ = await asyncio.to_thread(_raw_get, port, f"alpha.{BASE}")
        assert s == 200
        assert headers.get("x-custom-header") == "verbatim-value-123"
        assert headers.get("strict-transport-security") == "max-age=63072000"
        assert headers.get("connection", "").lower() != "close"  # we didn't inject it


async def test_https_scheme_with_upstream_tls(tmp_path: Path) -> None:
    # Behind nginx (upstream_tls=True) we advertise https without chute itself
    # holding any public cert.
    async with _multi(tmp_path, [("secure", "S")], scheme="https") as (_port, tunnels):
        assert tunnels[0].public_url == f"https://secure.{BASE}/"
        assert tunnels[0].subdomain == "secure"


async def test_server_rejects_invalid_subdomain(tmp_path: Path) -> None:
    # Defense in depth: even a hand-rolled agent that skips client validation
    # gets a clean rejection (not a crash, not a silent accept).
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
        base_domain=BASE,
    )
    server_task = asyncio.ensure_future(server.serve())
    await asyncio.sleep(0.3)
    ctx = certs.client_ssl_context(cert)
    try:
        async with websockets.connect(
            f"wss://127.0.0.1:{control_port}", ssl=ctx, open_timeout=5
        ) as ws:
            await ws.send(
                json.dumps(
                    {
                        "type": "auth",
                        "token": "secret",
                        "subdomain": "bad_label",
                        "v": protocol.VERSION,
                    }
                )
            )
            reply = json.loads(await asyncio.wait_for(ws.recv(), timeout=5))
            assert reply["type"] == "error"
            assert reply["reason"] == "invalid_subdomain"
    finally:
        await _quiet_cancel(server_task)


def test_sdk_rejects_bad_subdomain_locally() -> None:
    with pytest.raises(ValueError):
        Tunnel(server="x", token="y", local_port=1, subdomain="bad_label")
    with pytest.raises(ValueError):
        Tunnel(server="x", token="y", local_port=1, subdomain="-leading-hyphen")
