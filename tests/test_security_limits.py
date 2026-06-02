"""Behavioral regression tests for the audit hardening that test_security.py
didn't cover: connection caps actually reject, the per-stream queue resets a
stalled consumer, the pinned cert can't sign trusted children (CA:FALSE), and
the control channel negotiates no permessage-deflate.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import http.client
import socket
import ssl
from pathlib import Path

import pytest
import websockets
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

import chute.mux
import chute.server
from chute import certs, protocol
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
    finally:
        await _quiet_cancel(task)


# -- 3. a peer that floods past the hard backstop is reset (flow-control net) --
async def test_stream_flood_past_backstop_resets(monkeypatch) -> None:
    # With credit-window flow control a compliant peer never overflows; this is the
    # backstop for a peer that IGNORES its window and floods us -- a protocol
    # violation -> RESET, with the consumer woken (not buffered without bound).
    monkeypatch.setattr(chute.mux, "_STREAM_HARD_MAX", 10)

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
def test_server_ssl_context_disables_session_tickets(tmp_path: Path) -> None:
    # OpenSSL otherwise mints one session-ticket key at context creation and never
    # rotates it for the process lifetime; a later leak retroactively breaks the
    # forward secrecy of every resumed session. Both the control channel and the
    # edge-TLS listener use this context, so both must refuse resumption (F45).
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    certs.generate("127.0.0.1", cert, key)
    ctx = certs.server_ssl_context(cert, key)
    assert ctx.options & ssl.OP_NO_TICKET  # TLS 1.2 STEK off
    assert ctx.num_tickets == 0  # TLS 1.3 tickets off


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
        srv._record_auth_fail(f"2001:db8::{i:x}")  # all fresh within the window
    assert len(srv._auth_fails) <= 16
