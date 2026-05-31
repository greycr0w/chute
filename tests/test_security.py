"""Regression tests for the security-audit fixes.

Each test pins one hardening so a future refactor can't silently undo it:
  - control-channel frames are size-capped (no pre-auth unbounded buffering)
  - a non-object JSON hello is rejected cleanly (no AttributeError traceback)
  - the server never materializes peer-opened streams (no registry-growth OOM)
  - a short binary frame is dropped, not fatal (decode length guard)
  - the multi-tenant 503 page HTML-escapes the reflected Host (no XSS)
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import socket
from pathlib import Path

import pytest
import websockets

from chute import certs, protocol
from chute.mux import Mux
from chute.server import _MAX_WS_MESSAGE, Server, _no_tunnel_response


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


# -- pure unit tests ----------------------------------------------------------
def test_decode_rejects_short_frame() -> None:
    for bad in (b"", b"\x01", b"\x01\x02\x03\x04"):  # < 5-byte prefix
        with pytest.raises(ValueError):
            protocol.decode(bad)
    # a well-formed frame still round-trips
    assert protocol.decode(protocol.encode(protocol.DATA, 7, b"hi")) == (
        protocol.DATA,
        7,
        b"hi",
    )


def test_no_tunnel_response_escapes_host() -> None:
    body = _no_tunnel_response("<script>alert(document.domain)</script>.x")
    assert b"<script>" not in body  # raw markup must not survive
    assert b"&lt;script&gt;" in body  # it is HTML-escaped instead


async def test_mux_ignores_peer_opened_streams() -> None:
    # The server builds Mux(ws) with on_open=None. A (malicious) peer that sends
    # OPEN frames must NOT cause Stream objects to be registered, or it could
    # grow the registry without bound.
    class _PausingWS:
        def __init__(self, frames: list[bytes]) -> None:
            self.frames = frames
            self.sent: list[bytes] = []
            self.reached_end = asyncio.Event()
            self.released = asyncio.Event()

        async def send(self, data: bytes) -> None:
            self.sent.append(data)

        def __aiter__(self):
            return self._gen()

        async def _gen(self):
            for f in self.frames:
                yield f
            self.reached_end.set()
            await self.released.wait()  # park so run() doesn't clear _streams yet

    ws = _PausingWS(
        [
            protocol.encode(protocol.OPEN, 1, b""),
            protocol.encode(protocol.OPEN, 2, b""),
            protocol.encode(protocol.DATA, 1, b"junk"),
        ]
    )
    mux = Mux(ws)  # on_open=None => responder-less (server) side
    task = asyncio.ensure_future(mux.run())
    try:
        await asyncio.wait_for(ws.reached_end.wait(), timeout=5)
        assert mux._streams == {}, "server must not materialize peer-opened streams"
    finally:
        ws.released.set()
        await _quiet_cancel(task)


# -- integration against a real control listener ------------------------------
@contextlib.asynccontextmanager
async def _control_server(tmp_path: Path):
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
    task = asyncio.ensure_future(server.serve())
    await asyncio.sleep(0.3)
    try:
        yield control_port, cert
    finally:
        await _quiet_cancel(task)


async def test_oversized_preauth_frame_is_rejected(tmp_path: Path) -> None:
    async with _control_server(tmp_path) as (control_port, cert):
        ctx = certs.client_ssl_context(cert)
        # max_size=None on OUR side so we can send an oversized frame; the server
        # must refuse it (PayloadTooBig -> close) instead of buffering it.
        async with websockets.connect(
            f"wss://127.0.0.1:{control_port}", ssl=ctx, max_size=None, open_timeout=5
        ) as ws:
            with pytest.raises(websockets.exceptions.ConnectionClosed):
                await ws.send(b"x" * (_MAX_WS_MESSAGE + 50_000))
                await asyncio.wait_for(ws.recv(), timeout=5)


async def test_nonobject_hello_is_rejected_cleanly(tmp_path: Path) -> None:
    async with _control_server(tmp_path) as (control_port, cert):
        ctx = certs.client_ssl_context(cert)
        async with websockets.connect(
            f"wss://127.0.0.1:{control_port}", ssl=ctx, open_timeout=5
        ) as ws:
            await ws.send(json.dumps([1, 2, 3]))  # valid JSON, but not an object
            with pytest.raises(websockets.exceptions.ConnectionClosed):
                await asyncio.wait_for(ws.recv(), timeout=5)
            # closed via the benign 'bad handshake' path, not an internal error
            assert ws.close_code == 4000
