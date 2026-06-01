"""chute agent + SDK -- runs on your Mac (the client).

This is the part you ``import``. It dials *out* to the server's control port,
authenticates, and then waits for the server to open streams. For each stream
it connects to your local app and pipes bytes both ways.

It is built to be fire-and-forget: a single supervisory loop reconnects with
exponential backoff + jitter, so laptop sleep/wake, Wi-Fi changes and server
restarts all self-heal without you touching anything.

Three ways to consume it
------------------------

Async, in your own event loop::

    tunnel = Tunnel(server="vps.example.com", token="...", local_port=8000)
    await tunnel.serve_forever()          # runs until cancelled

Blocking script / context manager::

    with Tunnel(server="vps.example.com", token="...", local_port=8000) as t:
        print(t.public_url)               # ready by the time the body runs
        t.wait()                          # block until Ctrl-C

Fire-and-forget background thread::

    t = Tunnel(...).start()               # non-blocking; reconnects forever
    ...
    t.stop()
"""

from __future__ import annotations

import asyncio
import json
import logging
import random
import ssl
import threading
from pathlib import Path

import websockets

from . import certs, names
from .mux import Mux, Stream

log = logging.getLogger("chute.client")

# Match the server's control-channel framing cap: our frames are a 5-byte prefix
# + at most one 64 KiB pump read, so 256 KiB is ample headroom while bounding any
# single message. compression is disabled to mirror the server (no permessage-
# deflate). Neither touches proxied bytes -- they ride inside DATA frames.
_MAX_WS_MESSAGE = 256 * 1024
_DRAIN_TIMEOUT = 120.0

# Control-channel close codes the agent must NOT retry: a rejected token (4001) or
# a rejected subdomain / over-limit (4002) won't be fixed by reconnecting. Every
# other close (e.g. 1013 "try again later" when the authorizer is briefly down, or
# a plain network drop) is transient -> the supervisory loop backs off and retries.
_FATAL_CLOSE_CODES = frozenset({4001, 4002})


class Tunnel:
    def __init__(
        self,
        *,
        server: str,
        token: str,
        local_port: int,
        local_host: str = "127.0.0.1",
        control_port: int = 7000,
        server_cert: str | Path | None = None,
        max_backoff: float = 30.0,
        scheme: str = "http",
        subdomain: str | None = None,
    ) -> None:
        if scheme not in ("http", "https"):
            raise ValueError(f"scheme must be 'http' or 'https', got {scheme!r}")
        if subdomain is not None and not names.valid_label(subdomain.lower()):
            raise ValueError(
                f"subdomain must be a single DNS label (a-z, 0-9, hyphen), got {subdomain!r}"
            )
        self.server = server
        self.token = token
        self.local_host = local_host
        self.local_port = local_port
        self.control_port = control_port
        self.server_cert = Path(server_cert) if server_cert else None
        self.max_backoff = max_backoff
        # Which scheme the PUBLIC endpoint serves. "https" asks the server to
        # terminate TLS at its edge; the agent still speaks plaintext to the
        # local app, and the public cert lives on the server -- never here.
        self.scheme = scheme
        # Requested public subdomain label (None => the server auto-assigns one).
        # Only meaningful when the server runs multi-tenant (has a base domain).
        self._requested_subdomain = subdomain.lower() if subdomain else None

        # Populated once the tunnel is ready:
        self.public_url: str | None = None
        self.subdomain: str | None = None  # the label the server actually assigned
        self._stop = asyncio.Event()
        self._connected = asyncio.Event()

        # only used by the threaded start()/stop() convenience wrapper
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None

    # -- async API -------------------------------------------------------------
    async def serve_forever(self) -> None:
        """Connect and keep the tunnel alive, reconnecting until stopped."""
        attempt = 0
        while not self._stop.is_set():
            try:
                await self._run_once()
                attempt = 0  # clean disconnect (e.g. server restart): retry fast
            except _FatalError as exc:
                log.error("fatal: %s -- not retrying", exc)
                raise
            except Exception as exc:  # noqa: BLE001 -- any transport hiccup retries
                attempt += 1
                if self._stop.is_set():
                    break
                delay = min(self.max_backoff, 2 ** min(attempt, 6)) * (0.5 + random.random() / 2)
                log.warning("disconnected (%s); reconnecting in %.1fs", exc, delay)
                self._connected.clear()
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=delay)
                except TimeoutError:
                    pass

    async def wait_until_ready(self, timeout: float | None = None) -> str:
        """Block until connected; return the public URL."""
        await asyncio.wait_for(self._connected.wait(), timeout=timeout)
        assert self.public_url is not None
        return self.public_url

    async def aclose(self) -> None:
        self._stop.set()

    async def _run_once(self) -> None:
        uri = f"wss://{self.server}:{self.control_port}"
        ssl_ctx = self._build_ssl()
        async with websockets.connect(
            uri,
            ssl=ssl_ctx,
            ping_interval=20,
            ping_timeout=20,
            max_size=_MAX_WS_MESSAGE,
            compression=None,
            open_timeout=15,
        ) as ws:
            auth = {"type": "auth", "token": self.token, "scheme": self.scheme}
            if self._requested_subdomain:
                auth["subdomain"] = self._requested_subdomain
            await ws.send(json.dumps(auth))
            try:
                reply = json.loads(await asyncio.wait_for(ws.recv(), timeout=10))
            except websockets.ConnectionClosed as exc:
                # Server closed during the handshake without a reply frame. Decide
                # fatal-vs-retry by close code, not by frame presence, so a
                # retryable 1013 (authorizer briefly unavailable) backs off instead
                # of giving up, while a fatal 4001/4002 doesn't loop forever.
                close = exc.rcvd or exc.sent
                code = close.code if close is not None else None
                if code in _FATAL_CLOSE_CODES:
                    raise _FatalError((close.reason if close else "") or f"closed {code}") from exc
                raise
            if reply.get("type") != "ready":
                # auth/subdomain rejections can't be fixed by retrying
                raise _FatalError(reply.get("reason", "handshake rejected"))

            self.public_url = reply["public_url"]
            self.subdomain = reply.get("subdomain")  # None in single-tenant mode
            self._connected.set()
            log.info("tunnel ready -> %s", self.public_url)

            mux = Mux(ws, on_open=self._handle_stream)
            await mux.run()  # returns when the connection closes

    def _build_ssl(self) -> ssl.SSLContext:
        if self.server_cert is not None:
            return certs.client_ssl_context(self.server_cert)
        # No pinned cert supplied: fall back to system trust (public CA case).
        return ssl.create_default_context()

    # -- per-request handling --------------------------------------------------
    async def _handle_stream(self, stream: Stream) -> None:
        try:
            reader, writer = await asyncio.open_connection(self.local_host, self.local_port)
        except OSError as exc:
            log.warning("local app unreachable (%s:%s): %s", self.local_host, self.local_port, exc)
            await _safe_reset(stream)
            return
        try:
            async with asyncio.TaskGroup() as tg:
                tg.create_task(_pump_stream_to_local(stream, writer))
                tg.create_task(_pump_local_to_stream(reader, stream))
        except* Exception:
            await _safe_reset(stream)
        finally:
            _safe_close(writer)
            stream.close()

    # -- threaded convenience wrapper -----------------------------------------
    def start(self) -> Tunnel:
        """Run :meth:`serve_forever` in a background thread; return immediately."""
        if self._thread is not None:
            return self

        ready = threading.Event()

        def _runner() -> None:
            loop = asyncio.new_event_loop()
            self._loop = loop
            asyncio.set_event_loop(loop)
            ready.set()
            try:
                loop.run_until_complete(self.serve_forever())
            except (asyncio.CancelledError, _FatalError):
                pass
            finally:
                loop.close()

        self._thread = threading.Thread(target=_runner, name="chute", daemon=True)
        self._thread.start()
        ready.wait()
        return self

    def stop(self) -> None:
        if self._loop is not None:
            self._loop.call_soon_threadsafe(self._stop.set)
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    def wait(self) -> None:
        """Block the calling (main) thread until interrupted -- for scripts."""
        try:
            while self._thread is not None and self._thread.is_alive():
                self._thread.join(timeout=0.5)
        except KeyboardInterrupt:
            self.stop()

    def __enter__(self) -> Tunnel:
        self.start()
        # surface the public URL before handing control back to the caller
        deadline = 10.0
        step = 0.05
        waited = 0.0
        while self.public_url is None and waited < deadline:
            threading.Event().wait(step)
            waited += step
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop()


class _FatalError(Exception):
    """Auth/handshake errors that retrying cannot fix."""


# -- relay pumps: byte-transparent. chute never inspects or alters HTTP, so
# -- headers, keep-alive, SSE and WebSocket upgrades all pass through verbatim.
async def _pump_stream_to_local(stream: Stream, writer: asyncio.StreamWriter) -> None:
    while True:
        chunk = await stream.read()
        if chunk is None:
            if writer.can_write_eof():
                writer.write_eof()
            return
        writer.write(chunk)
        # Bound a stalled local app so it can't pin the stream/buffer forever.
        await asyncio.wait_for(writer.drain(), timeout=_DRAIN_TIMEOUT)


async def _pump_local_to_stream(reader: asyncio.StreamReader, stream: Stream) -> None:
    while True:
        data = await reader.read(65536)
        if not data:
            await stream.send_eof()
            return
        await stream.send(data)


def _safe_close(writer: asyncio.StreamWriter) -> None:
    try:
        writer.close()
    except Exception:
        pass


async def _safe_reset(stream: Stream) -> None:
    try:
        await stream.reset()
    except Exception:
        pass
