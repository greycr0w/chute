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
import contextlib
import json
import logging
import random
import ssl
import threading
from pathlib import Path

import websockets

from . import certs, names, protocol
from .mux import Mux, Stream

log = logging.getLogger("chute.client")

# Match the server's control-channel framing cap: our frames are a 5-byte prefix
# + at most one 64 KiB pump read, so 256 KiB is ample headroom while bounding any
# single message. compression is disabled to mirror the server (no permessage-
# deflate). Neither touches proxied bytes -- they ride inside DATA frames.
_MAX_WS_MESSAGE = 256 * 1024
_DRAIN_TIMEOUT = 120.0
# How long a graceful stop (Ctrl-C / aclose) waits for in-flight requests to finish
# before closing -- mirrors the server's drain grace. A permanent SSE/WS stream is
# force-closed at the deadline.
_AGENT_DRAIN_TIMEOUT = 10.0
# Bound the dial to the local app: a firewalled/blackholed port (SYN dropped) or a
# full listen backlog would otherwise pin the stream for the full OS connect window
# (minutes). Matches nginx proxy_connect_timeout / cloudflared connectTimeout.
_LOCAL_CONNECT_TIMEOUT = 10.0

# Control-channel close codes the agent must NOT retry: a rejected token (4001) or
# a rejected subdomain / over-limit (4002) won't be fixed by reconnecting. Every
# other close (e.g. 1013 "try again later" when the authorizer is briefly down, or
# a plain network drop) is transient -> the supervisory loop backs off and retries.
# 4004 = protocol-version mismatch (server too new/old): retrying won't fix it.
_FATAL_CLOSE_CODES = frozenset({4001, 4002, 4004})


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
        scheme: str = "https",
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
        # Only meaningful when the server has a base domain for Host-routed labels.
        self._requested_subdomain = subdomain.lower() if subdomain else None

        # Populated once the tunnel is ready:
        self.public_url: str | None = None
        self.subdomain: str | None = None  # the label the server actually assigned
        self._ready_error: _FatalError | None = None
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
            # Not connected until _run_once sets it. Clear at the top of every
            # attempt: a *clean* disconnect (server restart) loops back here without
            # going through the except branch, so clearing only there would leave a
            # stale public_url returnable by wait_until_ready until the next ready.
            self._connected.clear()
            self._ready_error = None
            self.public_url = None
            self.subdomain = None
            try:
                await self._run_once()
                attempt = 0  # clean disconnect (e.g. server restart): retry fast
            except _FatalError as exc:
                self._ready_error = exc
                self._connected.set()
                log.error("fatal: %s -- not retrying", exc)
                raise
            except Exception as exc:  # noqa: BLE001 -- any transport hiccup retries
                attempt += 1
                if self._stop.is_set():
                    break
                delay = min(self.max_backoff, 2 ** min(attempt, 6)) * (0.5 + random.random() / 2)
                log.warning("disconnected (%s); reconnecting in %.1fs", exc, delay)
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=delay)
                except TimeoutError:
                    pass

    async def wait_until_ready(self, timeout: float | None = None) -> str:
        """Block until connected; return the public URL."""
        await asyncio.wait_for(self._connected.wait(), timeout=timeout)
        if self._ready_error is not None:
            raise self._ready_error
        assert self.public_url is not None
        return self.public_url

    async def aclose(self) -> None:
        self._stop.set()

    def request_stop(self) -> None:
        """Signal the tunnel to drain in-flight streams and stop (no reconnect).
        Sync + idempotent, so it is safe to call from a signal handler."""
        self._stop.set()

    def _on_server_goaway(self) -> None:
        # The server is draining (e.g. a restart): our in-flight handlers finish, and
        # the clean close that follows is picked up by serve_forever's reconnect loop.
        # Just a breadcrumb so the disconnect doesn't look like an error.
        log.info("server is going away (draining); will reconnect once it closes")

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
            auth: dict[str, object] = {
                "type": "auth",
                "token": self.token,
                "scheme": self.scheme,
                "v": protocol.VERSION,
            }
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
            except (ValueError, RecursionError) as exc:
                # Non-JSON / pathologically-nested reply: a protocol violation from
                # the server, not a transient drop. Retrying gets the same bytes, so
                # fail loudly instead of silently reconnect-spinning.
                raise _FatalError(f"malformed handshake reply: {exc}") from exc
            if not isinstance(reply, dict) or reply.get("type") != "ready":
                # auth/subdomain rejections (and any non-object reply) can't be fixed
                # by retrying; surface the server's reason when it gave one.
                reason = reply.get("reason") if isinstance(reply, dict) else None
                raise _FatalError(reason or "handshake rejected")
            if reply.get("v") != protocol.VERSION:
                # Server doesn't speak our flow-control protocol (too old/new). A
                # mismatched pair would stall, so refuse instead of reconnect-spinning.
                raise _FatalError(
                    f"server protocol v={reply.get('v')!r}, need v{protocol.VERSION}; "
                    "upgrade chute on both ends"
                )
            url = reply.get("public_url")
            if not isinstance(url, str):
                # A "ready" with no usable URL is a protocol error, not a transport
                # hiccup -- don't KeyError into a silent retry loop (old reply["..."]).
                raise _FatalError("handshake reply missing public_url")

            self.public_url = url
            self._ready_error = None
            self.subdomain = reply.get("subdomain")  # None for the default route
            self._connected.set()
            log.info("tunnel ready -> %s", self.public_url)

            mux = Mux(ws, on_open=self._handle_stream, on_goaway=self._on_server_goaway)
            run_task = asyncio.ensure_future(mux.run())
            stop_task = asyncio.ensure_future(self._stop.wait())
            await asyncio.wait({run_task, stop_task}, return_when=asyncio.FIRST_COMPLETED)
            if self._stop.is_set() and not run_task.done():
                # User asked to stop: GOAWAY the server and let in-flight requests
                # finish before closing, instead of cutting them off mid-response.
                log.info("stopping: draining in-flight requests")
                with contextlib.suppress(Exception):
                    await mux.drain(_AGENT_DRAIN_TIMEOUT)
            stop_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await stop_task
            await run_task  # returns on a clean close, or re-raises to trigger reconnect

    def _build_ssl(self) -> ssl.SSLContext:
        if self.server_cert is not None:
            log.info("control TLS: pinned server cert (%s)", self.server_cert)
            return certs.client_ssl_context(self.server_cert)
        # No pinned cert supplied: fall back to system trust (public CA case). Log
        # it so a typo'd --server-cert (which silently lands here) is visible as a
        # CA-trust connect rather than a confusing generic TLS error.
        log.info("control TLS: system trust store (no --server-cert pinned)")
        return ssl.create_default_context()

    # -- per-request handling --------------------------------------------------
    async def _handle_stream(self, stream: Stream) -> None:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.local_host, self.local_port),
                timeout=_LOCAL_CONNECT_TIMEOUT,
            )
        except (OSError, TimeoutError) as exc:
            # TimeoutError: a blackholed local port (SYN dropped) or a full listen
            # backlog -- bound it instead of pinning the stream for the OS connect
            # window. Both failure modes get the same RESET-and-move-on handling.
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
        # Idempotent + safe after a fatal disconnect: once serve_forever raises
        # _FatalError the background thread's loop is already closed, and
        # call_soon_threadsafe on a closed loop raises RuntimeError out of stop()
        # (and out of __exit__). Guard on is_closed(), and suppress the residual
        # check->call race window.
        loop = self._loop
        if loop is not None and not loop.is_closed():
            with contextlib.suppress(RuntimeError):
                loop.call_soon_threadsafe(self._stop.set)
        if self._thread is not None:
            # Wait out the graceful drain (up to _AGENT_DRAIN_TIMEOUT) before giving up,
            # and only drop the handle if the worker actually finished -- otherwise a
            # caller could believe the tunnel stopped while it is still draining.
            self._thread.join(timeout=_AGENT_DRAIN_TIMEOUT + 2.0)
            if not self._thread.is_alive():
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
        while self.public_url is None and self._ready_error is None and waited < deadline:
            threading.Event().wait(step)
            waited += step
        if self._ready_error is not None:
            raise self._ready_error
        if self.public_url is None:
            raise TimeoutError("tunnel did not become ready")
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop()


class _FatalError(Exception):
    """Auth/handshake errors that retrying cannot fix."""


# -- relay pumps: after server-side HTTP-head admission, bytes pass through verbatim.
async def _pump_stream_to_local(stream: Stream, writer: asyncio.StreamWriter) -> None:
    while True:
        chunk = await stream.read()
        if chunk is None:
            if stream.reset_by_peer:
                # Request was aborted/truncated, not cleanly finished: RST the local
                # socket so the app doesn't treat a partial request as complete, and
                # so the sibling pump unblocks. (F22)
                _safe_abort(writer)
            elif writer.can_write_eof():
                # Clean half-close; suppress so a best-effort EOF can't raise out of
                # the pump and tear the TaskGroup down.
                with contextlib.suppress(Exception):
                    writer.write_eof()
            else:
                _safe_close(writer)
            return
        writer.write(chunk)
        # Bound a stalled local app so it can't pin the stream/buffer forever.
        await asyncio.wait_for(writer.drain(), timeout=_DRAIN_TIMEOUT)
        # Bytes accepted by the local app: return that much credit to the server.
        await stream.ack(len(chunk))


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


def _safe_abort(writer: asyncio.StreamWriter) -> None:
    # RST the local socket (asyncio-native): the right signal for an aborted relay,
    # and it instantly unblocks a sibling pump parked on read().
    try:
        writer.transport.abort()
    except Exception:
        pass


async def _safe_reset(stream: Stream) -> None:
    try:
        await stream.reset()
    except Exception:
        pass
