"""Stream multiplexer over a single WebSocket connection.

One physical WSS connection carries many logical byte streams -- one per public
HTTP request. This is the same idea as HTTP/2 streams or yamux/muxado: it avoids
a connection-per-request and the pool-exhaustion failure modes that come with
that. The agent maintains exactly one connection; everything rides inside it.

Resource bounds (DoS hardening; none of this touches payload bytes): each
stream's inbound queue is bounded, and a stream whose consumer stalls long
enough to overflow it is reset rather than buffered without limit. The number of
concurrent streams per connection is capped. The responder side never
materializes a peer-opened stream it wasn't told to accept.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any

from . import protocol

# Hard ceiling on bytes buffered for one stream before we give up on a stalled
# consumer: _STREAM_QUEUE_MAX chunks x <=64 KiB ~= 16 MiB. Generous enough that a
# slow-but-progressing reader never trips it; only a fully stalled/dead consumer
# does, and resetting that stream is the right call.
_STREAM_QUEUE_MAX = 256

# Cap concurrent streams per connection so a misbehaving peer can't grow the
# registry without bound. Far above any realistic concurrent-request count.
_MAX_STREAMS = 4096


class Stream:
    """One logical, bidirectional byte stream living inside a :class:`Mux`."""

    def __init__(self, mux: Mux, stream_id: int) -> None:
        self._mux = mux
        self.id = stream_id
        self._incoming: asyncio.Queue[bytes | None] = asyncio.Queue(maxsize=_STREAM_QUEUE_MAX)
        self.reset_by_peer = False

    async def send(self, data: bytes) -> None:
        await self._mux._send(protocol.DATA, self.id, data)

    async def send_eof(self) -> None:
        await self._mux._send(protocol.EOF, self.id, b"")

    async def read(self) -> bytes | None:
        """Next chunk of inbound data, or ``None`` once the peer half-closes."""
        return await self._incoming.get()

    async def reset(self) -> None:
        """Abort the stream and tell the peer to drop its end."""
        try:
            await self._mux._send(protocol.RESET, self.id, b"")
        finally:
            self._mux._remove(self.id)

    def close(self) -> None:
        self._mux._remove(self.id)

    # -- fed by the Mux read loop --
    def _feed(self, data: bytes) -> None:
        try:
            self._incoming.put_nowait(data)
        except asyncio.QueueFull:
            # Consumer has stalled long enough to buffer the whole cap. Don't
            # grow without bound and don't block the shared demux loop (which
            # would head-of-line-block every other stream): drop this stream and
            # reset it. The consumer is unblocked by the relay's drain timeout.
            self.reset_by_peer = True
            self._mux._spawn(self.reset())

    def _feed_eof(self) -> None:
        try:
            self._incoming.put_nowait(None)
        except asyncio.QueueFull:
            self._mux._spawn(self.reset())

    def _abort(self) -> None:
        self.reset_by_peer = True
        try:
            self._incoming.put_nowait(None)
        except asyncio.QueueFull:
            pass  # consumer already has plenty queued; it will stop on its own


class Mux:
    """Routes frames between a WebSocket and per-stream queues.

    The side that calls :meth:`open` is the initiator (the server). The side
    that passes ``on_open`` is the responder (the agent): its callback fires
    for every stream the peer opens.
    """

    def __init__(
        self,
        ws: Any,  # a websockets connection (send/recv/close, async-iterable)
        on_open: Callable[[Stream], Awaitable[None]] | None = None,
        max_streams: int = _MAX_STREAMS,
    ) -> None:
        self._ws = ws
        self._on_open = on_open
        self._streams: dict[int, Stream] = {}
        self._next_id = 1
        self._tasks: set[asyncio.Task[None]] = set()
        self._max_streams = max_streams

    async def open(self) -> Stream:
        """Allocate a new stream and announce it to the peer (initiator side)."""
        if len(self._streams) >= self._max_streams:
            raise RuntimeError("too many concurrent streams")
        sid = self._next_id
        # 4-byte stream ids (protocol.py: "!BI"); wrap before overflowing struct.
        self._next_id = self._next_id + 1 if self._next_id < 0xFFFFFFFF else 1
        stream = Stream(self, sid)
        self._streams[sid] = stream
        # Await the OPEN send so it is ordered strictly before any DATA the
        # caller sends next -- websockets preserves send order per connection.
        await self._send(protocol.OPEN, sid, b"")
        return stream

    async def aclose(self, code: int = 1000, reason: str = "") -> None:
        """Close the underlying WebSocket. The Mux owns its connection, so
        callers tear it down through here instead of touching the socket."""
        await self._ws.close(code=code, reason=reason)

    async def _send(self, ftype: int, sid: int, payload: bytes) -> None:
        await self._ws.send(protocol.encode(ftype, sid, payload))

    def _remove(self, sid: int) -> None:
        self._streams.pop(sid, None)

    def _spawn(self, coro: Awaitable[None]) -> None:
        task = asyncio.ensure_future(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def run(self) -> None:
        """Pump frames off the websocket until it closes, then abort streams."""
        try:
            async for message in self._ws:
                if not isinstance(message, bytes):
                    continue  # binary frames are bytes; ignore stray text (str) frames
                try:
                    ftype, sid, payload = protocol.decode(message)
                except ValueError:
                    continue  # malformed/short frame: drop it, keep the mux alive
                if ftype == protocol.OPEN:
                    if self._on_open is None:
                        # The server never accepts peer-opened streams; ignore so
                        # a malicious agent can't grow the registry with OPENs.
                        continue
                    if len(self._streams) >= self._max_streams:
                        self._spawn(self._send(protocol.RESET, sid, b""))
                        continue
                    stream = Stream(self, sid)
                    self._streams[sid] = stream
                    self._spawn(self._on_open(stream))
                elif ftype == protocol.DATA:
                    if (s := self._streams.get(sid)) is not None:
                        s._feed(payload)
                elif ftype == protocol.EOF:
                    if (s := self._streams.get(sid)) is not None:
                        s._feed_eof()
                elif ftype == protocol.RESET:
                    if (s := self._streams.get(sid)) is not None:
                        s._abort()
                        self._remove(sid)
        finally:
            for stream in list(self._streams.values()):
                stream._abort()
            self._streams.clear()
            # Cancel any spawned work (e.g. agent-side per-stream handlers) so
            # idle local-app sockets don't leak across a reconnect.
            for task in list(self._tasks):
                task.cancel()
            self._tasks.clear()
