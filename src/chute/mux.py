"""Stream multiplexer over a single WebSocket connection.

One physical WSS connection carries many logical byte streams -- one per public
HTTP request. This is the same idea as HTTP/2 streams or yamux/muxado: it avoids
a connection-per-request and the pool-exhaustion failure modes that come with
that. The agent maintains exactly one connection; everything rides inside it.

Flow control: each stream has a per-direction **credit window**. A sender may
only transmit up to the credit it has been granted; when the window is exhausted
it *blocks* -- which propagates TCP backpressure all the way back to whatever is
producing the bytes (the visitor socket, or the local app) -- instead of letting
the receiver buffer without bound. As the receiver drains data downstream it
returns credit with WINDOW_UPDATE frames. This is end-to-end backpressure across
the WS hop, the thing a plain multiplexer otherwise loses. None of it touches
payload bytes; it only paces them.

The frame reader (`Mux.run`) never blocks on *sending* -- it only enqueues, grants
credit, and spawns -- so a stalled *consumer* can never wedge the demux loop or
head-of-line-block other streams. That decoupling makes the scheme deadlock-free for
a cooperative-but-slow peer. A *malicious or wedged* peer is a separate problem that
flow control alone does not solve, so it is met with enforcement: a peer that stops
reading is broken by a connection-level write-stall abort (`_WRITE_STALL_TIMEOUT`); a
peer that floods or refuses credit is met with the backstops below and strict
WINDOW_UPDATE validation in `run`.

Backstops (a compliant peer never approaches any of them): a stream is RESET if it
buffers past `_STREAM_HARD_MAX` bytes or `_MAX_QUEUED_FRAMES` unread frames, or pushes
the connection-wide unread total past `_MAX_CONN_BUFFERED` bytes or `_MAX_CONN_FRAMES`
frames (the frame caps bound per-frame object overhead, which the byte caps are blind
to -- a tiny-frame flood). Empty DATA frames are dropped on receipt. The number of
concurrent streams per connection is capped. The responder side never materializes a
peer-opened stream it wasn't told to accept.

Graceful drain: either side may send GOAWAY (`drain`) to announce it will open no new
streams and will close once in-flight streams finish. The server uses it for zero-drop
restarts; the agent uses it so a Ctrl-C finishes the request in flight. The wait is
bounded (`_DRAIN_GRACE`) so a permanent SSE/WebSocket stream can't pin shutdown.

Teardown contract (per Stream method -- keep this honest):

    method        sends frame?     wakes consumer (None)?   stops sender?   dereg?
    send          DATA (windowed)  -                        -               -
    send_eof      EOF              -                        -               -
    read          WINDOW_UPDATE*   (consumes None)          -               -
    _feed         -                -                        -               -
    _feed_eof     -                yes (clean)              -               -
    _abort        -                yes (abort)              yes             yes
    reset         RESET            yes (abort)              yes             yes
    close         -                yes (if pending)         yes             yes

    *read() returns WINDOW_UPDATE credit via ack(), called by the consumer pump
     after the bytes are flushed downstream.

The receive terminal's nature (clean EOF vs abort) is the lane's `_RecvState`, and it
is write-once: _abort/reset/close deliver their terminal ONLY if the lane is still
OPEN. A terminal already reached is never rewritten -- so a late RESET can't truncate a
response that already ended cleanly, and `reset_by_peer` (derived from the state) can
never disagree with what the consumer was told.
"""

from __future__ import annotations

import asyncio
import contextlib
import enum
import logging
import struct
from collections.abc import Awaitable, Callable
from typing import Any

from . import protocol

log = logging.getLogger("chute.mux")

# Initial per-stream send credit, in bytes, for each direction. A sender may have
# at most this many bytes outstanding (sent but not yet WINDOW_UPDATE-acked) before
# it must block. This bounds the receiver's buffer for a *compliant* peer to ~one
# window, and sets the bandwidth-delay-product ceiling (window / RTT) for a single
# stream. 256 KiB matches yamux's default: ample for interactive/tunnel traffic,
# tunable upward for high-latency bulk transfer.
_FLOW_WINDOW = 256 * 1024

# Hard ceiling on accumulated send credit (RFC 9113 6.9.1's 2^31-1 window cap): a
# peer that floods large WINDOW_UPDATE grants can't grow our window without bound. A
# compliant peer never sends more than one window of credit, so this never engages.
_MAX_SEND_WINDOW = (1 << 31) - 1

# Return credit once this many bytes have been drained downstream since the last
# WINDOW_UPDATE -- batched at half a window so we send ~one update per window of
# data, not one per frame.
_WINDOW_UPDATE_THRESHOLD = _FLOW_WINDOW // 2

# Backstop on bytes buffered for one stream. A compliant sender's buffer is
# provably bounded by one window (it cannot send past the credit we've granted, and
# we only grant credit for bytes already drained), so a non-compliant peer is the
# only way to exceed it. Set at 2x the window: that can never false-positive on a
# compliant peer, yet RESETs a flooder ~one window past the limit -- close to
# yamux's hard "reject any frame past the window" contract, without rejecting a
# single in-flight frame on a boundary.
_STREAM_HARD_MAX = 2 * _FLOW_WINDOW

# Cap the NUMBER of unread frames queued for one stream, not just their bytes. The
# byte backstop is blind to a flood of empty/tiny DATA frames (each grows the queue
# while adding ~0 to the byte count), so bound frame count too. A compliant peer's
# unread queue is bounded by one window in bytes and, worst case (1-byte frames), by
# one window in frames -- so this never false-positives on a compliant peer.
_MAX_QUEUED_FRAMES = _FLOW_WINDOW

# Cap concurrent streams per connection so a misbehaving peer can't grow the
# registry without bound. Far above any realistic concurrent-request count.
_MAX_STREAMS = 4096

# Connection-level aggregate buffer cap across ALL streams on one mux. Per-stream
# windows alone bound memory only to window * stream_count (yamux's structural gap);
# this is the shared global budget HTTP/2 has and yamux lacks. When the sum of every
# stream's unread bytes exceeds this, the stream that pushed it over is RESET (load
# shed) rather than letting one connection exhaust the host.
_MAX_CONN_BUFFERED = 64 * 1024 * 1024

# Connection-level cap on the NUMBER of queued frames across all streams. The byte
# caps above don't reflect a frame's real cost -- a 1-byte DATA frame is a whole Python
# bytes object + a queue node, tens of bytes the payload count is blind to -- so a flood
# of tiny frames could pin GBs of RAM while `_buffered` still reads under 64 MiB. This
# bounds total queued frame OBJECTS; a compliant peer (few large frames per window)
# stays orders of magnitude under it.
_MAX_CONN_FRAMES = 1_048_576

# How long a sender will wait for credit (a WINDOW_UPDATE) before giving up on the
# stream. A peer that drains data but never returns credit -- dead, wedged, or
# refusing to honor flow control -- would otherwise block the sender (and pin its
# slot/FD) forever. The clock is per-wait, so any grant resets it: a slow-but-
# progressing consumer keeps the stream alive. This is the credit-side analogue of
# the relay's per-write drain timeout, and the same granularity (yamux leaves this
# to an opt-in write deadline; we apply it by default).
_CREDIT_STALL_TIMEOUT = 120.0

# How long any single frame may sit unsent on the transport before we declare the
# connection wedged and abort it. A peer that stops reading its socket pauses our
# write side; ws.send() then blocks with no timeout of its own, and the WebSocket
# keepalive can't help (its ping goes through the same paused write before the pong
# deadline is even armed). This is the connection-level deadlock breaker -- yamux's
# ConnectionWriteTimeout -- that the per-stream credit-stall can't provide.
_WRITE_STALL_TIMEOUT = 30.0

# How long graceful drain waits for in-flight streams to finish before forcing the
# connection closed -- the HA/restart knob. Long enough for an in-flight HTTP request
# to complete, short enough that a permanent SSE/WebSocket stream can't pin shutdown
# (it is force-closed at the deadline and the visitor reconnects).
_DRAIN_GRACE = 10.0


class _StreamClosed(Exception):
    """Raised by ``Stream.send`` when the stream has been torn down mid-transfer,
    so the caller's pump unwinds promptly instead of spinning on a dead stream."""


class _RecvState(enum.Enum):
    """The receive direction's lifecycle -- the one authoritative 'sign' for a lane.

    Write-once past OPEN: a terminal can never change, so a late RESET cannot turn an
    already-delivered clean EOF into an abort (nor the reverse). The relay pumps read
    it (via :attr:`Stream.reset_by_peer`) to choose the end-of-stream signal they send
    downstream: a clean FIN for EOF, a hard RST for RESET.
    """

    OPEN = "open"  # more data may still arrive
    EOF = "eof"  # peer cleanly half-closed our receive direction -> FIN downstream
    RESET = "reset"  # receive direction aborted -> RST downstream


class Stream:
    """One logical, bidirectional byte stream living inside a :class:`Mux`.

    Half-close is real and the two directions carry independent state:

    * **receive** -- one :class:`_RecvState` (OPEN -> EOF | RESET), the write-once
      sign ``read`` consults; ``_recv_buffered`` / ``_recv_frames`` track queued bytes
      and frame count.
    * **send** -- ``_send_window`` credit + ``_send_ended`` (we wrote our EOF).
    * **lifecycle** -- ``_closed`` once fully torn down and deregistered.

    Because only OPEN can move to a terminal, a clean EOF survives a later abort:
    teardown never rewrites a delivered EOF into a truncation.
    """

    def __init__(self, mux: Mux, stream_id: int) -> None:
        self._mux = mux
        self.id = stream_id
        self._incoming: asyncio.Queue[bytes | None] = asyncio.Queue()  # unbounded; window bounds it

        # -- receive side --
        self._recv = _RecvState.OPEN  # the lane's one authoritative state (see _RecvState)
        self._recv_buffered = 0  # bytes currently sitting in _incoming (backstop accounting)
        self._recv_frames = 0  # COUNT of data frames in _incoming (per-frame-overhead cap)
        self._unacked = 0  # bytes drained downstream since the last WINDOW_UPDATE we sent

        # -- send side --
        self._send_window = _FLOW_WINDOW  # credit we may send before awaiting a WINDOW_UPDATE
        self._send_ended = False
        # set on a credit grant OR on close, to wake a sender parked on the window
        self._window_waiter = asyncio.Event()

        # -- lifecycle --
        self._closed = False

    def __repr__(self) -> str:
        return (
            f"<Stream {self.id} recv={self._recv.value} "
            f"send={'eof' if self._send_ended else 'open'} "
            f"closed={self._closed} window={self._send_window}>"
        )

    @property
    def reset_by_peer(self) -> bool:
        """Whether the receive terminal is an abort (RST) rather than a clean EOF
        (FIN). The relay pumps read this after ``read`` returns ``None`` to choose the
        downstream teardown signal. Derived from the one authoritative state, so it can
        never disagree with it or be flipped after the terminal is set."""
        return self._recv is _RecvState.RESET

    # -- send direction (flow-controlled) -------------------------------------
    async def send(self, data: bytes) -> None:
        """Send ``data`` to the peer, respecting the credit window. Blocks while
        the window is exhausted (backpressure); raises :class:`_StreamClosed` if
        the stream is torn down while sending."""
        if self._closed or self._send_ended:
            # Closed, or we already sent our EOF -- either way the send side is done.
            # Refuse new DATA: sending after EOF is a local protocol error (our own
            # pumps never do it), so this is a guard against a refactor, not a hot path.
            raise _StreamClosed
        view = memoryview(data)
        while len(view):
            while self._send_window <= 0:
                if self._closed:
                    raise _StreamClosed
                # Clear-then-recheck closes the lost-wakeup race: a grant landing
                # between the while-test and the wait would have set the event,
                # which we observe on the recheck (or on the wait if still empty).
                self._window_waiter.clear()
                if self._send_window > 0 or self._closed:
                    break
                try:
                    await asyncio.wait_for(
                        self._window_waiter.wait(), timeout=_CREDIT_STALL_TIMEOUT
                    )
                except TimeoutError:
                    # No credit for the whole stall window: the peer is dead or not
                    # honoring flow control. Bail; the caller's pump RESETs the stream
                    # (notifying the peer) and frees the slot, instead of blocking forever.
                    self._mux._stats["credit_stall"] += 1
                    raise _StreamClosed from None
            if self._closed:
                raise _StreamClosed
            n = min(len(view), self._send_window)
            self._send_window -= n
            await self._mux._send(protocol.DATA, self.id, bytes(view[:n]))
            view = view[n:]

    async def send_eof(self) -> None:
        if self._closed or self._send_ended:
            return
        self._send_ended = True
        await self._mux._send(protocol.EOF, self.id, b"")

    def _grant(self, delta: int) -> None:
        """Peer returned ``delta`` bytes of credit (WINDOW_UPDATE). The caller in
        :meth:`Mux.run` has already rejected malformed frames and dropped delta == 0
        (a no-op grant must NOT wake the waiter, or it resets the credit-stall clock
        and a flood of them keeps a blocked sender alive forever)."""
        # Cap the window at 2^31-1 (RFC 9113 6.9.1) so a flood of large grants can't
        # grow it without bound; a compliant peer never approaches this.
        self._send_window = min(self._send_window + delta, _MAX_SEND_WINDOW)
        self._window_waiter.set()

    # -- receive direction ----------------------------------------------------
    async def read(self) -> bytes | None:
        """Next chunk of inbound data, or ``None`` once the receive direction
        ends. On ``None``, check :attr:`reset_by_peer` to tell a clean half-close
        (write EOF downstream) from an abort (RST downstream)."""
        chunk = await self._incoming.get()
        if chunk is not None and not self._closed:
            # Decrement only while live: _close_local reconciles the rest exactly
            # once, so a post-close read of a still-queued frame must not double
            # subtract (which would drift the connection counter low, weakening the cap).
            self._recv_buffered -= len(chunk)
            self._recv_frames -= 1
            self._mux._buffered -= len(chunk)
            self._mux._frames -= 1
        return chunk

    async def ack(self, n: int) -> None:
        """The consumer flushed ``n`` bytes downstream: return that much credit to
        the peer (batched). Called by the consumer pump after ``writer.drain()``."""
        if self._closed or self.reset_by_peer or n <= 0:
            return
        self._unacked += n
        if self._unacked >= _WINDOW_UPDATE_THRESHOLD:
            delta, self._unacked = self._unacked, 0
            with contextlib.suppress(Exception):
                await self._mux._send(protocol.WINDOW_UPDATE, self.id, struct.pack("!I", delta))

    def _feed(self, data: bytes) -> None:
        if self._recv is not _RecvState.OPEN:
            return  # terminal (EOF/RESET) or torn down: drop (DATA-after-EOF, post-reset -- F15)
        if not data:
            # Empty DATA frame: nothing to deliver, and it can't be a half-close (EOF
            # is its own frame type). A compliant sender never emits one, so dropping
            # it stops a flood of 5-byte frames from growing the queue while
            # _recv_buffered stays 0 -- the byte backstop's blind spot.
            return
        next_stream_buffered = self._recv_buffered + len(data)
        next_stream_frames = self._recv_frames + 1
        next_mux_buffered = self._mux._buffered + len(data)
        next_mux_frames = self._mux._frames + 1
        # Backstops, none reachable by a compliant peer: per stream by bytes AND by
        # frame count (a tiny-frame flood the byte cap is blind to), and the same two
        # aggregated across the whole connection -- the connection frame cap is what
        # bounds per-frame object overhead, not just payload bytes. Any breach is a
        # flow-control violation -> RESET this stream.
        if (
            next_stream_buffered > _STREAM_HARD_MAX
            or next_stream_frames > _MAX_QUEUED_FRAMES
            or next_mux_buffered > _MAX_CONN_BUFFERED
            or next_mux_frames > _MAX_CONN_FRAMES
        ):
            # Mark RESET synchronously so the very next _feed drops and the consumer
            # wakes with an abort terminal now; finish teardown + notify the peer off
            # the demux path.
            self._end_recv(_RecvState.RESET)
            self._mux._spawn(self.reset())
            return
        # unbounded queue: put_nowait cannot fail, so the sentinel is never lost
        self._incoming.put_nowait(data)
        self._recv_buffered = next_stream_buffered
        self._recv_frames = next_stream_frames
        self._mux._buffered = next_mux_buffered
        self._mux._frames = next_mux_frames

    def _feed_eof(self) -> None:
        # Idempotent: only OPEN -> EOF; a second EOF, or EOF after a reset/teardown,
        # is a no-op inside _end_recv.
        self._end_recv(_RecvState.EOF)

    def _end_recv(self, state: _RecvState) -> None:
        """Move the receive direction OPEN -> ``state`` exactly once, delivering the
        consumer's terminal ``None``. An already-terminal lane is untouched, so a
        clean EOF is never rewritten to an abort by a later RESET (F58, structural)."""
        if self._recv is not _RecvState.OPEN:
            return
        self._recv = state
        self._incoming.put_nowait(None)

    # -- teardown -------------------------------------------------------------
    def _abort(self) -> None:
        """Peer RESET us, or the connection died: stop both directions now. A receive
        direction that already ended cleanly stays clean (only OPEN can move to a
        terminal) -- a late RESET aborts only the still-open send direction; it never
        rewrites a delivered/queued EOF into a truncation signal downstream."""
        self._close_local(_RecvState.RESET)

    async def reset(self) -> None:
        """We are aborting the stream: tell the peer, then tear down locally."""
        if self._reset_local_now():
            with contextlib.suppress(Exception):
                await self._mux._send(protocol.RESET, self.id, b"")

    def _reset_local_now(self) -> bool:
        """Synchronously mark a local reset before any async RESET frame send."""
        first = not self._closed
        self._close_local(_RecvState.RESET)  # see _abort: a clean EOF is preserved
        if first:
            self._mux._stats["reset_local"] += 1
        return first

    def close(self) -> None:
        # A plain close is a clean end if the receive side was still open; if it
        # already reached EOF/RESET, _end_recv keeps that first terminal.
        self._close_local(_RecvState.EOF)

    def _close_local(self, recv_terminal: _RecvState) -> None:
        """Idempotent full teardown of local stream state: stop the sender, reconcile
        the connection buffer counter, deliver the receive terminal (``recv_terminal``
        unless the lane already ended), deregister. Never sends a frame."""
        if self._closed:
            return
        self._closed = True
        self._window_waiter.set()  # wake a sender parked on credit so it can bail
        # Reconcile the connection-level counter for whatever is still queued and now
        # abandoned (post-close read()s skip their own decrement), so the count never
        # drifts across a stream's lifetime.
        self._mux._buffered -= self._recv_buffered
        self._mux._frames -= self._recv_frames
        self._recv_buffered = 0
        self._recv_frames = 0
        self._end_recv(recv_terminal)  # no-op if the lane already reached a terminal
        self._mux._remove(self.id)


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
        on_goaway: Callable[[], None] | None = None,
        max_streams: int = _MAX_STREAMS,
    ) -> None:
        self._ws = ws
        self._on_open = on_open
        # Fired once when the peer sends GOAWAY (it is draining). The owner uses it to
        # stop routing NEW work to this connection while in-flight streams finish: the
        # server deregisters the agent; the agent just logs (its reconnect loop handles
        # the clean close that follows).
        self._on_goaway = on_goaway
        self._streams: dict[int, Stream] = {}
        self._next_id = 1
        self._tasks: set[asyncio.Task[None]] = set()
        self._max_streams = max_streams
        self._buffered = 0  # sum of unread bytes across all streams (connection cap)
        self._frames = 0  # sum of unread frame COUNT across all streams (per-frame cap)
        # Graceful drain (GOAWAY): _going_away once WE announce it (open() then refuses);
        # _peer_going_away once the peer does; _idle fires whenever _streams empties so
        # drain() can wait for in-flight streams to finish.
        self._going_away = False
        self._peer_going_away = False
        self._idle = asyncio.Event()
        # Operator-visible counters (see stats()). Cheap; single loop, so no lock.
        self._stats: dict[str, int] = {
            "opened": 0,
            "reset_local": 0,
            "reset_peer": 0,
            "credit_stall": 0,
            "write_stall": 0,
            "goaway_in": 0,
        }

    async def open(self) -> Stream:
        """Allocate a new stream and announce it to the peer (initiator side)."""
        if self._going_away or self._peer_going_away:
            # We announced GOAWAY, or the peer did -> no new streams either way: a
            # visitor that raced our shutdown, or a new visitor for an agent that is
            # itself draining. Refused here; the caller turns that into a 503.
            raise RuntimeError("draining; not opening new streams")
        if len(self._streams) >= self._max_streams:
            raise RuntimeError("too many concurrent streams")
        sid = self._next_id
        # 4-byte stream ids (protocol.py: "!BI"). Ids are monotonic and never
        # reused within a connection: at exhaustion we refuse rather than wrap,
        # because a wrapped id could collide with a still-live stream and hijack
        # it. ~4 billion streams per connection is a reconnect-scale event. Ids
        # 1..0xFFFFFFFF are usable; the next allocation past that refuses.
        if sid > 0xFFFFFFFF:
            raise RuntimeError("stream ids exhausted; reconnect for a fresh id space")
        self._next_id = sid + 1
        stream = Stream(self, sid)
        self._streams[sid] = stream
        # Await the OPEN send so it is ordered strictly before any DATA the
        # caller sends next -- websockets preserves send order per connection.
        try:
            await self._send(protocol.OPEN, sid, b"")
        except Exception:
            stream.close()
            raise
        self._stats["opened"] += 1
        return stream

    async def aclose(self, code: int = 1000, reason: str = "") -> None:
        """Close the underlying WebSocket. The Mux owns its connection, so
        callers tear it down through here instead of touching the socket."""
        await self._ws.close(code=code, reason=reason)

    async def goaway(self) -> None:
        """Announce GOAWAY: tell the peer we will open no new streams and are
        draining (connection-level, stream id 0). Best-effort -- a dead peer is
        handled by drain()'s close. This alone does not stop in-flight streams."""
        self._going_away = True
        with contextlib.suppress(Exception):
            await self._send(protocol.GOAWAY, 0, b"")

    async def drain(self, timeout: float = _DRAIN_GRACE) -> None:
        """Graceful shutdown: GOAWAY, then wait up to *timeout* for in-flight streams
        to finish before closing the connection. New opens are refused for the whole
        drain; streams still live at the deadline are torn down by the close (run()'s
        finally aborts them). Composes with a concurrent run(): run keeps servicing
        streams to completion while this waits for _streams to empty."""
        await self.goaway()
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while self._streams:
            self._idle.clear()  # re-arm BEFORE re-checking: closes the lost-wakeup race
            if not self._streams:
                break
            remaining = deadline - loop.time()
            if remaining <= 0:
                break
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._idle.wait(), timeout=remaining)
        await self.aclose(code=1001, reason="going away")

    @property
    def active_streams(self) -> int:
        """Live stream count on this connection (drift-free; derived from state)."""
        return len(self._streams)

    def stats(self) -> dict[str, int]:
        """Snapshot of counters + live gauges, for an operator's periodic log or a
        healthz endpoint. Cheap; single-threaded loop means no lock is needed."""
        return {
            "active_streams": self.active_streams,
            "buffered_bytes": self._buffered,
            "queued_frames": self._frames,
            "draining": int(self._going_away or self._peer_going_away),
            **self._stats,
        }

    async def _send(self, ftype: int, sid: int, payload: bytes) -> None:
        try:
            await asyncio.wait_for(
                self._ws.send(protocol.encode(ftype, sid, payload)),
                timeout=_WRITE_STALL_TIMEOUT,
            )
        except TimeoutError:
            # The peer stopped reading: the transport write side is paused and
            # ws.send() blocks with no timeout of its own; a graceful close would
            # block on the same path. Hard-abort (RST) so run()'s async-for unwinds
            # and every stream tears down. This is the connection-level deadlock
            # breaker the per-stream credit-stall can't provide -- it never engages
            # here, because the block is on ws.send(), not on the credit wait.
            self._stats["write_stall"] += 1
            with contextlib.suppress(Exception):
                self._ws.transport.abort()
            raise

    def _remove(self, sid: int) -> None:
        self._streams.pop(sid, None)
        if not self._streams:
            self._idle.set()  # wake drain(): all in-flight streams have finished

    def _spawn(self, coro: Awaitable[None]) -> None:
        task = asyncio.ensure_future(coro)
        self._tasks.add(task)
        task.add_done_callback(self._task_done)

    def _task_done(self, task: asyncio.Task[None]) -> None:
        self._tasks.discard(task)
        try:
            exc = task.exception()
        except asyncio.CancelledError:
            return
        if exc is not None:
            log.warning(
                "mux background task failed",
                exc_info=(type(exc), exc, exc.__traceback__),
            )

    async def _run_on_open(self, stream: Stream) -> None:
        try:
            if self._on_open is not None:
                await self._on_open(stream)
        except asyncio.CancelledError:
            stream.close()
            raise
        except Exception:
            await stream.reset()
        finally:
            stream.close()

    async def run(self) -> None:
        """Pump frames off the websocket until it closes, then abort streams.

        This loop only enqueues, grants credit, and spawns -- it never blocks on
        sending -- so a backpressured sender can never wedge it."""
        try:
            async for message in self._ws:
                if not isinstance(message, bytes):
                    continue  # binary frames are bytes; ignore stray text (str) frames
                try:
                    ftype, sid, payload = protocol.decode(message)
                except ValueError:
                    continue  # malformed/short frame: drop it, keep the mux alive
                if ftype == protocol.OPEN:
                    if sid == 0:
                        continue
                    if self._on_open is None:
                        # The server never accepts peer-opened streams; ignore so
                        # a malicious agent can't grow the registry with OPENs.
                        continue
                    if self._going_away or self._peer_going_away:
                        self._spawn(self._send(protocol.RESET, sid, b""))
                        continue
                    if sid in self._streams:
                        # Duplicate OPEN for a live id: refuse it (RESET) instead of
                        # silently overwriting the first handler + its local socket.
                        self._spawn(self._send(protocol.RESET, sid, b""))
                        continue
                    if len(self._streams) >= self._max_streams:
                        self._spawn(self._send(protocol.RESET, sid, b""))
                        continue
                    stream = Stream(self, sid)
                    self._streams[sid] = stream
                    self._stats["opened"] += 1
                    self._spawn(self._run_on_open(stream))
                elif ftype == protocol.DATA:
                    if sid == 0:
                        continue
                    if (s := self._streams.get(sid)) is not None:
                        s._feed(payload)
                elif ftype == protocol.EOF:
                    if sid == 0:
                        continue
                    if (s := self._streams.get(sid)) is not None:
                        s._feed_eof()
                elif ftype == protocol.WINDOW_UPDATE:
                    if sid == 0:
                        continue
                    if (s := self._streams.get(sid)) is not None:
                        if len(payload) != 4:
                            # A credit frame is exactly 4 bytes; anything else is
                            # malformed -- reset the stream instead of guessing.
                            if s._reset_local_now():
                                self._spawn(self._send(protocol.RESET, sid, b""))
                        else:
                            (delta,) = struct.unpack_from("!I", payload)
                            if delta != 0:
                                s._grant(delta)
                            # delta == 0 is a no-op grant: drop it WITHOUT waking the
                            # credit waiter, so it can't reset the per-wait stall clock
                            # and keep a blocked sender alive forever.
                elif ftype == protocol.RESET:
                    if sid == 0:
                        continue
                    if (s := self._streams.get(sid)) is not None:
                        self._stats["reset_peer"] += 1
                        s._abort()
                elif ftype == protocol.GOAWAY:
                    if sid != 0:
                        continue
                    # Peer is draining: it will open no new streams and will close once
                    # in-flight ones finish. Note it and let the owner stop routing NEW
                    # work here (server deregisters the agent; agent logs, and its
                    # reconnect loop handles the clean close). In-flight streams continue.
                    if self._peer_going_away:
                        continue
                    self._peer_going_away = True
                    self._stats["goaway_in"] += 1
                    if self._on_goaway is not None:
                        self._on_goaway()
        finally:
            for stream in list(self._streams.values()):
                stream._abort()
            self._streams.clear()
            # Cancel any spawned work (e.g. agent-side per-stream handlers) so
            # idle local-app sockets don't leak across a reconnect.
            tasks = list(self._tasks)
            for task in tasks:
                task.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            self._tasks.clear()
