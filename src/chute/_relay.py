"""Shared byte relay mechanics for visitor<->mux and mux<->local sockets.

The server owns visitor admission, accounting, throttling, idle policy, and logging.
The agent owns local-app dialing and reconnect policy. This module owns the common
hot-path mechanics both sides must keep identical: read chunk size, bounded drain,
clean EOF propagation, abortive reset propagation, and best-effort teardown.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Awaitable, Callable

from .mux import Stream

_PUMP_CHUNK_SIZE = 64 * 1024
_DRAIN_TIMEOUT = 120.0

_ByteThrottle = Callable[[int], Awaitable[None]]
_ByteObserver = Callable[[int], None]


async def _pump_reader_to_stream(
    reader: asyncio.StreamReader,
    stream: Stream,
    throttle: _ByteThrottle | None = None,
    on_forward: _ByteObserver | None = None,
) -> None:
    while True:
        data = await reader.read(_PUMP_CHUNK_SIZE)
        if not data:
            await stream.send_eof()
            return
        if throttle is not None:
            await throttle(len(data))
        await stream.send(data)
        if on_forward is not None:
            on_forward(len(data))


async def _pump_stream_to_writer(
    stream: Stream,
    writer: asyncio.StreamWriter,
    throttle: _ByteThrottle | None = None,
    on_forward: _ByteObserver | None = None,
) -> None:
    while True:
        chunk = await stream.read()
        if chunk is None:
            if stream.reset_by_peer:
                # The mux peer aborted/truncated its send direction. RST the socket
                # so downstream never mistakes a partial close-delimited body for a
                # complete one, and so the sibling reader pump unblocks.
                _safe_abort(writer)
            elif writer.can_write_eof():
                # Clean half-close. This may be unsupported or race teardown, so it
                # remains best-effort and must not tear down the sibling pump.
                with contextlib.suppress(Exception):
                    writer.write_eof()
            else:
                # SSL transports cannot half-close; full close is the observable EOF.
                _safe_close(writer)
            return
        if throttle is not None:
            await throttle(len(chunk))
        writer.write(chunk)
        # Bound stalled writes: a dead/slow downstream peer must not pin a mux stream
        # and its flow-control window forever.
        await asyncio.wait_for(writer.drain(), timeout=_DRAIN_TIMEOUT)
        if on_forward is not None:
            on_forward(len(chunk))
        # Bytes are flushed downstream: return that flow-control credit upstream.
        await stream.ack(len(chunk))


def _safe_close(writer: asyncio.StreamWriter) -> None:
    try:
        writer.close()
    except Exception:
        pass


def _safe_abort(writer: asyncio.StreamWriter) -> None:
    # RST the socket (asyncio-native): the right signal for an aborted/truncated
    # relay, and it instantly unblocks a peer or sibling pump parked on read().
    try:
        writer.transport.abort()
    except Exception:
        pass


async def _safe_drain(writer: asyncio.StreamWriter) -> None:
    try:
        await writer.drain()
    except Exception:
        pass


async def _safe_reset(stream: Stream) -> None:
    try:
        await stream.reset()
    except Exception:
        pass
