"""Enforcement against malicious / wedged mux peers (protocol hardening batch).

These are the adversarial counterparts to test_flow_control.py: where that file
proves the credit window works for a *cooperative* peer, this one proves the mux
defends itself against a peer that stops reading, floods empty/tiny frames, abuses
WINDOW_UPDATE, or races a RESET against a clean EOF. Each test is the repro that
surfaced the finding, hardened into a regression guard.

    F55  write-stall: a peer that stops reading must not wedge senders forever
    F56  empty/tiny DATA frames must not evade the byte backstop
    F57  WINDOW_UPDATE must be validated (no delta==0 stall-bypass, no overflow)
    F58  a late RESET must not turn an already-clean EOF into an abort
    F59  the connection-level buffer cap bounds aggregate memory
    F15  a flood past a stream cap must emit one RESET, not one per late frame
    F42  a late RESET after clean EOF must still stop the stream's send direction
    F23  local reset closes the send direction before any late producer can write
"""

from __future__ import annotations

import asyncio
import contextlib
import struct

import pytest

import chute.mux
from chute import protocol
from chute.mux import Mux, Stream, _StreamClosed


class _FakeWS:
    """Records every frame sent; never applies backpressure."""

    def __init__(self) -> None:
        self.sent: list[bytes] = []

    async def send(self, data: bytes) -> None:
        self.sent.append(data)


class _Transport:
    def __init__(self) -> None:
        self.aborted = False

    def abort(self) -> None:
        self.aborted = True


class _HangingWS:
    """Models a peer that stopped reading: send() blocks forever (paused write)."""

    def __init__(self) -> None:
        self.transport = _Transport()

    async def send(self, data: bytes) -> None:
        await asyncio.Event().wait()  # never returns


class _ScriptedWS:
    """Yields a fixed list of frames, then blocks so Mux.run stays alive while we
    inspect state."""

    def __init__(self, msgs: list[bytes]) -> None:
        self._msgs = msgs
        self._block = asyncio.Event()
        self.sent: list[bytes] = []
        self.transport = _Transport()

    def __aiter__(self) -> _ScriptedWS:
        return self

    async def __anext__(self) -> bytes:
        if self._msgs:
            return self._msgs.pop(0)
        await self._block.wait()  # never set -> keep the demux loop running
        raise StopAsyncIteration

    async def send(self, data: bytes) -> None:
        self.sent.append(data)

    async def close(self, **_kw: object) -> None:
        pass


async def _drive(mux: Mux) -> asyncio.Task[None]:
    task = asyncio.ensure_future(mux.run())
    await asyncio.sleep(0.05)  # let the scripted frames be processed
    return task


async def _quiet_cancel(task: asyncio.Task[None]) -> None:
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task


# -- F55: write-stall abort ---------------------------------------------------
async def test_send_aborts_transport_on_write_stall(monkeypatch) -> None:
    # A peer that stops reading pauses our write side; ws.send() then blocks with no
    # timeout of its own. _send must bound it and hard-abort the transport so the
    # connection tears down instead of wedging every sender forever.
    monkeypatch.setattr(chute.mux, "_WRITE_STALL_TIMEOUT", 0.2)
    ws = _HangingWS()
    mux = Mux(ws)
    with pytest.raises(TimeoutError):
        await mux._send(protocol.DATA, 1, b"x")
    assert ws.transport.aborted, "a wedged write must abort the transport (RST)"


async def test_stream_send_unwedges_via_write_stall(monkeypatch) -> None:
    # The same defense as seen by a stream: credit is available (window full), so the
    # block is on ws.send, not the credit wait -- only the write-stall can break it.
    monkeypatch.setattr(chute.mux, "_WRITE_STALL_TIMEOUT", 0.2)
    ws = _HangingWS()
    s = Stream(Mux(ws), 1)
    assert s._send_window == chute.mux._FLOW_WINDOW  # credit-stall would never engage
    with pytest.raises(TimeoutError):
        await s.send(b"hello")
    assert ws.transport.aborted


# -- F56: empty / tiny frame floods -------------------------------------------
async def test_empty_data_frames_are_dropped() -> None:
    s = Stream(Mux(_FakeWS()), 1)
    for _ in range(200_000):
        s._feed(b"")  # 5-byte DATA frames on the wire, b"" payload
    assert s._incoming.qsize() == 0, "empty DATA must not queue (was an unbounded leak)"
    assert s._recv_buffered == 0
    assert s.reset_by_peer is False


async def test_tiny_frame_flood_trips_frame_count_cap(monkeypatch) -> None:
    # The byte backstop is blind to tiny frames; the frame-count cap catches them.
    monkeypatch.setattr(chute.mux, "_MAX_QUEUED_FRAMES", 8)
    s = Stream(Mux(_FakeWS()), 1)
    for _ in range(8):
        s._feed(b"x")  # exactly the cap: still allowed
    assert s.reset_by_peer is False
    s._feed(b"x")  # 9 > 8 -> violation
    await asyncio.sleep(0.05)
    assert s.reset_by_peer is True


async def test_stream_overflow_reset_is_not_amplified(monkeypatch) -> None:
    # Once the first over-window frame marks the stream RESET, later DATA must be
    # dropped without spawning another RESET send. Otherwise a malicious burst turns
    # one buffer violation into O(N) control frames.
    monkeypatch.setattr(chute.mux, "_STREAM_HARD_MAX", 4)
    ws = _FakeWS()
    mux = Mux(ws)
    s = Stream(mux, 1)
    mux._streams[1] = s

    s._feed(b"aaaa")  # exactly the cap: still allowed
    for _ in range(20):
        s._feed(b"x")  # first one violates; the rest must be ignored
    await asyncio.sleep(0.05)

    resets = [frame for frame in ws.sent if protocol.decode(frame)[0] == protocol.RESET]
    assert len(resets) == 1
    assert protocol.decode(resets[0])[1] == 1
    assert s.reset_by_peer is True


async def test_unknown_frame_churn_is_capped_without_stream_or_task_growth(monkeypatch) -> None:
    monkeypatch.setattr(chute.mux, "_MAX_IGNORED_FRAMES", 6)
    ws = _ScriptedWS(
        [
            protocol.encode(protocol.DATA, 100, b"x"),
            protocol.encode(protocol.EOF, 101, b""),
            protocol.encode(protocol.RESET, 102, b""),
            protocol.encode(protocol.WINDOW_UPDATE, 103, struct.pack("!I", 1)),
            protocol.encode(protocol.OPEN, 104, b""),
            protocol.encode(protocol.DATA, 105, b"x"),
        ]
    )
    mux = Mux(ws)

    await asyncio.wait_for(mux.run(), timeout=1)

    assert ws.transport.aborted
    assert mux.stats()["ignored_frames"] == 6
    assert mux.stats()["ignored_frame_limit"] == 1
    assert mux.active_streams == 0
    assert mux._tasks == set()
    assert ws.sent == []


# -- F57: WINDOW_UPDATE validation --------------------------------------------
async def test_zero_window_update_is_ignored() -> None:
    # delta==0 must NOT wake the credit waiter -- otherwise a flood of them resets the
    # per-wait stall clock and keeps a blocked sender alive indefinitely.
    ws = _ScriptedWS([protocol.encode(protocol.WINDOW_UPDATE, 1, struct.pack("!I", 0))])
    mux = Mux(ws)
    s = Stream(mux, 1)
    mux._streams[1] = s
    s._send_window = 0
    s._window_waiter.clear()
    task = await _drive(mux)
    try:
        assert s._send_window == 0, "a zero grant must not add credit"
        assert not s._window_waiter.is_set(), "a zero grant must not wake the waiter"
    finally:
        await _quiet_cancel(task)


async def test_valid_window_update_grants() -> None:
    ws = _ScriptedWS([protocol.encode(protocol.WINDOW_UPDATE, 1, struct.pack("!I", 100))])
    mux = Mux(ws)
    s = Stream(mux, 1)
    mux._streams[1] = s
    s._send_window = 0
    task = await _drive(mux)
    try:
        assert s._send_window == 100
        assert s._window_waiter.is_set()
    finally:
        await _quiet_cancel(task)


async def test_malformed_window_update_resets_stream() -> None:
    ws = _ScriptedWS([protocol.encode(protocol.WINDOW_UPDATE, 1, b"\x00\x00")])  # 2 bytes != 4
    mux = Mux(ws)
    s = Stream(mux, 1)
    mux._streams[1] = s
    task = await _drive(mux)
    try:
        assert s.reset_by_peer is True, "a malformed credit frame must reset the stream"
        sent = [protocol.decode(m) for m in ws.sent]
        assert any(t == protocol.RESET and sid == 1 for t, sid, _p in sent)
    finally:
        await _quiet_cancel(task)


async def test_malformed_window_update_resets_before_later_data() -> None:
    ws = _ScriptedWS(
        [
            protocol.encode(protocol.WINDOW_UPDATE, 1, b"\x00\x00"),
            protocol.encode(protocol.DATA, 1, b"late-after-malformed-credit"),
        ]
    )
    mux = Mux(ws)
    s = Stream(mux, 1)
    mux._streams[1] = s
    task = await _drive(mux)
    try:
        assert await asyncio.wait_for(s.read(), timeout=1) is None
        assert s.reset_by_peer is True
        assert 1 not in mux._streams
        assert not s._incoming.qsize(), "DATA after malformed credit must not queue"
    finally:
        await _quiet_cancel(task)


async def test_local_reset_closes_send_direction_before_late_data() -> None:
    ws = _FakeWS()
    mux = Mux(ws)
    s = Stream(mux, 1)
    mux._streams[1] = s

    await s.reset()
    with pytest.raises(_StreamClosed):
        await s.send(b"late-after-reset")

    frames = [protocol.decode(frame) for frame in ws.sent]
    assert [(ftype, sid) for ftype, sid, _payload in frames] == [(protocol.RESET, 1)]
    assert 1 not in mux._streams


async def test_window_growth_is_capped() -> None:
    s = Stream(Mux(_FakeWS()), 1)
    s._send_window = chute.mux._MAX_SEND_WINDOW
    s._grant(1_000_000)  # a flood of credit can't grow the window past the ceiling
    assert s._send_window == chute.mux._MAX_SEND_WINDOW


# -- F58: RESET vs clean EOF lifecycle ----------------------------------------
async def test_reset_after_clean_eof_stays_clean() -> None:
    # A clean EOF was delivered; a RESET arriving afterwards must NOT retroactively
    # flip the (complete) receive direction to an abort, or a finished response gets
    # signalled to the client as a truncation.
    s = Stream(Mux(_FakeWS()), 1)
    s._feed(b"body")
    s._feed_eof()  # clean half-close
    s._abort()  # late RESET
    assert await s.read() == b"body"
    assert await s.read() is None
    assert s.reset_by_peer is False, "a late RESET must not turn a clean EOF into an abort"


async def test_late_reset_after_clean_eof_stops_send_direction(monkeypatch) -> None:
    # F42: preserving a clean receive EOF must not leave the opposite direction
    # alive. A peer RESET after response EOF still tears down the stream, wakes a
    # sender parked on credit, and frees the stream slot.
    monkeypatch.setattr(chute.mux, "_FLOW_WINDOW", 1)
    mux = Mux(_FakeWS())
    s = Stream(mux, 1)
    mux._streams[1] = s
    await s.send(b"A")
    blocked_send = asyncio.ensure_future(s.send(b"B"))
    await asyncio.sleep(0.05)
    assert not blocked_send.done()

    s._feed_eof()
    assert await s.read() is None
    assert s.reset_by_peer is False
    assert 1 in mux._streams

    s._abort()
    with pytest.raises(_StreamClosed):
        await asyncio.wait_for(blocked_send, timeout=1)
    assert 1 not in mux._streams
    assert s.reset_by_peer is False


async def test_reset_before_eof_is_abort() -> None:
    # The complement: a RESET with no prior clean EOF is a real abort.
    s = Stream(Mux(_FakeWS()), 1)
    s._feed(b"partial")
    s._abort()
    assert await s.read() == b"partial"  # buffered bytes still delivered first
    assert await s.read() is None
    assert s.reset_by_peer is True


async def test_recv_state_is_write_once() -> None:
    # The lane's _RecvState is the single authoritative 'sign': once it leaves OPEN it
    # is terminal and cannot change, in EITHER direction. This is the structural form
    # of F58 -- the clean/abort decision can never be misread or flipped.
    from chute.mux import _RecvState

    clean = Stream(Mux(_FakeWS()), 1)
    clean._feed_eof()  # OPEN -> EOF
    assert clean._recv is _RecvState.EOF
    clean._abort()  # a late RESET must NOT rewrite a clean EOF
    assert clean._recv is _RecvState.EOF
    assert clean.reset_by_peer is False

    aborted = Stream(Mux(_FakeWS()), 2)
    aborted._abort()  # OPEN -> RESET
    assert aborted._recv is _RecvState.RESET
    aborted._feed_eof()  # a stray EOF must NOT soften a RESET
    assert aborted._recv is _RecvState.RESET
    assert aborted.reset_by_peer is True


# -- F59: connection-level aggregate buffer cap -------------------------------
async def test_connection_buffer_cap_resets_offender(monkeypatch) -> None:
    monkeypatch.setattr(chute.mux, "_MAX_CONN_BUFFERED", 100)
    mux = Mux(_FakeWS())
    s1, s2 = Stream(mux, 1), Stream(mux, 2)
    mux._streams[1], mux._streams[2] = s1, s2
    s1._feed(b"x" * 80)  # under the connection cap
    assert s1.reset_by_peer is False
    assert mux._buffered == 80
    s2._feed(b"y" * 30)  # 80 + 30 = 110 > 100 -> the stream that breached it is reset
    await asyncio.sleep(0.05)
    assert s2.reset_by_peer is True
    assert s1.reset_by_peer is False


async def test_connection_buffer_reconciled_on_close() -> None:
    # The counters must not drift: abandoning a stream mid-buffer (consumer torn down)
    # reconciles its bytes AND its frame count, and a post-close read must double-subtract
    # neither. Drift in either would silently weaken the connection-level caps.
    mux = Mux(_FakeWS())
    s = Stream(mux, 1)
    mux._streams[1] = s
    s._feed(b"x" * 1000)
    assert mux._buffered == 1000 and mux._frames == 1
    s._abort()  # consumer abandons
    assert mux._buffered == 0 and mux._frames == 0, "abandoned buffer reconciled (no high drift)"
    assert await s.read() == b"x" * 1000  # still delivered first
    assert mux._buffered == 0 and mux._frames == 0, "post-close read must not double-subtract"


# -- connection-level frame-count cap (per-frame object overhead) -------------
async def test_connection_frame_cap_sheds_offending_stream(monkeypatch) -> None:
    # The byte caps are blind to per-frame object cost, so tiny frames are bounded by
    # COUNT at the connection level too. Hold the per-stream frame cap high so the
    # CONNECTION cap is what trips, and confirm the stream that pushed it over is RESET
    # while the other is untouched.
    monkeypatch.setattr(chute.mux, "_MAX_CONN_FRAMES", 8)
    monkeypatch.setattr(chute.mux, "_MAX_QUEUED_FRAMES", 10_000)
    mux = Mux(_FakeWS())
    s1 = await mux.open()
    s2 = await mux.open()
    for _ in range(5):
        s1._feed(b"x")
    assert not s1.reset_by_peer  # connection total (5) is under the cap
    for _ in range(5):
        s2._feed(b"x")  # crosses _MAX_CONN_FRAMES (8) partway through
    assert s2.reset_by_peer, "the stream that pushed the connection over its frame cap is shed"
    assert not s1.reset_by_peer
    await asyncio.sleep(0.01)  # let the spawned reset() run to completion
