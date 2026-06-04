"""Graceful drain (GOAWAY), observability counters, and the send-after-EOF guard.

These are the Tier-1 (GOAWAY/drain) + observability + Tier-3 additions to the mux:
either side may announce GOAWAY and wait for in-flight streams to finish before
closing (zero-drop restart / Ctrl-C finishes the request in flight), `stats()`
surfaces the data-path counters, and `send()` refuses DATA after its own EOF.
"""

from __future__ import annotations

import asyncio
import contextlib

import pytest

from chute import protocol
from chute.mux import Mux, Stream, _StreamClosed


class _FakeWS:
    """Records sent frames and the close (code, reason); never blocks."""

    def __init__(self) -> None:
        self.sent: list[bytes] = []
        self.closed: tuple[int, str] | None = None

    async def send(self, data: bytes) -> None:
        self.sent.append(data)

    async def close(self, code: int = 1000, reason: str = "") -> None:
        self.closed = (code, reason)


class _ScriptedWS(_FakeWS):
    """Yields a fixed list of frames to Mux.run, then blocks so the loop stays alive."""

    def __init__(self, msgs: list[bytes]) -> None:
        super().__init__()
        self._msgs = msgs
        self._block = asyncio.Event()

    def __aiter__(self) -> _ScriptedWS:
        return self

    async def __anext__(self) -> bytes:
        if self._msgs:
            return self._msgs.pop(0)
        await self._block.wait()  # never set -> keep the demux loop running
        raise StopAsyncIteration


class _FailingSendWS(_FakeWS):
    async def send(self, data: bytes) -> None:
        raise OSError("transport down")


class _AbortableTransport:
    def __init__(self) -> None:
        self.aborted = False

    def abort(self) -> None:
        self.aborted = True


class _HangingCloseWS(_FakeWS):
    def __init__(self) -> None:
        super().__init__()
        self.transport = _AbortableTransport()

    async def close(self, code: int = 1000, reason: str = "") -> None:
        await asyncio.Event().wait()


def _frame_types(ws: _FakeWS) -> list[int]:
    return [protocol.decode(f)[0] for f in ws.sent]


# -- GOAWAY announce + open() refusal -----------------------------------------
async def test_goaway_sets_flag_and_sends_frame() -> None:
    ws = _FakeWS()
    mux = Mux(ws)
    await mux.goaway()
    assert mux._going_away
    ftype, sid, _ = protocol.decode(ws.sent[-1])
    assert ftype == protocol.GOAWAY and sid == 0  # connection-level


async def test_open_refused_after_we_announce_goaway() -> None:
    mux = Mux(_FakeWS())
    await mux.goaway()
    with pytest.raises(RuntimeError):
        await mux.open()  # we promised the peer no new streams


async def test_open_refused_when_peer_is_going_away() -> None:
    # Inbound GOAWAY (peer draining) must also stop us opening new streams toward it.
    ws = _ScriptedWS([protocol.encode(protocol.GOAWAY, 0, b"")])
    fired: list[bool] = []
    mux = Mux(ws, on_goaway=lambda: fired.append(True))
    task = asyncio.ensure_future(mux.run())
    await asyncio.sleep(0.05)
    assert mux._peer_going_away and fired == [True]  # callback let the owner react
    with pytest.raises(RuntimeError):
        await mux.open()
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task


async def test_inbound_open_after_goaway_is_rejected() -> None:
    ws = _ScriptedWS(
        [
            protocol.encode(protocol.GOAWAY, 0, b""),
            protocol.encode(protocol.OPEN, 7, b""),
        ]
    )
    opened: list[int] = []

    async def _on_open(stream: Stream) -> None:
        opened.append(stream.id)

    mux = Mux(ws, on_open=_on_open)
    task = asyncio.ensure_future(mux.run())
    await asyncio.sleep(0.05)
    try:
        assert opened == []
        assert 7 not in mux._streams
        assert any(
            ftype == protocol.RESET and sid == 7
            for ftype, sid, _payload in (protocol.decode(frame) for frame in ws.sent)
        )
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task


async def test_stream_id_zero_open_is_ignored() -> None:
    ws = _ScriptedWS([protocol.encode(protocol.OPEN, 0, b"")])
    opened: list[int] = []

    async def _on_open(stream: Stream) -> None:
        opened.append(stream.id)

    mux = Mux(ws, on_open=_on_open)
    task = asyncio.ensure_future(mux.run())
    await asyncio.sleep(0.05)
    try:
        assert opened == []
        assert 0 not in mux._streams
        assert mux.stats()["opened"] == 0
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task


async def test_repeated_goaway_callback_is_idempotent() -> None:
    ws = _ScriptedWS(
        [
            protocol.encode(protocol.GOAWAY, 0, b""),
            protocol.encode(protocol.GOAWAY, 0, b""),
        ]
    )
    fired: list[bool] = []
    mux = Mux(ws, on_goaway=lambda: fired.append(True))
    task = asyncio.ensure_future(mux.run())
    await asyncio.sleep(0.05)
    try:
        assert fired == [True]
        assert mux.stats()["goaway_in"] == 1
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task


async def test_on_open_crash_resets_and_releases_stream() -> None:
    ws = _ScriptedWS([protocol.encode(protocol.OPEN, 9, b"")])

    async def _on_open(_stream: Stream) -> None:
        raise RuntimeError("handler crashed")

    mux = Mux(ws, on_open=_on_open)
    task = asyncio.ensure_future(mux.run())
    await asyncio.sleep(0.05)
    try:
        assert mux.active_streams == 0
        assert any(
            ftype == protocol.RESET and sid == 9
            for ftype, sid, _payload in (protocol.decode(frame) for frame in ws.sent)
        )
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task


async def test_run_awaits_owned_task_cleanup_on_cancel() -> None:
    ws = _ScriptedWS([protocol.encode(protocol.OPEN, 11, b"")])
    started = asyncio.Event()
    cleanup_finished = asyncio.Event()

    async def _on_open(_stream: Stream) -> None:
        started.set()
        try:
            await asyncio.Event().wait()
        finally:
            await asyncio.sleep(0)
            cleanup_finished.set()

    mux = Mux(ws, on_open=_on_open)
    task = asyncio.ensure_future(mux.run())
    await asyncio.wait_for(started.wait(), timeout=1)
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task
    assert cleanup_finished.is_set()
    assert mux.active_streams == 0


async def test_failed_open_send_removes_phantom_stream() -> None:
    mux = Mux(_FailingSendWS())
    with pytest.raises(OSError):
        await mux.open()
    assert mux.active_streams == 0
    assert mux.stats()["opened"] == 0


# -- drain: wait for in-flight, then close ------------------------------------
async def test_drain_closes_immediately_when_idle() -> None:
    ws = _FakeWS()
    mux = Mux(ws)
    await mux.drain(timeout=5)
    assert ws.closed is not None and ws.closed[0] == 1001  # going-away close
    assert protocol.GOAWAY in _frame_types(ws)


async def test_drain_close_timeout_aborts_transport(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("chute.mux._CLOSE_TIMEOUT", 0.01)
    ws = _HangingCloseWS()
    mux = Mux(ws)

    await asyncio.wait_for(mux.drain(timeout=0), timeout=1)

    assert ws.transport.aborted
    assert mux.stats()["close_stall"] == 1


async def test_drain_waits_for_inflight_then_closes() -> None:
    ws = _FakeWS()
    mux = Mux(ws)
    stream = await mux.open()  # one in-flight stream
    drain = asyncio.ensure_future(mux.drain(timeout=5))
    await asyncio.sleep(0.05)
    assert ws.closed is None, "drain must wait while a stream is still in flight"
    stream.close()  # stream finishes -> _remove fires _idle -> drain proceeds
    await asyncio.wait_for(drain, timeout=2)
    assert ws.closed is not None and ws.closed[0] == 1001


async def test_drain_force_closes_at_deadline() -> None:
    ws = _FakeWS()
    mux = Mux(ws)
    await mux.open()  # never finishes (e.g. a permanent SSE/WS stream)
    await asyncio.wait_for(mux.drain(timeout=0.2), timeout=2)
    assert ws.closed is not None  # bounded: forced closed at the deadline


# -- observability counters ---------------------------------------------------
async def test_stats_track_open_active_and_reset() -> None:
    mux = Mux(_FakeWS())
    stream = await mux.open()
    assert mux.stats()["opened"] == 1
    assert mux.stats()["active_streams"] == 1
    await stream.reset()
    after = mux.stats()
    assert after["reset_local"] == 1
    assert after["active_streams"] == 0


async def test_stats_count_peer_reset() -> None:
    ws = _ScriptedWS([protocol.encode(protocol.RESET, 7, b"")])
    mux = Mux(ws)
    mux._streams[7] = Stream(mux, 7)  # a stream the peer will RESET
    task = asyncio.ensure_future(mux.run())
    await asyncio.sleep(0.05)
    assert mux.stats()["reset_peer"] == 1
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task


# -- Tier-3: send after our own EOF is a local protocol error -----------------
async def test_send_after_eof_is_refused() -> None:
    stream = Stream(Mux(_FakeWS()), 1)
    await stream.send_eof()
    with pytest.raises(_StreamClosed):
        await stream.send(b"late")  # DATA after EOF must not go on the wire
