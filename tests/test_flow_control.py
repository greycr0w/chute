"""Credit-window flow control (protocol v2) at the mux layer.

These drive Stream/Mux directly with a fake WebSocket so the window mechanics are
deterministic. The end-to-end >16 MiB transparency + slow-consumer tests live in
test_transparency.py.
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
    """Records every frame sent; never applies its own backpressure."""

    def __init__(self) -> None:
        self.sent: list[bytes] = []

    async def send(self, data: bytes) -> None:
        self.sent.append(data)


def _frames(ws: _FakeWS) -> list[tuple[int, int, bytes]]:
    return [protocol.decode(m) for m in ws.sent]


# -- the sender respects the window and blocks when credit is exhausted --------
async def test_sender_blocks_until_credit_granted(monkeypatch) -> None:
    monkeypatch.setattr(chute.mux, "_FLOW_WINDOW", 4)
    ws = _FakeWS()
    s = Stream(Mux(ws), 1)  # _send_window picks up the patched 4

    await s.send(b"ABCD")  # exactly one window -> goes out, window now 0
    assert s._send_window == 0

    blocked = asyncio.ensure_future(s.send(b"E"))
    await asyncio.sleep(0.05)
    assert not blocked.done(), "sender must block once the window is exhausted"

    s._grant(4)  # peer returned credit (WINDOW_UPDATE)
    await asyncio.wait_for(blocked, timeout=1)
    payloads = b"".join(p for t, _sid, p in _frames(ws) if t == protocol.DATA)
    assert payloads == b"ABCDE"  # the late byte left only after credit arrived


# -- the receiver returns credit (WINDOW_UPDATE) after draining a half-window --
async def test_receiver_returns_credit_after_draining(monkeypatch) -> None:
    monkeypatch.setattr(chute.mux, "_FLOW_WINDOW", 8)  # threshold = 4
    monkeypatch.setattr(chute.mux, "_WINDOW_UPDATE_THRESHOLD", 4)
    ws = _FakeWS()
    s = Stream(Mux(ws), 1)

    s._feed(b"abcd")
    s._feed(b"efgh")
    assert await s.read() == b"abcd"
    await s.ack(4)  # drained 4 >= threshold -> emit WINDOW_UPDATE(4)

    wus = [(sid, p) for t, sid, p in _frames(ws) if t == protocol.WINDOW_UPDATE]
    assert wus, "draining a half-window must return credit"
    assert struct.unpack("!I", wus[0][1])[0] == 4

    # below threshold -> no new update
    before = len(wus)
    await s.ack(1)
    assert len([1 for t, _s, _p in _frames(ws) if t == protocol.WINDOW_UPDATE]) == before


# -- teardown wakes a sender parked on credit (no leak on reset mid-transfer) --
async def test_teardown_wakes_blocked_sender(monkeypatch) -> None:
    monkeypatch.setattr(chute.mux, "_FLOW_WINDOW", 2)
    s = Stream(Mux(_FakeWS()), 1)
    await s.send(b"AB")  # window exhausted
    blocked = asyncio.ensure_future(s.send(b"C"))
    await asyncio.sleep(0.05)
    assert not blocked.done()

    s._abort()  # peer RESET / connection died
    with pytest.raises(_StreamClosed):  # the sender wakes and bails, not hangs
        await asyncio.wait_for(blocked, timeout=1)


# -- a sender gives up if the peer never returns credit (no infinite block) ----
async def test_sender_resets_on_credit_stall(monkeypatch) -> None:
    monkeypatch.setattr(chute.mux, "_FLOW_WINDOW", 4)
    monkeypatch.setattr(chute.mux, "_CREDIT_STALL_TIMEOUT", 0.2)
    s = Stream(Mux(_FakeWS()), 1)
    await s.send(b"ABCD")  # exhausts the window; no WINDOW_UPDATE will ever come
    # The next send blocks on credit; with no grant it must time out and bail
    # (_StreamClosed) rather than hang forever -- the outer bound would trip if it didn't.
    with pytest.raises(_StreamClosed):
        await asyncio.wait_for(s.send(b"E"), timeout=2)


# -- the backstop is window-relative and tolerates a full window of buffering --
async def test_backstop_is_two_windows_and_tolerates_one(monkeypatch) -> None:
    assert chute.mux._STREAM_HARD_MAX == 2 * chute.mux._FLOW_WINDOW
    monkeypatch.setattr(chute.mux, "_STREAM_HARD_MAX", 200)
    s = Stream(Mux(_FakeWS()), 1)
    s._feed(b"x" * 200)  # exactly the backstop -> still allowed (a compliant peer can sit here)
    assert s.reset_by_peer is False
    assert s._recv_buffered == 200
    s._feed(b"y")  # 201 > 200 -> violation -> RESET
    await asyncio.sleep(0.05)
    assert s.reset_by_peer is True


# -- a reset delivers an ABORT terminal, distinguishable from a clean EOF ------
async def test_reset_terminal_is_marked_abort() -> None:
    s = Stream(Mux(_FakeWS()), 1)
    s._feed(b"partial")
    s._abort()  # peer reset mid-stream
    assert await s.read() == b"partial"  # buffered bytes still delivered first
    assert await s.read() is None  # then the terminal
    assert s.reset_by_peer is True  # ...flagged so the pump RSTs instead of write_eof


async def test_clean_eof_terminal_is_not_abort() -> None:
    s = Stream(Mux(_FakeWS()), 1)
    s._feed(b"body")
    s._feed_eof()
    assert await s.read() == b"body"
    assert await s.read() is None
    assert s.reset_by_peer is False  # clean half-close


# -- EOF is idempotent and DATA-after-EOF is dropped (illegal transitions) -----
async def test_eof_idempotent_and_data_after_eof_dropped() -> None:
    s = Stream(Mux(_FakeWS()), 1)
    s._feed(b"hello")
    s._feed_eof()
    s._feed_eof()  # second EOF: no second terminal
    s._feed(b"after-eof")  # DATA after EOF: dropped
    assert await s.read() == b"hello"
    assert await s.read() is None
    assert s._incoming.empty()  # exactly one terminal, no stray frames


# -- stream-id exhaustion refuses (never wraps onto a live id) -----------------
async def test_open_refuses_at_id_exhaustion() -> None:
    mux = Mux(_FakeWS())
    mux._next_id = 0xFFFFFFFF  # the last id
    s = await mux.open()  # allocates 0xFFFFFFFF
    assert s.id == 0xFFFFFFFF
    with pytest.raises(RuntimeError, match="exhausted"):
        await mux.open()  # must refuse, not wrap to 1 (which could hijack a live stream)


# -- duplicate OPEN for a live id is RESET, not silently overwritten -----------
class _ScriptedWS:
    """Yields a fixed list of frames, then blocks so Mux.run stays alive while we
    inspect state (instead of exhausting and tearing everything down)."""

    def __init__(self, msgs: list[bytes]) -> None:
        self._msgs = msgs
        self._block = asyncio.Event()
        self.sent: list[bytes] = []

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


async def test_duplicate_open_is_reset() -> None:
    opened: list[Stream] = []
    started = asyncio.Event()

    async def _on_open(stream: Stream) -> None:
        opened.append(stream)
        started.set()
        await asyncio.sleep(60)  # keep the first handler "live"

    ws = _ScriptedWS(
        [protocol.encode(protocol.OPEN, 7, b""), protocol.encode(protocol.OPEN, 7, b"")]
    )
    mux = Mux(ws, on_open=_on_open)
    run_task = asyncio.ensure_future(mux.run())
    try:
        await asyncio.wait_for(started.wait(), timeout=1)  # first handler started
        await asyncio.sleep(0.05)  # let the duplicate OPEN be processed
        assert len(opened) == 1, "the duplicate OPEN must not start a second handler"
        sent = [protocol.decode(m) for m in ws.sent]
        assert any(t == protocol.RESET and sid == 7 for t, sid, _p in sent), (
            "a duplicate OPEN for a live id must be RESET"
        )
    finally:
        run_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await run_task
