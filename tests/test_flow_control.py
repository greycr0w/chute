"""Credit-window flow control at the mux layer.

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


async def test_send_eof_cannot_overtake_blocked_data(monkeypatch) -> None:
    monkeypatch.setattr(chute.mux, "_FLOW_WINDOW", 1)
    ws = _FakeWS()
    s = Stream(Mux(ws), 1)

    await s.send(b"A")
    blocked_data = asyncio.ensure_future(s.send(b"B"))
    await asyncio.sleep(0.05)
    assert not blocked_data.done()

    eof = asyncio.ensure_future(s.send_eof())
    await asyncio.sleep(0.05)
    assert not eof.done(), "EOF must wait behind the already-started DATA send"

    s._grant(1)
    await asyncio.wait_for(blocked_data, timeout=1)
    await asyncio.wait_for(eof, timeout=1)

    frames = [(t, p) for t, _sid, p in _frames(ws)]
    assert frames == [
        (protocol.DATA, b"A"),
        (protocol.DATA, b"B"),
        (protocol.EOF, b""),
    ]


async def test_send_chunks_to_websocket_message_limit() -> None:
    ws = _FakeWS()
    s = Stream(Mux(ws), 1)
    payload = b"x" * (chute.mux._MAX_FRAME_PAYLOAD + 1)

    await s.send(payload)

    data_payloads = [p for t, _sid, p in _frames(ws) if t == protocol.DATA]
    assert b"".join(data_payloads) == payload
    assert all(len(p) <= chute.mux._MAX_FRAME_PAYLOAD for p in data_payloads)


async def test_mux_custom_flow_window_derives_window_backstops() -> None:
    mux = Mux(_FakeWS(), flow_window=10)
    s = Stream(mux, 1)
    mux._streams[1] = s

    assert s._send_window == 10
    assert mux.window_update_threshold == 5
    assert mux.stream_hard_max == 20
    assert mux.max_queued_frames == 10

    s._feed(b"x" * 20)
    assert s.reset_by_peer is False
    s._feed(b"y")
    await asyncio.sleep(0.05)
    assert s.reset_by_peer is True


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


async def test_buffer_accounting_hooks_reserve_and_release_unread_bytes() -> None:
    reserved: list[int] = []
    released: list[int] = []

    def reserve(n: int) -> bool:
        reserved.append(n)
        return True

    def release(n: int) -> None:
        released.append(n)

    mux = Mux(_FakeWS(), buffer_reserve=reserve, buffer_release=release)
    s = Stream(mux, 1)
    mux._streams[1] = s

    s._feed(b"abc")
    assert reserved == [3]
    assert mux._buffered == 3

    assert await s.read() == b"abc"
    assert released == [3]
    assert mux._buffered == 0

    s._feed(b"de")
    s.close()
    assert released == [3, 2]
    assert mux._buffered == 0
    assert await s.read() == b"de"
    assert released == [3, 2], "post-close reads must not double-release"


async def test_buffer_reserve_rejection_resets_without_queueing() -> None:
    released: list[int] = []
    mux = Mux(
        _FakeWS(),
        buffer_reserve=lambda _n: False,
        buffer_release=lambda n: released.append(n),
    )
    s = Stream(mux, 1)
    mux._streams[1] = s

    s._feed(b"abc")
    await asyncio.sleep(0.05)

    assert s.reset_by_peer is True
    assert mux._buffered == 0
    assert mux._frames == 0
    assert released == []
    assert await s.read() is None


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


async def test_server_mux_ignores_peer_open_without_materializing_streams() -> None:
    ws = _ScriptedWS(
        [
            protocol.encode(protocol.OPEN, 7, b""),
            protocol.encode(protocol.OPEN, 8, b"unexpected-payload"),
            protocol.encode(protocol.OPEN, 0, b""),
        ]
    )
    mux = Mux(ws)  # server side: no on_open callback, so peer OPEN is never accepted
    run_task = asyncio.ensure_future(mux.run())
    try:
        await asyncio.sleep(0.05)
        assert mux.active_streams == 0
        assert mux.stats()["ignored_frames"] == 3
        assert mux._tasks == set()
        assert ws.sent == []
        assert not run_task.done(), "ignored peer OPENs must not close the mux connection"
    finally:
        run_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await run_task


async def test_inbound_open_over_max_streams_is_reset_without_closing_mux() -> None:
    opened: list[Stream] = []
    started = asyncio.Event()

    async def _on_open(stream: Stream) -> None:
        opened.append(stream)
        started.set()
        await asyncio.sleep(60)  # keep the first handler live at the stream cap

    ws = _ScriptedWS(
        [protocol.encode(protocol.OPEN, 7, b""), protocol.encode(protocol.OPEN, 9, b"")]
    )
    mux = Mux(ws, on_open=_on_open, max_streams=1)
    run_task = asyncio.ensure_future(mux.run())
    try:
        await asyncio.wait_for(started.wait(), timeout=1)
        await asyncio.sleep(0.05)
        assert [stream.id for stream in opened] == [7]
        assert mux.active_streams == 1
        assert mux.stats()["opened"] == 1
        sent = [protocol.decode(m) for m in ws.sent]
        assert [(t, sid) for t, sid, _p in sent] == [(protocol.RESET, 9)]
        assert not run_task.done(), "stream-limit refusal must not close the mux connection"
    finally:
        run_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await run_task


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


async def test_eof_payload_resets_stream_instead_of_clean_half_close() -> None:
    terminals: list[tuple[bytes | None, bool]] = []
    started = asyncio.Event()

    async def _on_open(stream: Stream) -> None:
        started.set()
        chunk = await stream.read()
        terminals.append((chunk, stream.reset_by_peer))

    ws = _ScriptedWS(
        [protocol.encode(protocol.OPEN, 7, b""), protocol.encode(protocol.EOF, 7, b"lost")]
    )
    mux = Mux(ws, on_open=_on_open)
    run_task = asyncio.ensure_future(mux.run())
    try:
        await asyncio.wait_for(started.wait(), timeout=1)
        await asyncio.sleep(0.05)
        assert terminals == [(None, True)]
        sent = [protocol.decode(m) for m in ws.sent]
        assert any(t == protocol.RESET and sid == 7 for t, sid, _p in sent)
    finally:
        run_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await run_task


class _BlockedSendWS(_ScriptedWS):
    async def send(self, data: bytes) -> None:
        await self._block.wait()
        self.sent.append(data)


async def test_duplicate_open_reset_send_is_deduplicated() -> None:
    started = asyncio.Event()

    async def _on_open(stream: Stream) -> None:
        started.set()
        await asyncio.sleep(60)

    ws = _BlockedSendWS(
        [protocol.encode(protocol.OPEN, 7, b"")]
        + [protocol.encode(protocol.OPEN, 7, b"") for _ in range(50)]
    )
    mux = Mux(ws, on_open=_on_open)
    run_task = asyncio.ensure_future(mux.run())
    try:
        await asyncio.wait_for(started.wait(), timeout=1)
        await asyncio.sleep(0.05)
        assert len(mux._reset_sends) == 1
        assert len([task for task in mux._tasks if not task.done()]) <= 2
    finally:
        run_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await run_task
