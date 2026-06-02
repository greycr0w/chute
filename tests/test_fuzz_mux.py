"""Stateful transport fuzzing for the mux (gap 4 — a custom mux needs more than
example-based regression tests).

Two properties, checked over machine-generated inputs:

1. ``protocol.decode`` never raises anything but ``ValueError`` on arbitrary bytes
   (the frame reader relies on exactly that to drop a bad frame without tearing the
   connection down).
2. The mux's buffer accounting never drifts and never crashes under an arbitrary
   interleaving of open / data / eof / reset / read / window-update. After every op
   the connection counters stay non-negative and within their caps; after teardown
   they reconcile to zero. This is the invariant the byte/frame caps depend on, and
   the class of bug (counter drift, illegal transitions) that hand-written examples
   kept missing.
"""

from __future__ import annotations

import asyncio

from hypothesis import given
from hypothesis import strategies as st

from chute import protocol
from chute.mux import _MAX_CONN_BUFFERED, _MAX_CONN_FRAMES, Mux


class _FakeWS:
    """Records frames, never blocks, supports close (for reset's RESET send)."""

    def __init__(self) -> None:
        self.sent: list[bytes] = []

    async def send(self, data: bytes) -> None:
        self.sent.append(data)

    async def close(self, code: int = 1000, reason: str = "") -> None:
        pass


# -- 1. the frame decoder must never crash, only ValueError -------------------
@given(data=st.binary(min_size=0, max_size=512))
def test_decode_only_raises_valueerror_on_garbage(data: bytes) -> None:
    try:
        ftype, sid, payload = protocol.decode(data)
    except ValueError:
        return  # documented: a sub-prefix frame raises ValueError so the loop drops it
    assert isinstance(ftype, int) and isinstance(sid, int) and isinstance(payload, bytes)
    assert payload == data[protocol.PREFIX_SIZE :]


# -- 2. accounting never drifts / crashes under random op interleavings -------
_idx = st.integers(min_value=0, max_value=7)
_op = st.one_of(
    st.tuples(st.just("open")),
    st.tuples(st.just("data"), _idx, st.binary(min_size=0, max_size=64)),
    st.tuples(st.just("eof"), _idx),
    st.tuples(st.just("reset"), _idx),
    st.tuples(st.just("read"), _idx),
    st.tuples(st.just("grant"), _idx, st.integers(min_value=0, max_value=1 << 20)),
)


async def _replay(ops: list[tuple]) -> None:
    mux = Mux(_FakeWS())
    streams = []
    for op in ops:
        kind = op[0]
        if kind == "open":
            if len(streams) < 8:
                streams.append(await mux.open())
        elif streams:
            s = streams[op[1] % len(streams)]
            if kind == "data":
                s._feed(op[2])
            elif kind == "eof":
                s._feed_eof()
            elif kind == "reset":
                await s.reset()
            elif kind == "grant":
                s._grant(op[2])
            elif kind == "read" and not s._incoming.empty():
                await s.read()
        # Per-step invariants: counters never go negative or exceed their caps.
        assert mux._buffered >= 0 and mux._frames >= 0
        assert mux._buffered <= _MAX_CONN_BUFFERED and mux._frames <= _MAX_CONN_FRAMES
    await asyncio.sleep(0)  # let any spawned reset() reconcile
    for s in list(mux._streams.values()):
        s._abort()
    for s in streams:  # drain queued data/sentinels so nothing is left referenced
        while not s._incoming.empty():
            await s.read()
    # No residual drift once every stream is torn down.
    assert mux._buffered == 0, f"buffer drift: {mux._buffered}"
    assert mux._frames == 0, f"frame drift: {mux._frames}"


@given(ops=st.lists(_op, max_size=120))
def test_mux_accounting_never_drifts_under_random_ops(ops: list[tuple]) -> None:
    asyncio.run(_replay(ops))
