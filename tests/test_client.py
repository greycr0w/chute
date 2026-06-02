"""Agent-side robustness: bounded local-app dial and reconnect state hygiene.
These drive Tunnel internals directly (no server needed)."""

from __future__ import annotations

import asyncio

import chute.client
from chute.client import Tunnel


# -- F24: an unreachable local app must RESET within the connect timeout -------
async def test_local_connect_timeout_resets(monkeypatch) -> None:
    monkeypatch.setattr(chute.client, "_LOCAL_CONNECT_TIMEOUT", 0.2)

    async def _hang(*_args, **_kwargs):
        await asyncio.sleep(30)  # simulate a blackholed port (SYN dropped)

    monkeypatch.setattr(chute.client.asyncio, "open_connection", _hang)

    t = Tunnel(server="x", token="y", local_port=9)
    reset = asyncio.Event()

    class _FakeStream:
        id = 1
        reset_by_peer = False

        async def reset(self) -> None:
            reset.set()

        def close(self) -> None:
            pass

    # Bound well above the 0.2s connect timeout but far below the 30s hang.
    await asyncio.wait_for(t._handle_stream(_FakeStream()), timeout=3)
    assert reset.is_set(), "a timed-out local connect must reset the stream"


# -- F30: _connected is cleared at the top of EVERY attempt, incl. clean ones --
async def test_connected_cleared_before_each_attempt(monkeypatch) -> None:
    t = Tunnel(server="x", token="y", local_port=1)
    seen: list[bool] = []
    calls = 0

    async def _fake_run_once() -> None:
        nonlocal calls
        seen.append(t._connected.is_set())  # observed at the start of each attempt
        t._connected.set()  # simulate "connected"
        calls += 1
        if calls >= 2:
            t._stop.set()
        # returns cleanly -> exercises the clean-disconnect path (no except branch)

    monkeypatch.setattr(t, "_run_once", _fake_run_once)
    await asyncio.wait_for(t.serve_forever(), timeout=3)
    # Pre-fix the clean path never cleared _connected, so attempt 2 would see True
    # (a stale, still-"connected" state). Post-fix both attempts start cleared.
    assert seen == [False, False]


# -- F13/F52: stop() after the loop has closed (post-fatal) must not raise -----
def test_stop_is_idempotent_after_loop_closed() -> None:
    t = Tunnel(server="x", token="y", local_port=1)
    loop = asyncio.new_event_loop()
    loop.close()
    t._loop = loop  # simulate the background thread having exited (fatal auth)
    t.stop()  # pre-fix: RuntimeError("Event loop is closed"); post-fix: clean no-op
    t.stop()  # and genuinely idempotent
