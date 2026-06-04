"""Account-aware relay primitives: cross-account label ownership, per-account
concurrency caps, the per-IP failed-auth limiter, and retryable-vs-fatal auth.

The single shared token (StaticTokenAuthorizer) maps every agent to account "0"
with no per-account cap; relay-global caps still apply. Account-specific behavior
surfaces once an authorizer hands out distinct accounts/limits -- which is exactly
what the fakes here do. The pure-logic cases poke the Server's synchronous decision
methods directly (no sockets); integration cases drive the real WSS handshake
end-to-end.
"""

from __future__ import annotations

import asyncio
import contextlib
import datetime as _dt
import hashlib
import json
import logging
import socket
import time
from collections.abc import Callable

import pytest
import websockets

import chute.server as server_module
from chute import certs, protocol
from chute._relay import _pump_reader_to_stream, _pump_stream_to_writer
from chute.auth import AuthResult, Budget
from chute.client import Tunnel
from chute.control import (
    AccountBudgetUpdate,
    LeaseRevocation,
    PolicyUpdate,
    PolicyUpdateRequest,
    StaticPolicyControlPlane,
    TunnelAdmission,
    TunnelLease,
)
from chute.events import (
    AuthRejectedEvent,
    RelayStatsEvent,
    TunnelClosedEvent,
    TunnelOpenedEvent,
    VisitorRejectedEvent,
)
from chute.server import (
    Server,
    TunnelRegistration,
    _BandwidthLimitExceeded,
    _LabelError,
)

BASE = "tun.test"


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


async def _quiet_cancel(*tasks: asyncio.Future) -> None:
    for t in tasks:
        t.cancel()
    for t in tasks:
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await t


async def _eventually(predicate: Callable[[], bool], timeout: float = 1.0) -> None:
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        if predicate():
            return
        await asyncio.sleep(0.01)
    assert predicate()


def _server() -> Server:
    # Nothing binds until serve(); safe to construct for synchronous unit tests.
    return Server(
        token="secret", base_domain=BASE, public_host="127.0.0.1", control_host="127.0.0.1"
    )


class _FakeMux:
    """Identity stand-in for a Mux in the routing map (`is` identity + a stream count)."""

    def __init__(self, active_streams: int = 0) -> None:
        self.active_streams = active_streams
        self.draining = False
        self.drain_calls: list[float] = []
        self.close_calls: list[tuple[int, str]] = []
        self.stats_snapshot: dict[str, int] = {}

    async def drain(self, timeout: float) -> None:
        self.draining = True
        self.drain_calls.append(timeout)

    async def aclose(self, code: int = 1000, reason: str = "") -> None:
        self.close_calls.append((code, reason))

    def stats(self) -> dict[str, int]:
        return {
            "active_streams": self.active_streams,
            "buffered_bytes": 0,
            "queued_frames": 0,
            "draining": int(self.draining),
            "opened": 0,
            "reset_local": 0,
            "reset_peer": 0,
            "credit_stall": 0,
            "write_stall": 0,
            "goaway_in": 0,
            **self.stats_snapshot,
        }


class _NoItemsDict(dict[str, TunnelRegistration]):
    """Dict that catches accidental full-registry scans in indexed tests."""

    def items(self):  # type: ignore[override]
        raise AssertionError("revocation should use the lease index")


def _reg(
    account_id: str,
    active_streams: int = 0,
    budget: Budget | None = None,
    *,
    lease_id: str | None = "lease-1",
    lease_expires_at: _dt.datetime | None = None,
    lease_observed_at: _dt.datetime | None = None,
):
    return TunnelRegistration(
        mux=_FakeMux(active_streams),
        account_id=account_id,
        budget=budget or Budget(),
        connection_id="conn",
        credential_id=None,
        scheme="https",
        public_url="https://example.test/",
        agent_ip=None,
        requested_subdomain=None,
        accepting_visitors=True,
        lease_id=lease_id,
        lease_expires_at=lease_expires_at,
        lease_observed_at=lease_observed_at,
    )


def _install_agent(s: Server, label: str, registration: TunnelRegistration) -> None:
    s._install_registration(label, registration)


class _RecordingSendStream:
    def __init__(self) -> None:
        self.sent: list[bytes] = []
        self.eof = False

    async def send(self, data: bytes) -> None:
        self.sent.append(data)

    async def send_eof(self) -> None:
        self.eof = True


class _ReadableStream:
    def __init__(self, chunks: list[bytes]) -> None:
        self.chunks = chunks
        self.acks: list[int] = []
        self.reset_by_peer = False

    async def read(self) -> bytes | None:
        if self.chunks:
            return self.chunks.pop(0)
        return None

    async def ack(self, n: int) -> None:
        self.acks.append(n)


class _RecordingWriter:
    def __init__(self) -> None:
        self.writes: list[bytes] = []
        self.eof = False
        self.closed = False
        self.transport = _RecordingTransport()

    def write(self, chunk: bytes) -> None:
        self.writes.append(chunk)

    async def drain(self) -> None:
        return None

    def can_write_eof(self) -> bool:
        return True

    def write_eof(self) -> None:
        self.eof = True

    def close(self) -> None:
        self.closed = True


class _RecordingTransport:
    def __init__(self) -> None:
        self.aborted = False

    def abort(self) -> None:
        self.aborted = True


# --------------------------------------------------------------------------- #
# P1.1 / P1.2 -- _authorize_claim (synchronous, await-free)
# --------------------------------------------------------------------------- #


def test_free_label_is_claimable():
    _server()._authorize_claim(AuthResult(account_id="A"), "free")  # no raise


def test_label_held_by_another_account_is_rejected():
    s = _server()
    s._agents["shared"] = _reg("A")
    s._account_labels["A"] = {"shared"}
    with pytest.raises(_LabelError) as exc:
        s._authorize_claim(AuthResult(account_id="B"), "shared")
    assert str(exc.value) == "subdomain_taken"


def test_same_account_may_reclaim_its_own_label_even_at_cap():
    s = _server()
    s._agents["mine"] = _reg("A")
    s._account_labels["A"] = {"mine"}
    s._authorize_claim(AuthResult(account_id="A", max_tunnels=1), "mine")


def test_concurrency_cap_rejects_a_new_label_over_the_limit():
    s = _server()
    s._account_labels["A"] = {"a", "b", "c"}
    with pytest.raises(_LabelError) as exc:
        s._authorize_claim(AuthResult(account_id="A", max_tunnels=3), "d")
    assert str(exc.value) == "tunnel_limit"


def test_reclaim_does_not_count_against_the_cap():
    s = _server()
    s._agents["a"] = _reg("A")
    s._account_labels["A"] = {"a", "b", "c"}
    s._authorize_claim(AuthResult(account_id="A", max_tunnels=3), "a")


def test_global_agent_cap_rejects_only_new_labels():
    s = Server(
        token="secret",
        base_domain=BASE,
        public_host="127.0.0.1",
        control_host="127.0.0.1",
        max_agents=1,
    )
    s._agents["mine"] = _reg("A")

    assert s._global_agent_budget_ok("mine")
    assert not s._global_agent_budget_ok("other")


def test_allowed_label_is_enforced():
    s = _server()
    s._authorize_claim(AuthResult(account_id="A", allowed_label="owned"), "owned")
    with pytest.raises(_LabelError) as exc:
        s._authorize_claim(AuthResult(account_id="A", allowed_label="owned"), "admin")
    assert str(exc.value) == "subdomain_not_allowed"


def test_malformed_allowed_label_is_rejected_cleanly():
    s = _server()
    with pytest.raises(_LabelError) as exc:
        s._authorize_claim(
            AuthResult(account_id="A", allowed_label=123),
            "owned",  # type: ignore[arg-type]
        )
    assert str(exc.value) == "subdomain_not_allowed"


# --------------------------------------------------------------------------- #
# Budget enforcement -- per-account local caps (synchronous decisions)
# --------------------------------------------------------------------------- #


def test_account_active_streams_uses_reserved_visitor_counter():
    s = _server()
    reg_a = _reg("A", active_streams=99)
    reg_b = _reg("A")

    assert s._account_active_streams("A") == 0
    assert s._try_acquire_visitor_budget(reg_a) is True
    assert s._try_acquire_visitor_budget(reg_b) is True
    assert s._account_active_streams("A") == 2

    s._release_visitor_budget(reg_a)
    assert s._account_active_streams("A") == 1
    s._release_visitor_budget(reg_b)
    assert s._account_active_streams("A") == 0


def test_visitor_budget_blocks_only_over_max_visitors():
    s = _server()
    s._account_active_visitors["A"] = 2

    assert s._visitor_budget_exceeded(_reg("A", budget=Budget(max_visitors=2))) is True
    assert s._visitor_budget_exceeded(_reg("A", budget=Budget(max_visitors=3))) is False
    assert s._visitor_budget_exceeded(_reg("A", budget=Budget())) is False


def test_try_acquire_visitor_budget_is_atomic_and_releases_to_zero():
    s = _server()
    reg = _reg("A", budget=Budget(max_visitors=1))

    assert s._try_acquire_visitor_budget(reg) is True
    assert s._try_acquire_visitor_budget(reg) is False
    assert s._account_active_streams("A") == 1

    s._release_visitor_budget(reg)
    assert s._account_active_streams("A") == 0
    assert "A" not in s._account_active_visitors


def test_account_reconnect_budget_limits_known_account_connects():
    s = _server()
    budget = Budget(max_reconnects_per_min=2)

    assert s._account_reconnect_budget_ok("A", budget) is True
    assert s._account_reconnect_budget_ok("A", budget) is True
    assert s._account_reconnect_budget_ok("A", budget) is False
    assert s._account_reconnect_budget_ok("B", budget) is True
    assert s._account_reconnect_budget_ok("A", Budget()) is True

    assert len(s._account_reconnects["A"]) == 2


def test_account_reconnect_budget_prunes_expired_slots_and_rejects_bad_limits():
    s = _server()
    s._account_reconnects["A"] = [time.monotonic() - 61.0]

    assert s._account_reconnect_budget_ok("A", Budget(max_reconnects_per_min=1)) is True
    assert len(s._account_reconnects["A"]) == 1
    assert (
        s._account_reconnect_budget_ok(
            "A",
            Budget(max_reconnects_per_min=True),  # type: ignore[arg-type]
        )
        is False
    )


async def test_account_bandwidth_budget_delays_aggregate_bytes(monkeypatch):
    s = _server()
    reg_a = _reg("A", budget=Budget(max_bytes_per_sec=1000))
    reg_b = _reg("A", budget=Budget(max_bytes_per_sec=1000))
    sleeps: list[float] = []

    async def fake_sleep(delay: float) -> None:
        sleeps.append(delay)

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)

    await s._throttle_account_bytes(reg_a, 50)
    await s._throttle_account_bytes(reg_b, 50)

    assert len(sleeps) == 1
    assert sleeps[0] == pytest.approx(0.05, abs=0.01)
    assert "A" in s._account_bandwidth


async def test_account_bandwidth_budget_rejects_zero_or_malformed_limits():
    s = _server()

    with pytest.raises(_BandwidthLimitExceeded):
        await s._throttle_account_bytes(_reg("A", budget=Budget(max_bytes_per_sec=0)), 1)
    with pytest.raises(_BandwidthLimitExceeded):
        await s._throttle_account_bytes(
            _reg(
                "A",
                budget=Budget(max_bytes_per_sec=True),  # type: ignore[arg-type]
            ),
            1,
        )


async def test_account_bandwidth_state_drops_when_account_idle():
    s = _server()
    reg = _reg("A", budget=Budget(max_bytes_per_sec=1000))
    s._agents["alpha"] = reg
    s._account_labels["A"] = {"alpha"}

    assert s._try_acquire_visitor_budget(reg) is True
    await s._throttle_account_bytes(reg, 1)
    assert "A" in s._account_bandwidth

    s._deregister_if_current("alpha", reg.mux)
    assert "A" in s._account_bandwidth
    s._release_visitor_budget(reg)
    assert "A" not in s._account_bandwidth


async def test_account_budget_update_applies_to_detached_in_flight_work():
    s = _server()
    reg = _reg("A", budget=Budget())
    s._agents["alpha"] = reg
    s._account_labels["A"] = {"alpha"}

    assert s._try_acquire_visitor_budget(reg) is True
    assert s._try_reserve_account_buffer(reg, 7) is True
    s._deregister_if_current("alpha", reg.mux)

    s._set_account_budget(
        "A",
        Budget(max_visitors=1, max_bytes_per_sec=0, max_buffered_bytes=7),
    )

    assert s._try_acquire_visitor_budget(reg) is False
    assert s._try_reserve_account_buffer(reg, 1) is False
    with pytest.raises(_BandwidthLimitExceeded):
        await s._throttle_account_bytes(reg, 1)

    s._release_visitor_budget(reg)
    s._release_account_buffer("A", 7)


def test_account_buffer_budget_reserves_across_tunnels_and_releases():
    s = _server()
    reg_a = _reg("A", budget=Budget(max_buffered_bytes=10))
    reg_b = _reg("A", budget=Budget(max_buffered_bytes=10))

    assert s._try_reserve_account_buffer(reg_a, 6) is True
    assert s._try_reserve_account_buffer(reg_b, 4) is True
    assert s._account_buffered["A"] == 10
    assert s._try_reserve_account_buffer(reg_b, 1) is False
    assert s._account_buffered["A"] == 10

    s._release_account_buffer("A", 3)
    assert s._account_buffered["A"] == 7
    assert s._try_reserve_account_buffer(reg_a, 3) is True
    assert s._account_buffered["A"] == 10

    s._release_account_buffer("A", 10)
    assert "A" not in s._account_buffered


def test_account_buffer_budget_rejects_zero_or_malformed_limits():
    s = _server()

    assert s._try_reserve_account_buffer(_reg("A", budget=Budget(max_buffered_bytes=0)), 1) is False
    assert (
        s._try_reserve_account_buffer(
            _reg(
                "A",
                budget=Budget(max_buffered_bytes=True),  # type: ignore[arg-type]
            ),
            1,
        )
        is False
    )
    assert s._try_reserve_account_buffer(_reg("A", budget=Budget()), 1) is True
    assert s._account_buffered["A"] == 1
    s._release_account_buffer("A", 1)
    assert "A" not in s._account_buffered


def test_account_buffer_budget_applies_to_existing_tracked_buffers_after_policy_update():
    s = _server()
    reg = _reg("A", budget=Budget())

    assert s._try_reserve_account_buffer(reg, 7) is True
    assert s._account_buffered["A"] == 7

    reg.budget = Budget(max_buffered_bytes=10)
    assert s._try_reserve_account_buffer(reg, 3) is True
    assert s._try_reserve_account_buffer(reg, 1) is False
    assert s._account_buffered["A"] == 10


async def test_relay_pumps_apply_byte_throttle_before_forwarding():
    reader = asyncio.StreamReader()
    reader.feed_data(b"abc")
    reader.feed_eof()
    send_stream = _RecordingSendStream()
    reader_calls: list[int] = []
    reader_forwarded: list[int] = []

    async def reader_throttle(n: int) -> None:
        reader_calls.append(n)
        assert send_stream.sent == []

    def record_reader_forwarded(n: int) -> None:
        reader_forwarded.append(n)
        assert send_stream.sent == [b"abc"]

    await _pump_reader_to_stream(
        reader,
        send_stream,
        reader_throttle,
        record_reader_forwarded,
    )

    assert reader_calls == [3]
    assert reader_forwarded == [3]
    assert send_stream.sent == [b"abc"]
    assert send_stream.eof is True

    read_stream = _ReadableStream([b"abcd"])
    writer = _RecordingWriter()
    writer_calls: list[int] = []
    writer_forwarded: list[int] = []

    async def writer_throttle(n: int) -> None:
        writer_calls.append(n)
        assert writer.writes == []

    def record_writer_forwarded(n: int) -> None:
        writer_forwarded.append(n)
        assert writer.writes == [b"abcd"]
        assert read_stream.acks == []

    await _pump_stream_to_writer(
        read_stream,
        writer,
        writer_throttle,
        record_writer_forwarded,
    )

    assert writer_calls == [4]
    assert writer_forwarded == [4]
    assert writer.writes == [b"abcd"]
    assert read_stream.acks == [4]
    assert writer.eof is True


async def test_relay_stream_reset_aborts_writer_not_clean_eof():
    read_stream = _ReadableStream([b"partial"])
    read_stream.reset_by_peer = True
    writer = _RecordingWriter()

    await _pump_stream_to_writer(read_stream, writer)

    assert writer.writes == [b"partial"]
    assert read_stream.acks == [7]
    assert writer.transport.aborted is True
    assert writer.eof is False
    assert writer.closed is False


def test_relay_stats_snapshot_aggregates_mux_gauges_and_byte_counters():
    s = _server()
    reg_a = _reg("A", active_streams=2)
    reg_b = _reg("B", active_streams=3)
    reg_a.mux.stats_snapshot.update(
        {
            "buffered_bytes": 1024,
            "queued_frames": 4,
            "opened": 7,
            "reset_local": 2,
            "reset_peer": 3,
            "credit_stall": 1,
        }
    )
    reg_b.mux.draining = True
    reg_b.mux.stats_snapshot.update(
        {
            "buffered_bytes": 2048,
            "queued_frames": 5,
            "opened": 11,
            "write_stall": 2,
        }
    )
    s._agents["alpha"] = reg_a
    s._agents["beta"] = reg_b
    s._account_labels["A"] = {"alpha"}
    s._account_labels["B"] = {"beta"}
    s._account_active_visitors["C"] = 1
    s._policy_version = 9
    s._relay_bytes_to_agent = 123
    s._relay_bytes_to_visitor = 456
    s._control_in_flight = 2
    s._auth_in_flight = 3
    s._visitors_in_flight = 4
    s._control_busy = 8
    s._auth_busy = 9
    s._visitor_pool_busy = 10
    s._visitor_ip_limited = 11
    s._visitor_ips["198.51.100.1"] = 2
    s._visitor_ips["198.51.100.2"] = 1
    s._event_generated.update(
        {
            "tunnel_opened": 2,
            "tunnel_closed": 1,
            "visitor_opened": 5,
            "visitor_closed": 4,
            "auth_rejected": 3,
            "visitor_rejected": 6,
            "relay_stats": 7,
        }
    )
    s._policy_update_poll_failures = 12
    s._policy_updates_applied = 13
    s._policy_updates_rejected = 14
    s._lease_renewals_succeeded = 15
    s._lease_renewals_failed = 16
    s._lease_renewals_invalid = 17
    s._lease_renewals_revoked = 18
    s._lease_revocations = 19
    s._lease_expirations = 20

    stats = s._collect_relay_stats()

    assert isinstance(stats, RelayStatsEvent)
    assert stats.active_tunnels == 2
    assert stats.account_count == 3
    assert stats.control_capacity == s.max_control_conns
    assert stats.control_in_flight == 2
    assert stats.auth_capacity == s.max_auth_conns
    assert stats.auth_in_flight == 3
    assert stats.visitor_capacity == s.max_visitors
    assert stats.visitors_in_flight == 4
    assert stats.visitor_ip_capacity == s.max_visitors_per_ip
    assert stats.visitor_ip_buckets == 2
    assert stats.control_busy == 8
    assert stats.auth_busy == 9
    assert stats.visitor_pool_busy == 10
    assert stats.visitor_ip_limited == 11
    assert stats.active_streams == 5
    assert stats.buffered_bytes == 3072
    assert stats.queued_frames == 9
    assert stats.draining_tunnels == 1
    assert stats.opened_streams == 18
    assert stats.reset_streams == 5
    assert stats.reset_peer_streams == 3
    assert stats.credit_stalls == 1
    assert stats.write_stalls == 2
    assert stats.bytes_to_agent == 123
    assert stats.bytes_to_visitor == 456
    assert stats.event_tunnel_opened_generated == 2
    assert stats.event_tunnel_closed_generated == 1
    assert stats.event_visitor_opened_generated == 5
    assert stats.event_visitor_closed_generated == 4
    assert stats.event_auth_rejected_generated == 3
    assert stats.event_visitor_rejected_generated == 6
    assert stats.event_relay_stats_generated == 7
    assert stats.event_queue_depth == 0
    assert stats.event_queue_capacity == s._event_queue.maxsize
    assert stats.event_queue_enqueued == 0
    assert stats.event_queue_delivered == 0
    assert stats.event_queue_retried == 0
    assert stats.event_queue_dropped == 0
    assert stats.policy_version == 9
    assert stats.policy_update_poll_failures == 12
    assert stats.policy_updates_applied == 13
    assert stats.policy_updates_rejected == 14
    assert stats.lease_renewals_succeeded == 15
    assert stats.lease_renewals_failed == 16
    assert stats.lease_renewals_invalid == 17
    assert stats.lease_renewals_revoked == 18
    assert stats.lease_revocations == 19
    assert stats.lease_expirations == 20


def test_relay_stats_log_snapshot_includes_pool_shed_and_event_queue(
    caplog: pytest.LogCaptureFixture,
) -> None:
    s = _server()
    s._agents["alpha"] = _reg("A", active_streams=2)
    s._control_in_flight = 1
    s._auth_in_flight = 2
    s._visitors_in_flight = 3
    s._control_busy = 4
    s._auth_busy = 5
    s._visitor_pool_busy = 6
    s._visitor_ip_limited = 7
    s._event_queue_dropped = 8
    s._event_generated.update({"visitor_rejected": 9, "relay_stats": 10})
    s._policy_version = 11
    s._policy_update_poll_failures = 12
    s._policy_updates_applied = 13
    s._policy_updates_rejected = 14
    s._lease_renewals_succeeded = 15
    s._lease_renewals_failed = 16
    s._lease_renewals_invalid = 17
    s._lease_renewals_revoked = 18
    s._lease_revocations = 19
    s._lease_expirations = 20
    caplog.set_level(logging.INFO, logger="chute.server")

    s._log_relay_stats_snapshot(s._collect_relay_stats())

    assert len(caplog.records) == 1
    message = caplog.records[0].getMessage()
    assert "visitors=3/2048" in message
    assert "control=1/256" in message
    assert "auth=2/256" in message
    assert "shed(control=4 auth=5 visitor_pool=6 visitor_ip=7)" in message
    assert "policy(version=11 applied=13 rejected=14 poll_failed=12)" in message
    assert (
        "lease(renewed=15 failed=16 invalid=17 renewal_revoked=18 revoked=19 expired=20)" in message
    )
    assert "events(generated=19 queue=0/1024 dropped=8)" in message
    assert "bytes_to_agent=0 bytes_to_visitor=0" in message
    assert "account_id" not in message
    assert "label" not in message


def test_unexpired_finite_lease_remains_selectable():
    s = _server()
    expires_at = _dt.datetime.now(_dt.UTC) + _dt.timedelta(minutes=1)
    reg = _reg("A", lease_id="lease-live", lease_expires_at=expires_at)
    s._agents["beta"] = reg
    s._account_labels["A"] = {"beta"}

    selected = s._select_agent_for_visitor(b"GET / HTTP/1.1\r\nHost: beta.tun.test\r\n\r\n")

    assert selected == ("beta", reg)
    assert "beta" in s._agents
    assert reg.accepting_visitors is True


async def test_expired_lease_stops_new_visitors_and_drains_tunnel():
    s = _server()
    expires_at = _dt.datetime.now(_dt.UTC) - _dt.timedelta(seconds=1)
    reg = _reg("A", lease_id="lease-expired", lease_expires_at=expires_at)
    s._agents["beta"] = reg
    s._account_labels["A"] = {"beta"}

    selected = s._select_agent_for_visitor(b"GET / HTTP/1.1\r\nHost: beta.tun.test\r\n\r\n")

    assert selected is None
    assert "beta" not in s._agents
    assert "A" not in s._account_labels
    assert reg.accepting_visitors is False
    await asyncio.sleep(0)
    assert reg.mux.drain_calls == [10.0]


def test_naive_lease_expiry_fails_closed():
    s = _server()
    naive_future = _dt.datetime.now() + _dt.timedelta(minutes=1)
    reg = _reg("A", lease_id="lease-naive", lease_expires_at=naive_future)
    s._agents["beta"] = reg
    s._account_labels["A"] = {"beta"}

    selected = s._select_agent_for_visitor(b"GET / HTTP/1.1\r\nHost: beta.tun.test\r\n\r\n")

    assert selected is None
    assert "beta" not in s._agents
    assert reg.accepting_visitors is False


def test_long_lease_renewal_uses_lifetime_window_not_short_poll_cap():
    s = _server()
    observed_at = _dt.datetime.now(_dt.UTC)
    expires_at = observed_at + _dt.timedelta(hours=1)
    reg = _reg(
        "A",
        lease_id="lease-long",
        lease_expires_at=expires_at,
        lease_observed_at=observed_at,
    )

    delay = s._lease_renew_delay(reg)

    assert delay is not None
    assert 30.0 < delay
    assert (60 * 60 * 0.60) <= delay <= (60 * 60 * 0.90)


def test_late_lease_renewal_retries_with_bounded_jitter_until_expiry():
    s = _server()
    observed_at = _dt.datetime.now(_dt.UTC) - _dt.timedelta(minutes=55)
    expires_at = observed_at + _dt.timedelta(hours=1)
    reg = _reg(
        "A",
        lease_id="lease-late",
        lease_expires_at=expires_at,
        lease_observed_at=observed_at,
    )

    delay = s._lease_renew_delay(reg)

    assert delay is not None
    assert 30.0 <= delay <= 50.0


async def test_malformed_lease_renewal_is_ignored_until_local_expiry():
    now = _dt.datetime.now(_dt.UTC)
    cases = (
        object(),
        TunnelLease(
            lease_id="lease-1",
            account_id="A",
            expires_at=None,
            generation=8,
        ),
        TunnelLease(
            lease_id="lease-1",
            account_id="A",
            expires_at=(now + _dt.timedelta(minutes=5)).replace(tzinfo=None),
            generation=8,
        ),
        TunnelLease(
            lease_id="lease-1",
            account_id="A",
            expires_at=now - _dt.timedelta(seconds=1),
            generation=8,
        ),
        TunnelLease(
            lease_id="lease-1",
            account_id="A",
            expires_at=now + _dt.timedelta(minutes=5),
            generation=6,
        ),
    )

    for renewed in cases:
        s = _server()
        original_expiry = now + _dt.timedelta(minutes=1)
        reg = _reg("A", lease_id="lease-1", lease_expires_at=original_expiry)
        reg.lease_generation = 7
        s._agents["beta"] = reg
        s._account_labels["A"] = {"beta"}
        cp = _MalformedRenewalControlPlane(renewed)
        s.control_plane = cp

        assert await s._try_renew_lease("beta", reg) is True

        assert cp.renewals
        assert s._agents["beta"] is reg
        assert reg.accepting_visitors is True
        assert reg.lease_expires_at == original_expiry
        assert reg.lease_generation == 7
        assert s._lease_renewals_invalid == 1


async def test_stale_lease_renewal_result_after_revocation_is_ignored():
    s = _server()
    original_expiry = _dt.datetime.now(_dt.UTC) + _dt.timedelta(minutes=1)
    reg = _reg("A", lease_id="lease-race", lease_expires_at=original_expiry)
    _install_agent(s, "race", reg)
    cp = _BlockingRenewalControlPlane()
    s.control_plane = cp

    renewal = asyncio.create_task(s._try_renew_lease("race", reg))
    try:
        await asyncio.wait_for(cp.started.wait(), timeout=1)
        assert s.revoke_lease("lease-race") == 1
        cp.release.set()

        assert await asyncio.wait_for(renewal, timeout=1) is False
    finally:
        if not renewal.done():
            renewal.cancel()
            await _quiet_cancel(renewal)

    assert "race" not in s._agents
    assert reg.lease_expires_at == original_expiry
    assert reg.lease_generation == 0
    assert s._lease_renewals_succeeded == 0
    assert s._lease_revocations == 1


def test_registration_install_and_deregister_maintains_lease_index():
    s = _server()
    reg = _reg("A", lease_id="lease-alpha")

    assert s._install_registration("alpha", reg) is None
    assert s._lease_labels == {"lease-alpha": {"alpha"}}
    assert s._account_labels["A"] == {"alpha"}

    s._deregister_if_current("alpha", reg.mux)

    assert "alpha" not in s._agents
    assert "lease-alpha" not in s._lease_labels
    assert "A" not in s._account_labels


def test_registration_replacement_updates_lease_index():
    s = _server()
    old = _reg("A", lease_id="lease-old")
    new = _reg("A", lease_id="lease-new")

    assert s._install_registration("alpha", old) is None
    assert s._install_registration("alpha", new) is old

    assert "lease-old" not in s._lease_labels
    assert s._lease_labels == {"lease-new": {"alpha"}}
    assert s._agents["alpha"] is new
    assert s._account_labels["A"] == {"alpha"}


async def test_revoke_lease_stops_new_visitors_and_drains_tunnel():
    s = _server()
    reg = _reg("A", lease_id="lease-revoked")
    _install_agent(s, "beta", reg)

    assert s.revoke_lease("missing") == 0
    assert s._lease_revocations == 0
    assert s.revoke_lease("lease-revoked", drain_timeout=0.25) == 1
    with pytest.raises(ValueError, match="revocation action"):
        s.revoke_lease("lease-revoked", action="drop")

    assert "beta" not in s._agents
    assert "A" not in s._account_labels
    assert reg.accepting_visitors is False
    assert s._lease_revocations == 1
    await asyncio.sleep(0)
    assert reg.mux.drain_calls == [0.25]


async def test_revoke_lease_uses_lease_index_without_scanning_agents():
    s = _server()
    target = _reg("A", lease_id="lease-target")
    other = _reg("A", lease_id="lease-other")
    _install_agent(s, "target", target)
    _install_agent(s, "other", other)
    s._agents = _NoItemsDict(s._agents)

    assert s.revoke_lease("lease-target", drain_timeout=0.25) == 1

    assert "target" not in s._agents
    assert s._agents["other"] is other
    assert "lease-target" not in s._lease_labels
    assert s._lease_labels["lease-other"] == {"other"}
    await asyncio.sleep(0)
    assert target.mux.drain_calls == [0.25]
    assert other.mux.drain_calls == []


async def test_policy_update_can_close_revoked_lease_immediately():
    s = _server()
    reg = _reg("A", lease_id="lease-close")
    _install_agent(s, "alpha", reg)

    update = PolicyUpdate(
        version=1,
        lease_revocations=(LeaseRevocation("lease-close", action="close"),),
    )

    assert s._apply_policy_update(update) is True

    assert s._policy_version == 1
    assert s._lease_revocations == 1
    assert "alpha" not in s._agents
    assert "A" not in s._account_labels
    assert reg.accepting_visitors is False
    await asyncio.sleep(0)
    assert reg.mux.drain_calls == [0.0]


async def test_policy_update_revokes_leases_and_updates_account_budget():
    s = _server()
    reg_a = _reg("A", lease_id="lease-a", budget=Budget(max_visitors=5))
    reg_b = _reg("B", lease_id="lease-b", budget=Budget(max_visitors=5))
    _install_agent(s, "alpha", reg_a)
    _install_agent(s, "beta", reg_b)

    update = PolicyUpdate(
        version=1,
        revoke_lease_ids=("lease-a",),
        account_budgets=(AccountBudgetUpdate("B", Budget(max_visitors=0)),),
    )

    assert s._apply_policy_update(update) is True

    assert s._policy_version == 1
    assert s._policy_updates_applied == 1
    assert s._policy_updates_rejected == 0
    assert s._lease_revocations == 1
    assert "alpha" not in s._agents
    assert "A" not in s._account_labels
    assert s._agents["beta"].budget.max_visitors == 0
    await asyncio.sleep(0)
    assert reg_a.mux.drain_calls == [10.0]


async def test_policy_update_bulk_revocations_use_lease_index():
    s = _server()
    bulk_count = 2000
    registrations = []
    for index in range(bulk_count):
        reg = _reg(f"A{index}", lease_id=f"lease-{index}")
        registrations.append(reg)
        _install_agent(s, f"label-{index}", reg)
    survivor = _reg("survivor", lease_id="lease-survivor")
    _install_agent(s, "survivor", survivor)
    s._agents = _NoItemsDict(s._agents)

    update = PolicyUpdate(
        version=1,
        revoke_lease_ids=tuple(f"lease-{i}" for i in range(bulk_count)),
    )

    assert s._apply_policy_update(update) is True

    assert s._policy_version == 1
    assert s._lease_revocations == bulk_count
    assert s._lease_labels == {"lease-survivor": {"survivor"}}
    assert s._agents["survivor"] is survivor
    await asyncio.sleep(0)
    assert all(reg.mux.drain_calls == [10.0] for reg in registrations)
    assert survivor.mux.drain_calls == []


async def test_pending_registration_participates_in_lease_index_and_revocation():
    s = _server()
    pending = _reg("A", lease_id="lease-pending")
    s._pending_agents["alpha"] = pending
    s._index_pending_registration("alpha", pending)

    assert s._active_lease_ids() == ("lease-pending",)

    assert s.revoke_lease("lease-pending", drain_timeout=0.25) == 1

    assert s._active_lease_ids() == ()
    assert "alpha" not in s._pending_agents
    assert "lease-pending" not in s._pending_lease_labels
    assert pending.accepting_visitors is False
    assert s._lease_revocations == 1
    await asyncio.sleep(0)
    assert pending.mux.close_calls == [(1013, "lease revoked")]


async def test_policy_update_bulk_revocations_use_pending_lease_index():
    s = _server()
    bulk_count = 2000
    registrations = []
    for index in range(bulk_count):
        reg = _reg(f"A{index}", lease_id=f"lease-{index}")
        registrations.append(reg)
        s._pending_agents[f"label-{index}"] = reg
        s._index_pending_registration(f"label-{index}", reg)
    survivor = _reg("survivor", lease_id="lease-survivor")
    s._pending_agents["survivor"] = survivor
    s._index_pending_registration("survivor", survivor)
    s._pending_agents = _NoItemsDict(s._pending_agents)

    update = PolicyUpdate(
        version=1,
        revoke_lease_ids=tuple(f"lease-{i}" for i in range(bulk_count)),
    )

    assert s._apply_policy_update(update) is True

    assert s._policy_version == 1
    assert s._lease_revocations == bulk_count
    assert s._pending_lease_labels == {"lease-survivor": {"survivor"}}
    assert s._pending_agents["survivor"] is survivor
    await asyncio.sleep(0)
    assert all(reg.mux.close_calls == [(1013, "lease revoked")] for reg in registrations)
    assert survivor.mux.close_calls == []


def test_policy_update_rejects_stale_or_malformed_updates_without_partial_apply():
    class _NotPolicyUpdate:
        version = 3

    s = _server()
    reg_a = _reg("A", lease_id="lease-a", budget=Budget(max_visitors=5))
    reg_b = _reg("B", lease_id="lease-b", budget=Budget(max_visitors=5))
    s._agents["alpha"] = reg_a
    s._agents["beta"] = reg_b
    s._account_labels["A"] = {"alpha"}
    s._account_labels["B"] = {"beta"}
    s._policy_version = 2

    stale = PolicyUpdate(version=2, revoke_lease_ids=("lease-a",))
    list_revoke = PolicyUpdate(version=3, revoke_lease_ids=["lease-a"])  # type: ignore[arg-type]
    unhashable_revoke = PolicyUpdate(version=3, revoke_lease_ids=([],))  # type: ignore[list-item]
    duplicate_revoke = PolicyUpdate(version=3, revoke_lease_ids=("lease-a", "lease-a"))
    duplicate_structured_revoke = PolicyUpdate(
        version=3,
        revoke_lease_ids=("lease-a",),
        lease_revocations=(LeaseRevocation("lease-a"),),
    )
    list_structured_revoke = PolicyUpdate(
        version=3,
        lease_revocations=[LeaseRevocation("lease-a")],  # type: ignore[arg-type]
    )
    bad_revoke_action = PolicyUpdate(
        version=3,
        lease_revocations=(
            LeaseRevocation("lease-a", action="drop"),  # type: ignore[arg-type]
        ),
    )
    duplicate_budget = PolicyUpdate(
        version=3,
        account_budgets=(
            AccountBudgetUpdate("B", Budget(max_visitors=1)),
            AccountBudgetUpdate("B", Budget(max_visitors=2)),
        ),
    )
    malformed_budget = PolicyUpdate(
        version=3,
        account_budgets=(AccountBudgetUpdate("B", Budget(max_visitors=True)),),
    )
    malformed_buffer_budget = PolicyUpdate(
        version=3,
        account_budgets=(
            AccountBudgetUpdate(
                "B",
                Budget(max_buffered_bytes=True),  # type: ignore[arg-type]
            ),
        ),
    )

    assert s._apply_policy_update(stale) is False
    assert s._apply_policy_update(_NotPolicyUpdate()) is False
    assert s._apply_policy_update(list_revoke) is False
    assert s._apply_policy_update(unhashable_revoke) is False
    assert s._apply_policy_update(duplicate_revoke) is False
    assert s._apply_policy_update(duplicate_structured_revoke) is False
    assert s._apply_policy_update(list_structured_revoke) is False
    assert s._apply_policy_update(bad_revoke_action) is False
    assert s._apply_policy_update(duplicate_budget) is False
    assert s._apply_policy_update(malformed_budget) is False
    assert s._apply_policy_update(malformed_buffer_budget) is False

    assert s._policy_version == 2
    assert s._policy_updates_applied == 0
    assert s._policy_updates_rejected == 11
    assert set(s._agents) == {"alpha", "beta"}
    assert s._agents["beta"].budget.max_visitors == 5


def test_policy_update_rejects_oversized_deltas_without_partial_apply():
    s = _server()
    reg = _reg("A", lease_id="lease-a", budget=Budget(max_visitors=5))
    _install_agent(s, "alpha", reg)

    too_many_legacy_revocations = PolicyUpdate(
        version=1,
        revoke_lease_ids=tuple(
            f"lease-{index}"
            for index in range(server_module._MAX_POLICY_UPDATE_REVOKE_LEASE_IDS + 1)
        ),
    )
    too_many_structured_revocations = PolicyUpdate(
        version=1,
        lease_revocations=tuple(
            LeaseRevocation(f"lease-{index}")
            for index in range(server_module._MAX_POLICY_UPDATE_LEASE_REVOCATIONS + 1)
        ),
    )
    too_many_budget_updates = PolicyUpdate(
        version=1,
        account_budgets=tuple(
            AccountBudgetUpdate(f"acct-{index}", Budget(max_visitors=1))
            for index in range(server_module._MAX_POLICY_UPDATE_ACCOUNT_BUDGETS + 1)
        ),
    )

    assert s._apply_policy_update(too_many_legacy_revocations) is False
    assert s._apply_policy_update(too_many_structured_revocations) is False
    assert s._apply_policy_update(too_many_budget_updates) is False

    assert s._policy_version == 0
    assert s._policy_updates_rejected == 3
    assert s._agents["alpha"] is reg
    assert s._agents["alpha"].budget.max_visitors == 5


def test_account_budget_overrides_are_scoped_to_local_work():
    s = _server()

    s._set_account_budget("missing", Budget(max_visitors=1))
    assert s._account_budget_overrides == {}

    reg = _reg("A", lease_id="lease-a")
    _install_agent(s, "alpha", reg)
    s._set_account_budget("A", Budget(max_visitors=1))

    assert s._account_budget_overrides["A"].max_visitors == 1
    assert reg.budget.max_visitors == 1

    s._deregister_if_current("alpha", reg.mux)

    assert "A" not in s._account_budget_overrides


def test_policy_update_request_is_bounded_for_custom_control_planes_by_default():
    class _CustomControlPlane:
        async def admit_tunnel(self, request):
            return None

        async def renew_lease(self, request):
            return None

        async def poll_policy_updates(self, request):
            return None

    server = Server(
        token="secret",
        base_domain=BASE,
        public_host="127.0.0.1",
        control_host="127.0.0.1",
        control_plane=_CustomControlPlane(),
    )
    for index in range(2000):
        _install_agent(server, f"label-{index}", _reg("acct", lease_id=f"lease-{index}"))
    pending = _reg("acct", lease_id="lease-pending")
    server._pending_agents["pending"] = pending
    server._index_pending_registration("pending", pending)

    request = server._policy_update_request()

    assert request == PolicyUpdateRequest(current_version=0, active_lease_count=2001)
    assert request.active_lease_ids == ()


def test_policy_update_request_includes_active_lease_ids_for_opt_in_control_planes():
    class _CustomControlPlane:
        include_active_lease_ids_in_policy_poll = True

        async def admit_tunnel(self, request):
            return None

        async def renew_lease(self, request):
            return None

        async def poll_policy_updates(self, request):
            return None

    server = Server(
        token="secret",
        base_domain=BASE,
        public_host="127.0.0.1",
        control_host="127.0.0.1",
        control_plane=_CustomControlPlane(),
    )
    _install_agent(server, "alpha", _reg("acct", lease_id="lease-alpha"))
    pending = _reg("acct", lease_id="lease-pending")
    server._pending_agents["pending"] = pending
    server._index_pending_registration("pending", pending)

    request = server._policy_update_request()

    assert request.active_lease_count == 2
    assert request.active_lease_ids == ("lease-alpha", "lease-pending")


async def test_policy_update_poll_failures_are_counted_without_advancing_version():
    s = _server()
    cp = _FailingPolicyUpdateControlPlane()
    s.control_plane = cp
    s.policy_poll_interval = 0.01

    task = asyncio.create_task(s._poll_policy_updates())
    try:
        await _eventually(lambda: s._policy_update_poll_failures > 0)
    finally:
        task.cancel()
        await _quiet_cancel(task)

    assert cp.requests
    assert s._policy_update_poll_failures >= 1
    assert s._policy_version == 0


# --------------------------------------------------------------------------- #
# P1.3 -- per-IP failed-auth limiter
# --------------------------------------------------------------------------- #


def test_failed_auth_limiter_trips_after_max_and_is_per_ip():
    s = _server()
    ip = "203.0.113.7"
    for _ in range(5):
        assert s._auth_rate_ok(ip) is True
        s._record_auth_fail(ip)
    assert s._auth_rate_ok(ip) is False  # 6th attempt from this IP is blocked
    assert s._auth_rate_ok("203.0.113.8") is True  # a different IP is unaffected


def test_failed_auth_limiter_tolerates_missing_ip():
    s = _server()
    for _ in range(50):
        s._record_auth_fail(None)
    assert s._auth_rate_ok(None) is True


# --------------------------------------------------------------------------- #
# integration -- the real WSS handshake under a multi-account / failing authorizer
# --------------------------------------------------------------------------- #


class _MappingAuthorizer:
    def __init__(self, mapping: dict[str, AuthResult]) -> None:
        self._mapping = mapping

    async def authenticate(self, request):
        return self._mapping.get(request.token)


class _RaisingAuthorizer:
    async def authenticate(self, request):
        raise RuntimeError("authorizer unavailable (e.g. DB down)")


class _HangingAuthorizer:
    def __init__(self) -> None:
        self.calls = 0

    async def authenticate(self, request):
        self.calls += 1
        await asyncio.Event().wait()


class _CountingAuthorizer:
    def __init__(self) -> None:
        self.calls = 0
        self.requests = []

    async def authenticate(self, request):
        self.calls += 1
        self.requests.append(request)
        return AuthResult(account_id="A")


class _ExpiredControlPlane:
    async def admit_tunnel(self, request):
        return TunnelAdmission(
            lease=TunnelLease(
                lease_id="expired-lease",
                account_id="A",
                expires_at=_dt.datetime.now(_dt.UTC) - _dt.timedelta(seconds=1),
            ),
            max_tunnels=10,
        )

    async def renew_lease(self, request):
        return None

    async def poll_policy_updates(self, request):
        return None


class _MalformedAdmissionControlPlane:
    async def admit_tunnel(self, request):
        return object()

    async def renew_lease(self, request):
        return None

    async def poll_policy_updates(self, request):
        return None


class _RenewingControlPlane:
    def __init__(self) -> None:
        self.renewals = []

    async def admit_tunnel(self, request):
        return TunnelAdmission(
            lease=TunnelLease(
                lease_id="renewable-lease",
                account_id="A",
                expires_at=_dt.datetime.now(_dt.UTC) + _dt.timedelta(seconds=0.2),
            ),
            max_tunnels=10,
        )

    async def renew_lease(self, request):
        self.renewals.append(request)
        return TunnelLease(
            lease_id=request.lease_id,
            account_id=request.account_id,
            credential_id=request.credential_id,
            expires_at=_dt.datetime.now(_dt.UTC) + _dt.timedelta(seconds=30),
            generation=request.generation + 1,
        )

    async def poll_policy_updates(self, request):
        return None


class _FailingRenewalControlPlane(_RenewingControlPlane):
    async def renew_lease(self, request):
        self.renewals.append(request)
        raise RuntimeError("control plane unavailable")


class _RevokingRenewalControlPlane(_RenewingControlPlane):
    async def renew_lease(self, request):
        self.renewals.append(request)
        return None


class _MalformedRenewalControlPlane(_RenewingControlPlane):
    def __init__(self, renewed):
        self.renewed = renewed
        self.renewals = []

    async def renew_lease(self, request):
        self.renewals.append(request)
        return self.renewed


class _BlockingRenewalControlPlane(_RenewingControlPlane):
    def __init__(self) -> None:
        super().__init__()
        self.started = asyncio.Event()
        self.release = asyncio.Event()

    async def renew_lease(self, request):
        self.renewals.append(request)
        self.started.set()
        await self.release.wait()
        return TunnelLease(
            lease_id=request.lease_id,
            account_id=request.account_id,
            credential_id=request.credential_id,
            expires_at=_dt.datetime.now(_dt.UTC) + _dt.timedelta(seconds=30),
            generation=request.generation + 1,
        )


class _PolicyUpdateControlPlane:
    include_active_lease_ids_in_policy_poll = True

    def __init__(self, update: PolicyUpdate | None) -> None:
        self.update = update
        self.requests = []
        self.sent = False

    async def admit_tunnel(self, request):
        return TunnelAdmission(
            lease=TunnelLease(
                lease_id="policy-lease",
                account_id="A",
            ),
            max_tunnels=10,
            budget=Budget(max_visitors=5),
        )

    async def renew_lease(self, request):
        return None

    async def poll_policy_updates(self, request):
        self.requests.append(request)
        if self.sent or "policy-lease" not in request.active_lease_ids:
            return None
        self.sent = True
        return self.update


class _FailingPolicyUpdateControlPlane(_PolicyUpdateControlPlane):
    def __init__(self) -> None:
        super().__init__(None)

    async def poll_policy_updates(self, request):
        self.requests.append(request)
        raise RuntimeError("control plane unavailable")


class _ReconnectLimitedControlPlane:
    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.admissions = 0

    async def admit_tunnel(self, request):
        self.admissions += 1
        return TunnelAdmission(
            lease=TunnelLease(
                lease_id=f"reconnect-lease-{self.admissions}",
                account_id="A",
            ),
            max_tunnels=10,
            budget=Budget(max_reconnects_per_min=self.limit),
        )

    async def renew_lease(self, request):
        return None

    async def poll_policy_updates(self, request):
        return None


class _RecordingEventSink:
    def __init__(self, *, fail_tunnel_opened: bool = False) -> None:
        self.fail_tunnel_opened = fail_tunnel_opened
        self.tunnel_opened_events: list[TunnelOpenedEvent] = []
        self.tunnel_closed_events: list[TunnelClosedEvent] = []
        self.auth_rejected_events: list[AuthRejectedEvent] = []
        self.visitor_rejected_events: list[VisitorRejectedEvent] = []
        self.relay_stats_events: list[RelayStatsEvent] = []

    async def tunnel_opened(self, event):
        if self.fail_tunnel_opened:
            raise RuntimeError("event store unavailable")
        self.tunnel_opened_events.append(event)

    async def tunnel_closed(self, event):
        self.tunnel_closed_events.append(event)

    async def visitor_opened(self, event):
        return None

    async def visitor_closed(self, event):
        return None

    async def auth_rejected(self, event):
        self.auth_rejected_events.append(event)

    async def visitor_rejected(self, event):
        self.visitor_rejected_events.append(event)

    async def relay_stats(self, event):
        self.relay_stats_events.append(event)


class _BlockingEventSink(_RecordingEventSink):
    def __init__(self) -> None:
        super().__init__()
        self.started = asyncio.Event()
        self.release = asyncio.Event()

    async def visitor_rejected(self, event):
        self.started.set()
        await self.release.wait()
        await super().visitor_rejected(event)


class _BlockFirstTunnelOpenedSink(_RecordingEventSink):
    def __init__(self) -> None:
        super().__init__()
        self.started = asyncio.Event()
        self.release = asyncio.Event()
        self.calls = 0

    async def tunnel_opened(self, event):
        self.calls += 1
        if self.calls == 1:
            self.started.set()
            await self.release.wait()
        await super().tunnel_opened(event)


class _FlakyEventSink(_RecordingEventSink):
    def __init__(self) -> None:
        super().__init__()
        self.failures_left = 1

    async def relay_stats(self, event):
        if self.failures_left:
            self.failures_left -= 1
            raise RuntimeError("temporary exporter failure")
        await super().relay_stats(event)


class _FailingEventSink(_RecordingEventSink):
    async def relay_stats(self, event):
        raise RuntimeError("persistent exporter failure")


async def test_best_effort_events_enqueue_without_waiting_for_sink() -> None:
    sink = _BlockingEventSink()
    server = Server(
        token="secret",
        public_host="127.0.0.1",
        control_host="127.0.0.1",
        event_sink=sink,
    )
    worker: asyncio.Task[None] | None = None
    event = VisitorRejectedEvent(
        reason="no_tunnel",
        label=None,
        account_id=None,
        credential_id=None,
        host="missing.tun.test",
        visitor_ip="127.0.0.1",
        at=_dt.datetime.now(_dt.UTC),
    )
    try:
        assert await asyncio.wait_for(server._emit_event("visitor_rejected", event), timeout=0.2)
        queued_stats = server._collect_relay_stats()
        assert queued_stats.event_queue_depth == 1
        assert queued_stats.event_queue_capacity == server._event_queue.maxsize
        assert queued_stats.event_queue_enqueued == 1
        assert queued_stats.event_queue_delivered == 0
        assert queued_stats.event_queue_retried == 0
        assert queued_stats.event_queue_dropped == 0
        assert queued_stats.event_visitor_rejected_generated == 1
        worker = asyncio.ensure_future(server._run_event_queue())
        await asyncio.wait_for(sink.started.wait(), timeout=1)
        assert sink.visitor_rejected_events == []

        sink.release.set()
        await _eventually(lambda: sink.visitor_rejected_events == [event])
        delivered_stats = server._collect_relay_stats()
        assert delivered_stats.event_queue_depth == 0
        assert delivered_stats.event_queue_enqueued == 1
        assert delivered_stats.event_queue_delivered == 1
        assert delivered_stats.event_queue_retried == 0
        assert delivered_stats.event_queue_dropped == 0
        assert delivered_stats.event_visitor_rejected_generated == 1
    finally:
        if worker is not None:
            await _quiet_cancel(worker)


async def test_best_effort_event_queue_retries_transient_sink_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("chute.server._EVENT_RETRY_DELAY", 0.01)
    sink = _FlakyEventSink()
    server = Server(
        token="secret",
        public_host="127.0.0.1",
        control_host="127.0.0.1",
        event_sink=sink,
    )
    worker = asyncio.ensure_future(server._run_event_queue())
    stats = server._collect_relay_stats()
    try:
        assert await server._emit_event("relay_stats", stats)
        await _eventually(lambda: sink.relay_stats_events == [stats])
        assert sink.failures_left == 0
        retry_stats = server._collect_relay_stats()
        assert retry_stats.event_queue_enqueued == 1
        assert retry_stats.event_queue_delivered == 1
        assert retry_stats.event_queue_retried == 1
        assert retry_stats.event_queue_dropped == 0
        assert retry_stats.event_relay_stats_generated == 1
    finally:
        await _quiet_cancel(worker)


async def test_best_effort_event_queue_overflow_is_counted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("chute.server._EVENT_QUEUE_MAX", 1)
    server = Server(
        token="secret",
        public_host="127.0.0.1",
        control_host="127.0.0.1",
        event_sink=_RecordingEventSink(),
    )
    stats = server._collect_relay_stats()

    assert await server._emit_event("relay_stats", stats)
    assert not await server._emit_event("relay_stats", stats)

    overflow_stats = server._collect_relay_stats()
    assert overflow_stats.event_queue_depth == 1
    assert overflow_stats.event_queue_capacity == 1
    assert overflow_stats.event_queue_enqueued == 1
    assert overflow_stats.event_queue_delivered == 0
    assert overflow_stats.event_queue_retried == 0
    assert overflow_stats.event_queue_dropped == 1
    assert overflow_stats.event_relay_stats_generated == 2


async def test_best_effort_event_queue_drop_after_retries_is_counted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("chute.server._EVENT_RETRY_ATTEMPTS", 2)
    monkeypatch.setattr("chute.server._EVENT_RETRY_DELAY", 0.01)
    server = Server(
        token="secret",
        public_host="127.0.0.1",
        control_host="127.0.0.1",
        event_sink=_FailingEventSink(),
    )
    worker = asyncio.ensure_future(server._run_event_queue())
    stats = server._collect_relay_stats()
    try:
        assert await server._emit_event("relay_stats", stats)
        await _eventually(lambda: server._collect_relay_stats().event_queue_dropped == 1)
        drop_stats = server._collect_relay_stats()
        assert drop_stats.event_queue_depth == 0
        assert drop_stats.event_queue_enqueued == 1
        assert drop_stats.event_queue_delivered == 0
        assert drop_stats.event_queue_retried == 1
        assert drop_stats.event_queue_dropped == 1
        assert drop_stats.event_relay_stats_generated == 1
    finally:
        await _quiet_cancel(worker)


@pytest.mark.parametrize(
    "hello",
    [
        {"token": "anything", "v": protocol.VERSION},
        {"type": "hello", "token": "anything", "v": protocol.VERSION},
        {"type": "auth", "token": 123, "v": protocol.VERSION},
    ],
)
async def test_malformed_auth_object_is_bad_handshake_before_authorizer(tmp_path, hello):
    authz = _CountingAuthorizer()
    async with _serve(tmp_path, authz) as (control_port, cert, _server):
        ctx = certs.client_ssl_context(cert)
        async with websockets.connect(
            f"wss://127.0.0.1:{control_port}", ssl=ctx, open_timeout=5
        ) as ws:
            await ws.send(json.dumps(hello))
            with pytest.raises(websockets.exceptions.ConnectionClosed):
                await asyncio.wait_for(ws.recv(), timeout=5)
            assert ws.close_code == 4000
    assert authz.calls == 0


async def test_protocol_version_mismatch_counts_as_failed_handshake(tmp_path):
    authz = _CountingAuthorizer()
    async with _serve(tmp_path, authz) as (control_port, cert, server):
        ctx = certs.client_ssl_context(cert)
        async with websockets.connect(
            f"wss://127.0.0.1:{control_port}", ssl=ctx, open_timeout=5
        ) as ws:
            await ws.send(json.dumps({"type": "auth", "token": "anything", "v": 999}))
            reply = json.loads(await asyncio.wait_for(ws.recv(), timeout=5))
            assert reply["type"] == "error"
            assert "protocol v" in reply["reason"]
            with pytest.raises(websockets.exceptions.ConnectionClosed):
                await asyncio.wait_for(ws.recv(), timeout=5)
            assert ws.close_code == 4004
        assert sum(len(failures) for failures in server._auth_fails.values()) == 1
    assert authz.calls == 0


async def test_malformed_flow_window_is_bad_handshake_before_authorizer(tmp_path):
    authz = _CountingAuthorizer()
    async with _serve(tmp_path, authz) as (control_port, cert, server):
        ctx = certs.client_ssl_context(cert)
        async with websockets.connect(
            f"wss://127.0.0.1:{control_port}", ssl=ctx, open_timeout=5
        ) as ws:
            await ws.send(
                json.dumps(
                    {
                        "type": "auth",
                        "token": "anything",
                        "flow_window": True,
                        "v": protocol.VERSION,
                    }
                )
            )
            with pytest.raises(websockets.exceptions.ConnectionClosed):
                await asyncio.wait_for(ws.recv(), timeout=5)
            assert ws.close_code == 4000
        assert sum(len(failures) for failures in server._auth_fails.values()) == 1
    assert authz.calls == 0


async def test_flow_window_negotiates_lower_preference_and_configures_mux(tmp_path):
    authz = _CountingAuthorizer()
    async with _serve(tmp_path, authz, mux_flow_window=1024) as (control_port, cert, server):
        ctx = certs.client_ssl_context(cert)
        async with websockets.connect(
            f"wss://127.0.0.1:{control_port}", ssl=ctx, open_timeout=5
        ) as ws:
            await ws.send(
                json.dumps(
                    {
                        "type": "auth",
                        "token": "anything",
                        "subdomain": "window",
                        "scheme": "https",
                        "flow_window": 512,
                        "v": protocol.VERSION,
                    }
                )
            )
            ready = json.loads(await asyncio.wait_for(ws.recv(), timeout=5))
            assert ready["type"] == "ready"
            assert ready["flow_window"] == 512
            assert server._agents["window"].mux.flow_window == 512


async def test_authorizer_receives_structured_request(tmp_path):
    authz = _CountingAuthorizer()
    async with _serve(tmp_path, authz) as (control_port, cert, _server):
        ctx = certs.client_ssl_context(cert)
        async with websockets.connect(
            f"wss://127.0.0.1:{control_port}", ssl=ctx, open_timeout=5
        ) as ws:
            await ws.send(
                json.dumps(
                    {
                        "type": "auth",
                        "token": "anything",
                        "subdomain": "structured",
                        "scheme": "https",
                        "v": protocol.VERSION,
                    }
                )
            )
            ready = json.loads(await asyncio.wait_for(ws.recv(), timeout=5))
            assert ready["type"] == "ready"
        assert authz.calls == 1
        request = authz.requests[0]
        assert request.token == "anything"
        assert request.requested_subdomain == "structured"
        assert request.agent_ip == "127.0.0.1"
        assert request.scheme == "https"
        assert request.protocol_version == protocol.VERSION


async def test_expired_control_plane_admission_is_retryable_and_not_registered(tmp_path):
    async with _serve(tmp_path, control_plane=_ExpiredControlPlane()) as (
        control_port,
        cert,
        server,
    ):
        ctx = certs.client_ssl_context(cert)
        async with websockets.connect(
            f"wss://127.0.0.1:{control_port}", ssl=ctx, open_timeout=5
        ) as ws:
            await ws.send(
                json.dumps(
                    {
                        "type": "auth",
                        "token": "anything",
                        "subdomain": "expired",
                        "scheme": "https",
                        "v": protocol.VERSION,
                    }
                )
            )
            with pytest.raises(websockets.exceptions.ConnectionClosed):
                await asyncio.wait_for(ws.recv(), timeout=5)
            assert ws.close_code == 1013
        assert "expired" not in server._agents


async def test_malformed_control_plane_admission_is_retryable_and_not_registered(tmp_path):
    async with _serve(tmp_path, control_plane=_MalformedAdmissionControlPlane()) as (
        control_port,
        cert,
        server,
    ):
        ctx = certs.client_ssl_context(cert)
        async with websockets.connect(
            f"wss://127.0.0.1:{control_port}", ssl=ctx, open_timeout=5
        ) as ws:
            await ws.send(
                json.dumps(
                    {
                        "type": "auth",
                        "token": "anything",
                        "subdomain": "malformed",
                        "scheme": "https",
                        "v": protocol.VERSION,
                    }
                )
            )
            with pytest.raises(websockets.exceptions.ConnectionClosed):
                await asyncio.wait_for(ws.recv(), timeout=5)
            assert ws.close_code == 1013
        assert "malformed" not in server._agents


async def test_finite_lease_is_renewed_in_background(tmp_path):
    cp = _RenewingControlPlane()
    async with _serve(tmp_path, control_plane=cp) as (control_port, cert, server):
        ctx = certs.client_ssl_context(cert)
        async with websockets.connect(
            f"wss://127.0.0.1:{control_port}", ssl=ctx, open_timeout=5
        ) as ws:
            await ws.send(
                json.dumps(
                    {
                        "type": "auth",
                        "token": "anything",
                        "subdomain": "renew",
                        "scheme": "https",
                        "v": protocol.VERSION,
                    }
                )
            )
            ready = json.loads(await asyncio.wait_for(ws.recv(), timeout=5))
            assert ready["type"] == "ready"

            await _eventually(
                lambda: (
                    bool(cp.renewals)
                    and "renew" in server._agents
                    and server._agents["renew"].lease_generation == 1
                    and server._lease_renewals_succeeded == 1
                )
            )
            assert server._agents["renew"].accepting_visitors is True
            assert server._agents["renew"].lease_expires_at is not None


async def test_failed_lease_renewal_keeps_tunnel_until_local_expiry(tmp_path):
    cp = _FailingRenewalControlPlane()
    async with _serve(tmp_path, control_plane=cp) as (control_port, cert, server):
        ctx = certs.client_ssl_context(cert)
        async with websockets.connect(
            f"wss://127.0.0.1:{control_port}", ssl=ctx, open_timeout=5
        ) as ws:
            await ws.send(
                json.dumps(
                    {
                        "type": "auth",
                        "token": "anything",
                        "subdomain": "failrenew",
                        "scheme": "https",
                        "v": protocol.VERSION,
                    }
                )
            )
            ready = json.loads(await asyncio.wait_for(ws.recv(), timeout=5))
            assert ready["type"] == "ready"

            await _eventually(lambda: bool(cp.renewals))
            assert server._lease_renewals_failed >= 1
            assert "failrenew" in server._agents
            await _eventually(lambda: "failrenew" not in server._agents, timeout=2.0)
            assert server._lease_expirations == 1


async def test_lease_renewal_none_revokes_tunnel_before_expiry(tmp_path):
    cp = _RevokingRenewalControlPlane()
    async with _serve(tmp_path, control_plane=cp) as (control_port, cert, server):
        ctx = certs.client_ssl_context(cert)
        async with websockets.connect(
            f"wss://127.0.0.1:{control_port}", ssl=ctx, open_timeout=5
        ) as ws:
            await ws.send(
                json.dumps(
                    {
                        "type": "auth",
                        "token": "anything",
                        "subdomain": "revoked",
                        "scheme": "https",
                        "v": protocol.VERSION,
                    }
                )
            )
            ready = json.loads(await asyncio.wait_for(ws.recv(), timeout=5))
            assert ready["type"] == "ready"

            await _eventually(lambda: bool(cp.renewals))
            await _eventually(lambda: "revoked" not in server._agents)
            assert server._lease_renewals_revoked == 1
            assert server._lease_revocations == 1


async def test_policy_update_poll_applies_budget_update_for_live_tunnel(tmp_path):
    cp = _PolicyUpdateControlPlane(
        PolicyUpdate(
            version=1,
            account_budgets=(AccountBudgetUpdate("A", Budget(max_visitors=0)),),
        )
    )
    async with _serve(tmp_path, control_plane=cp, policy_poll_interval=0.05) as (
        control_port,
        cert,
        server,
    ):
        ctx = certs.client_ssl_context(cert)
        async with websockets.connect(
            f"wss://127.0.0.1:{control_port}", ssl=ctx, open_timeout=5
        ) as ws:
            await ws.send(
                json.dumps(
                    {
                        "type": "auth",
                        "token": "anything",
                        "subdomain": "policy",
                        "scheme": "https",
                        "v": protocol.VERSION,
                    }
                )
            )
            ready = json.loads(await asyncio.wait_for(ws.recv(), timeout=5))
            assert ready["type"] == "ready"

            await _eventually(
                lambda: (
                    "policy" in server._agents
                    and server._agents["policy"].budget.max_visitors == 0
                    and server._policy_version == 1
                    and server._policy_updates_applied == 1
                ),
                timeout=2.0,
            )
            assert any("policy-lease" in request.active_lease_ids for request in cp.requests)


async def test_reconnect_budget_rejects_retryable_before_registration(tmp_path):
    cp = _ReconnectLimitedControlPlane(limit=1)
    sink = _RecordingEventSink()
    async with _serve(
        tmp_path,
        control_plane=cp,
        event_sink=sink,
        policy_poll_interval=0,
    ) as (control_port, cert, server):
        ctx = certs.client_ssl_context(cert)
        async with websockets.connect(
            f"wss://127.0.0.1:{control_port}", ssl=ctx, open_timeout=5
        ) as first:
            await first.send(
                json.dumps(
                    {
                        "type": "auth",
                        "token": "anything",
                        "subdomain": "first",
                        "scheme": "https",
                        "v": protocol.VERSION,
                    }
                )
            )
            ready = json.loads(await asyncio.wait_for(first.recv(), timeout=5))
            assert ready["type"] == "ready"

            async with websockets.connect(
                f"wss://127.0.0.1:{control_port}", ssl=ctx, open_timeout=5
            ) as second:
                await second.send(
                    json.dumps(
                        {
                            "type": "auth",
                            "token": "anything",
                            "subdomain": "second",
                            "scheme": "https",
                            "v": protocol.VERSION,
                        }
                    )
                )
                with pytest.raises(websockets.exceptions.ConnectionClosed):
                    await asyncio.wait_for(second.recv(), timeout=5)
                assert second.close_code == 1013

            assert cp.admissions == 2
            assert "first" in server._agents
            assert "second" not in server._agents
            await _eventually(lambda: bool(sink.auth_rejected_events))
            assert sink.auth_rejected_events[-1].reason == "reconnect_limit"
            assert sink.auth_rejected_events[-1].account_id == "A"


@contextlib.asynccontextmanager
async def _serve(tmp_path, authorizer=None, **server_kwargs):
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    certs.generate("127.0.0.1", cert, key)
    control_port = _free_port()
    kwargs = {
        "token": "unused-when-authorizer-given",
        "public_host": "127.0.0.1",
        "public_port": _free_port(),
        "control_host": "127.0.0.1",
        "control_port": control_port,
        "ssl_context": certs.server_ssl_context(cert, key),
        "base_domain": BASE,
        "upstream_tls": True,
        **server_kwargs,
    }
    if authorizer is not None:
        kwargs["authorizer"] = authorizer
    server = Server(**kwargs)
    task = asyncio.ensure_future(server.serve())
    await asyncio.sleep(0.3)
    try:
        yield control_port, cert, server
    finally:
        await _quiet_cancel(task)


def _agent(control_port, cert, token, subdomain=None) -> Tunnel:
    return Tunnel(
        server="127.0.0.1",
        token=token,
        local_port=_free_port(),
        control_port=control_port,
        server_cert=str(cert),
        subdomain=subdomain,
    )


async def test_cross_account_label_is_rejected_end_to_end(tmp_path):
    authz = _MappingAuthorizer(
        {
            "tok-A": AuthResult(account_id="A", max_tunnels=10),
            "tok-B": AuthResult(account_id="B", max_tunnels=10),
        }
    )
    async with _serve(tmp_path, authz) as (control_port, cert, _server):
        a = _agent(control_port, cert, "tok-A", subdomain="shared")
        a_task = asyncio.ensure_future(a.serve_forever())
        await a.wait_until_ready(timeout=5)

        # A different account asking for A's live label is rejected (fatal).
        b = _agent(control_port, cert, "tok-B", subdomain="shared")
        with pytest.raises(Exception):
            await asyncio.wait_for(b.serve_forever(), timeout=5)

        # A is untouched. https:// because the default scheme is https and this
        # server advertises upstream TLS (upstream_tls=True).
        assert a.public_url == "https://shared.tun.test/"
        await a.aclose()
        await _quiet_cancel(a_task)


async def test_tunnel_lifecycle_events_are_emitted_end_to_end(tmp_path):
    sink = _RecordingEventSink()
    authz = _MappingAuthorizer(
        {"tok-A": AuthResult(account_id="A", max_tunnels=10, credential_id="token-1")}
    )
    async with _serve(tmp_path, authz, event_sink=sink) as (control_port, cert, _server):
        agent = _agent(control_port, cert, "tok-A", subdomain="events")
        agent_task = asyncio.ensure_future(agent.serve_forever())
        await agent.wait_until_ready(timeout=5)

        await _eventually(lambda: len(sink.tunnel_opened_events) == 1)
        assert len(sink.tunnel_opened_events) == 1
        opened = sink.tunnel_opened_events[0]
        assert opened.label == "events"
        assert opened.account_id == "A"
        assert opened.credential_id == "token-1"
        assert opened.public_url == "https://events.tun.test/"
        assert opened.agent_ip == "127.0.0.1"
        assert opened.lease_id

        await agent.aclose()
        await _quiet_cancel(agent_task)
        await _eventually(lambda: len(sink.tunnel_closed_events) == 1)
        closed = sink.tunnel_closed_events[0]
        assert closed.connection_id == opened.connection_id
        assert closed.label == opened.label
        assert closed.account_id == opened.account_id
        assert closed.credential_id == opened.credential_id
        assert closed.lease_id == opened.lease_id


async def test_static_policy_control_plane_admits_agent_end_to_end(tmp_path):
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "credentials": [
                    {
                        "credential_id": "cred-policy",
                        "token_sha256": hashlib.sha256(b"policy-token").hexdigest(),
                        "account_id": "A",
                        "allowed_label": "policyfile",
                        "max_tunnels": 1,
                        "budget": {"max_visitors": 3},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    policy_file.chmod(0o600)
    cp = StaticPolicyControlPlane(policy_file)

    async with _serve(tmp_path, control_plane=cp) as (control_port, cert, server):
        agent = _agent(control_port, cert, "policy-token", subdomain="policyfile")
        agent_task = asyncio.ensure_future(agent.serve_forever())
        await agent.wait_until_ready(timeout=5)

        registration = server._agents["policyfile"]
        assert registration.account_id == "A"
        assert registration.credential_id == "cred-policy"
        assert registration.budget.max_visitors == 3
        assert server._account_labels["A"] == {"policyfile"}

        await agent.aclose()
        await _quiet_cancel(agent_task)


async def test_visitor_requests_do_not_call_control_plane(tmp_path):
    class _CountingControlPlane:
        def __init__(self) -> None:
            self.admissions = 0
            self.renewals = 0
            self.polls = 0

        async def admit_tunnel(self, request):
            self.admissions += 1
            return TunnelAdmission(
                lease=TunnelLease(
                    lease_id="hotpath-lease",
                    account_id="A",
                    credential_id="cred-hotpath",
                ),
                max_tunnels=10,
            )

        async def renew_lease(self, request):
            self.renewals += 1
            return None

        async def poll_policy_updates(self, request):
            self.polls += 1
            return None

    async def handle_local(reader, writer):
        await reader.readuntil(b"\r\n\r\n")
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    async def visitor_get(port: int, path: str) -> bytes:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        request = f"GET {path} HTTP/1.1\r\nHost: hotpath.{BASE}\r\nConnection: close\r\n\r\n"
        writer.write(request.encode())
        await writer.drain()
        response = await asyncio.wait_for(reader.read(), timeout=5)
        writer.close()
        await writer.wait_closed()
        return response

    local = await asyncio.start_server(handle_local, "127.0.0.1", 0)
    local_port = local.sockets[0].getsockname()[1]
    cp = _CountingControlPlane()
    async with _serve(tmp_path, control_plane=cp, policy_poll_interval=0) as (
        control_port,
        cert,
        server,
    ):
        agent = Tunnel(
            server="127.0.0.1",
            token="anything",
            local_port=local_port,
            control_port=control_port,
            server_cert=str(cert),
            subdomain="hotpath",
        )
        agent_task = asyncio.ensure_future(agent.serve_forever())
        try:
            await agent.wait_until_ready(timeout=5)
            before = (cp.admissions, cp.renewals, cp.polls)

            for index in range(3):
                response = await visitor_get(server.public_port, f"/{index}")
                assert b"200 OK" in response
                assert response.endswith(b"ok")

            assert (cp.admissions, cp.renewals, cp.polls) == before
        finally:
            await agent.aclose()
            await _quiet_cancel(agent_task)
            local.close()
            await local.wait_closed()


async def test_admitted_tunnel_wires_account_buffer_budget(tmp_path):
    authz = _MappingAuthorizer(
        {
            "tok-A": AuthResult(
                account_id="A",
                max_tunnels=10,
                budget=Budget(max_buffered_bytes=3),
            )
        }
    )
    async with _serve(tmp_path, authz) as (control_port, cert, server):
        agent = _agent(control_port, cert, "tok-A", subdomain="buffered")
        agent_task = asyncio.ensure_future(agent.serve_forever())
        await agent.wait_until_ready(timeout=5)

        registration = server._agents["buffered"]
        assert registration.mux._reserve_buffer(3) is True
        assert server._account_buffered["A"] == 3
        assert registration.mux._reserve_buffer(1) is False
        assert server._account_buffered["A"] == 3
        registration.mux._release_buffer(3)
        assert "A" not in server._account_buffered

        await agent.aclose()
        await _quiet_cancel(agent_task)


async def test_required_tunnel_open_event_failure_is_retryable(tmp_path):
    sink = _RecordingEventSink(fail_tunnel_opened=True)
    authz = _MappingAuthorizer({"tok-A": AuthResult(account_id="A", max_tunnels=10)})
    async with _serve(tmp_path, authz, event_sink=sink, require_event_sink=True) as (
        control_port,
        cert,
        server,
    ):
        ctx = certs.client_ssl_context(cert)
        async with websockets.connect(
            f"wss://127.0.0.1:{control_port}", ssl=ctx, open_timeout=5
        ) as ws:
            await ws.send(
                json.dumps(
                    {
                        "type": "auth",
                        "token": "tok-A",
                        "subdomain": "events",
                        "v": protocol.VERSION,
                    }
                )
            )
            with pytest.raises(websockets.exceptions.ConnectionClosed):
                await asyncio.wait_for(ws.recv(), timeout=5)
            assert ws.close_code == 1013
        assert "events" not in server._agents


async def test_required_tunnel_open_event_wait_does_not_block_unrelated_registration(tmp_path):
    sink = _BlockFirstTunnelOpenedSink()
    authz = _MappingAuthorizer(
        {
            "tok-A": AuthResult(account_id="A", max_tunnels=10),
            "tok-B": AuthResult(account_id="B", max_tunnels=10),
        }
    )
    async with _serve(
        tmp_path,
        authz,
        event_sink=sink,
        event_timeout=5,
        require_event_sink=True,
    ) as (control_port, cert, server):
        blocked = _agent(control_port, cert, "tok-A", subdomain="blocked")
        blocked_task = asyncio.ensure_future(blocked.serve_forever())
        await asyncio.wait_for(sink.started.wait(), timeout=2)

        other = _agent(control_port, cert, "tok-B", subdomain="other")
        other_task = asyncio.ensure_future(other.serve_forever())
        await other.wait_until_ready(timeout=2)

        assert other.public_url == "https://other.tun.test/"
        assert "other" in server._agents
        assert "blocked" in server._pending_agents

        sink.release.set()
        await blocked.wait_until_ready(timeout=2)

        await other.aclose()
        await blocked.aclose()
        await _quiet_cancel(other_task, blocked_task)


async def test_policy_update_can_revoke_pending_tunnel_before_ready(tmp_path):
    sink = _BlockFirstTunnelOpenedSink()
    cp = _PolicyUpdateControlPlane(
        PolicyUpdate(
            version=1,
            lease_revocations=(LeaseRevocation("policy-lease", action="close"),),
        )
    )
    async with _serve(
        tmp_path,
        control_plane=cp,
        event_sink=sink,
        event_timeout=5,
        require_event_sink=True,
        policy_poll_interval=0.05,
    ) as (control_port, cert, server):
        ctx = certs.client_ssl_context(cert)
        async with websockets.connect(
            f"wss://127.0.0.1:{control_port}", ssl=ctx, open_timeout=5
        ) as ws:
            try:
                await ws.send(
                    json.dumps(
                        {
                            "type": "auth",
                            "token": "anything",
                            "subdomain": "blocked",
                            "scheme": "https",
                            "v": protocol.VERSION,
                        }
                    )
                )
                await asyncio.wait_for(sink.started.wait(), timeout=2)

                await _eventually(
                    lambda: (
                        server._lease_revocations == 1
                        and "blocked" not in server._pending_agents
                        and "blocked" not in server._agents
                    ),
                    timeout=2.0,
                )
                assert any("policy-lease" in request.active_lease_ids for request in cp.requests)
                assert server._pending_lease_labels == {}

                with pytest.raises(websockets.exceptions.ConnectionClosed):
                    await asyncio.wait_for(ws.recv(), timeout=2)
                assert ws.close_code == 1013
            finally:
                sink.release.set()

        await _eventually(
            lambda: len(sink.tunnel_opened_events) == 1 and len(sink.tunnel_closed_events) == 1
        )
        opened = sink.tunnel_opened_events[0]
        closed = sink.tunnel_closed_events[0]
        assert opened.connection_id == closed.connection_id
        assert opened.lease_id == "policy-lease"
        assert closed.lease_id == "policy-lease"


def test_required_event_sink_rejects_noop_default() -> None:
    with pytest.raises(ValueError, match="configured event sink"):
        Server(token="secret", require_event_sink=True)


async def test_required_tunnel_open_event_failure_does_not_hide_existing_tunnel(tmp_path):
    sink = _RecordingEventSink()
    authz = _MappingAuthorizer({"tok-A": AuthResult(account_id="A", max_tunnels=10)})
    async with _serve(tmp_path, authz, event_sink=sink, require_event_sink=True) as (
        control_port,
        cert,
        server,
    ):
        agent = _agent(control_port, cert, "tok-A", subdomain="events")
        agent_task = asyncio.ensure_future(agent.serve_forever())
        await agent.wait_until_ready(timeout=5)

        existing = server._agents["events"]
        assert existing.accepting_visitors is True

        sink.fail_tunnel_opened = True
        ctx = certs.client_ssl_context(cert)
        async with websockets.connect(
            f"wss://127.0.0.1:{control_port}", ssl=ctx, open_timeout=5
        ) as ws:
            await ws.send(
                json.dumps(
                    {
                        "type": "auth",
                        "token": "tok-A",
                        "subdomain": "events",
                        "scheme": "https",
                        "v": protocol.VERSION,
                    }
                )
            )
            with pytest.raises(websockets.exceptions.ConnectionClosed):
                await asyncio.wait_for(ws.recv(), timeout=5)
            assert ws.close_code == 1013

        assert server._agents["events"] is existing
        assert existing.accepting_visitors is True

        await agent.aclose()
        await _quiet_cancel(agent_task)


async def test_global_agent_cap_is_retryable_and_does_not_grow_registry(tmp_path):
    sink = _RecordingEventSink()
    authz = _MappingAuthorizer(
        {
            "tok-A": AuthResult(account_id="A", max_tunnels=10),
            "tok-B": AuthResult(account_id="B", max_tunnels=10),
        }
    )
    async with _serve(tmp_path, authz, event_sink=sink, max_agents=1) as (
        control_port,
        cert,
        server,
    ):
        first = _agent(control_port, cert, "tok-A", subdomain="first")
        first_task = asyncio.ensure_future(first.serve_forever())
        await first.wait_until_ready(timeout=5)

        ctx = certs.client_ssl_context(cert)
        async with websockets.connect(
            f"wss://127.0.0.1:{control_port}", ssl=ctx, open_timeout=5
        ) as ws:
            await ws.send(
                json.dumps(
                    {
                        "type": "auth",
                        "token": "tok-B",
                        "subdomain": "second",
                        "scheme": "https",
                        "v": protocol.VERSION,
                    }
                )
            )
            with pytest.raises(websockets.exceptions.ConnectionClosed):
                await asyncio.wait_for(ws.recv(), timeout=5)
            assert ws.close_code == 1013

        assert set(server._agents) == {"first"}
        await _eventually(lambda: bool(sink.auth_rejected_events))
        assert sink.auth_rejected_events[-1].reason == "server_tunnel_limit"
        assert sink.auth_rejected_events[-1].account_id == "B"

        first_replacement = _agent(control_port, cert, "tok-A", subdomain="first")
        replacement_task = asyncio.ensure_future(first_replacement.serve_forever())
        await first_replacement.wait_until_ready(timeout=5)
        assert set(server._agents) == {"first"}

        await first.aclose()
        await first_replacement.aclose()
        await _quiet_cancel(first_task, replacement_task)


async def test_agent_goaway_remains_registered_for_accounting_until_disconnect(tmp_path):
    authz = _MappingAuthorizer({"tok-A": AuthResult(account_id="A", max_tunnels=1)})
    async with _serve(tmp_path, authz) as (control_port, cert, server):
        ctx = certs.client_ssl_context(cert)
        async with websockets.connect(
            f"wss://127.0.0.1:{control_port}", ssl=ctx, open_timeout=5
        ) as ws:
            await ws.send(
                json.dumps(
                    {
                        "type": "auth",
                        "token": "tok-A",
                        "subdomain": "beta",
                        "v": protocol.VERSION,
                    }
                )
            )
            ready = json.loads(await asyncio.wait_for(ws.recv(), timeout=5))
            assert ready["type"] == "ready"

            await ws.send(protocol.encode(protocol.GOAWAY, 0, b""))
            await _eventually(
                lambda: "beta" in server._agents and server._agents["beta"].mux.draining
            )

            mux = server._agents["beta"].mux
            assert server._account_labels["A"] == {"beta"}
            assert server._live_muxes() == [mux]
            with pytest.raises(_LabelError) as exc:
                server._authorize_claim(AuthResult(account_id="A", max_tunnels=1), "other")
            assert str(exc.value) == "tunnel_limit"
            assert (
                server._select_agent_for_visitor(b"GET / HTTP/1.1\r\nHost: beta.tun.test\r\n\r\n")
                is None
            )

        await _eventually(lambda: "beta" not in server._agents)


async def test_unavailable_authorizer_is_retryable_not_fatal(tmp_path):
    async with _serve(tmp_path, _RaisingAuthorizer()) as (control_port, cert, _server):
        t = _agent(control_port, cert, "anything")
        # The authorizer raises -> server closes 1013 -> the agent backs off and
        # retries rather than raising _FatalError, so serve_forever never returns.
        # A fatal close would propagate instead of timing out.
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(t.serve_forever(), timeout=2.5)
        await t.aclose()


async def test_non_string_subdomain_is_bad_handshake_before_authorizer(tmp_path):
    authz = _CountingAuthorizer()
    async with _serve(tmp_path, authz) as (control_port, cert, _server):
        ctx = certs.client_ssl_context(cert)
        async with websockets.connect(
            f"wss://127.0.0.1:{control_port}", ssl=ctx, open_timeout=5
        ) as ws:
            await ws.send(
                json.dumps(
                    {
                        "type": "auth",
                        "token": "anything",
                        "subdomain": 123,
                        "v": protocol.VERSION,
                    }
                )
            )
            with pytest.raises(websockets.exceptions.ConnectionClosed):
                await asyncio.wait_for(ws.recv(), timeout=5)
            assert ws.close_code == 4000
    assert authz.calls == 0


async def test_invalid_subdomain_is_rejected_before_authorizer(tmp_path):
    authz = _CountingAuthorizer()
    async with _serve(tmp_path, authz) as (control_port, cert, server):
        ctx = certs.client_ssl_context(cert)
        async with websockets.connect(
            f"wss://127.0.0.1:{control_port}", ssl=ctx, open_timeout=5
        ) as ws:
            await ws.send(
                json.dumps(
                    {
                        "type": "auth",
                        "token": "anything",
                        "subdomain": "bad_label",
                        "v": protocol.VERSION,
                    }
                )
            )
            reply = json.loads(await asyncio.wait_for(ws.recv(), timeout=5))
            assert reply["type"] == "error"
            assert reply["reason"] == "invalid_subdomain"
            with pytest.raises(websockets.exceptions.ConnectionClosed):
                await asyncio.wait_for(ws.recv(), timeout=5)
            assert ws.close_code == 4002
    assert authz.calls == 0
    assert sum(len(failures) for failures in server._auth_fails.values()) == 1


async def test_hanging_authorizer_is_retryable_and_timeout_bounded(tmp_path):
    authz = _HangingAuthorizer()
    async with _serve(tmp_path, authz, auth_timeout=0.2) as (control_port, cert, _server):
        t = _agent(control_port, cert, "anything")
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(t.serve_forever(), timeout=1.0)
        assert authz.calls >= 1
        await t.aclose()


async def test_auth_concurrency_cap_is_bounded(tmp_path):
    authz = _CountingAuthorizer()
    async with _serve(tmp_path, authz, auth_timeout=0.2, max_auth_conns=1) as (
        control_port,
        cert,
        server,
    ):
        await server._auth_sem.acquire()
        try:
            ctx = certs.client_ssl_context(cert)
            async with websockets.connect(
                f"wss://127.0.0.1:{control_port}", ssl=ctx, open_timeout=5
            ) as ws:
                await ws.send(
                    json.dumps({"type": "auth", "token": "anything", "v": protocol.VERSION})
                )
                with pytest.raises(websockets.exceptions.ConnectionClosed):
                    await asyncio.wait_for(ws.recv(), timeout=5)
                assert ws.close_code == 1013
            assert authz.calls == 0
            assert server._auth_busy == 1
        finally:
            server._auth_sem.release()
