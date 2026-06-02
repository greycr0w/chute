"""Account-aware relay primitives: cross-account label ownership, per-account
concurrency caps, the per-IP failed-auth limiter, and retryable-vs-fatal auth.

The single shared token (StaticTokenAuthorizer) maps every agent to account "0"
with no cap, so these behaviors only surface once an authorizer hands out distinct
accounts/limits -- which is exactly what the fakes here do. The pure-logic cases
poke the Server's synchronous decision methods directly (no sockets); two
integration cases drive the real WSS handshake end-to-end.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import socket

import pytest
import websockets

from chute import certs, protocol
from chute.auth import AuthResult, Budget
from chute.client import Tunnel
from chute.server import Server, TunnelRegistration, _LabelError

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


def _server() -> Server:
    # Nothing binds until serve(); safe to construct for synchronous unit tests.
    return Server(
        token="secret", base_domain=BASE, public_host="127.0.0.1", control_host="127.0.0.1"
    )


class _FakeMux:
    """Identity stand-in for a Mux in the routing map (`is` identity + a stream count)."""

    def __init__(self, active_streams: int = 0) -> None:
        self.active_streams = active_streams


def _reg(account_id: str, active_streams: int = 0, budget: Budget | None = None):
    return TunnelRegistration(_FakeMux(active_streams), account_id, budget or Budget())


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
# Budget.max_visitors -- per-account concurrent-visitor cap (synchronous decision)
# --------------------------------------------------------------------------- #


def test_account_active_streams_sums_across_an_accounts_tunnels():
    s = _server()
    s._agents["a"] = _reg("A", active_streams=3)
    s._agents["b"] = _reg("A", active_streams=2)
    s._agents["c"] = _reg("B", active_streams=9)
    s._account_labels["A"] = {"a", "b"}
    s._account_labels["B"] = {"c"}
    assert s._account_active_streams("A") == 5  # summed across A's two tunnels
    assert s._account_active_streams("B") == 9
    assert s._account_active_streams("nobody") == 0


def test_visitor_budget_blocks_only_over_max_visitors():
    s = _server()
    s._agents["a"] = _reg("A", active_streams=2, budget=Budget(max_visitors=2))
    s._account_labels["A"] = {"a"}
    assert s._visitor_budget_exceeded(s._agents["a"]) is True
    s._agents["a"] = _reg("A", active_streams=2, budget=Budget(max_visitors=3))
    assert s._visitor_budget_exceeded(s._agents["a"]) is False
    s._agents["a"] = _reg("A", active_streams=2, budget=Budget())
    assert s._visitor_budget_exceeded(s._agents["a"]) is False


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

    async def authenticate(self, token, requested_subdomain, agent_ip):
        return self._mapping.get(token)


class _RaisingAuthorizer:
    async def authenticate(self, token, requested_subdomain, agent_ip):
        raise RuntimeError("authorizer unavailable (e.g. DB down)")


class _HangingAuthorizer:
    def __init__(self) -> None:
        self.calls = 0

    async def authenticate(self, token, requested_subdomain, agent_ip):
        self.calls += 1
        await asyncio.Event().wait()


class _CountingAuthorizer:
    def __init__(self) -> None:
        self.calls = 0

    async def authenticate(self, token, requested_subdomain, agent_ip):
        self.calls += 1
        return AuthResult(account_id="A")


@contextlib.asynccontextmanager
async def _serve(tmp_path, authorizer, **server_kwargs):
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    certs.generate("127.0.0.1", cert, key)
    control_port = _free_port()
    server = Server(
        token="unused-when-authorizer-given",
        public_host="127.0.0.1",
        public_port=_free_port(),
        control_host="127.0.0.1",
        control_port=control_port,
        ssl_context=certs.server_ssl_context(cert, key),
        base_domain=BASE,
        upstream_tls=True,
        authorizer=authorizer,
        **server_kwargs,
    )
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
        finally:
            server._auth_sem.release()
