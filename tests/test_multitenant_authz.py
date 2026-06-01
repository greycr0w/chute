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
import socket

import pytest

from chute import certs
from chute.auth import UNLIMITED_TUNNELS, AuthResult
from chute.client import Tunnel
from chute.server import Server, _LabelError

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
    """Identity stand-in for a Mux in the routing map (only `is` identity matters)."""


# --------------------------------------------------------------------------- #
# P1.1 / P1.2 -- _authorize_claim (synchronous, await-free)
# --------------------------------------------------------------------------- #


def test_free_label_is_claimable():
    _server()._authorize_claim("A", "free", UNLIMITED_TUNNELS)  # no raise


def test_label_held_by_another_account_is_rejected():
    s = _server()
    s._agents["shared"] = (_FakeMux(), "A")
    s._account_labels["A"] = {"shared"}
    with pytest.raises(_LabelError) as exc:
        s._authorize_claim("B", "shared", UNLIMITED_TUNNELS)
    assert str(exc.value) == "subdomain_taken"


def test_same_account_may_reclaim_its_own_label_even_at_cap():
    s = _server()
    s._agents["mine"] = (_FakeMux(), "A")
    s._account_labels["A"] = {"mine"}
    s._authorize_claim("A", "mine", 1)  # reclaim is exempt from the cap -> no raise


def test_concurrency_cap_rejects_a_new_label_over_the_limit():
    s = _server()
    s._account_labels["A"] = {"a", "b", "c"}
    with pytest.raises(_LabelError) as exc:
        s._authorize_claim("A", "d", 3)
    assert str(exc.value) == "tunnel_limit"


def test_reclaim_does_not_count_against_the_cap():
    s = _server()
    s._agents["a"] = (_FakeMux(), "A")
    s._account_labels["A"] = {"a", "b", "c"}
    s._authorize_claim("A", "a", 3)  # reclaiming "a" at cap 3 is fine -> no raise


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


@contextlib.asynccontextmanager
async def _serve(tmp_path, authorizer):
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
    )
    task = asyncio.ensure_future(server.serve())
    await asyncio.sleep(0.3)
    try:
        yield control_port, cert
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
    async with _serve(tmp_path, authz) as (control_port, cert):
        a = _agent(control_port, cert, "tok-A", subdomain="shared")
        a_task = asyncio.ensure_future(a.serve_forever())
        await a.wait_until_ready(timeout=5)

        # A different account asking for A's live label is rejected (fatal).
        b = _agent(control_port, cert, "tok-B", subdomain="shared")
        with pytest.raises(Exception):
            await asyncio.wait_for(b.serve_forever(), timeout=5)

        assert a.public_url == "http://shared.tun.test/"  # A is untouched
        await a.aclose()
        await _quiet_cancel(a_task)


async def test_unavailable_authorizer_is_retryable_not_fatal(tmp_path):
    async with _serve(tmp_path, _RaisingAuthorizer()) as (control_port, cert):
        t = _agent(control_port, cert, "anything")
        # The authorizer raises -> server closes 1013 -> the agent backs off and
        # retries rather than raising _FatalError, so serve_forever never returns.
        # A fatal close would propagate instead of timing out.
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(t.serve_forever(), timeout=2.5)
        await t.aclose()
