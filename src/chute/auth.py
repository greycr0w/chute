"""Pluggable authorization for the control channel.

The relay calls a single ``Authorizer.authenticate`` once per agent connect and is
otherwise a dumb byte pipe. This is the relay's one extension point for alternative
authorization strategies: the default :class:`StaticTokenAuthorizer` preserves
chute's original single-shared-token behavior, so a self-hoster keeps a working tool
with no database, while an alternative authorizer -- for example a database-backed
one that maps tokens to accounts -- can be injected at runtime via the
``CHUTE_AUTHORIZER`` env knob without changing the relay.

``authenticate`` is ``async`` because a database-backed authorizer does I/O
(e.g. asyncpg); the static one just returns a constant.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

__all__ = ["UNLIMITED_TUNNELS", "AuthResult", "Authorizer", "Budget", "StaticTokenAuthorizer"]

# The single-tenant default: no per-account tunnel cap. Large but finite so callers
# can compare/relational-test it without special-casing math.inf. An alternative
# authorizer can return a real per-account limit (e.g. 3) instead.
UNLIMITED_TUNNELS = 1 << 62


@dataclass(frozen=True, slots=True)
class Budget:
    """Per-account resource budget an :class:`Authorizer` may attach to an
    :class:`AuthResult`. ``None`` on a field means *unlimited*; the all-``None``
    default preserves single-tenant behaviour.

    chute can only enforce **transport-level** budgets. It is a byte-transparent pipe,
    not a WAF -- application facts (failed-request rates, per-route abuse) are invisible
    to it and belong to the app behind the tunnel, so they are deliberately NOT here.

    ENFORCED today (the relay checks these):

    - ``max_visitors`` -- max concurrent visitor streams summed across all of the
      account's live tunnels. Admission past it is refused (503).

    RESERVED -- an authorizer MAY set these and a future relay will honour them, but
    they are **not enforced yet**; do not rely on them as a control:

    - ``max_bytes_per_sec``      -- aggregate relayed bandwidth per account.
    - ``max_reconnects_per_min`` -- control-channel reconnect rate per account.
    - ``max_buffered_bytes``     -- aggregate in-flight memory per account (today
      bounded only indirectly by ``max_tunnels`` × the per-connection memory cap).
    """

    max_visitors: int | None = None  # ENFORCED
    max_bytes_per_sec: int | None = None  # reserved (not yet enforced)
    max_reconnects_per_min: int | None = None  # reserved (not yet enforced)
    max_buffered_bytes: int | None = None  # reserved (not yet enforced)


@dataclass(frozen=True, slots=True)
class AuthResult:
    """What an authenticated agent may do. Returned by :meth:`Authorizer.authenticate`;
    ``None`` from that call means *rejected*.

    - ``account_id``  -- the owning account (``"0"`` is the single-tenant/bootstrap
      account). A string so an alternative authorizer can use whatever id shape fits.
    - ``max_tunnels`` -- how many concurrent tunnels this account may hold; an
      authorizer that enforces limits sets it (the relay can compare against it).
    - ``allowed_label`` -- a label this account may always claim (a reserved name),
      or ``None`` for no special grant.
    - ``budget`` -- per-account resource :class:`Budget` (default: unlimited). The
      relay enforces the transport-level fields it can; see :class:`Budget`.
    """

    account_id: str
    max_tunnels: int = UNLIMITED_TUNNELS
    allowed_label: str | None = None
    budget: Budget = field(default_factory=Budget)


@runtime_checkable
class Authorizer(Protocol):
    """One async call per agent connect: "which account is this token, and what may
    it do?" Implementations must tolerate concurrent calls. They must not assume the
    relay holds any lock -- it deliberately authorizes outside its pre-auth semaphore.
    """

    async def authenticate(
        self, token: str, requested_subdomain: str | None, agent_ip: str | None
    ) -> AuthResult | None: ...


class StaticTokenAuthorizer:
    """The default: one shared secret gates one effectively-unbounded tenant.

    This is exactly chute's original behavior -- a constant-time compare against the
    configured token -- repackaged behind the :class:`Authorizer` seam so the relay
    has a single code path. No accounts, no database, no per-account limits.
    """

    def __init__(self, token: str) -> None:
        self._token = token

    async def authenticate(
        self, token: str, requested_subdomain: str | None, agent_ip: str | None
    ) -> AuthResult | None:
        # Constant-time compare, identical to the inline check the server used
        # before. requested_subdomain/agent_ip are irrelevant to a single shared
        # token; the relay still does its own label assignment downstream.
        # Compare as bytes: hmac.compare_digest raises TypeError on a non-ASCII
        # str, and the server's blanket except would mistake that crash for
        # "authorizer unavailable" (retryable 1013) -- bypassing the failed-auth
        # limiter on any Unicode token. encode() makes a bad token a clean reject.
        if hmac.compare_digest(str(token).encode(), self._token.encode()):
            return AuthResult(account_id="0")
        return None
