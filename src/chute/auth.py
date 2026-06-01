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
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

__all__ = ["UNLIMITED_TUNNELS", "AuthResult", "Authorizer", "StaticTokenAuthorizer"]

# The single-tenant default: no per-account tunnel cap. Large but finite so callers
# can compare/relational-test it without special-casing math.inf. An alternative
# authorizer can return a real per-account limit (e.g. 3) instead.
UNLIMITED_TUNNELS = 1 << 62


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
    """

    account_id: str
    max_tunnels: int = UNLIMITED_TUNNELS
    allowed_label: str | None = None


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
        if hmac.compare_digest(str(token), self._token):
            return AuthResult(account_id="0")
        return None
