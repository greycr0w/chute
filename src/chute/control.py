"""Control-plane primitives for chute's relay.

The relay is the data plane: it owns sockets, the active tunnel registry, mux
streams, and local enforcement. A control plane decides whether a tunnel may
exist and what transport budget applies. The default control plane wraps the
existing static-token authorizer, so standalone chute stays fully functional
without a database or hosted service.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import hmac
import json
import logging
import os
import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, Protocol, runtime_checkable

from ._files import PrivateFileFingerprint, read_private_text_file_snapshot
from .auth import (
    UNLIMITED_TUNNELS,
    Authorizer,
    AuthRequest,
    AuthResult,
    Budget,
    StaticTokenAuthorizer,
)
from .names import valid_label

log = logging.getLogger("chute.control")

__all__ = [
    "AccountBudgetUpdate",
    "AuthorizerControlPlane",
    "ControlPlane",
    "LeaseRevocation",
    "LeaseRenewalRequest",
    "PolicyUpdate",
    "PolicyUpdateRequest",
    "RevocationAction",
    "StaticPolicyControlPlane",
    "StaticTokenControlPlane",
    "TunnelAdmission",
    "TunnelAdmissionRequest",
    "TunnelLease",
    "token_sha256",
    "validate_static_policy_file",
]

RevocationAction = Literal["drain", "close"]
_POLICY_SCHEMA_VERSION = 1
_BUDGET_FIELDS = frozenset(
    {
        "max_visitors",
        "max_bytes_per_sec",
        "max_reconnects_per_min",
        "max_buffered_bytes",
    }
)
_MAX_POLICY_FILE_BYTES = 1024 * 1024
_MAX_POLICY_CREDENTIALS = 4096
_MAX_POLICY_REVOKE_LEASE_IDS = 10000
_MAX_POLICY_LEASE_REVOCATIONS = 10000
_MAX_POLICY_ACCOUNT_BUDGETS = 4096


@dataclass(frozen=True, slots=True)
class TunnelAdmissionRequest:
    """Facts the relay knows before accepting an agent tunnel."""

    token: str
    requested_subdomain: str | None
    agent_ip: str | None
    scheme: str
    protocol_version: int

    def to_auth_request(self) -> AuthRequest:
        return AuthRequest(
            token=self.token,
            requested_subdomain=self.requested_subdomain,
            agent_ip=self.agent_ip,
            scheme=self.scheme,
            protocol_version=self.protocol_version,
        )


@dataclass(frozen=True, slots=True)
class TunnelLease:
    """An admitted tunnel's control-plane handle.

    ``expires_at=None`` means the lease is static/local and does not expire. A
    hosted or sidecar control plane can return a finite expiry later without
    changing the relay's admission flow.
    """

    lease_id: str
    account_id: str
    credential_id: str | None = None
    expires_at: _dt.datetime | None = None
    generation: int = 0


@dataclass(frozen=True, slots=True)
class LeaseRenewalRequest:
    """Facts the relay sends when refreshing a finite tunnel lease."""

    lease_id: str
    account_id: str
    credential_id: str | None
    label: str
    connection_id: str
    generation: int
    expires_at: _dt.datetime


@dataclass(frozen=True, slots=True)
class PolicyUpdateRequest:
    """Relay state supplied when asking for out-of-band policy changes."""

    current_version: int
    active_lease_count: int = 0
    active_lease_ids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class AccountBudgetUpdate:
    """Replace the local transport budget for an account's live tunnels."""

    account_id: str
    budget: Budget


@dataclass(frozen=True, slots=True)
class LeaseRevocation:
    """Stop a live lease, either gracefully or immediately.

    ``drain`` stops new visitors and gives in-flight streams the relay drain
    window. ``close`` stops new visitors and closes the mux connection immediately.
    """

    lease_id: str
    action: RevocationAction = "drain"


@dataclass(frozen=True, slots=True)
class PolicyUpdate:
    """Versioned control-plane delta the relay can apply locally."""

    version: int
    revoke_lease_ids: tuple[str, ...] = ()
    account_budgets: tuple[AccountBudgetUpdate, ...] = ()
    lease_revocations: tuple[LeaseRevocation, ...] = ()


@dataclass(frozen=True, slots=True)
class TunnelAdmission:
    """The local policy the relay should install for an admitted tunnel."""

    lease: TunnelLease
    max_tunnels: int = UNLIMITED_TUNNELS
    allowed_label: str | None = None
    budget: Budget = field(default_factory=Budget)

    @property
    def account_id(self) -> str:
        return self.lease.account_id

    @property
    def credential_id(self) -> str | None:
        return self.lease.credential_id

    @classmethod
    def from_auth_result(cls, auth: AuthResult, *, lease_id: str | None = None) -> TunnelAdmission:
        return cls(
            lease=TunnelLease(
                lease_id=lease_id or uuid.uuid4().hex,
                account_id=auth.account_id,
                credential_id=auth.credential_id,
            ),
            max_tunnels=auth.max_tunnels,
            allowed_label=auth.allowed_label,
            budget=auth.budget,
        )

    def to_auth_result(self) -> AuthResult:
        """Compatibility view for code that still reasons in AuthResult terms."""
        return AuthResult(
            account_id=self.account_id,
            max_tunnels=self.max_tunnels,
            allowed_label=self.allowed_label,
            budget=self.budget,
            credential_id=self.credential_id,
        )


@runtime_checkable
class ControlPlane(Protocol):
    """Admit an agent tunnel and return locally enforceable policy."""

    async def admit_tunnel(self, request: TunnelAdmissionRequest) -> TunnelAdmission | None: ...
    async def renew_lease(self, request: LeaseRenewalRequest) -> TunnelLease | None: ...
    async def poll_policy_updates(self, request: PolicyUpdateRequest) -> PolicyUpdate | None: ...


class AuthorizerControlPlane:
    """Adapter from chute's original Authorizer hook to the control-plane seam."""

    def __init__(self, authorizer: Authorizer) -> None:
        self.authorizer = authorizer

    async def admit_tunnel(self, request: TunnelAdmissionRequest) -> TunnelAdmission | None:
        auth = await self.authorizer.authenticate(request.to_auth_request())
        if auth is None:
            return None
        return TunnelAdmission.from_auth_result(auth)

    async def renew_lease(self, request: LeaseRenewalRequest) -> TunnelLease | None:
        # Authorizer-backed standalone/local auth does not issue finite leases, so
        # renewal is a compatibility no-op if called by a subclass or test fixture.
        return TunnelLease(
            lease_id=request.lease_id,
            account_id=request.account_id,
            credential_id=request.credential_id,
            generation=request.generation,
        )

    async def poll_policy_updates(self, request: PolicyUpdateRequest) -> PolicyUpdate | None:
        return None


class StaticTokenControlPlane(AuthorizerControlPlane):
    """Standalone chute: one shared token, one bootstrap account, no database."""

    def __init__(self, token: str) -> None:
        super().__init__(StaticTokenAuthorizer(token))


@dataclass(frozen=True, slots=True)
class _StaticCredential:
    credential_id: str
    token_sha256: str
    account_id: str
    max_tunnels: int
    allowed_label: str | None
    budget: Budget
    lease_seconds: int | None


@dataclass(frozen=True, slots=True)
class _StaticPolicy:
    credentials: tuple[_StaticCredential, ...]
    policy_update: PolicyUpdate | None


@dataclass(frozen=True, slots=True)
class _LeaseState:
    account_id: str
    credential_id: str
    token_sha256: str
    lease_seconds: int


class StaticPolicyControlPlane:
    """Local JSON policy-file control plane.

    This is intentionally small and synchronous-on-read: admission and policy polling
    are control-plane work, not visitor hot-path work. Reloading the file on each
    call gives a self-hosted operator live credential/budget/revocation changes
    without adding a database or sidecar service.
    """

    include_active_lease_ids_in_policy_poll = True

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path).expanduser()
        self._leases: dict[str, _LeaseState] = {}
        self._policy: _StaticPolicy | None = None
        self._policy_fingerprint: PrivateFileFingerprint | None = None
        self._bad_policy_fingerprint: PrivateFileFingerprint | None = None
        self._policy_load_error: str | None = None
        self._load_policy()

    async def admit_tunnel(self, request: TunnelAdmissionRequest) -> TunnelAdmission | None:
        policy = self._load_policy()
        requested_hash = token_sha256(request.token)
        credential = next(
            (
                item
                for item in policy.credentials
                if hmac.compare_digest(item.token_sha256, requested_hash)
            ),
            None,
        )
        if credential is None:
            return None

        lease_id = uuid.uuid4().hex
        expires_at = None
        if credential.lease_seconds is not None:
            expires_at = _dt.datetime.now(_dt.UTC) + _dt.timedelta(seconds=credential.lease_seconds)
            self._leases[lease_id] = _LeaseState(
                account_id=credential.account_id,
                credential_id=credential.credential_id,
                token_sha256=credential.token_sha256,
                lease_seconds=credential.lease_seconds,
            )
        return TunnelAdmission(
            lease=TunnelLease(
                lease_id=lease_id,
                account_id=credential.account_id,
                credential_id=credential.credential_id,
                expires_at=expires_at,
            ),
            max_tunnels=credential.max_tunnels,
            allowed_label=credential.allowed_label,
            budget=credential.budget,
        )

    async def renew_lease(self, request: LeaseRenewalRequest) -> TunnelLease | None:
        state = self._leases.get(request.lease_id)
        if state is None:
            return None
        if state.account_id != request.account_id or state.credential_id != request.credential_id:
            return None

        policy = self._load_policy()
        credential = next(
            (
                item
                for item in policy.credentials
                if item.credential_id == state.credential_id
                and item.account_id == state.account_id
                and hmac.compare_digest(item.token_sha256, state.token_sha256)
            ),
            None,
        )
        if credential is None or credential.lease_seconds is None:
            self._leases.pop(request.lease_id, None)
            return None
        state = _LeaseState(
            account_id=credential.account_id,
            credential_id=credential.credential_id,
            token_sha256=credential.token_sha256,
            lease_seconds=credential.lease_seconds,
        )
        self._leases[request.lease_id] = state
        return TunnelLease(
            lease_id=request.lease_id,
            account_id=request.account_id,
            credential_id=request.credential_id,
            expires_at=_dt.datetime.now(_dt.UTC) + _dt.timedelta(seconds=state.lease_seconds),
            generation=request.generation + 1,
        )

    async def poll_policy_updates(self, request: PolicyUpdateRequest) -> PolicyUpdate | None:
        if request.active_lease_ids or request.active_lease_count == 0:
            self._prune_inactive_leases(request.active_lease_ids)
        update = self._load_policy().policy_update
        if update is None or update.version <= request.current_version:
            return None
        return update

    def _prune_inactive_leases(self, active_lease_ids: tuple[str, ...]) -> None:
        active = set(active_lease_ids)
        for lease_id in tuple(self._leases):
            if lease_id not in active:
                self._leases.pop(lease_id, None)

    def _load_policy(self) -> _StaticPolicy:
        try:
            snapshot = read_private_text_file_snapshot(
                self.path,
                "policy file",
                max_bytes=_MAX_POLICY_FILE_BYTES,
            )
        except ValueError as exc:
            return self._handle_policy_load_error(exc)
        if snapshot.fingerprint == self._policy_fingerprint and self._policy is not None:
            return self._policy
        if snapshot.fingerprint == self._bad_policy_fingerprint and self._policy is not None:
            return self._policy
        try:
            policy = _parse_static_policy_text(snapshot.text, self.path)
        except ValueError as exc:
            self._bad_policy_fingerprint = snapshot.fingerprint
            return self._handle_policy_load_error(exc)
        self._policy = policy
        self._policy_fingerprint = snapshot.fingerprint
        self._bad_policy_fingerprint = None
        if self._policy_load_error is not None:
            log.info("policy file reload recovered; using latest policy")
            self._policy_load_error = None
        return policy

    def _handle_policy_load_error(self, exc: ValueError) -> _StaticPolicy:
        if self._policy is None:
            raise exc
        message = str(exc)
        if message != self._policy_load_error:
            log.warning("policy file reload failed; keeping last-good policy: %s", message)
            self._policy_load_error = message
        return self._policy


def _parse_static_policy_text(text: str, path: Path) -> _StaticPolicy:
    data = _parse_private_json(text, path, "policy file")
    if not isinstance(data, dict):
        raise ValueError("policy file must contain a JSON object")
    allowed_keys = {
        "schema_version",
        "credentials",
        "policy_version",
        "revoke_lease_ids",
        "lease_revocations",
        "account_budgets",
    }
    _reject_unknown_keys(data, allowed_keys, "policy file")
    if data.get("schema_version") != _POLICY_SCHEMA_VERSION:
        raise ValueError(f"policy file schema_version must be {_POLICY_SCHEMA_VERSION}")
    credentials = _parse_credentials(data.get("credentials"))
    policy_update = _parse_policy_update(data)
    return _StaticPolicy(credentials=credentials, policy_update=policy_update)


def token_sha256(token: str) -> str:
    """Return the policy-file SHA-256 verifier for a high-entropy token."""

    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def validate_static_policy_file(path: str | os.PathLike[str]) -> None:
    """Validate a local static policy file without installing it in a relay."""

    StaticPolicyControlPlane(path)


def _parse_private_json(text: str, path: Path, name: str) -> object:
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{name} {path} is invalid JSON: {exc}") from None


def _parse_credentials(raw: object) -> tuple[_StaticCredential, ...]:
    if not isinstance(raw, list) or not raw:
        raise ValueError("policy credentials must be a non-empty array")
    if len(raw) > _MAX_POLICY_CREDENTIALS:
        raise ValueError(f"policy credentials must contain at most {_MAX_POLICY_CREDENTIALS} items")
    credentials: list[_StaticCredential] = []
    seen_ids: set[str] = set()
    seen_hashes: set[str] = set()
    label_owners: dict[str, str] = {}
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            raise ValueError(f"policy credentials[{index}] must be an object")
        _reject_unknown_keys(
            item,
            {
                "credential_id",
                "token_sha256",
                "account_id",
                "max_tunnels",
                "allowed_label",
                "budget",
                "lease_seconds",
            },
            f"policy credentials[{index}]",
        )
        credential_id = _required_str(
            item.get("credential_id"),
            f"credentials[{index}].credential_id",
        )
        token_sha256 = _parse_token_sha256(
            item.get("token_sha256"), f"credentials[{index}].token_sha256"
        )
        account_id = _required_str(item.get("account_id"), f"credentials[{index}].account_id")
        max_tunnels = _optional_nonnegative_int(
            item.get("max_tunnels", UNLIMITED_TUNNELS),
            f"credentials[{index}].max_tunnels",
        )
        assert max_tunnels is not None
        allowed_label = _optional_label(
            item.get("allowed_label"), f"credentials[{index}].allowed_label"
        )
        budget = _parse_budget(item.get("budget", {}), f"credentials[{index}].budget")
        lease_seconds = _optional_positive_int(
            item.get("lease_seconds"), f"credentials[{index}].lease_seconds"
        )
        if credential_id in seen_ids:
            raise ValueError(f"duplicate credential_id {credential_id!r}")
        if token_sha256 in seen_hashes:
            raise ValueError("duplicate token_sha256 in policy credentials")
        if allowed_label is not None:
            owner = label_owners.get(allowed_label)
            if owner is not None and owner != account_id:
                raise ValueError(
                    f"allowed_label {allowed_label!r} is assigned to multiple accounts"
                )
            label_owners[allowed_label] = account_id
        seen_ids.add(credential_id)
        seen_hashes.add(token_sha256)
        credentials.append(
            _StaticCredential(
                credential_id=credential_id,
                token_sha256=token_sha256,
                account_id=account_id,
                max_tunnels=max_tunnels,
                allowed_label=allowed_label,
                budget=budget,
                lease_seconds=lease_seconds,
            )
        )
    return tuple(credentials)


def _parse_policy_update(data: dict[str, Any]) -> PolicyUpdate | None:
    has_update = any(
        key in data
        for key in (
            "policy_version",
            "revoke_lease_ids",
            "lease_revocations",
            "account_budgets",
        )
    )
    if not has_update:
        return None
    version = _required_positive_int(data.get("policy_version"), "policy_version")
    revoke_lease_ids = _parse_revoke_lease_ids(data.get("revoke_lease_ids", []))
    lease_revocations = _parse_lease_revocations(data.get("lease_revocations", []))
    account_budgets = _parse_account_budget_updates(data.get("account_budgets", []))
    duplicate_revocations = _duplicates(
        (*revoke_lease_ids, *(revocation.lease_id for revocation in lease_revocations))
    )
    if duplicate_revocations:
        raise ValueError(
            "policy update revocations duplicate lease_id values across "
            f"revoke_lease_ids and lease_revocations: {', '.join(duplicate_revocations)}"
        )
    if not (revoke_lease_ids or lease_revocations or account_budgets):
        return None
    return PolicyUpdate(
        version=version,
        revoke_lease_ids=revoke_lease_ids,
        account_budgets=account_budgets,
        lease_revocations=lease_revocations,
    )


def _parse_revoke_lease_ids(raw: object) -> tuple[str, ...]:
    if not isinstance(raw, list):
        raise ValueError("revoke_lease_ids must be an array")
    if len(raw) > _MAX_POLICY_REVOKE_LEASE_IDS:
        raise ValueError(
            f"revoke_lease_ids must contain at most {_MAX_POLICY_REVOKE_LEASE_IDS} items"
        )
    lease_ids = tuple(
        _required_str(item, f"revoke_lease_ids[{index}]") for index, item in enumerate(raw)
    )
    duplicates = _duplicates(lease_ids)
    if duplicates:
        raise ValueError(f"revoke_lease_ids has duplicates: {', '.join(duplicates)}")
    return lease_ids


def _parse_lease_revocations(raw: object) -> tuple[LeaseRevocation, ...]:
    if not isinstance(raw, list):
        raise ValueError("lease_revocations must be an array")
    if len(raw) > _MAX_POLICY_LEASE_REVOCATIONS:
        raise ValueError(
            f"lease_revocations must contain at most {_MAX_POLICY_LEASE_REVOCATIONS} items"
        )
    revocations: list[LeaseRevocation] = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            raise ValueError(f"lease_revocations[{index}] must be an object")
        _reject_unknown_keys(item, {"lease_id", "action"}, f"lease_revocations[{index}]")
        lease_id = _required_str(item.get("lease_id"), f"lease_revocations[{index}].lease_id")
        action = item.get("action", "drain")
        if action not in ("drain", "close"):
            raise ValueError(f"lease_revocations[{index}].action must be 'drain' or 'close'")
        revocations.append(LeaseRevocation(lease_id=lease_id, action=action))
    duplicates = _duplicates(revocation.lease_id for revocation in revocations)
    if duplicates:
        raise ValueError(
            f"lease_revocations has duplicate lease_id values: {', '.join(duplicates)}"
        )
    return tuple(revocations)


def _parse_account_budget_updates(raw: object) -> tuple[AccountBudgetUpdate, ...]:
    if not isinstance(raw, list):
        raise ValueError("account_budgets must be an array")
    if len(raw) > _MAX_POLICY_ACCOUNT_BUDGETS:
        raise ValueError(
            f"account_budgets must contain at most {_MAX_POLICY_ACCOUNT_BUDGETS} items"
        )
    updates: list[AccountBudgetUpdate] = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            raise ValueError(f"account_budgets[{index}] must be an object")
        _reject_unknown_keys(item, {"account_id", "budget"}, f"account_budgets[{index}]")
        account_id = _required_str(item.get("account_id"), f"account_budgets[{index}].account_id")
        budget = _parse_budget(item.get("budget", {}), f"account_budgets[{index}].budget")
        updates.append(AccountBudgetUpdate(account_id=account_id, budget=budget))
    duplicates = _duplicates(update.account_id for update in updates)
    if duplicates:
        raise ValueError(
            f"account_budgets has duplicate account_id values: {', '.join(duplicates)}"
        )
    return tuple(updates)


def _duplicates(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    duplicates: list[str] = []
    for value in values:
        if value in seen and value not in duplicates:
            duplicates.append(value)
        seen.add(value)
    return duplicates


def _parse_budget(raw: object, name: str) -> Budget:
    if not isinstance(raw, dict):
        raise ValueError(f"{name} must be an object")
    _reject_unknown_keys(raw, _BUDGET_FIELDS, name)
    return Budget(
        max_visitors=_optional_nonnegative_int(raw.get("max_visitors"), f"{name}.max_visitors"),
        max_bytes_per_sec=_optional_nonnegative_int(
            raw.get("max_bytes_per_sec"), f"{name}.max_bytes_per_sec"
        ),
        max_reconnects_per_min=_optional_nonnegative_int(
            raw.get("max_reconnects_per_min"), f"{name}.max_reconnects_per_min"
        ),
        max_buffered_bytes=_optional_nonnegative_int(
            raw.get("max_buffered_bytes"), f"{name}.max_buffered_bytes"
        ),
    )


def _reject_unknown_keys(
    data: dict[str, Any],
    allowed: set[str] | frozenset[str],
    name: str,
) -> None:
    unknown = set(data) - set(allowed)
    if unknown:
        raise ValueError(f"{name} has unknown keys: {', '.join(sorted(unknown))}")


def _required_str(raw: object, name: str) -> str:
    if not isinstance(raw, str) or not raw:
        raise ValueError(f"{name} must be a non-empty string")
    return raw


def _optional_str(raw: object, name: str) -> str | None:
    if raw is None:
        return None
    return _required_str(raw, name)


def _optional_label(raw: object, name: str) -> str | None:
    value = _optional_str(raw, name)
    if value is None:
        return None
    label = value.lower()
    if not valid_label(label):
        raise ValueError(f"{name} must be a valid hostname label")
    return label


def _parse_token_sha256(raw: object, name: str) -> str:
    value = _required_str(raw, name)
    if value.startswith("sha256:"):
        value = value.removeprefix("sha256:")
    value = value.lower()
    if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise ValueError(f"{name} must be a sha256 hex digest")
    return value


def _optional_nonnegative_int(raw: object, name: str) -> int | None:
    if raw is None:
        return None
    if not isinstance(raw, int) or isinstance(raw, bool) or raw < 0:
        raise ValueError(f"{name} must be a non-negative integer or null")
    return raw


def _optional_positive_int(raw: object, name: str) -> int | None:
    if raw is None:
        return None
    if not isinstance(raw, int) or isinstance(raw, bool) or raw < 1:
        raise ValueError(f"{name} must be a positive integer or null")
    return raw


def _required_positive_int(raw: object, name: str) -> int:
    parsed = _optional_positive_int(raw, name)
    if parsed is None:
        raise ValueError(f"{name} is required")
    return parsed
