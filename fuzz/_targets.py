from __future__ import annotations

import asyncio
import struct
from collections.abc import AsyncIterator
from pathlib import Path

from chute import names, protocol
from chute.control import (
    AccountBudgetUpdate,
    LeaseRevocation,
    PolicyUpdate,
    _parse_static_policy_text,
    _StaticCredential,
    _StaticPolicy,
)
from chute.mux import _MAX_CONN_BUFFERED, _MAX_CONN_FRAMES, Mux, Stream
from chute.server import Server, _BadRequest, _host_from_head, _parse_request_head


class _HostRouter:
    base_domain = "chute.sh"


class _FrameWS:
    def __init__(self, messages: list[bytes]) -> None:
        self._messages = iter(messages)
        self.sent: list[bytes] = []
        self.closed: tuple[int, str] | None = None

    def __aiter__(self) -> AsyncIterator[bytes]:
        return self

    async def __anext__(self) -> bytes:
        try:
            return next(self._messages)
        except StopIteration as exc:
            raise StopAsyncIteration from exc

    async def send(self, data: bytes) -> None:
        self.sent.append(data)

    async def close(self, code: int = 1000, reason: str = "") -> None:
        self.closed = (code, reason)


async def _consume_stream(stream: Stream) -> None:
    while await stream.read() is not None:
        pass


def check_protocol_decode(data: bytes) -> None:
    try:
        frame_type, stream_id, payload = protocol.decode(data)
    except ValueError:
        return

    assert len(data) >= protocol.PREFIX_SIZE
    assert 0 <= frame_type <= 0xFF
    assert 0 <= stream_id <= 0xFFFFFFFF
    assert payload == data[protocol.PREFIX_SIZE :]


def check_request_head(data: bytes) -> None:
    for require_host in (False, True):
        try:
            parsed = _parse_request_head(data, require_host=require_host)
        except _BadRequest:
            continue

        if require_host:
            assert parsed.host is not None
        if parsed.host is not None:
            assert parsed.host == _host_from_head(data)
            _assert_normalized_host(parsed.host)


def _assert_normalized_host(host: str) -> None:
    assert host == host.strip()
    assert host == host.lower()
    assert all(0x21 <= ord(ch) <= 0x7E for ch in host)
    assert host
    assert "@" not in host
    if host.startswith("["):
        assert host.endswith("]")
        return
    assert ":" not in host
    rootless = host[:-1] if host.endswith(".") else host
    assert rootless
    assert all(names.valid_label(label) for label in rootless.split("."))


def check_host_label(data: bytes) -> None:
    try:
        host = data.decode("ascii")
    except UnicodeDecodeError:
        return

    label = Server._label_from_host(_HostRouter(), host)  # type: ignore[arg-type]
    if label is None:
        return

    assert label == label.lower()
    assert names.valid_label(label)
    normalized = host.lower().rstrip(".")
    assert normalized == f"{label}.chute.sh"


def check_mux_frames(data: bytes) -> None:
    asyncio.run(_check_mux_frames(data))


def check_policy_json(data: bytes) -> None:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return

    try:
        policy = _parse_static_policy_text(text, path=Path(__file__))
    except ValueError:
        return

    _assert_static_policy(policy)


def _assert_static_policy(policy: _StaticPolicy) -> None:
    assert isinstance(policy, _StaticPolicy)
    assert policy.credentials
    credential_ids: set[str] = set()
    token_hashes: set[str] = set()
    label_owners: dict[str, str] = {}
    for credential in policy.credentials:
        _assert_static_credential(credential)
        assert credential.credential_id not in credential_ids
        assert credential.token_sha256 not in token_hashes
        credential_ids.add(credential.credential_id)
        token_hashes.add(credential.token_sha256)
        if credential.allowed_label is not None:
            owner = label_owners.get(credential.allowed_label)
            assert owner is None or owner == credential.account_id
            label_owners[credential.allowed_label] = credential.account_id
    if policy.policy_update is not None:
        _assert_policy_update(policy.policy_update)


def _assert_static_credential(credential: _StaticCredential) -> None:
    assert isinstance(credential, _StaticCredential)
    assert credential.credential_id
    assert credential.account_id
    assert len(credential.token_sha256) == 64
    int(credential.token_sha256, 16)
    assert credential.max_tunnels >= 0
    if credential.allowed_label is not None:
        assert credential.allowed_label == credential.allowed_label.lower()
        assert names.valid_label(credential.allowed_label)
    for value in (
        credential.budget.max_visitors,
        credential.budget.max_bytes_per_sec,
        credential.budget.max_reconnects_per_min,
        credential.budget.max_buffered_bytes,
    ):
        assert value is None or (
            isinstance(value, int) and not isinstance(value, bool) and value >= 0
        )
    assert credential.lease_seconds is None or credential.lease_seconds > 0


def _assert_policy_update(update: PolicyUpdate) -> None:
    assert isinstance(update, PolicyUpdate)
    assert isinstance(update.version, int) and not isinstance(update.version, bool)
    assert update.version > 0
    seen_revocations: set[str] = set()
    for lease_id in update.revoke_lease_ids:
        assert isinstance(lease_id, str) and lease_id
        assert lease_id not in seen_revocations
        seen_revocations.add(lease_id)
    for revocation in update.lease_revocations:
        assert isinstance(revocation, LeaseRevocation)
        assert revocation.lease_id
        assert revocation.action in ("drain", "close")
        assert revocation.lease_id not in seen_revocations
        seen_revocations.add(revocation.lease_id)
    seen_accounts: set[str] = set()
    for budget_update in update.account_budgets:
        assert isinstance(budget_update, AccountBudgetUpdate)
        assert budget_update.account_id
        assert budget_update.account_id not in seen_accounts
        seen_accounts.add(budget_update.account_id)


async def _check_mux_frames(data: bytes) -> None:
    frames = _frames_from_bytes(data)
    goaway_calls = 0

    def on_goaway() -> None:
        nonlocal goaway_calls
        goaway_calls += 1

    mux = Mux(_FrameWS(frames), on_open=_consume_stream, on_goaway=on_goaway, max_streams=8)
    await mux.run()

    stats = mux.stats()
    assert stats["active_streams"] == 0
    assert stats["buffered_bytes"] == 0
    assert stats["queued_frames"] == 0
    assert 0 <= mux._buffered <= _MAX_CONN_BUFFERED
    assert 0 <= mux._frames <= _MAX_CONN_FRAMES
    assert goaway_calls <= 1


def _frames_from_bytes(data: bytes) -> list[bytes]:
    frames: list[bytes] = []
    i = 0
    while i < len(data) and len(frames) < 128:
        op = data[i] % 8
        sid = 0
        if i + 5 <= len(data):
            sid = int.from_bytes(data[i + 1 : i + 5], "big") % 12
        payload_len = data[i + 5] % 33 if i + 5 < len(data) else 0
        start = i + 6
        payload = data[start : start + payload_len]
        i = start + payload_len

        if op == 0:
            frames.append(data[start : start + payload_len])
            continue
        if op == 1:
            frames.append(protocol.encode(protocol.OPEN, sid, b""))
        elif op == 2:
            frames.append(protocol.encode(protocol.DATA, sid, payload))
        elif op == 3:
            frames.append(protocol.encode(protocol.EOF, sid, b""))
        elif op == 4:
            frames.append(protocol.encode(protocol.RESET, sid, b""))
        elif op == 5:
            frames.append(protocol.encode(protocol.WINDOW_UPDATE, sid, payload[:4]))
        elif op == 6:
            frames.append(protocol.encode(protocol.WINDOW_UPDATE, sid, struct.pack("!I", sid + 1)))
        elif op == 7:
            frames.append(protocol.encode(protocol.GOAWAY, 0 if sid % 2 == 0 else sid, b""))

    return frames


def run_all_targets_once(data: bytes) -> None:
    check_protocol_decode(data)
    check_request_head(data)
    check_host_label(data)
    check_mux_frames(data)
    check_policy_json(data)
