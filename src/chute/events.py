"""Optional lifecycle/stat events emitted by the relay.

The default sink is a no-op, so self-hosted chute remains fully standalone. A
control plane can inject an EventSink to persist tunnel/visitor lifecycle history
and relay stats or audit rejected admissions without putting database or billing
concepts in core.
"""

from __future__ import annotations

import asyncio
import datetime as _dt
import json
import os
import stat
import threading
from dataclasses import asdict, dataclass, is_dataclass
from pathlib import Path
from typing import Any, Protocol, cast, runtime_checkable

__all__ = [
    "AuthRejectedEvent",
    "DEFAULT_JSONL_EVENT_LOG_BACKUPS",
    "DEFAULT_JSONL_EVENT_LOG_MAX_BYTES",
    "EventSink",
    "JsonlEventSink",
    "NoopEventSink",
    "RelayStatsEvent",
    "TunnelClosedEvent",
    "TunnelOpenedEvent",
    "VisitorClosedEvent",
    "VisitorOpenedEvent",
    "VisitorRejectedEvent",
]

DEFAULT_JSONL_EVENT_LOG_MAX_BYTES = 100 * 1024 * 1024
DEFAULT_JSONL_EVENT_LOG_BACKUPS = 5


@dataclass(frozen=True, slots=True)
class TunnelOpenedEvent:
    connection_id: str
    label: str
    account_id: str
    credential_id: str | None
    scheme: str
    public_url: str
    agent_ip: str | None
    requested_subdomain: str | None
    at: _dt.datetime
    lease_id: str | None = None


@dataclass(frozen=True, slots=True)
class TunnelClosedEvent:
    connection_id: str
    label: str
    account_id: str
    credential_id: str | None
    scheme: str
    agent_ip: str | None
    at: _dt.datetime
    lease_id: str | None = None


@dataclass(frozen=True, slots=True)
class VisitorOpenedEvent:
    connection_id: str
    label: str
    account_id: str
    credential_id: str | None
    stream_id: int
    host: str | None
    visitor_ip: str | None
    at: _dt.datetime


@dataclass(frozen=True, slots=True)
class VisitorClosedEvent:
    connection_id: str
    label: str
    account_id: str
    credential_id: str | None
    stream_id: int
    host: str | None
    visitor_ip: str | None
    at: _dt.datetime


@dataclass(frozen=True, slots=True)
class AuthRejectedEvent:
    reason: str
    agent_ip: str | None
    requested_subdomain: str | None
    scheme: str | None
    account_id: str | None
    credential_id: str | None
    at: _dt.datetime


@dataclass(frozen=True, slots=True)
class VisitorRejectedEvent:
    reason: str
    label: str | None
    account_id: str | None
    credential_id: str | None
    host: str | None
    visitor_ip: str | None
    at: _dt.datetime


@dataclass(frozen=True, slots=True)
class RelayStatsEvent:
    """Low-cardinality relay-local gauges and cumulative counters.

    Exporters can turn these into Prometheus, OTLP, logs, or a control-plane row
    without forcing chute core to own a metrics backend.
    """

    active_tunnels: int
    account_count: int
    control_capacity: int
    control_in_flight: int
    auth_capacity: int
    auth_in_flight: int
    visitor_capacity: int
    visitors_in_flight: int
    visitor_ip_capacity: int | None
    visitor_ip_buckets: int
    control_busy: int
    auth_busy: int
    visitor_pool_busy: int
    visitor_ip_limited: int
    active_streams: int
    buffered_bytes: int
    queued_frames: int
    draining_tunnels: int
    opened_streams: int
    reset_streams: int
    reset_peer_streams: int
    credit_stalls: int
    write_stalls: int
    bytes_to_agent: int
    bytes_to_visitor: int
    event_tunnel_opened_generated: int
    event_tunnel_closed_generated: int
    event_visitor_opened_generated: int
    event_visitor_closed_generated: int
    event_auth_rejected_generated: int
    event_visitor_rejected_generated: int
    event_relay_stats_generated: int
    event_queue_depth: int
    event_queue_capacity: int
    event_queue_enqueued: int
    event_queue_delivered: int
    event_queue_retried: int
    event_queue_dropped: int
    policy_version: int
    policy_update_poll_failures: int
    policy_updates_applied: int
    policy_updates_rejected: int
    lease_renewals_succeeded: int
    lease_renewals_failed: int
    lease_renewals_invalid: int
    lease_renewals_revoked: int
    lease_revocations: int
    lease_expirations: int
    at: _dt.datetime


@runtime_checkable
class EventSink(Protocol):
    """Async lifecycle/stat sink. Implementations must tolerate concurrent calls."""

    async def tunnel_opened(self, event: TunnelOpenedEvent) -> None: ...
    async def tunnel_closed(self, event: TunnelClosedEvent) -> None: ...
    async def visitor_opened(self, event: VisitorOpenedEvent) -> None: ...
    async def visitor_closed(self, event: VisitorClosedEvent) -> None: ...
    async def auth_rejected(self, event: AuthRejectedEvent) -> None: ...
    async def visitor_rejected(self, event: VisitorRejectedEvent) -> None: ...
    async def relay_stats(self, event: RelayStatsEvent) -> None: ...


class NoopEventSink:
    """Default sink for standalone chute: lifecycle events are ignored."""

    async def tunnel_opened(self, event: TunnelOpenedEvent) -> None:
        return None

    async def tunnel_closed(self, event: TunnelClosedEvent) -> None:
        return None

    async def visitor_opened(self, event: VisitorOpenedEvent) -> None:
        return None

    async def visitor_closed(self, event: VisitorClosedEvent) -> None:
        return None

    async def auth_rejected(self, event: AuthRejectedEvent) -> None:
        return None

    async def visitor_rejected(self, event: VisitorRejectedEvent) -> None:
        return None

    async def relay_stats(self, event: RelayStatsEvent) -> None:
        return None


class JsonlEventSink:
    """Owner-only local JSONL event sink for self-hosted audit/lifecycle logs."""

    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        max_bytes: int | None = DEFAULT_JSONL_EVENT_LOG_MAX_BYTES,
        backup_count: int = DEFAULT_JSONL_EVENT_LOG_BACKUPS,
    ) -> None:
        if max_bytes is not None and max_bytes < 0:
            raise ValueError("event log max_bytes must be a non-negative integer or None")
        if backup_count < 0:
            raise ValueError("event log backup_count must be a non-negative integer")
        self.path = Path(path).expanduser()
        self.max_bytes = None if max_bytes == 0 else max_bytes
        self.backup_count = backup_count
        self._lock = threading.Lock()
        self._ensure_log_file()

    async def tunnel_opened(self, event: TunnelOpenedEvent) -> None:
        await self._write_event("tunnel_opened", event)

    async def tunnel_closed(self, event: TunnelClosedEvent) -> None:
        await self._write_event("tunnel_closed", event)

    async def visitor_opened(self, event: VisitorOpenedEvent) -> None:
        await self._write_event("visitor_opened", event)

    async def visitor_closed(self, event: VisitorClosedEvent) -> None:
        await self._write_event("visitor_closed", event)

    async def auth_rejected(self, event: AuthRejectedEvent) -> None:
        await self._write_event("auth_rejected", event)

    async def visitor_rejected(self, event: VisitorRejectedEvent) -> None:
        await self._write_event("visitor_rejected", event)

    async def relay_stats(self, event: RelayStatsEvent) -> None:
        await self._write_event("relay_stats", event)

    async def _write_event(self, event_type: str, event: object) -> None:
        await asyncio.to_thread(self._write_event_sync, event_type, event)

    def _write_event_sync(self, event_type: str, event: object) -> None:
        record = {
            "type": event_type,
            "event": _json_safe_event(event),
        }
        line = json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
        line_bytes = len(line.encode("utf-8"))
        with self._lock:
            self._rotate_if_needed(line_bytes)
            with self._open_append_file() as handle:
                handle.write(line)

    def _ensure_log_file(self) -> None:
        self._validate_parent_dir()
        try:
            self.path.lstat()
        except FileNotFoundError:
            self._create_log_file()
        else:
            self._validate_existing_log_file()
            return

    def _validate_parent_dir(self) -> None:
        parent = self.path.parent
        try:
            st = parent.stat()
        except OSError as exc:
            raise ValueError(f"event log parent {parent} is not readable: {exc}") from None
        if not stat.S_ISDIR(st.st_mode):
            raise ValueError(f"event log parent {parent} must exist and be a directory")
        if os.name != "nt" and st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise ValueError(f"event log parent {parent} must not be group- or world-writable")
        if os.name != "nt" and st.st_uid != os.geteuid():
            raise ValueError(f"event log parent {parent} must be owned by this user")

    def _create_log_file(self) -> None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(self.path, flags, 0o600)
        try:
            if hasattr(os, "fchmod"):
                os.fchmod(fd, 0o600)
        finally:
            os.close(fd)

    def _validate_existing_log_file(self) -> None:
        self._validate_log_file(self.path, "event log")

    def _validate_log_file(self, path: Path, label: str) -> None:
        try:
            st = path.lstat()
        except OSError as exc:
            raise ValueError(f"{label} {path} is not readable: {exc}") from None
        if stat.S_ISLNK(st.st_mode):
            raise ValueError(f"{label} {path} must not be a symlink")
        _validate_log_stat(st, path, label)

    def _rotated_path(self, index: int) -> Path:
        return self.path.with_name(f"{self.path.name}.{index}")

    def _rotate_if_needed(self, bytes_to_write: int) -> None:
        if self.max_bytes is None or self.backup_count == 0:
            return
        try:
            st = self.path.stat()
        except FileNotFoundError:
            return
        if st.st_size == 0 or st.st_size + bytes_to_write <= self.max_bytes:
            return
        self._rotate_locked()

    def _rotate_locked(self) -> None:
        for index in range(self.backup_count, 0, -1):
            path = self._rotated_path(index)
            if path.exists() or path.is_symlink():
                self._validate_log_file(path, "event log backup")
                if index == self.backup_count:
                    path.unlink()
        for index in range(self.backup_count - 1, 0, -1):
            src = self._rotated_path(index)
            if src.exists() or src.is_symlink():
                self._validate_log_file(src, "event log backup")
                os.replace(src, self._rotated_path(index + 1))
        if self.path.exists() or self.path.is_symlink():
            self._validate_existing_log_file()
            os.replace(self.path, self._rotated_path(1))
        self._create_log_file()

    def _open_append_file(self) -> Any:
        self._validate_parent_dir()
        if self.path.exists() or self.path.is_symlink():
            self._validate_existing_log_file()
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(self.path, flags, 0o600)
        try:
            st = os.fstat(fd)
            _validate_log_stat(st, self.path, "event log")
            return os.fdopen(fd, "a", encoding="utf-8")
        except Exception:
            os.close(fd)
            raise


def _validate_log_stat(st: os.stat_result, path: Path, label: str) -> None:
    if not stat.S_ISREG(st.st_mode):
        raise ValueError(f"{label} {path} must be a regular file")
    if os.name != "nt" and st.st_uid != os.geteuid():
        raise ValueError(f"{label} {path} must be owned by this user")
    if os.name != "nt" and st.st_mode & 0o077:
        raise ValueError(f"{label} {path} must be readable only by its owner (chmod 600)")


def _json_safe_event(event: object) -> object:
    if is_dataclass(event):
        return _json_safe(asdict(cast(Any, event)))
    return _json_safe(event)


def _json_safe(value: object) -> object:
    if isinstance(value, _dt.datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, tuple | list):
        return [_json_safe(item) for item in value]
    return value
