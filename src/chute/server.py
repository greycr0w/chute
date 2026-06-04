"""chute server -- runs on the public VPS.

Two listeners:

* **control** (WSS): accepts agents. Each agent dials *out* to here, which is
  what lets the whole thing traverse NAT/firewalls.
* **public** (plain TCP): accepts visitor connections and relays each one, as a
  multiplexed stream, to the right agent -- which forwards it to the local app
  and pipes the response back.

The public side is an HTTP tunnel: it reads a complete request head before it
opens an agent stream, then forwards the buffered head plus the rest verbatim.
Without ``base_domain`` every valid HTTP request routes to the reserved internal
``default`` label. With ``base_domain`` the public side strictly parses Host to
choose a label and rejects (400) any head a downstream hop could parse
differently -- duplicate/missing/whitespace-mangled Host, malformed request
lines, obs-fold, bare LF, or a non-origin-form target (see
``_parse_request_head``). Host-routed mode commits one agent per connection, so
it is **loopback-only by construction** (the ctor refuses a routable bind) and
runs behind a reverse proxy that gives it one request per connection. The full
threat model is the README's "Security model", not restated across the
codebase.

Security posture: the control port is the only internet-facing pre-auth surface.
It caps WebSocket message size (no unbounded buffering), disables permessage-
deflate (no decompression bomb), bounds concurrent handshakes, and times out the
hello. The mux bounds per-stream buffering and the relay times out stalled
writes. None of this touches proxied bytes -- it limits framing, size, rate,
concurrency and timeouts only.
"""

from __future__ import annotations

import asyncio
import contextlib
import datetime as _dt
import hashlib
import html
import ipaddress
import json
import logging
import math
import os
import signal
import socket
import ssl
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import websockets

from . import certs, names, protocol
from ._relay import (
    _pump_reader_to_stream,
    _pump_stream_to_writer,
    _safe_close,
    _safe_drain,
    _safe_reset,
)
from ._sockets import enable_tcp_keepalive
from .auth import Authorizer, AuthResult, Budget, StaticTokenAuthorizer
from .control import (
    AccountBudgetUpdate,
    AuthorizerControlPlane,
    ControlPlane,
    LeaseRenewalRequest,
    LeaseRevocation,
    PolicyUpdate,
    PolicyUpdateRequest,
    TunnelAdmission,
    TunnelAdmissionRequest,
    TunnelLease,
)
from .events import (
    AuthRejectedEvent,
    EventSink,
    NoopEventSink,
    RelayStatsEvent,
    TunnelClosedEvent,
    TunnelOpenedEvent,
    VisitorClosedEvent,
    VisitorOpenedEvent,
    VisitorRejectedEvent,
)
from .mux import _FLOW_WINDOW, Mux, Stream, validate_flow_window

log = logging.getLogger("chute.server")

# Cap any single control-channel WebSocket message. chute's own frames are a
# 5-byte prefix + at most one 64 KiB pump read (see _pump_reader_to_stream and
# the agent side), so the largest legitimate frame is ~64 KiB; 256 KiB leaves
# headroom while closing the pre-auth unbounded-buffer / deflate-bomb OOM. This
# bounds chute's OWN framing envelope only -- proxied HTTP rides inside DATA
# frames as <=64 KiB chunks, untouched, so byte-transparency is preserved.
_MAX_WS_MESSAGE = 256 * 1024
_WS_MAX_QUEUE = 16
# Keep this positive. Forcing an SSL transport's write-buffer high-water mark to
# 0 can deadlock `drain()` on Python 3.11+; chute should bound writes with timeouts,
# not by disabling the transport buffer.
_WS_WRITE_LIMIT = 32 * 1024
_MAX_REQUEST_HEAD = 64 * 1024
_STREAM_READER_LIMIT = _MAX_REQUEST_HEAD

# Backstops for the pre-auth control surface and the relay.
_DEFAULT_MAX_CONTROL_CONNS = 256  # concurrent in-flight (pre-auth) handshakes
_DEFAULT_MAX_AGENTS = 1024  # concurrent registered agent labels on this relay
_DEFAULT_MAX_VISITORS = 2048  # concurrent public connections
_DEFAULT_MAX_VISITORS_PER_IP = 64  # concurrent direct non-loopback public connections
_DEFAULT_HELLO_TIMEOUT = 5.0  # seconds an unauthenticated peer may squat
_DEFAULT_AUTH_TIMEOUT = 5.0  # bound authorizer I/O after a valid hello
_DEFAULT_EVENT_TIMEOUT = 5.0  # bound optional lifecycle sink I/O
_DEFAULT_POLICY_POLL_INTERVAL = 1.0  # custom control planes: dynamic policy cadence
_VISITOR_ACQUIRE_TIMEOUT = 5.0  # wait for a visitor slot before 503
_VISITOR_IP_MAX_KEYS = 65536
_FIRST_BYTE_TIMEOUT = 30.0  # visitor must send a complete HTTP request head within this
_GRACEFUL_DRAIN_TIMEOUT = 10.0  # SIGTERM: max wait for in-flight streams before close
_LEASE_EXPIRY_DRAIN_TIMEOUT = 10.0  # finite lease expiry: stop new visitors, drain active
_DEFAULT_RELAY_IDLE_TIMEOUT: float | None = None  # no app-level byte-idle timeout by default
_STATS_LOG_INTERVAL = 300.0  # seconds between data-path summary log lines
_DATA_PATH_LOG_INTERVAL = 60.0  # rate-limit repeated metadata-only failure logs
_DATA_PATH_LOG_MAX_KEYS = 1024
_METRICS_REQUEST_HEAD_LIMIT = 8 * 1024
_METRICS_REQUEST_TIMEOUT = 2.0
_EVENT_QUEUE_MAX = 1024
_EVENT_RETRY_ATTEMPTS = 3
_EVENT_RETRY_DELAY = 1.0
_EVENT_COUNT_METHODS = (
    "tunnel_opened",
    "tunnel_closed",
    "visitor_opened",
    "visitor_closed",
    "auth_rejected",
    "visitor_rejected",
    "relay_stats",
)
_DEFAULT_LABEL = "default"

# Failed-auth limiter: a source bucket gets _AUTH_FAIL_MAX bad handshakes per
# _AUTH_FAIL_WINDOW seconds before further connects are turned away (close 1013).
# Only failures count, so a legitimate agent on a clean source is never throttled.
_AUTH_FAIL_MAX = 5
_AUTH_FAIL_WINDOW = 60.0
# Keep the failure map bounded under any input: opportunistically sweep stale buckets
# past _SWEEP_AT, and hard-cap the total distinct source buckets (evicting
# oldest-inserted) so a flood of FRESH addresses can't grow it without bound.
_AUTH_FAIL_SWEEP_AT = 4096
_AUTH_FAIL_MAX_IPS = 65536

# Per-account reconnect limiter: after admission identifies the account, known
# accounts can be throttled locally before the tunnel is registered.
_RECONNECT_WINDOW = 60.0
_RECONNECT_SWEEP_AT = 4096
_RECONNECT_MAX_ACCOUNTS = 65536
_BANDWIDTH_MAX_ACCOUNTS = 65536
_MAX_POLICY_UPDATE_REVOKE_LEASE_IDS = 10000
_MAX_POLICY_UPDATE_LEASE_REVOCATIONS = 10000
_MAX_POLICY_UPDATE_ACCOUNT_BUDGETS = 4096


def _http_response(status: str, body: bytes) -> bytes:
    # Our own error pages (not an app's response) so injecting Connection: close
    # here is correct -- there is no upstream we'd be lying about.
    return (
        b"HTTP/1.1 " + status.encode() + b"\r\n"
        b"Content-Type: text/html; charset=utf-8\r\n"
        b"Connection: close\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"\r\n" + body
    )


def _plain_response(
    status: str,
    body: bytes,
    *,
    content_type: bytes = b"text/plain; charset=utf-8",
) -> bytes:
    return (
        b"HTTP/1.1 " + status.encode() + b"\r\n"
        b"Content-Type: " + content_type + b"\r\n"
        b"X-Content-Type-Options: nosniff\r\n"
        b"Cache-Control: no-store\r\n"
        b"Connection: close\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"\r\n" + body
    )


_OFFLINE_RESPONSE = _http_response(
    "503 Service Unavailable",
    b"<!doctype html><meta charset=utf-8><title>tunnel offline</title>"
    b"<h1>503 - tunnel offline</h1>"
    b"<p>No chute agent is currently connected.</p>",
)
_BAD_REQUEST_RESPONSE = _http_response(
    "400 Bad Request",
    b"<!doctype html><meta charset=utf-8><title>bad request</title><h1>400 - bad request</h1>",
)
_BUSY_RESPONSE = _http_response(
    "503 Service Unavailable",
    b"<!doctype html><meta charset=utf-8><title>busy</title>"
    b"<h1>503 - server busy</h1><p>Too many connections; try again shortly.</p>",
)


def _no_tunnel_response(host: str) -> bytes:
    # HTML-escape BEFORE ascii-encoding so an attacker-controlled Host can't
    # inject markup into our own error page (reflected-XSS hardening for the
    # edge-facing run mode; behind nginx a bad Host never reaches us).
    safe = html.escape(host)[:128].encode("ascii", "replace")
    return _http_response(
        "503 Service Unavailable",
        b"<!doctype html><meta charset=utf-8><title>tunnel offline</title>"
        b"<h1>503 - no tunnel here</h1>"
        b"<p>No chute agent is serving <code>" + safe + b"</code>.</p>",
    )


class _LabelError(Exception):
    """A subdomain request we can't honor; the message is the wire `reason`."""


class _BadRequest(Exception):
    """A visitor request head we refuse to route: malformed or ambiguous in a way
    a downstream hop could parse differently than we do. The caller answers 400 and
    closes the connection. The message is a short machine reason, for the log only."""


class _BadHandshake(Exception):
    """A control-channel hello that is syntactically valid JSON but not a valid chute
    auth request. It is counted like other bad handshakes and closed 4000."""


class _BandwidthLimitExceeded(Exception):
    """A local account bandwidth budget refused this byte transfer."""


class _RelayIdleTimeout(Exception):
    """No bytes crossed the visitor relay within the configured idle window."""


class _MetricsRequestError(Exception):
    """A malformed or unsupported local metrics request."""

    def __init__(self, status: str) -> None:
        super().__init__(status)
        self.status = status


@dataclass(frozen=True, slots=True)
class _QueuedEvent:
    method: str
    event: object
    attempts: int = 0


@dataclass(slots=True)
class TunnelRegistration:
    mux: Mux
    account_id: str
    budget: Budget
    connection_id: str
    credential_id: str | None
    scheme: str
    public_url: str
    agent_ip: str | None
    requested_subdomain: str | None
    accepting_visitors: bool = False
    lease_id: str | None = None
    lease_expires_at: _dt.datetime | None = None
    lease_observed_at: _dt.datetime | None = None
    lease_generation: int = 0


class _BandwidthSchedule:
    """Per-account local byte-rate schedule shared by all relay pumps."""

    def __init__(self) -> None:
        self.next_at = 0.0
        self.lock = asyncio.Lock()


@dataclass(frozen=True, slots=True)
class RequestHead:
    host: str | None


# Strong refs to fire-and-forget close tasks: the event loop keeps only a weak
# reference, so an untracked task could be garbage-collected before it runs.
_pending_closes: set[asyncio.Task[None]] = set()


def _schedule_ws_close(mux: Mux, code: int, reason: str) -> None:
    """Tear down a control connection without blocking on a hung peer."""

    async def _close() -> None:
        try:
            await mux.aclose(code=code, reason=reason)
        except Exception:
            pass

    task = asyncio.ensure_future(_close())
    _pending_closes.add(task)
    task.add_done_callback(_pending_closes.discard)


def _schedule_mux_drain(mux: Mux, timeout: float) -> None:
    """Drain an expired/revoked tunnel without blocking the visitor handler."""

    async def _drain() -> None:
        try:
            await mux.drain(timeout)
        except Exception:
            pass

    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return
    task = loop.create_task(_drain())
    _pending_closes.add(task)
    task.add_done_callback(_pending_closes.discard)


def _systemd_notify(message: str, *, warn: bool = True) -> bool:
    """Send one sd_notify-style datagram when running under systemd."""
    notify_socket = os.environ.get("NOTIFY_SOCKET")
    if not notify_socket:
        return False
    address: str = notify_socket
    if notify_socket.startswith("@"):
        address = "\0" + notify_socket[1:]
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
            sock.connect(address)
            sock.sendall(message.encode())
        return True
    except OSError as exc:
        if warn:
            log.warning("systemd notify failed: %s", exc)
        return False


def _systemd_watchdog_interval() -> float | None:
    """Return the watchdog ping interval from systemd env, or None when disabled."""
    raw = os.environ.get("WATCHDOG_USEC")
    if not raw:
        return None
    watchdog_pid = os.environ.get("WATCHDOG_PID")
    if watchdog_pid:
        try:
            if int(watchdog_pid) != os.getpid():
                return None
        except ValueError:
            return None
    try:
        usec = int(raw)
    except ValueError:
        return None
    if usec <= 0:
        return None
    return usec / 2_000_000


async def _systemd_watchdog(interval: float) -> None:
    while True:
        await asyncio.sleep(interval)
        _systemd_notify("WATCHDOG=1", warn=False)


class Server:
    def __init__(
        self,
        *,
        token: str,
        public_host: str = "0.0.0.0",
        public_port: int = 80,
        control_host: str = "0.0.0.0",
        control_port: int = 7000,
        public_url: str | None = None,
        ssl_context: ssl.SSLContext | None = None,
        tls_cert: str | Path | None = None,
        tls_key: str | Path | None = None,
        public_tls_port: int = 443,
        public_https_url: str | None = None,
        cert_reload_interval: float = 30.0,
        base_domain: str | None = None,
        upstream_tls: bool = False,
        max_control_conns: int = _DEFAULT_MAX_CONTROL_CONNS,
        max_agents: int = _DEFAULT_MAX_AGENTS,
        max_visitors: int = _DEFAULT_MAX_VISITORS,
        max_visitors_per_ip: int | None = _DEFAULT_MAX_VISITORS_PER_IP,
        hello_timeout: float = _DEFAULT_HELLO_TIMEOUT,
        auth_timeout: float = _DEFAULT_AUTH_TIMEOUT,
        max_auth_conns: int | None = None,
        authorizer: Authorizer | None = None,
        control_plane: ControlPlane | None = None,
        event_sink: EventSink | None = None,
        event_timeout: float = _DEFAULT_EVENT_TIMEOUT,
        require_event_sink: bool = False,
        policy_poll_interval: float | None = None,
        relay_idle_timeout: float | None = _DEFAULT_RELAY_IDLE_TIMEOUT,
        mux_flow_window: int = _FLOW_WINDOW,
        metrics_host: str = "127.0.0.1",
        metrics_port: int | None = None,
    ) -> None:
        self.token = token
        if control_plane is not None and authorizer is not None:
            raise ValueError("pass either control_plane or authorizer, not both")
        # The authorization seam. Default preserves the original single-shared-token
        # behavior; an alternative authorizer (e.g. database-backed) can be injected
        # via the CHUTE_AUTHORIZER knob (see cli.py).
        self.authorizer: Authorizer = authorizer or StaticTokenAuthorizer(token)
        # The control-plane seam. For now it wraps the existing authorizer hook; a
        # sidecar/hosted implementation can later return finite leases, revocations,
        # and richer budgets without putting those concerns in the visitor hot path.
        self.control_plane: ControlPlane = control_plane or AuthorizerControlPlane(self.authorizer)
        # Optional open-core lifecycle seam. The default is no-op, preserving a
        # fully standalone self-hosted server. A control plane can require the
        # tunnel_opened event to succeed before an agent is accepted.
        self.event_sink: EventSink = event_sink or NoopEventSink()
        self.event_timeout = event_timeout
        self.require_event_sink = require_event_sink
        if require_event_sink and isinstance(self.event_sink, NoopEventSink):
            raise ValueError("require_event_sink needs a configured event sink")
        self._event_queue: asyncio.Queue[_QueuedEvent] = asyncio.Queue(maxsize=_EVENT_QUEUE_MAX)
        self._event_generated = {method: 0 for method in _EVENT_COUNT_METHODS}
        self._event_queue_enqueued = 0
        self._event_queue_delivered = 0
        self._event_queue_retried = 0
        self._event_queue_dropped = 0
        if policy_poll_interval is None:
            policy_poll_interval = (
                0.0
                if isinstance(self.control_plane, AuthorizerControlPlane)
                else _DEFAULT_POLICY_POLL_INTERVAL
            )
        if policy_poll_interval < 0:
            raise ValueError("policy_poll_interval must be >= 0")
        if max_control_conns < 0:
            raise ValueError("max_control_conns must be >= 0")
        if max_agents < 0:
            raise ValueError("max_agents must be >= 0")
        if max_auth_conns is not None and max_auth_conns < 0:
            raise ValueError("max_auth_conns must be >= 0 or None")
        if max_visitors < 0:
            raise ValueError("max_visitors must be >= 0")
        if max_visitors_per_ip is not None and max_visitors_per_ip < 1:
            raise ValueError("max_visitors_per_ip must be >= 1 or None")
        if not math.isfinite(hello_timeout) or hello_timeout <= 0:
            raise ValueError("hello_timeout must be a positive finite number")
        if not math.isfinite(auth_timeout) or auth_timeout <= 0:
            raise ValueError("auth_timeout must be a positive finite number")
        if not math.isfinite(event_timeout) or event_timeout <= 0:
            raise ValueError("event_timeout must be a positive finite number")
        if relay_idle_timeout is not None and (
            not math.isfinite(relay_idle_timeout) or relay_idle_timeout <= 0
        ):
            raise ValueError("relay_idle_timeout must be a positive finite number or None")
        if metrics_port is not None:
            if metrics_port < 0:
                raise ValueError("metrics_port must be >= 0 or None")
            if not _is_loopback(metrics_host):
                raise ValueError("metrics listener is loopback-only")
        self.policy_poll_interval = policy_poll_interval
        self.relay_idle_timeout = relay_idle_timeout
        self.mux_flow_window = validate_flow_window(mux_flow_window, name="mux_flow_window")
        self.metrics_host = metrics_host
        self.metrics_port = metrics_port
        self.public_host = public_host
        self.public_port = public_port
        self.control_host = control_host
        self.control_port = control_port
        self.public_url = public_url or f"http://{public_host}:{public_port}/"
        self.ssl_context = ssl_context

        # Unified tunnel registry. With base_domain set, visitors select a label by
        # Host. Without it, every valid HTTP request routes to the reserved internal
        # default label. Everything after selection uses the same registry/relay path.
        self.base_domain = base_domain.lower().strip(".") if base_domain else None
        # Host routing is loopback-only by construction. Its router commits the whole
        # connection to one agent on the first request, so it is only safe behind a
        # proxy that gives it one request per connection (see README "Security
        # model"). We refuse a routable bind rather than warn-and-run: a public
        # Host-routed port is a cross-tenant request-bleed waiting to happen.
        if self.base_domain and not _is_loopback(public_host):
            raise ValueError(
                f"Host routing (base_domain={self.base_domain!r}) is loopback-only, but "
                f"public_host={public_host!r} is routable. Bind 127.0.0.1 and put a "
                "normalizing reverse proxy (one request per upstream connection) in front."
            )
        self.upstream_tls = upstream_tls
        self._agents: dict[str, TunnelRegistration] = {}
        # Labels reserved by agent registrations that passed local admission but are
        # still waiting on pre-ready I/O such as required event-sink delivery.
        self._pending_agents: dict[str, TunnelRegistration] = {}
        # Reverse indexes lease id -> labels, so revocation policy applies
        # directly instead of scanning every active/pending tunnel for each lease.
        self._lease_labels: dict[str, set[str]] = {}
        self._pending_lease_labels: dict[str, set[str]] = {}
        # Reverse index account id -> live labels, for per-account caps and same-account
        # reclaim. Single-tenant uses the same registry under _DEFAULT_LABEL.
        self._account_labels: dict[str, set[str]] = {}
        # Latest policy-pushed account budgets. Registration.budget is the admission
        # default; this map lets detached in-flight relay work observe live updates.
        self._account_budget_overrides: dict[str, Budget] = {}
        # Active visitor streams reserved per account. This intentionally survives
        # tunnel deregistration while in-flight streams drain, so a revoked/replaced
        # tunnel cannot temporarily escape its account's visitor budget.
        self._account_active_visitors: dict[str, int] = {}
        # Per-account byte-rate limiter state. Created only for accounts with a
        # max_bytes_per_sec budget and pruned once the account has no local work.
        self._account_bandwidth: dict[str, _BandwidthSchedule] = {}
        # Relay-local unread mux payload bytes by account. This is always tracked,
        # even before a finite Budget.max_buffered_bytes arrives from a policy update,
        # so newly-applied memory budgets start from the true current queue depth.
        self._account_buffered: dict[str, int] = {}
        self._policy_version = 0
        self._policy_update_poll_failures = 0
        self._policy_updates_applied = 0
        self._policy_updates_rejected = 0
        self._lease_renewals_succeeded = 0
        self._lease_renewals_failed = 0
        self._lease_renewals_invalid = 0
        self._lease_renewals_revoked = 0
        self._lease_revocations = 0
        self._lease_expirations = 0
        self._policy_poll_fraction = self._stable_fraction(
            f"{socket.gethostname()}:{self.control_host}:{self.control_port}:"
            f"{self.public_host}:{self.public_port}:{self.base_domain or ''}"
        )
        # Registry decisions were historically await-free and therefore atomic on the
        # event loop. Event sinks add awaited work before ready; this lock keeps label
        # assignment/replacement decisions serialized while old tunnels continue serving.
        self._registration_lock = asyncio.Lock()
        # Per-IP failed-auth timestamps (monotonic), pruned opportunistically.
        self._auth_fails: dict[str, list[float]] = {}
        # Per-account successful control-connect timestamps. This protects the
        # relay from valid-account reconnect storms after admission identifies
        # ownership; it does not replace control-plane auth.
        self._account_reconnects: dict[str, list[float]] = {}
        # Cumulative process-local relay byte counters. They count bytes after the
        # relay has forwarded them across the mux or to the visitor socket.
        self._relay_bytes_to_agent = 0
        self._relay_bytes_to_visitor = 0
        # Rate-limit metadata-only data-path failure logs. Keyed by reason/scope;
        # capped so attacker-controlled hosts/IPs can't grow it without bound.
        self._data_path_log_state: dict[tuple[str, str], tuple[float, int]] = {}

        # Pre-auth / concurrency backstops (framing & rate only; never payload).
        self.hello_timeout = hello_timeout
        self.auth_timeout = auth_timeout
        self.max_agents = max_agents
        self.max_control_conns = max_control_conns
        self.max_auth_conns = max_auth_conns if max_auth_conns is not None else max_control_conns
        self.max_visitors = max_visitors
        self.max_visitors_per_ip = max_visitors_per_ip
        self._control_in_flight = 0
        self._auth_in_flight = 0
        self._visitors_in_flight = 0
        self._control_busy = 0
        self._auth_busy = 0
        self._visitor_pool_busy = 0
        self._visitor_ip_limited = 0
        # Direct public edge mode sees the true visitor peer here. Host-routed
        # loopback mode only sees nginx, so true client-IP concurrency belongs to
        # nginx's limit_conn there.
        self._visitor_ips: dict[str, int] = {}
        self._control_sem = asyncio.Semaphore(max_control_conns)
        self._auth_sem = asyncio.Semaphore(
            max_auth_conns if max_auth_conns is not None else max_control_conns
        )
        self._visitor_sem = asyncio.Semaphore(max_visitors)

        # Optional public HTTPS terminated at this edge (standalone, no nginx):
        # TLS ends here, decrypted bytes flow through the SAME relay the http
        # path uses, so the agent still gets plaintext and the key stays on the
        # VPS. Behind nginx you leave this unset and pass upstream_tls=True.
        self.tls_cert = Path(tls_cert) if tls_cert else None
        self.tls_key = Path(tls_key) if tls_key else None
        self.public_tls_port = public_tls_port
        self.public_https_url = public_https_url
        self.cert_reload_interval = cert_reload_interval
        self._public_tls_context: ssl.SSLContext | None = None
        self._active_public_tls_context: ssl.SSLContext | None = None
        if self.tls_cert and self.tls_key:
            self._public_tls_context = certs.server_ssl_context(self.tls_cert, self.tls_key)
            self._public_tls_context.sni_callback = self._select_public_tls_context
            self._active_public_tls_context = self._public_tls_context

    @property
    def _https_available(self) -> bool:
        """Can we hand out https:// URLs? Either we terminate TLS at the edge,
        or something upstream (nginx) does it for us."""
        return self._active_public_tls_context is not None or self.upstream_tls

    def _select_public_tls_context(
        self,
        ssl_sock: ssl.SSLSocket | ssl.SSLObject,
        _server_name: str | None,
        _initial_context: ssl.SSLContext,
    ) -> None:
        active = self._active_public_tls_context
        if active is not None:
            ssl_sock.context = active

    def _log_data_path(
        self,
        level: int,
        reason: str,
        *,
        label: str | None = None,
        account_id: str | None = None,
        host: str | None = None,
        visitor_ip: str | None = None,
        stream_id: int | None = None,
        detail: str | None = None,
    ) -> None:
        """Metadata-only, rate-limited data-path failure log.

        Never pass request targets, headers beyond validated Host, or body bytes here.
        The goal is operator diagnosis without turning chute into an HTTP logger.
        """
        scope = label or host or visitor_ip or "-"
        key = (reason, scope)
        now = time.monotonic()
        existing = self._data_path_log_state.get(key)
        if existing is not None:
            last, suppressed = existing
            if now - last < _DATA_PATH_LOG_INTERVAL:
                self._data_path_log_state[key] = (last, suppressed + 1)
                return
        else:
            while len(self._data_path_log_state) >= _DATA_PATH_LOG_MAX_KEYS:
                self._data_path_log_state.pop(next(iter(self._data_path_log_state)))
            suppressed = 0

        fields = [f"reason={reason}"]
        for name, value in (
            ("label", label),
            ("account_id", account_id),
            ("host", host),
            ("visitor_ip", visitor_ip),
            ("stream_id", stream_id),
            ("detail", detail),
        ):
            if value is not None:
                fields.append(f"{name}={value!r}")
        if suppressed:
            fields.append(f"suppressed={suppressed}")
        log.log(level, "data path | %s", " ".join(fields))
        self._data_path_log_state[key] = (now, 0)

    async def serve(self) -> None:
        control = await websockets.serve(
            self._handle_agent,
            self.control_host,
            self.control_port,
            ssl=self.ssl_context,
            ping_interval=20,
            ping_timeout=20,
            # Bound the pre-auth surface: finite message/frame/write caps stop
            # unbounded buffering, and compression=None removes the permessage-
            # deflate decompression-bomb vector. These limit ONLY chute's framing.
            max_size=_MAX_WS_MESSAGE,
            max_queue=_WS_MAX_QUEUE,
            write_limit=_WS_WRITE_LIMIT,
            compression=None,
        )
        public = None
        public_tls = None
        metrics = None
        background: list[asyncio.Task[None]] = []
        event_worker: asyncio.Task[None] | None = None
        try:
            public = await asyncio.start_server(
                self._handle_visitor,
                self.public_host,
                self.public_port,
                limit=_STREAM_READER_LIMIT,
            )
            if self._public_tls_context is not None:
                public_tls = await asyncio.start_server(
                    self._handle_visitor,
                    self.public_host,
                    self.public_tls_port,
                    ssl=self._public_tls_context,
                    limit=_STREAM_READER_LIMIT,
                )
            if self.metrics_port is not None:
                metrics = await asyncio.start_server(
                    self._handle_metrics,
                    self.metrics_host,
                    self.metrics_port,
                    limit=_METRICS_REQUEST_HEAD_LIMIT,
                )
        except BaseException:
            with contextlib.suppress(Exception):
                control.close()
            if public is not None:
                public.close()
            if public_tls is not None:
                public_tls.close()
            if metrics is not None:
                metrics.close()
            for srv in (public, public_tls, metrics):
                if srv is not None:
                    with contextlib.suppress(Exception):
                        await asyncio.wait_for(srv.wait_closed(), timeout=5.0)
            with contextlib.suppress(Exception):
                await asyncio.wait_for(control.wait_closed(), timeout=5.0)
            raise
        log.info(
            "chute up | %s | http %s:%s | %s | control %s:%s | %s",
            f"host-routed *.{self.base_domain}" if self.base_domain else "default-route",
            self.public_host,
            self.public_port,
            f"https {self.public_host}:{self.public_tls_port}" if public_tls else "edge-https off",
            self.control_host,
            self.control_port,
            "wss" if self.ssl_context else "ws (NO TLS)",
        )
        if metrics is not None:
            log.info("metrics listening on %s:%s", self.metrics_host, self.metrics_port)
        _systemd_notify("READY=1\nSTATUS=chute accepting tunnels")
        # Graceful shutdown. SIGTERM (systemd) and SIGINT (Ctrl-C) stop accepting new
        # work and DRAIN in-flight requests instead of hard-dropping every tunnel --
        # the zero-drop restart the HA story needs. add_signal_handler isn't available
        # on every platform/loop (e.g. a non-main-thread loop in tests), so degrade
        # cleanly where it raises.
        shutdown = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            with contextlib.suppress(NotImplementedError, RuntimeError, ValueError):
                loop.add_signal_handler(sig, shutdown.set)

        background.append(asyncio.ensure_future(self._log_stats()))
        watchdog_interval = _systemd_watchdog_interval()
        if watchdog_interval is not None:
            background.append(asyncio.ensure_future(_systemd_watchdog(watchdog_interval)))
        if public_tls is not None:
            background.append(asyncio.ensure_future(self._watch_cert()))
        if self.policy_poll_interval > 0:
            background.append(asyncio.ensure_future(self._poll_policy_updates()))
        if not isinstance(self.event_sink, NoopEventSink):
            event_worker = asyncio.ensure_future(self._run_event_queue())
            background.append(event_worker)

        try:
            await shutdown.wait()
        finally:
            for sig in (signal.SIGTERM, signal.SIGINT):
                with contextlib.suppress(NotImplementedError, RuntimeError, ValueError):
                    loop.remove_signal_handler(sig)
            # A real signal => graceful drain; a plain cancel (e.g. test teardown) =>
            # timeout 0, so we GOAWAY + close at once instead of waiting on streams.
            timeout = _GRACEFUL_DRAIN_TIMEOUT if shutdown.is_set() else 0.0
            muxes = self._live_muxes()
            if shutdown.is_set():
                log.info("shutdown: stop accepting, drain %d agent(s)", len(muxes))
                _systemd_notify("STOPPING=1\nSTATUS=chute draining tunnels")
            # Stop NEW connections. close_connections=False keeps the live agent control
            # channels up so we can drain them gracefully below; the public listener's
            # in-flight visitor sockets keep flowing until their stream ends.
            with contextlib.suppress(Exception):
                control.close(close_connections=False)
            public.close()
            if public_tls is not None:
                public_tls.close()
            if metrics is not None:
                metrics.close()
            # Keep the event worker alive while mux teardown emits final lifecycle
            # events. On Python 3.11, canceling a Queue.get waiter and then enqueueing
            # before it resumes can lose the intended worker shutdown.
            for task in background:
                if task is not event_worker:
                    task.cancel()
            # GOAWAY each agent and wait (bounded) for its in-flight visitor streams to
            # finish, then close. A permanent SSE/WS stream is force-closed at the deadline.
            await asyncio.gather(*(mux.drain(timeout) for mux in muxes), return_exceptions=True)
            for srv in (public, public_tls, metrics):
                if srv is not None:
                    with contextlib.suppress(Exception):
                        await asyncio.wait_for(srv.wait_closed(), timeout=5.0)
            with contextlib.suppress(Exception):
                await asyncio.wait_for(control.wait_closed(), timeout=5.0)
            if event_worker is not None:
                event_worker.cancel()
            if background:
                await asyncio.gather(*background, return_exceptions=True)

    def _live_muxes(self) -> list[Mux]:
        """Every currently-registered agent mux."""
        return [registration.mux for registration in self._agents.values()]

    async def _poll_policy_updates(self) -> None:
        """Fetch versioned policy deltas outside the visitor hot path."""

        while True:
            await asyncio.sleep(self._policy_poll_delay())
            try:
                await asyncio.wait_for(self._auth_sem.acquire(), timeout=self.auth_timeout)
            except TimeoutError:
                self._auth_busy += 1
                log.warning("policy update poll busy; keeping last-good policy")
                continue
            self._auth_in_flight += 1
            try:
                try:
                    update = await asyncio.wait_for(
                        self.control_plane.poll_policy_updates(self._policy_update_request()),
                        timeout=self.auth_timeout,
                    )
                except Exception:
                    self._policy_update_poll_failures += 1
                    log.warning("policy update poll failed; keeping last-good policy")
                    continue
            finally:
                self._auth_in_flight -= 1
                self._auth_sem.release()
            if update is not None:
                self._apply_policy_update(update)

    def _policy_poll_delay(self) -> float:
        return self.policy_poll_interval * (0.8 + (0.4 * self._policy_poll_fraction))

    def _policy_update_request(self) -> PolicyUpdateRequest:
        return PolicyUpdateRequest(
            current_version=self._policy_version,
            active_lease_count=self._active_lease_count(),
            active_lease_ids=(
                self._active_lease_ids()
                if getattr(
                    self.control_plane,
                    "include_active_lease_ids_in_policy_poll",
                    False,
                )
                else ()
            ),
        )

    def _active_lease_count(self) -> int:
        return len(self._agents) + len(self._pending_agents)

    def _active_lease_ids(self) -> tuple[str, ...]:
        return tuple(
            sorted(
                {
                    registration.lease_id
                    for registration in (
                        *self._agents.values(),
                        *self._pending_agents.values(),
                    )
                    if registration.lease_id is not None
                }
            )
        )

    def _apply_policy_update(self, update: object) -> bool:
        """Apply a versioned policy delta, or keep last-good state if invalid."""

        if not isinstance(update, PolicyUpdate) or not self._valid_policy_update(update):
            self._policy_updates_rejected += 1
            log.warning(
                "rejected invalid policy update version=%r", getattr(update, "version", None)
            )
            return False
        for lease_id in update.revoke_lease_ids:
            self.revoke_lease(lease_id)
        for revocation in update.lease_revocations:
            self.revoke_lease(revocation.lease_id, action=revocation.action)
        for budget_update in update.account_budgets:
            self._set_account_budget(budget_update.account_id, budget_update.budget)
        self._policy_version = update.version
        self._policy_updates_applied += 1
        return True

    def _valid_policy_update(self, update: PolicyUpdate) -> bool:
        if not isinstance(update.version, int) or isinstance(update.version, bool):
            return False
        if update.version <= self._policy_version:
            return False
        if not isinstance(update.revoke_lease_ids, tuple):
            return False
        if len(update.revoke_lease_ids) > _MAX_POLICY_UPDATE_REVOKE_LEASE_IDS:
            return False
        revoked_lease_ids: set[str] = set()
        for lease_id in update.revoke_lease_ids:
            if not isinstance(lease_id, str) or not lease_id:
                return False
            if lease_id in revoked_lease_ids:
                return False
            revoked_lease_ids.add(lease_id)
        if not isinstance(update.lease_revocations, tuple):
            return False
        if len(update.lease_revocations) > _MAX_POLICY_UPDATE_LEASE_REVOCATIONS:
            return False
        for revocation in update.lease_revocations:
            if not isinstance(revocation, LeaseRevocation):
                return False
            if not isinstance(revocation.lease_id, str) or not revocation.lease_id:
                return False
            if revocation.action not in ("drain", "close"):
                return False
            if revocation.lease_id in revoked_lease_ids:
                return False
            revoked_lease_ids.add(revocation.lease_id)
        if not isinstance(update.account_budgets, tuple):
            return False
        if len(update.account_budgets) > _MAX_POLICY_UPDATE_ACCOUNT_BUDGETS:
            return False
        seen_accounts: set[str] = set()
        for budget_update in update.account_budgets:
            if not isinstance(budget_update, AccountBudgetUpdate):
                return False
            if not isinstance(budget_update.account_id, str) or not budget_update.account_id:
                return False
            if budget_update.account_id in seen_accounts:
                return False
            seen_accounts.add(budget_update.account_id)
            if not self._valid_budget(budget_update.budget):
                return False
        return True

    def _set_account_budget(self, account_id: str, budget: Budget) -> None:
        if not self._account_has_local_work(account_id):
            self._account_budget_overrides.pop(account_id, None)
            return
        self._account_budget_overrides[account_id] = budget
        for label in self._account_labels.get(account_id, ()):
            registration = self._agents.get(label)
            if registration is not None:
                registration.budget = budget

    def _account_has_local_work(self, account_id: str) -> bool:
        if account_id in self._account_labels:
            return True
        if self._account_active_streams(account_id) > 0:
            return True
        if self._account_buffered.get(account_id, 0) > 0:
            return True
        return any(
            registration.account_id == account_id for registration in self._pending_agents.values()
        )

    def _account_budget_for(self, account_id: str, default: Budget) -> Budget:
        return self._account_budget_overrides.get(account_id, default)

    def _account_budget(self, registration: TunnelRegistration) -> Budget:
        return self._account_budget_for(registration.account_id, registration.budget)

    def _valid_budget(self, budget: Budget) -> bool:
        if not isinstance(budget, Budget):
            return False
        return all(
            self._valid_optional_limit(value)
            for value in (
                budget.max_visitors,
                budget.max_bytes_per_sec,
                budget.max_reconnects_per_min,
                budget.max_buffered_bytes,
            )
        )

    def _valid_optional_limit(self, value: int | None) -> bool:
        if value is None:
            return True
        return isinstance(value, int) and not isinstance(value, bool) and value >= 0

    async def _emit_event(self, method: str, event: object, *, required: bool = False) -> bool:
        """Emit one lifecycle event through the optional sink.

        Best-effort events enqueue and return so visitor/relay hot paths don't
        wait on a database/exporter. The queue is bounded; overflow drops the
        event and logs once through the usual logging path. Required events stay
        synchronous so the caller can fail closed before advertising an accepted
        tunnel.
        """
        if method in self._event_generated:
            self._event_generated[method] += 1
        if isinstance(self.event_sink, NoopEventSink):
            return True
        if not required:
            try:
                self._event_queue.put_nowait(_QueuedEvent(method, event))
            except asyncio.QueueFull:
                self._event_queue_dropped += 1
                log.warning("event sink queue full; dropping %s", method)
                return False
            self._event_queue_enqueued += 1
            return True
        return await self._send_event_now(method, event, required=True)

    async def _send_event_now(self, method: str, event: object, *, required: bool = False) -> bool:
        try:
            handler = getattr(self.event_sink, method)
            await asyncio.wait_for(handler(event), timeout=self.event_timeout)
        except Exception as exc:
            log.warning("event sink %s failed: %s", method, exc)
            if required:
                raise
            return False
        return True

    async def _run_event_queue(self) -> None:
        """Drain best-effort lifecycle/stat events outside visitor hot paths."""

        while True:
            item = await self._event_queue.get()
            delivered = await self._send_event_now(item.method, item.event)
            if delivered:
                self._event_queue_delivered += 1
                continue
            if item.attempts + 1 >= _EVENT_RETRY_ATTEMPTS:
                self._event_queue_dropped += 1
                log.warning("event sink dropped %s after retries", item.method)
                continue
            await asyncio.sleep(_EVENT_RETRY_DELAY)
            try:
                self._event_queue.put_nowait(
                    _QueuedEvent(item.method, item.event, item.attempts + 1)
                )
            except asyncio.QueueFull:
                self._event_queue_dropped += 1
                log.warning("event sink queue full; dropping retry for %s", item.method)
            else:
                self._event_queue_retried += 1

    async def _emit_auth_rejected(
        self,
        reason: str,
        *,
        agent_ip: str | None,
        requested_subdomain: str | None = None,
        scheme: str | None = None,
        account_id: str | None = None,
        credential_id: str | None = None,
    ) -> None:
        await self._emit_event(
            "auth_rejected",
            AuthRejectedEvent(
                reason=reason,
                agent_ip=agent_ip,
                requested_subdomain=requested_subdomain,
                scheme=scheme,
                account_id=account_id,
                credential_id=credential_id,
                at=_dt.datetime.now(_dt.UTC),
            ),
        )

    def _collect_relay_stats(self) -> RelayStatsEvent:
        muxes = self._live_muxes()
        agg: dict[str, int] = {}
        for mux in muxes:
            for key, value in mux.stats().items():
                agg[key] = agg.get(key, 0) + value
        reset_peer = agg.get("reset_peer", 0)
        reset_local = agg.get("reset_local", 0)
        active_accounts = set(self._account_labels) | set(self._account_active_visitors)
        return RelayStatsEvent(
            active_tunnels=len(muxes),
            account_count=len(active_accounts),
            control_capacity=self.max_control_conns,
            control_in_flight=self._control_in_flight,
            auth_capacity=self.max_auth_conns,
            auth_in_flight=self._auth_in_flight,
            visitor_capacity=self.max_visitors,
            visitors_in_flight=self._visitors_in_flight,
            visitor_ip_capacity=self.max_visitors_per_ip,
            visitor_ip_buckets=len(self._visitor_ips),
            control_busy=self._control_busy,
            auth_busy=self._auth_busy,
            visitor_pool_busy=self._visitor_pool_busy,
            visitor_ip_limited=self._visitor_ip_limited,
            active_streams=agg.get("active_streams", 0),
            buffered_bytes=agg.get("buffered_bytes", 0),
            queued_frames=agg.get("queued_frames", 0),
            draining_tunnels=agg.get("draining", 0),
            opened_streams=agg.get("opened", 0),
            reset_streams=reset_local + reset_peer,
            reset_peer_streams=reset_peer,
            credit_stalls=agg.get("credit_stall", 0),
            write_stalls=agg.get("write_stall", 0),
            bytes_to_agent=self._relay_bytes_to_agent,
            bytes_to_visitor=self._relay_bytes_to_visitor,
            event_tunnel_opened_generated=self._event_generated["tunnel_opened"],
            event_tunnel_closed_generated=self._event_generated["tunnel_closed"],
            event_visitor_opened_generated=self._event_generated["visitor_opened"],
            event_visitor_closed_generated=self._event_generated["visitor_closed"],
            event_auth_rejected_generated=self._event_generated["auth_rejected"],
            event_visitor_rejected_generated=self._event_generated["visitor_rejected"],
            event_relay_stats_generated=self._event_generated["relay_stats"],
            event_queue_depth=self._event_queue.qsize(),
            event_queue_capacity=self._event_queue.maxsize,
            event_queue_enqueued=self._event_queue_enqueued,
            event_queue_delivered=self._event_queue_delivered,
            event_queue_retried=self._event_queue_retried,
            event_queue_dropped=self._event_queue_dropped,
            policy_version=self._policy_version,
            policy_update_poll_failures=self._policy_update_poll_failures,
            policy_updates_applied=self._policy_updates_applied,
            policy_updates_rejected=self._policy_updates_rejected,
            lease_renewals_succeeded=self._lease_renewals_succeeded,
            lease_renewals_failed=self._lease_renewals_failed,
            lease_renewals_invalid=self._lease_renewals_invalid,
            lease_renewals_revoked=self._lease_renewals_revoked,
            lease_revocations=self._lease_revocations,
            lease_expirations=self._lease_expirations,
            at=_dt.datetime.now(_dt.UTC),
        )

    async def _handle_metrics(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Loopback health/metrics endpoint.

        This is deliberately not a public visitor path: it closes every request,
        logs no request data, and exports only aggregate relay-local counters.
        """

        try:
            target = await self._read_metrics_target(reader)
            if target == b"/healthz":
                response = _plain_response("200 OK", b"ok\n")
            elif target == b"/metrics":
                response = _plain_response(
                    "200 OK",
                    self._render_prometheus_metrics(),
                    content_type=b"text/plain; version=0.0.4; charset=utf-8",
                )
            else:  # pragma: no cover - _read_metrics_target only returns known targets
                response = _plain_response("404 Not Found", b"not found\n")
        except _MetricsRequestError as exc:
            body = (exc.status.split(" ", 1)[1].lower() + "\n").encode()
            response = _plain_response(exc.status, body)
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, TimeoutError):
            response = _plain_response("400 Bad Request", b"bad request\n")
        try:
            writer.write(response)
            await _safe_drain(writer)
        finally:
            _safe_close(writer)

    async def _read_metrics_target(self, reader: asyncio.StreamReader) -> bytes:
        head = await asyncio.wait_for(
            reader.readuntil(b"\r\n\r\n"),
            timeout=_METRICS_REQUEST_TIMEOUT,
        )
        if len(head) > _METRICS_REQUEST_HEAD_LIMIT:
            raise _MetricsRequestError("400 Bad Request")
        try:
            _parse_request_head(head, require_host=False)
        except _BadRequest as exc:
            raise _MetricsRequestError("400 Bad Request") from exc
        request_line = head.split(b"\r\n", 1)[0]
        method, target, _version = request_line.split(b" ")
        if method != b"GET":
            raise _MetricsRequestError("405 Method Not Allowed")
        path = target.split(b"?", 1)[0]
        if path not in (b"/healthz", b"/metrics"):
            raise _MetricsRequestError("404 Not Found")
        return path

    def _render_prometheus_metrics(self) -> bytes:
        stats = self._collect_relay_stats()
        metrics = (
            (
                "chute_active_tunnels",
                "gauge",
                "Currently registered agent tunnels.",
                stats.active_tunnels,
            ),
            (
                "chute_account_count",
                "gauge",
                "Accounts with active local state.",
                stats.account_count,
            ),
            (
                "chute_control_capacity",
                "gauge",
                "Configured concurrent control handshake capacity.",
                stats.control_capacity,
            ),
            (
                "chute_control_in_flight",
                "gauge",
                "Control handshakes currently in flight.",
                stats.control_in_flight,
            ),
            (
                "chute_auth_capacity",
                "gauge",
                "Configured concurrent auth/control-plane call capacity.",
                stats.auth_capacity,
            ),
            (
                "chute_auth_in_flight",
                "gauge",
                "Auth/control-plane calls currently in flight.",
                stats.auth_in_flight,
            ),
            (
                "chute_visitor_capacity",
                "gauge",
                "Configured concurrent public visitor capacity.",
                stats.visitor_capacity,
            ),
            (
                "chute_visitors_in_flight",
                "gauge",
                "Public visitor connections currently in flight.",
                stats.visitors_in_flight,
            ),
            (
                "chute_visitor_ip_capacity",
                "gauge",
                "Configured direct visitor capacity per source bucket; -1 means disabled.",
                stats.visitor_ip_capacity if stats.visitor_ip_capacity is not None else -1,
            ),
            (
                "chute_visitor_ip_buckets",
                "gauge",
                "Direct visitor source buckets currently tracked.",
                stats.visitor_ip_buckets,
            ),
            (
                "chute_control_busy_total",
                "counter",
                "Control handshakes rejected because the control pool was busy.",
                stats.control_busy,
            ),
            (
                "chute_auth_busy_total",
                "counter",
                "Auth/control-plane operations skipped or rejected because the auth pool was busy.",
                stats.auth_busy,
            ),
            (
                "chute_visitor_pool_busy_total",
                "counter",
                "Visitor connections rejected because the visitor pool was busy.",
                stats.visitor_pool_busy,
            ),
            (
                "chute_visitor_ip_limited_total",
                "counter",
                "Visitor connections rejected by the direct source-bucket limit.",
                stats.visitor_ip_limited,
            ),
            (
                "chute_active_streams",
                "gauge",
                "Currently active mux streams.",
                stats.active_streams,
            ),
            (
                "chute_buffered_bytes",
                "gauge",
                "Unread mux payload bytes currently buffered on this relay.",
                stats.buffered_bytes,
            ),
            (
                "chute_queued_frames",
                "gauge",
                "Unread mux DATA frames currently queued on this relay.",
                stats.queued_frames,
            ),
            (
                "chute_draining_tunnels",
                "gauge",
                "Tunnels currently draining GOAWAY.",
                stats.draining_tunnels,
            ),
            (
                "chute_opened_streams_total",
                "counter",
                "Mux streams opened since process start.",
                stats.opened_streams,
            ),
            (
                "chute_reset_streams_total",
                "counter",
                "Mux streams reset locally or by the peer since process start.",
                stats.reset_streams,
            ),
            (
                "chute_reset_peer_streams_total",
                "counter",
                "Mux streams reset by the peer since process start.",
                stats.reset_peer_streams,
            ),
            (
                "chute_credit_stalls_total",
                "counter",
                "Credit-stall stream resets since process start.",
                stats.credit_stalls,
            ),
            (
                "chute_write_stalls_total",
                "counter",
                "Connection write stalls since process start.",
                stats.write_stalls,
            ),
            (
                "chute_bytes_to_agent_total",
                "counter",
                "Payload bytes forwarded from visitors to agents since process start.",
                stats.bytes_to_agent,
            ),
            (
                "chute_bytes_to_visitor_total",
                "counter",
                "Payload bytes forwarded from agents to visitors since process start.",
                stats.bytes_to_visitor,
            ),
            (
                "chute_policy_version",
                "gauge",
                "Last applied control-plane policy version.",
                stats.policy_version,
            ),
            (
                "chute_policy_update_poll_failures_total",
                "counter",
                "Control-plane policy update polls that failed since process start.",
                stats.policy_update_poll_failures,
            ),
            (
                "chute_policy_updates_applied_total",
                "counter",
                "Control-plane policy updates applied since process start.",
                stats.policy_updates_applied,
            ),
            (
                "chute_policy_updates_rejected_total",
                "counter",
                "Control-plane policy updates rejected as invalid since process start.",
                stats.policy_updates_rejected,
            ),
            (
                "chute_lease_renewals_succeeded_total",
                "counter",
                "Lease renewal calls that returned a valid renewed lease since process start.",
                stats.lease_renewals_succeeded,
            ),
            (
                "chute_lease_renewals_failed_total",
                "counter",
                "Lease renewal calls that failed or timed out since process start.",
                stats.lease_renewals_failed,
            ),
            (
                "chute_lease_renewals_invalid_total",
                "counter",
                "Lease renewal calls that returned invalid leases since process start.",
                stats.lease_renewals_invalid,
            ),
            (
                "chute_lease_renewals_revoked_total",
                "counter",
                "Lease renewal calls that explicitly revoked a lease since process start.",
                stats.lease_renewals_revoked,
            ),
            (
                "chute_lease_revocations_total",
                "counter",
                "Registered tunnels retired because their lease was revoked since process start.",
                stats.lease_revocations,
            ),
            (
                "chute_lease_expirations_total",
                "counter",
                "Registered tunnels retired because their lease expired since process start.",
                stats.lease_expirations,
            ),
            (
                "chute_event_tunnel_opened_generated_total",
                "counter",
                "Tunnel-opened lifecycle events generated since process start.",
                stats.event_tunnel_opened_generated,
            ),
            (
                "chute_event_tunnel_closed_generated_total",
                "counter",
                "Tunnel-closed lifecycle events generated since process start.",
                stats.event_tunnel_closed_generated,
            ),
            (
                "chute_event_visitor_opened_generated_total",
                "counter",
                "Visitor-opened lifecycle events generated since process start.",
                stats.event_visitor_opened_generated,
            ),
            (
                "chute_event_visitor_closed_generated_total",
                "counter",
                "Visitor-closed lifecycle events generated since process start.",
                stats.event_visitor_closed_generated,
            ),
            (
                "chute_event_auth_rejected_generated_total",
                "counter",
                "Auth-rejected audit events generated since process start.",
                stats.event_auth_rejected_generated,
            ),
            (
                "chute_event_visitor_rejected_generated_total",
                "counter",
                "Visitor-rejected audit events generated since process start.",
                stats.event_visitor_rejected_generated,
            ),
            (
                "chute_event_relay_stats_generated_total",
                "counter",
                "Relay-stats events generated since process start.",
                stats.event_relay_stats_generated,
            ),
            (
                "chute_event_queue_depth",
                "gauge",
                "Best-effort event sink queue items currently waiting locally.",
                stats.event_queue_depth,
            ),
            (
                "chute_event_queue_capacity",
                "gauge",
                "Best-effort event sink queue capacity on this relay.",
                stats.event_queue_capacity,
            ),
            (
                "chute_event_queue_enqueued_total",
                "counter",
                "Best-effort event sink items enqueued since process start.",
                stats.event_queue_enqueued,
            ),
            (
                "chute_event_queue_delivered_total",
                "counter",
                "Best-effort event sink items delivered since process start.",
                stats.event_queue_delivered,
            ),
            (
                "chute_event_queue_retried_total",
                "counter",
                "Best-effort event sink retry attempts requeued since process start.",
                stats.event_queue_retried,
            ),
            (
                "chute_event_queue_dropped_total",
                "counter",
                "Best-effort event sink items dropped since process start.",
                stats.event_queue_dropped,
            ),
        )
        lines: list[str] = []
        for name, metric_type, help_text, value in metrics:
            lines.append(f"# HELP {name} {help_text}")
            lines.append(f"# TYPE {name} {metric_type}")
            lines.append(f"{name} {value}")
        return ("\n".join(lines) + "\n").encode("utf-8")

    async def _log_stats(self) -> None:
        """Periodically surface a low-cardinality data-path summary.

        The mux tracks stream/buffer/reset/stall gauges and counters; the server
        adds relay byte counters and sends the same snapshot to the optional event
        sink so operators can export it without a built-in metrics backend.
        """
        while True:
            await asyncio.sleep(_STATS_LOG_INTERVAL)
            stats = self._collect_relay_stats()
            if stats.active_tunnels == 0:
                continue
            self._log_relay_stats_snapshot(stats)
            await self._emit_event("relay_stats", stats)

    def _log_relay_stats_snapshot(self, stats: RelayStatsEvent) -> None:
        event_generated = (
            stats.event_tunnel_opened_generated
            + stats.event_tunnel_closed_generated
            + stats.event_visitor_opened_generated
            + stats.event_visitor_closed_generated
            + stats.event_auth_rejected_generated
            + stats.event_visitor_rejected_generated
            + stats.event_relay_stats_generated
        )
        log.info(
            "stats | agents=%d streams=%d visitors=%d/%d control=%d/%d auth=%d/%d "
            "visitor_ip_buckets=%d buffered=%dKiB queued_frames=%d opened=%d "
            "reset=%d(peer=%d) stalls(credit=%d write=%d) "
            "shed(control=%d auth=%d visitor_pool=%d visitor_ip=%d) "
            "policy(version=%d applied=%d rejected=%d poll_failed=%d) "
            "lease(renewed=%d failed=%d invalid=%d renewal_revoked=%d revoked=%d expired=%d) "
            "events(generated=%d queue=%d/%d dropped=%d) "
            "bytes_to_agent=%d bytes_to_visitor=%d",
            stats.active_tunnels,
            stats.active_streams,
            stats.visitors_in_flight,
            stats.visitor_capacity,
            stats.control_in_flight,
            stats.control_capacity,
            stats.auth_in_flight,
            stats.auth_capacity,
            stats.visitor_ip_buckets,
            stats.buffered_bytes // 1024,
            stats.queued_frames,
            stats.opened_streams,
            stats.reset_streams,
            stats.reset_peer_streams,
            stats.credit_stalls,
            stats.write_stalls,
            stats.control_busy,
            stats.auth_busy,
            stats.visitor_pool_busy,
            stats.visitor_ip_limited,
            stats.policy_version,
            stats.policy_updates_applied,
            stats.policy_updates_rejected,
            stats.policy_update_poll_failures,
            stats.lease_renewals_succeeded,
            stats.lease_renewals_failed,
            stats.lease_renewals_invalid,
            stats.lease_renewals_revoked,
            stats.lease_revocations,
            stats.lease_expirations,
            event_generated,
            stats.event_queue_depth,
            stats.event_queue_capacity,
            stats.event_queue_dropped,
            stats.bytes_to_agent,
            stats.bytes_to_visitor,
        )

    async def _watch_cert(self) -> None:
        """Hot-reload the public TLS cert when the files change on disk.

        An external ACME client (dehydrated/lego/certbot via a systemd timer)
        owns issuance + renewal; we just notice the new files, validate them in a
        fresh SSLContext, then atomically make that context active for new
        handshakes. A torn cert/key pair never mutates the live listener context.
        """
        assert self._public_tls_context is not None
        assert self.tls_cert is not None
        assert self.tls_key is not None
        paths = [self.tls_cert, self.tls_key]

        def _mtimes() -> tuple[float, ...] | None:
            try:
                return tuple(p.stat().st_mtime for p in paths)
            except OSError:
                return None

        last = _mtimes()
        while True:
            await asyncio.sleep(self.cert_reload_interval)
            current = _mtimes()
            if current is None or current == last:
                continue
            try:
                next_context = certs.server_ssl_context(self.tls_cert, self.tls_key)
                self._active_public_tls_context = next_context
                last = current
                log.info("reloaded public TLS cert (files changed)")
            except (ssl.SSLError, OSError) as exc:
                log.warning("public TLS cert reload failed: %s", exc)

    # -- control channel -------------------------------------------------------
    async def _handle_agent(self, ws: Any) -> None:
        # Per-IP failed-auth limiter, checked FIRST: an IP that has burned its budget
        # of bad handshakes -- malformed/timed-out hello OR bad token -- is turned away
        # before we spend a sem slot, a JSON parse, or an authorize call on it. Only
        # failures consume budget, so a good token from a clean IP is never throttled.
        agent_ip = ws.remote_address[0] if ws.remote_address else None
        if not self._auth_rate_ok(agent_ip):
            with contextlib.suppress(Exception):
                await ws.close(code=1013, reason="too many auth failures")
            log.warning("rate-limited agent handshakes from %s", ws.remote_address)
            return
        # Bound concurrent PRE-AUTH handshakes: the control port is internet-
        # facing and unauthenticated until the token check below, so an uncapped
        # flood of half-open handshakes could exhaust FDs/CPU. Authenticated,
        # long-lived connections do NOT hold a slot (released before mux.run).
        try:
            await asyncio.wait_for(self._control_sem.acquire(), timeout=self.hello_timeout)
        except TimeoutError:
            self._control_busy += 1
            with contextlib.suppress(Exception):
                await ws.close(code=1013, reason="server busy")
            return
        self._control_in_flight += 1
        try:
            try:
                hello = json.loads(await asyncio.wait_for(ws.recv(), timeout=self.hello_timeout))
            except (
                TimeoutError,
                ValueError,
                TypeError,
                RecursionError,
                websockets.ConnectionClosed,
            ):
                # A malformed/timed-out hello is a failed handshake: record it so a
                # flood from one IP burns the per-IP budget checked at the top (the 4000
                # path now genuinely feeds the limiter). RecursionError: json.loads on
                # deeply-nested (but sub-max_size) JSON raises it -- a RuntimeError
                # subclass, NOT ValueError/TypeError -- so without it here the error
                # would escape as an uncaught 1011 (retryable -> reconnect-loop).
                self._record_auth_fail(agent_ip)
                with contextlib.suppress(Exception):
                    await ws.close(code=4000, reason="bad handshake")
                return
            if not isinstance(hello, dict):
                # non-object JSON (list/int/str/...) -- a failed handshake too.
                self._record_auth_fail(agent_ip)
                with contextlib.suppress(Exception):
                    await ws.close(code=4000, reason="bad handshake")
                return
        finally:
            # Release the pre-auth handshake slot BEFORE authorizing. The semaphore
            # bounds half-open handshakes -- which are over once we have the hello --
            # not the authorize call, which may do slow I/O (e.g. a database lookup)
            # in an alternative authorizer. Holding it across a slow authorize would
            # turn the concurrency cap into a DoS amplifier.
            self._control_in_flight -= 1
            self._control_sem.release()

        try:
            token = self._token_from_hello(hello)
        except _BadHandshake:
            self._record_auth_fail(agent_ip)
            with contextlib.suppress(Exception):
                await ws.close(code=4000, reason="bad handshake")
            return

        # Refuse a peer that doesn't speak our exact protocol version, before any
        # further work. Flow control requires BOTH ends to honor credit windows; a
        # version-mismatched agent would stall or overflow later, so fail it cleanly
        # now with a reason. Fatal on the agent side (it won't retry-spin).
        if hello.get("v") != protocol.VERSION:
            self._record_auth_fail(agent_ip)
            reason = f"protocol v{protocol.VERSION} required; upgrade the chute agent"
            with contextlib.suppress(Exception):
                await ws.send(json.dumps({"type": "error", "reason": reason}))
                await ws.close(code=4004, reason="protocol version")
            log.warning(
                "rejected agent (protocol v=%r, need %r) from %s",
                hello.get("v"),
                protocol.VERSION,
                ws.remote_address,
            )
            return

        try:
            requested_subdomain = self._requested_subdomain_from_hello(hello)
            scheme = self._scheme_from_hello(hello)
            agent_flow_window = self._flow_window_from_hello(hello)
        except _BadHandshake:
            self._record_auth_fail(agent_ip)
            with contextlib.suppress(Exception):
                await ws.close(code=4000, reason="bad handshake")
            return
        except _LabelError as exc:
            self._record_auth_fail(agent_ip)
            with contextlib.suppress(Exception):
                await ws.send(json.dumps({"type": "error", "reason": str(exc)}))
                await ws.close(code=4002, reason=str(exc))
            log.warning("rejected agent label %r: %s", hello.get("subdomain"), exc)
            return

        # Exactly one tunnel-admission call per connect, outside the pre-auth
        # semaphore but inside its own cap/timeout, so a slow database-backed
        # control plane cannot become the new unbounded pre-auth resource.
        try:
            await asyncio.wait_for(self._auth_sem.acquire(), timeout=self.auth_timeout)
        except TimeoutError:
            self._auth_busy += 1
            with contextlib.suppress(Exception):
                await ws.close(code=1013, reason="server busy")
            return
        self._auth_in_flight += 1
        try:
            try:
                admission = await asyncio.wait_for(
                    self.control_plane.admit_tunnel(
                        TunnelAdmissionRequest(
                            token=token,
                            requested_subdomain=requested_subdomain,
                            agent_ip=agent_ip,
                            scheme=scheme,
                            protocol_version=protocol.VERSION,
                        )
                    ),
                    timeout=self.auth_timeout,
                )
            except TimeoutError:
                log.warning("control plane unavailable for agent from %s", ws.remote_address)
                with contextlib.suppress(Exception):
                    await ws.close(code=1013, reason="try again later")
                return
            except Exception:
                log.warning("control plane unavailable for agent from %s", ws.remote_address)
                with contextlib.suppress(Exception):
                    await ws.close(code=1013, reason="try again later")
                return
        finally:
            self._auth_in_flight -= 1
            self._auth_sem.release()
        if admission is None:
            self._record_auth_fail(agent_ip)
            await self._emit_auth_rejected(
                "unauthorized",
                agent_ip=agent_ip,
                requested_subdomain=requested_subdomain,
                scheme=scheme,
            )
            await ws.send(json.dumps({"type": "error", "reason": "unauthorized"}))
            await ws.close(code=4001, reason="unauthorized")
            log.warning("rejected agent (unauthorized) from %s", ws.remote_address)
            return
        if not isinstance(admission, TunnelAdmission) or not self._valid_tunnel_admission(
            admission
        ):
            log.warning(
                "control plane returned invalid tunnel admission from %s",
                ws.remote_address,
            )
            with contextlib.suppress(Exception):
                await ws.close(code=1013, reason="try again later")
            return

        flow_window = min(agent_flow_window, self.mux_flow_window)
        await self._serve_agent(ws, requested_subdomain, scheme, admission, agent_ip, flow_window)

    def _token_from_hello(self, hello: dict[str, Any]) -> str:
        if hello.get("type") != "auth":
            raise _BadHandshake("bad auth type")
        token = hello.get("token")
        if not isinstance(token, str):
            raise _BadHandshake("bad token")
        return token

    def _requested_subdomain_from_hello(self, hello: dict[str, Any]) -> str | None:
        raw = hello.get("subdomain")
        if raw is None:
            return None
        if not isinstance(raw, str):
            raise _BadHandshake("bad subdomain")
        label = raw.lower()
        if not names.valid_label(label):
            raise _LabelError("invalid_subdomain")
        return label

    def _scheme_from_hello(self, hello: dict[str, Any]) -> str:
        raw = hello.get("scheme", "http")
        if not isinstance(raw, str) or raw not in ("http", "https"):
            raise _BadHandshake("bad scheme")
        return raw

    def _flow_window_from_hello(self, hello: dict[str, Any]) -> int:
        raw = hello.get("flow_window", _FLOW_WINDOW)
        try:
            return validate_flow_window(raw)
        except ValueError as exc:
            raise _BadHandshake(str(exc)) from exc

    async def _serve_agent(
        self,
        ws: Any,
        requested_subdomain: str | None,
        scheme: str,
        admission: TunnelAdmission,
        agent_ip: str | None,
        flow_window: int,
    ) -> None:
        auth = admission.to_auth_result()
        label = ""
        public_url = ""
        registration: TunnelRegistration | None = None
        previous: TunnelRegistration | None = None
        renewal_task: asyncio.Task[None] | None = None
        opened_emitted = False
        rejection: tuple[str, int, str, bool] | None = None
        lease_expired = False

        async with self._registration_lock:
            try:
                if self.base_domain:
                    label = self._assign_label(requested_subdomain)
                else:
                    if requested_subdomain is not None:
                        raise _LabelError("subdomain_unsupported")
                    label = _DEFAULT_LABEL
                self._authorize_claim(auth, label)
                if not self._global_agent_budget_ok(label):
                    log.warning("rejected agent label %r: relay tunnel limit", label)
                    rejection = ("server_tunnel_limit", 1013, "server tunnel limit", False)
                else:
                    public_url = self._public_url_for(label, scheme)
                    effective_budget = self._account_budget_for(auth.account_id, auth.budget)
                    if not self._account_reconnect_budget_ok(auth.account_id, effective_budget):
                        log.warning("rate-limited agent reconnect for account %r", auth.account_id)
                        rejection = ("reconnect_limit", 1013, "reconnect limit", False)
                    else:

                        def _on_agent_goaway() -> None:
                            log.info(
                                "agent %r going away; keeping registration accounted "
                                "while it drains",
                                label,
                            )

                        def _reserve_buffer(n: int) -> bool:
                            assert registration is not None
                            return self._try_reserve_account_buffer(registration, n)

                        def _release_buffer(n: int) -> None:
                            assert registration is not None
                            self._release_account_buffer(registration.account_id, n)

                        mux = Mux(
                            ws,
                            on_goaway=_on_agent_goaway,
                            buffer_reserve=_reserve_buffer,
                            buffer_release=_release_buffer,
                            flow_window=flow_window,
                        )
                        registration = TunnelRegistration(
                            mux=mux,
                            account_id=auth.account_id,
                            budget=effective_budget,
                            connection_id=uuid.uuid4().hex,
                            lease_id=admission.lease.lease_id,
                            lease_expires_at=admission.lease.expires_at,
                            lease_observed_at=(
                                _dt.datetime.now(_dt.UTC)
                                if admission.lease.expires_at is not None
                                else None
                            ),
                            lease_generation=admission.lease.generation,
                            credential_id=auth.credential_id,
                            scheme=scheme,
                            public_url=public_url,
                            agent_ip=agent_ip,
                            requested_subdomain=requested_subdomain,
                        )
                        if self._lease_expired(registration):
                            log.warning(
                                "rejected agent %r because admission lease is expired", label
                            )
                            lease_expired = True
                        else:
                            self._pending_agents[label] = registration
                            self._index_pending_registration(label, registration)
            except _LabelError as exc:
                log.warning("rejected agent label %r: %s", requested_subdomain, exc)
                rejection = (str(exc), 4002, str(exc), True)

        if rejection is not None:
            reason, close_code, close_reason, send_error = rejection
            await self._emit_auth_rejected(
                reason,
                agent_ip=agent_ip,
                requested_subdomain=requested_subdomain,
                scheme=scheme,
                account_id=auth.account_id,
                credential_id=auth.credential_id,
            )
            if send_error:
                with contextlib.suppress(Exception):
                    await ws.send(json.dumps({"type": "error", "reason": reason}))
            with contextlib.suppress(Exception):
                await ws.close(code=close_code, reason=close_reason)
            return

        if lease_expired:
            with contextlib.suppress(Exception):
                await ws.close(code=1013, reason="lease expired")
            return

        assert registration is not None
        async with self._registration_lock:
            stale_pending = self._pending_agents.get(label) is not registration
        if stale_pending:
            with contextlib.suppress(Exception):
                await ws.close(code=1013, reason="lease revoked")
            return
        try:
            opened_emitted = await self._emit_event(
                "tunnel_opened",
                TunnelOpenedEvent(
                    connection_id=registration.connection_id,
                    label=label,
                    account_id=registration.account_id,
                    credential_id=registration.credential_id,
                    scheme=registration.scheme,
                    public_url=registration.public_url,
                    agent_ip=registration.agent_ip,
                    requested_subdomain=registration.requested_subdomain,
                    at=_dt.datetime.now(_dt.UTC),
                    lease_id=registration.lease_id,
                ),
                required=self.require_event_sink,
            )
        except Exception:
            log.warning("rejecting agent %r because required event sink failed", label)
            async with self._registration_lock:
                self._drop_pending_if_current(label, registration)
            with contextlib.suppress(Exception):
                await ws.close(code=1013, reason="event sink unavailable")
            return

        async with self._registration_lock:
            stale_pending = self._pending_agents.get(label) is not registration
        if stale_pending:
            if opened_emitted:
                await self._emit_event(
                    "tunnel_closed",
                    TunnelClosedEvent(
                        connection_id=registration.connection_id,
                        label=label,
                        account_id=registration.account_id,
                        credential_id=registration.credential_id,
                        scheme=registration.scheme,
                        agent_ip=registration.agent_ip,
                        at=_dt.datetime.now(_dt.UTC),
                        lease_id=registration.lease_id,
                    ),
                )
            with contextlib.suppress(Exception):
                await ws.close(code=1013, reason="lease revoked")
            return

        ready = {
            "type": "ready",
            "public_url": public_url,
            "subdomain": None if label == _DEFAULT_LABEL else label,
            "flow_window": flow_window,
            "v": protocol.VERSION,
        }
        try:
            await ws.send(json.dumps(ready))
        except Exception:
            async with self._registration_lock:
                self._drop_pending_if_current(label, registration)
            if opened_emitted:
                await self._emit_event(
                    "tunnel_closed",
                    TunnelClosedEvent(
                        connection_id=registration.connection_id,
                        label=label,
                        account_id=registration.account_id,
                        credential_id=registration.credential_id,
                        scheme=registration.scheme,
                        agent_ip=registration.agent_ip,
                        at=_dt.datetime.now(_dt.UTC),
                        lease_id=registration.lease_id,
                    ),
                )
            return

        stale_pending = False
        async with self._registration_lock:
            if self._pending_agents.get(label) is not registration:
                stale_pending = True
            else:
                self._unindex_pending_registration(label, registration)
                self._pending_agents.pop(label, None)
                registration.accepting_visitors = True
                previous = self._install_registration(label, registration)
                renewal_task = self._schedule_lease_renewal(label, registration)
        if stale_pending:
            if opened_emitted:
                await self._emit_event(
                    "tunnel_closed",
                    TunnelClosedEvent(
                        connection_id=registration.connection_id,
                        label=label,
                        account_id=registration.account_id,
                        credential_id=registration.credential_id,
                        scheme=registration.scheme,
                        agent_ip=registration.agent_ip,
                        at=_dt.datetime.now(_dt.UTC),
                        lease_id=registration.lease_id,
                    ),
                )
            with contextlib.suppress(Exception):
                await ws.close(code=4003, reason="superseded")
            return
        if previous is not None:
            log.info("replacing previous agent for label %r (newest wins)", label)
            _schedule_ws_close(previous.mux, 4003, "superseded")

        log.info("agent %r connected from %s -> %s", label, ws.remote_address, public_url)
        try:
            await registration.mux.run()
        finally:
            if renewal_task is not None:
                renewal_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await renewal_task
            self._deregister_if_current(label, registration.mux)
            if opened_emitted:
                await self._emit_event(
                    "tunnel_closed",
                    TunnelClosedEvent(
                        connection_id=registration.connection_id,
                        label=label,
                        account_id=registration.account_id,
                        credential_id=registration.credential_id,
                        scheme=registration.scheme,
                        agent_ip=registration.agent_ip,
                        at=_dt.datetime.now(_dt.UTC),
                        lease_id=registration.lease_id,
                    ),
                )
            log.info("agent %r disconnected", label)

    def _deregister_if_current(self, label: str, mux: Mux) -> None:
        current = self._agents.get(label)
        if current is None or current.mux is not mux:
            return
        del self._agents[label]
        self._unindex_registration(label, current)
        labels = self._account_labels.get(current.account_id)
        if labels is not None:
            labels.discard(label)
            if not labels:
                del self._account_labels[current.account_id]
        self._drop_account_bandwidth_if_idle(current.account_id)

    def _index_registration(self, label: str, registration: TunnelRegistration) -> None:
        self._index_lease_label(self._lease_labels, label, registration)

    def _unindex_registration(self, label: str, registration: TunnelRegistration) -> None:
        self._unindex_lease_label(self._lease_labels, label, registration)

    def _index_pending_registration(self, label: str, registration: TunnelRegistration) -> None:
        self._index_lease_label(self._pending_lease_labels, label, registration)

    def _unindex_pending_registration(self, label: str, registration: TunnelRegistration) -> None:
        self._unindex_lease_label(self._pending_lease_labels, label, registration)

    def _index_lease_label(
        self,
        index: dict[str, set[str]],
        label: str,
        registration: TunnelRegistration,
    ) -> None:
        lease_id = registration.lease_id
        if lease_id is not None:
            index.setdefault(lease_id, set()).add(label)

    def _unindex_lease_label(
        self,
        index: dict[str, set[str]],
        label: str,
        registration: TunnelRegistration,
    ) -> None:
        lease_id = registration.lease_id
        if lease_id is None:
            return
        labels = index.get(lease_id)
        if labels is None:
            return
        labels.discard(label)
        if not labels:
            del index[lease_id]

    def _drop_pending_if_current(self, label: str, registration: TunnelRegistration) -> None:
        if self._pending_agents.get(label) is registration:
            self._unindex_pending_registration(label, registration)
            self._pending_agents.pop(label, None)

    def _schedule_lease_renewal(
        self, label: str, registration: TunnelRegistration
    ) -> asyncio.Task[None] | None:
        if registration.lease_expires_at is None:
            return None
        task = asyncio.create_task(self._renew_lease_until_closed(label, registration))
        _pending_closes.add(task)
        task.add_done_callback(_pending_closes.discard)
        return task

    async def _renew_lease_until_closed(self, label: str, registration: TunnelRegistration) -> None:
        while True:
            if self._agents.get(label) is not registration or registration.mux.draining:
                return
            delay = self._lease_renew_delay(registration)
            if delay is None:
                return
            if delay <= 0:
                self._retire_registration(label, registration, reason="lease expired")
                return
            await asyncio.sleep(delay)
            if self._agents.get(label) is not registration or registration.mux.draining:
                return
            if self._lease_expired(registration):
                self._retire_registration(label, registration, reason="lease expired")
                return
            should_continue = await self._try_renew_lease(label, registration)
            if not should_continue:
                return

    def _lease_renew_delay(self, registration: TunnelRegistration) -> float | None:
        remaining = self._lease_seconds_remaining(registration)
        if remaining is None:
            return None
        if remaining <= 0:
            return 0.0
        if remaining <= 1.0:
            delay = remaining * 0.5
            return max(0.01, delay) if remaining >= 0.02 else delay
        expires_at = registration.lease_expires_at
        observed_at = registration.lease_observed_at
        if (
            expires_at is not None
            and observed_at is not None
            and observed_at.tzinfo is not None
            and observed_at.utcoffset() is not None
        ):
            ttl = max(remaining, (expires_at - observed_at).total_seconds())
            fraction = self._lease_renew_fraction(registration)
            target_at = observed_at + _dt.timedelta(seconds=ttl * fraction)
            delay = (target_at - _dt.datetime.now(_dt.UTC)).total_seconds()
            if delay > 0:
                return min(delay, remaining)
        # We are already past the preferred renewal point, usually because a
        # renewal failed or the relay accepted a nearly-expired lease. Retry at a
        # bounded, jittered cadence until local expiry instead of hammering the
        # control plane or waiting blindly for a long lease to lapse.
        return min(30.0 + (20.0 * self._lease_renew_fraction(registration)), remaining)

    def _lease_renew_fraction(self, registration: TunnelRegistration) -> float:
        """Stable per-lease renewal point in the 65-85% lease-lifetime window."""

        value = self._stable_fraction(
            f"{registration.lease_id or ''}:{registration.lease_generation}"
        )
        return 0.65 + (0.20 * value)

    @staticmethod
    def _stable_fraction(seed: str) -> float:
        digest = hashlib.blake2b(seed.encode(), digest_size=8).digest()
        return int.from_bytes(digest, "big") / float(1 << 64)

    async def _try_renew_lease(self, label: str, registration: TunnelRegistration) -> bool:
        expires_at = registration.lease_expires_at
        if registration.lease_id is None or expires_at is None:
            return False
        try:
            await asyncio.wait_for(self._auth_sem.acquire(), timeout=self.auth_timeout)
        except TimeoutError:
            self._auth_busy += 1
            log.warning("lease renewal busy for %r; will retry until expiry", label)
            return True
        self._auth_in_flight += 1
        try:
            try:
                renewed = await asyncio.wait_for(
                    self.control_plane.renew_lease(
                        LeaseRenewalRequest(
                            lease_id=registration.lease_id,
                            account_id=registration.account_id,
                            credential_id=registration.credential_id,
                            label=label,
                            connection_id=registration.connection_id,
                            generation=registration.lease_generation,
                            expires_at=expires_at,
                        )
                    ),
                    timeout=self.auth_timeout,
                )
            except Exception:
                self._lease_renewals_failed += 1
                log.warning("lease renewal failed for %r; will retry until expiry", label)
                return True
        finally:
            self._auth_in_flight -= 1
            self._auth_sem.release()

        if self._agents.get(label) is not registration or registration.mux.draining:
            return False
        if renewed is None:
            self._lease_renewals_revoked += 1
            self._retire_registration(label, registration, reason="lease revoked")
            return False
        if not self._valid_renewed_lease(registration, renewed):
            self._lease_renewals_invalid += 1
            log.warning("lease renewal returned invalid lease for %r; will retry", label)
            return True
        registration.lease_expires_at = renewed.expires_at
        registration.lease_observed_at = (
            _dt.datetime.now(_dt.UTC) if renewed.expires_at is not None else None
        )
        registration.lease_generation = renewed.generation
        if self._lease_expired(registration):
            self._retire_registration(label, registration, reason="lease expired")
            return False
        self._lease_renewals_succeeded += 1
        return True

    def _valid_renewed_lease(self, registration: TunnelRegistration, renewed: TunnelLease) -> bool:
        if not isinstance(renewed, TunnelLease):
            return False
        if renewed.lease_id != registration.lease_id:
            return False
        if renewed.account_id != registration.account_id:
            return False
        if renewed.credential_id != registration.credential_id:
            return False
        if not isinstance(renewed.generation, int) or isinstance(renewed.generation, bool):
            return False
        if renewed.generation < registration.lease_generation:
            return False
        expires_at = renewed.expires_at
        if not isinstance(expires_at, _dt.datetime):
            return False
        if expires_at.tzinfo is None or expires_at.utcoffset() is None:
            return False
        return expires_at > _dt.datetime.now(_dt.UTC)

    def _valid_tunnel_admission(self, admission: TunnelAdmission) -> bool:
        if not isinstance(admission.lease, TunnelLease):
            return False
        lease = admission.lease
        if not isinstance(lease.lease_id, str) or not lease.lease_id:
            return False
        if not isinstance(lease.account_id, str) or not lease.account_id:
            return False
        if lease.credential_id is not None and not isinstance(lease.credential_id, str):
            return False
        if not isinstance(lease.generation, int) or isinstance(lease.generation, bool):
            return False
        if lease.generation < 0:
            return False
        if lease.expires_at is not None:
            if not isinstance(lease.expires_at, _dt.datetime):
                return False
            if lease.expires_at.tzinfo is None or lease.expires_at.utcoffset() is None:
                return False
        if not isinstance(admission.max_tunnels, int) or isinstance(admission.max_tunnels, bool):
            return False
        if admission.max_tunnels < 0:
            return False
        if admission.allowed_label is not None and not isinstance(admission.allowed_label, str):
            return False
        return self._valid_budget(admission.budget)

    def revoke_lease(
        self,
        lease_id: str,
        *,
        drain_timeout: float = _LEASE_EXPIRY_DRAIN_TIMEOUT,
        action: str = "drain",
    ) -> int:
        """Stop routing every current tunnel with *lease_id* and drain it.

        This is the local enforcement hook a future policy watcher can call when a
        control plane revokes a lease. It is synchronous because routing state is
        in-memory and event-loop local; mux draining is scheduled in the background.
        """
        if action not in ("drain", "close"):
            raise ValueError("revocation action must be 'drain' or 'close'")
        if not lease_id:
            return 0
        effective_drain_timeout = 0.0 if action == "close" else drain_timeout
        revoked = 0
        candidates = self._registrations_for_lease(lease_id)
        for label, registration in candidates:
            self._retire_registration(
                label,
                registration,
                reason="lease revoked",
                drain_timeout=effective_drain_timeout,
            )
            revoked += 1
        pending_candidates = self._pending_registrations_for_lease(lease_id)
        for label, registration in pending_candidates:
            if self._retire_pending_registration(
                label,
                registration,
                reason="lease revoked",
            ):
                revoked += 1
        return revoked

    def _registrations_for_lease(self, lease_id: str) -> list[tuple[str, TunnelRegistration]]:
        return self._registrations_for_lease_index(lease_id, self._lease_labels, self._agents)

    def _pending_registrations_for_lease(
        self, lease_id: str
    ) -> list[tuple[str, TunnelRegistration]]:
        return self._registrations_for_lease_index(
            lease_id, self._pending_lease_labels, self._pending_agents
        )

    def _registrations_for_lease_index(
        self,
        lease_id: str,
        index: dict[str, set[str]],
        registrations: dict[str, TunnelRegistration],
    ) -> list[tuple[str, TunnelRegistration]]:
        labels = index.get(lease_id)
        if labels is None:
            # Defensive fallback for tests/custom code that mutate private relay
            # registries directly. Normal registration keeps lease indexes current.
            return [
                (label, registration)
                for label, registration in list(registrations.items())
                if registration.lease_id == lease_id
            ]
        candidates: list[tuple[str, TunnelRegistration]] = []
        stale_labels: list[str] = []
        for label in tuple(labels):
            registration = registrations.get(label)
            if registration is None or registration.lease_id != lease_id:
                stale_labels.append(label)
                continue
            candidates.append((label, registration))
        for label in stale_labels:
            labels.discard(label)
        if not labels:
            index.pop(lease_id, None)
        return candidates

    def _install_registration(
        self, label: str, registration: TunnelRegistration
    ) -> TunnelRegistration | None:
        previous = self._agents.get(label)
        if previous is not None:
            self._unindex_registration(label, previous)
            if previous.account_id != registration.account_id:
                labels = self._account_labels.get(previous.account_id)
                if labels is not None:
                    labels.discard(label)
                    if not labels:
                        del self._account_labels[previous.account_id]
                self._drop_account_bandwidth_if_idle(previous.account_id)
        self._agents[label] = registration
        self._account_labels.setdefault(registration.account_id, set()).add(label)
        self._index_registration(label, registration)
        return previous

    def _retire_registration(
        self,
        label: str,
        registration: TunnelRegistration,
        *,
        reason: str,
        drain_timeout: float = _LEASE_EXPIRY_DRAIN_TIMEOUT,
    ) -> None:
        current = self._agents.get(label)
        if current is not registration:
            return
        registration.accepting_visitors = False
        self._deregister_if_current(label, registration.mux)
        if reason == "lease revoked":
            self._lease_revocations += 1
        elif reason == "lease expired":
            self._lease_expirations += 1
        log.info("agent %r stopped accepting visitors: %s", label, reason)
        _schedule_mux_drain(registration.mux, drain_timeout)

    def _retire_pending_registration(
        self,
        label: str,
        registration: TunnelRegistration,
        *,
        reason: str,
    ) -> bool:
        if self._pending_agents.get(label) is not registration:
            return False
        registration.accepting_visitors = False
        self._drop_pending_if_current(label, registration)
        if reason == "lease revoked":
            self._lease_revocations += 1
        log.info("pending agent %r stopped accepting visitors: %s", label, reason)
        _schedule_ws_close(registration.mux, 1013, reason)
        return True

    def _lease_expired(self, registration: TunnelRegistration) -> bool:
        remaining = self._lease_seconds_remaining(registration)
        return remaining is not None and remaining <= 0

    def _lease_seconds_remaining(self, registration: TunnelRegistration) -> float | None:
        expires_at = registration.lease_expires_at
        if expires_at is None:
            return None
        if expires_at.tzinfo is None or expires_at.utcoffset() is None:
            return 0.0
        return (expires_at - _dt.datetime.now(_dt.UTC)).total_seconds()

    def _assign_label(self, requested: str | None) -> str:
        if requested is not None:
            if not names.valid_label(requested):
                raise _LabelError("invalid_subdomain")
            return requested
        for _ in range(100):  # auto-assign: pick a free, friendly random label
            label = names.random_phrase()
            if label not in self._agents and label not in self._pending_agents:
                return label
        raise _LabelError("no_free_subdomain")  # astronomically unlikely

    def _public_url_for(self, label: str, scheme: str) -> str:
        if scheme == "http":
            return self._http_public_url_for(label)
        if self._https_available:
            return self._https_public_url_for(label)
        raise _LabelError("https_unavailable")

    def _http_public_url_for(self, label: str) -> str:
        if self.base_domain:
            return f"http://{label}.{self.base_domain}/"
        return _with_url_scheme(self.public_url, "http")

    def _https_public_url_for(self, label: str) -> str:
        if self.base_domain:
            return f"https://{label}.{self.base_domain}/"
        if self.public_https_url:
            return self.public_https_url
        if self.upstream_tls:
            return _with_url_scheme(self.public_url, "https")
        raise _LabelError("https_unavailable")

    def _authorize_claim(self, auth: AuthResult, label: str) -> None:
        """Decide whether *auth* may claim *label*; raise _LabelError otherwise."""
        if auth.allowed_label is not None and not isinstance(auth.allowed_label, str):
            raise _LabelError("subdomain_not_allowed")
        allowed_label = auth.allowed_label.lower() if auth.allowed_label is not None else None
        if allowed_label is not None:
            if not names.valid_label(allowed_label) or label != allowed_label:
                raise _LabelError("subdomain_not_allowed")
        held = self._agents.get(label)
        if held is not None and held.account_id != auth.account_id:
            raise _LabelError("subdomain_taken")
        pending = self._pending_agents.get(label)
        if pending is not None:
            raise _LabelError("subdomain_pending")
        owned = set(self._account_labels.get(auth.account_id, ()))
        owned.update(
            pending_label
            for pending_label, pending_registration in self._pending_agents.items()
            if pending_registration.account_id == auth.account_id
        )
        if label not in owned and len(owned) >= auth.max_tunnels:
            raise _LabelError("tunnel_limit")

    def _global_agent_budget_ok(self, label: str) -> bool:
        """True when registering *label* would not grow the relay past its cap."""

        return (
            label in self._agents or len(self._agents) + len(self._pending_agents) < self.max_agents
        )

    def _auth_rate_ok(self, ip: str | None) -> bool:
        """True if *ip* is under its failed-auth budget; prunes this source
        bucket's expired failures as a side effect."""
        key = self._auth_fail_key(ip)
        if key is None:
            return True  # no usable peer address to key a bucket on; don't block
        fails = self._auth_fails.get(key)
        if not fails:
            return True
        now = time.monotonic()
        fresh = [t for t in fails if now - t < _AUTH_FAIL_WINDOW]
        if fresh:
            self._auth_fails[key] = fresh
        else:
            del self._auth_fails[key]
        return len(fresh) < _AUTH_FAIL_MAX

    def _record_auth_fail(self, ip: str | None) -> None:
        """Note a failed auth from *ip*, keeping the map bounded under any input."""
        key = self._auth_fail_key(ip)
        if key is None:
            return
        now = time.monotonic()
        self._auth_fails.setdefault(key, []).append(now)
        if len(self._auth_fails) > _AUTH_FAIL_SWEEP_AT:  # opportunistic stale sweep
            stale = [
                k
                for k, v in self._auth_fails.items()
                if all(now - t >= _AUTH_FAIL_WINDOW for t in v)
            ]
            for k in stale:
                del self._auth_fails[k]
        # Hard cap: a flood of FRESH distinct IPs sweeps nothing above, so cap the map
        # and evict oldest-inserted entries. Bounded memory beats perfect fairness --
        # an evicted attacker merely regains its budget, which this limiter was always
        # best-effort about anyway.
        while len(self._auth_fails) > _AUTH_FAIL_MAX_IPS:
            self._auth_fails.pop(next(iter(self._auth_fails)))

    @staticmethod
    def _auth_fail_key(ip: str | None) -> str | None:
        return _source_ip_bucket(ip, group_ipv6_by_64=True)

    def _account_reconnect_budget_ok(self, account_id: str, budget: Budget) -> bool:
        """Reserve one account reconnect slot if the configured budget allows it."""

        limit = budget.max_reconnects_per_min
        if limit is None:
            return True
        if not self._valid_optional_limit(limit):
            return False
        now = time.monotonic()
        attempts = self._fresh_account_reconnects(account_id, now)
        if len(attempts) >= limit:
            if attempts:
                self._account_reconnects[account_id] = attempts
            else:
                self._account_reconnects.pop(account_id, None)
            return False
        attempts.append(now)
        self._account_reconnects[account_id] = attempts
        if len(self._account_reconnects) > _RECONNECT_SWEEP_AT:
            self._sweep_account_reconnects(now)
        while len(self._account_reconnects) > _RECONNECT_MAX_ACCOUNTS:
            self._account_reconnects.pop(next(iter(self._account_reconnects)))
        return True

    def _fresh_account_reconnects(self, account_id: str, now: float) -> list[float]:
        attempts = self._account_reconnects.get(account_id)
        if not attempts:
            return []
        fresh = [t for t in attempts if now - t < _RECONNECT_WINDOW]
        if fresh:
            self._account_reconnects[account_id] = fresh
        else:
            self._account_reconnects.pop(account_id, None)
        return fresh

    def _sweep_account_reconnects(self, now: float) -> None:
        stale = [
            account_id
            for account_id, attempts in self._account_reconnects.items()
            if all(now - t >= _RECONNECT_WINDOW for t in attempts)
        ]
        for account_id in stale:
            del self._account_reconnects[account_id]

    # -- public side -----------------------------------------------------------
    async def _handle_visitor(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        # OS-level keepalive so a vanished visitor (half-open TCP) is reaped without
        # inspecting bytes -- SSE/WebSocket-safe, unlike an idle-data timeout.
        enable_tcp_keepalive(writer)
        visitor_ip = _peer_ip(writer)
        acquired, visitor_ip_key = self._try_acquire_visitor_ip(visitor_ip)
        if not acquired:
            self._visitor_ip_limited += 1
            self._log_data_path(logging.WARNING, "visitor_ip_limit", visitor_ip=visitor_ip)
            writer.write(_BUSY_RESPONSE)
            await _safe_drain(writer)
            _safe_close(writer)
            return
        # Cap concurrent public connections so a flood can't exhaust FDs / open
        # an unbounded number of mux streams against the agent.
        try:
            try:
                await asyncio.wait_for(
                    self._visitor_sem.acquire(), timeout=_VISITOR_ACQUIRE_TIMEOUT
                )
            except TimeoutError:
                self._visitor_pool_busy += 1
                self._log_data_path(logging.WARNING, "visitor_pool_busy", visitor_ip=visitor_ip)
                writer.write(_BUSY_RESPONSE)
                await _safe_drain(writer)
                _safe_close(writer)
                return
            self._visitors_in_flight += 1
            try:
                await self._handle_visitor_registered(reader, writer)
            finally:
                self._visitors_in_flight -= 1
                self._visitor_sem.release()
        finally:
            self._release_visitor_ip(visitor_ip_key)

    async def _handle_visitor_registered(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            head = await self._read_request_head(reader)
        except asyncio.IncompleteReadError:
            _safe_close(writer)
            return
        except TimeoutError:
            self._log_data_path(
                logging.WARNING, "request_head_timeout", visitor_ip=_peer_ip(writer)
            )
            writer.write(_BAD_REQUEST_RESPONSE)
            await _safe_drain(writer)
            _safe_close(writer)
            return
        except asyncio.LimitOverrunError:
            self._log_data_path(
                logging.WARNING, "request_head_too_large", visitor_ip=_peer_ip(writer)
            )
            writer.write(_BAD_REQUEST_RESPONSE)
            await _safe_drain(writer)
            _safe_close(writer)
            return
        except Exception as exc:
            self._log_data_path(
                logging.INFO,
                "request_head_error",
                visitor_ip=_peer_ip(writer),
                detail=type(exc).__name__,
            )
            writer.write(_BAD_REQUEST_RESPONSE)
            await _safe_drain(writer)
            _safe_close(writer)
            return

        try:
            selection = self._select_agent_for_visitor(head)
        except _BadRequest as exc:
            self._log_data_path(
                logging.INFO,
                "bad_request",
                visitor_ip=_peer_ip(writer),
                detail=str(exc),
            )
            writer.write(_BAD_REQUEST_RESPONSE)
            await _safe_drain(writer)
            _safe_close(writer)
            return
        if selection is None:
            host = _parse_request_head(head, require_host=bool(self.base_domain)).host
            self._log_data_path(
                logging.INFO,
                "no_tunnel",
                host=host,
                visitor_ip=_peer_ip(writer),
            )
            await self._emit_event(
                "visitor_rejected",
                VisitorRejectedEvent(
                    reason="no_tunnel",
                    label=None,
                    account_id=None,
                    credential_id=None,
                    host=host,
                    visitor_ip=_peer_ip(writer),
                    at=_dt.datetime.now(_dt.UTC),
                ),
            )
            if self.base_domain:
                assert host is not None
                writer.write(_no_tunnel_response(host))
            else:
                writer.write(_OFFLINE_RESPONSE)
            await _safe_drain(writer)
            _safe_close(writer)
            return
        _label, registration = selection
        host = _parse_request_head(head, require_host=bool(self.base_domain)).host
        visitor_ip = _peer_ip(writer)

        if not self._try_acquire_visitor_budget(registration):
            self._log_data_path(
                logging.WARNING,
                "account_visitor_limit",
                label=_label,
                account_id=registration.account_id,
                host=host,
                visitor_ip=visitor_ip,
            )
            await self._emit_event(
                "visitor_rejected",
                VisitorRejectedEvent(
                    reason="visitor_limit",
                    label=_label,
                    account_id=registration.account_id,
                    credential_id=registration.credential_id,
                    host=host,
                    visitor_ip=visitor_ip,
                    at=_dt.datetime.now(_dt.UTC),
                ),
            )
            writer.write(_BUSY_RESPONSE)
            await _safe_drain(writer)
            _safe_close(writer)
            return

        try:
            stream = await registration.mux.open()
        except Exception as exc:
            self._release_visitor_budget(registration)
            self._log_data_path(
                logging.WARNING,
                "agent_stream_open_failed",
                label=_label,
                account_id=registration.account_id,
                host=host,
                visitor_ip=visitor_ip,
                detail=type(exc).__name__,
            )
            writer.write(_OFFLINE_RESPONSE)
            await _safe_drain(writer)
            _safe_close(writer)
            return
        visitor_opened = await self._emit_event(
            "visitor_opened",
            VisitorOpenedEvent(
                connection_id=registration.connection_id,
                label=_label,
                account_id=registration.account_id,
                credential_id=registration.credential_id,
                stream_id=stream.id,
                host=host,
                visitor_ip=visitor_ip,
                at=_dt.datetime.now(_dt.UTC),
            ),
        )
        try:
            await self._relay(reader, writer, stream, head, registration, _label, host, visitor_ip)
        finally:
            self._release_visitor_budget(registration)
            if visitor_opened:
                await self._emit_event(
                    "visitor_closed",
                    VisitorClosedEvent(
                        connection_id=registration.connection_id,
                        label=_label,
                        account_id=registration.account_id,
                        credential_id=registration.credential_id,
                        stream_id=stream.id,
                        host=host,
                        visitor_ip=visitor_ip,
                        at=_dt.datetime.now(_dt.UTC),
                    ),
                )

    async def _read_request_head(self, reader: asyncio.StreamReader) -> bytes:
        return await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=_FIRST_BYTE_TIMEOUT)

    def _select_agent_for_visitor(self, head: bytes) -> tuple[str, TunnelRegistration] | None:
        parsed = _parse_request_head(head, require_host=bool(self.base_domain))
        if self.base_domain:
            label = self._label_from_host(parsed.host)
            if label is None:
                return None
        else:
            label = _DEFAULT_LABEL
        registration = self._agents.get(label)
        if registration is None or not registration.accepting_visitors or registration.mux.draining:
            return None
        if self._lease_expired(registration):
            self._retire_registration(label, registration, reason="lease expired")
            return None
        return label, registration

    async def _relay(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        stream: Stream,
        initial: bytes,
        registration: TunnelRegistration,
        label: str,
        host: str | None,
        visitor_ip: str | None,
    ) -> None:
        relay_idle_timeout = self.relay_idle_timeout
        last_activity = asyncio.get_running_loop().time()
        activity = asyncio.Event()

        def mark_activity() -> None:
            nonlocal last_activity
            if relay_idle_timeout is None:
                return
            last_activity = asyncio.get_running_loop().time()
            activity.set()

        async def watch_relay_idle() -> None:
            assert relay_idle_timeout is not None
            loop = asyncio.get_running_loop()
            while True:
                remaining = relay_idle_timeout - (loop.time() - last_activity)
                if remaining <= 0:
                    raise _RelayIdleTimeout(f"no relay bytes for {relay_idle_timeout:g}s")
                activity.clear()
                try:
                    await asyncio.wait_for(activity.wait(), timeout=remaining)
                except TimeoutError as exc:
                    if loop.time() - last_activity >= relay_idle_timeout:
                        raise _RelayIdleTimeout(
                            f"no relay bytes for {relay_idle_timeout:g}s"
                        ) from exc

        async def throttle(n: int) -> None:
            await self._throttle_account_bytes(registration, n)

        def record_to_agent(n: int) -> None:
            self._relay_bytes_to_agent += n
            mark_activity()

        def record_to_visitor(n: int) -> None:
            self._relay_bytes_to_visitor += n
            mark_activity()

        try:
            await throttle(len(initial))
            await stream.send(initial)
            record_to_agent(len(initial))
            reader_task = asyncio.ensure_future(
                _pump_reader_to_stream(reader, stream, throttle, record_to_agent)
            )
            writer_task = asyncio.ensure_future(
                _pump_stream_to_writer(stream, writer, throttle, record_to_visitor)
            )
            idle_task = (
                asyncio.ensure_future(watch_relay_idle())
                if relay_idle_timeout is not None
                else None
            )
            try:
                relay_tasks = {reader_task, writer_task}
                if idle_task is not None:
                    relay_tasks.add(idle_task)
                done, _pending = await asyncio.wait(
                    relay_tasks, return_when=asyncio.FIRST_COMPLETED
                )
                if idle_task is not None and idle_task in done:
                    await idle_task
                if writer_task in done:
                    await writer_task
                    reader_task.cancel()
                    with contextlib.suppress(Exception):
                        await stream.send_eof()
                else:
                    # Visitor EOF is only a half-close: keep the mux->visitor writer
                    # alive so a response body produced after the request ends still
                    # reaches the downstream client.
                    await reader_task
                    if idle_task is not None:
                        done, _pending = await asyncio.wait(
                            {writer_task, idle_task}, return_when=asyncio.FIRST_COMPLETED
                        )
                        if idle_task in done:
                            await idle_task
                    await writer_task
            finally:
                for task in (reader_task, writer_task, idle_task):
                    if task is None:
                        continue
                    task.cancel()
                    with contextlib.suppress(asyncio.CancelledError, Exception):
                        await task
        except Exception as exc:
            self._log_data_path(
                logging.WARNING,
                "relay_aborted",
                label=label,
                account_id=registration.account_id,
                host=host,
                visitor_ip=visitor_ip,
                stream_id=stream.id,
                detail=type(exc).__name__,
            )
            await _safe_reset(stream)
        finally:
            stream.close()
            _safe_close(writer)

    def _account_active_streams(self, account_id: str) -> int:
        """Concurrent visitor streams reserved across the account's tunnels."""

        return self._account_active_visitors.get(account_id, 0)

    def _visitor_budget_exceeded(self, registration: TunnelRegistration) -> bool:
        """True if admitting another visitor would exceed the account's enforced
        ``Budget.max_visitors``. No budget / unlimited -> never exceeded."""
        budget = self._account_budget(registration)
        if budget is None or budget.max_visitors is None:
            return False
        return self._account_active_streams(registration.account_id) >= budget.max_visitors

    def _try_acquire_visitor_budget(self, registration: TunnelRegistration) -> bool:
        """Reserve one visitor stream slot for *registration* if the account allows it."""

        if self._visitor_budget_exceeded(registration):
            return False
        account_id = registration.account_id
        self._account_active_visitors[account_id] = self._account_active_streams(account_id) + 1
        return True

    def _release_visitor_budget(self, registration: TunnelRegistration) -> None:
        account_id = registration.account_id
        current = self._account_active_visitors.get(account_id, 0)
        if current <= 1:
            self._account_active_visitors.pop(account_id, None)
            self._drop_account_bandwidth_if_idle(account_id)
        else:
            self._account_active_visitors[account_id] = current - 1

    def _visitor_ip_key(self, ip: str | None) -> str | None:
        if self.max_visitors_per_ip is None:
            return None
        return _source_ip_bucket(ip, group_ipv6_by_64=True, exempt_loopback=True)

    def _try_acquire_visitor_ip(self, ip: str | None) -> tuple[bool, str | None]:
        limit = self.max_visitors_per_ip
        key = self._visitor_ip_key(ip)
        if limit is None or key is None:
            return True, None
        current = self._visitor_ips.get(key, 0)
        if current >= limit:
            return False, key
        if current == 0 and len(self._visitor_ips) >= _VISITOR_IP_MAX_KEYS:
            return False, key
        self._visitor_ips[key] = current + 1
        return True, key

    def _release_visitor_ip(self, key: str | None) -> None:
        if key is None:
            return
        current = self._visitor_ips.get(key, 0)
        if current <= 1:
            self._visitor_ips.pop(key, None)
        else:
            self._visitor_ips[key] = current - 1

    def _try_reserve_account_buffer(self, registration: TunnelRegistration, n: int) -> bool:
        """Reserve unread mux payload bytes for this account before queueing DATA."""

        if n <= 0:
            return True
        account_id = registration.account_id
        current = self._account_buffered.get(account_id, 0)
        budget = self._account_budget(registration)
        limit = budget.max_buffered_bytes if budget is not None else None
        if limit is not None and (not self._valid_optional_limit(limit) or current + n > limit):
            return False
        self._account_buffered[account_id] = current + n
        return True

    def _release_account_buffer(self, account_id: str, n: int) -> None:
        if n <= 0:
            return
        current = self._account_buffered.get(account_id, 0)
        if current <= n:
            self._account_buffered.pop(account_id, None)
            self._drop_account_bandwidth_if_idle(account_id)
        else:
            self._account_buffered[account_id] = current - n

    async def _throttle_account_bytes(self, registration: TunnelRegistration, n: int) -> None:
        """Apply the account's aggregate byte-rate budget before relaying *n* bytes."""

        if n <= 0:
            return
        budget = self._account_budget(registration)
        limit = budget.max_bytes_per_sec if budget is not None else None
        if limit is None:
            return
        if not self._valid_optional_limit(limit) or limit == 0:
            raise _BandwidthLimitExceeded
        schedule = self._account_bandwidth.get(registration.account_id)
        if schedule is None:
            if len(self._account_bandwidth) >= _BANDWIDTH_MAX_ACCOUNTS:
                self._sweep_idle_bandwidth()
            if len(self._account_bandwidth) >= _BANDWIDTH_MAX_ACCOUNTS:
                raise _BandwidthLimitExceeded
            schedule = _BandwidthSchedule()
            self._account_bandwidth[registration.account_id] = schedule
        loop = asyncio.get_running_loop()
        async with schedule.lock:
            now = loop.time()
            start = max(schedule.next_at, now)
            delay = start - now
            schedule.next_at = start + (n / limit)
        if delay > 0:
            await asyncio.sleep(delay)

    def _sweep_idle_bandwidth(self) -> None:
        for account_id in list(self._account_bandwidth):
            self._drop_account_bandwidth_if_idle(account_id)

    def _drop_account_bandwidth_if_idle(self, account_id: str) -> None:
        if self._account_has_local_work(account_id):
            return
        self._account_bandwidth.pop(account_id, None)
        self._account_budget_overrides.pop(account_id, None)

    def _label_from_host(self, host: str | None) -> str | None:
        if not host or not self.base_domain:
            return None
        host = host.lower().rstrip(".")  # tolerate a trailing FQDN-root dot
        if host == self.base_domain:
            return None  # the apex itself is not a tunnel
        suffix = "." + self.base_domain
        if host.endswith(suffix):
            label = host[: -len(suffix)]
            return label if names.valid_label(label) else None
        return None  # not under our base domain


def _is_loopback(host: str) -> bool:
    return host in ("127.0.0.1", "::1", "localhost")


def _with_url_scheme(url: str, scheme: str) -> str:
    parts = urlsplit(url)
    if parts.scheme:
        return urlunsplit(parts._replace(scheme=scheme))
    return url


def _peer_ip(writer: asyncio.StreamWriter) -> str | None:
    peer = writer.get_extra_info("peername")
    if isinstance(peer, tuple) and peer:
        return str(peer[0])
    if peer is None:
        return None
    return str(peer)


def _source_ip_bucket(
    ip: str | None,
    *,
    group_ipv6_by_64: bool,
    exempt_loopback: bool = False,
) -> str | None:
    """Return the source bucket used by local abuse/concurrency limiters."""

    if ip is None:
        return None
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if isinstance(parsed, ipaddress.IPv6Address):
        mapped = parsed.ipv4_mapped
        if mapped is not None:
            parsed = mapped
    if exempt_loopback and parsed.is_loopback:
        return None
    if group_ipv6_by_64 and isinstance(parsed, ipaddress.IPv6Address):
        network_int = int(parsed) & ~((1 << 64) - 1)
        return str(ipaddress.IPv6Network((network_int, 64)))
    return str(parsed)


# -- request-head parsing -----------------------------------------------------
# We admit HTTP by request head but NEVER rewrite that head -- it is forwarded to
# the agent verbatim. That makes chute the "back-end" in PortSwigger's desync
# model: it can't normalize, so the only safe response to a request a downstream
# hop might read differently is to refuse it. This is a reject-only backstop; the
# public cloud assurance still belongs to nginx's parser and its one-request-per-
# upstream-connection deployment shape.
_TCHARS = frozenset(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&'*+-.^_`|~"
)


def _parse_request_head(head: bytes, *, require_host: bool) -> RequestHead:
    """Validate a buffered HTTP/1.x request head and return its normalized Host.

    The default route may accept HTTP/1.0 without Host. Host-routed mode, and all
    HTTP/1.1 requests, require exactly one valid Host.
    """
    # Bare CR or LF: we split on CRLF and forward verbatim, so a lone LF that a
    # downstream treats as a line end would split the head into a different set of
    # fields than we saw -- a smuggling differential (cf. CVE-2025-22871). A
    # well-formed head is exactly CRLF-delimited, so nothing survives this strip.
    if b"\r" in head.replace(b"\r\n", b"") or b"\n" in head.replace(b"\r\n", b""):
        raise _BadRequest("bare-cr-or-lf")
    lines = head.split(b"\r\n")

    # Request line: METHOD SP request-target SP HTTP-version, with exactly one SP
    # separator in each position. A visitor addresses the tunnel as an origin
    # server, so the target must be origin-form ("/...") or exact asterisk-form
    # ("*"). absolute-form and authority-form carry their own authority, which can
    # disagree with Host, so we refuse them.
    parts = lines[0].split(b" ")
    if (
        len(parts) != 3
        or not _is_http_token(parts[0])
        or not parts[1]
        or parts[2] not in (b"HTTP/1.0", b"HTTP/1.1")
    ):
        raise _BadRequest("bad-request-line")
    _method, target, version = parts
    if target == b"*":
        pass
    elif target.startswith(b"/"):
        pass
    elif target.startswith(b"*"):
        raise _BadRequest("bad-asterisk-target")
    else:
        raise _BadRequest("non-origin-form-target")

    raw_hosts: list[bytes] = []
    for line in lines[1:]:
        if not line:
            break  # the blank line terminates the field block
        if line[:1] in (b" ", b"\t"):
            # A field line starting with SP/HTAB is obs-fold (RFC 9112 §5.2). We
            # never unfold, so a downstream that does would see a different field.
            raise _BadRequest("obs-fold")
        name, sep, value = line.partition(b":")
        if not sep:
            raise _BadRequest("malformed-field")  # a field line requires a colon
        if not _is_http_token(name) or name.strip(b" \t") != name:
            # Whitespace between field name and colon ("Host : x"): RFC 9112 §5.1
            # says a server MUST reject it 400. Also rejects invalid field names.
            raise _BadRequest("ws-before-colon")
        if name.lower() == b"host":
            raw_hosts.append(value)
    # RFC 9110 §7.2: a server MUST 400 an HTTP/1.1 request that lacks a Host,
    # carries more than one Host field line, or has a Host with an invalid value.
    if not raw_hosts:
        if require_host or version == b"HTTP/1.1":
            raise _BadRequest("missing-host")
        return RequestHead(host=None)
    if len(raw_hosts) > 1:
        raise _BadRequest("duplicate-host")
    return RequestHead(host=_validate_host(raw_hosts[0]))


def _host_from_head(head: bytes) -> str:
    """Return the single routable Host (port stripped) from a buffered request
    head, or raise _BadRequest if the head is malformed/ambiguous."""
    parsed = _parse_request_head(head, require_host=True)
    if parsed.host is None:  # pragma: no cover - require_host=True prevents this
        raise _BadRequest("missing-host")
    return parsed.host


def _is_http_token(value: bytes) -> bool:
    return bool(value) and all(b in _TCHARS for b in value)


def _validate_host(value: bytes) -> str:
    """OWS-trim and validate a single Host field value, then strip any port."""
    v = value.strip(b" \t")  # leading/trailing OWS is not part of the field value
    if not v:
        raise _BadRequest("empty-host")
    # A Host is one token (uri-host[:port]): printable ASCII, no SP/CTL/non-ASCII.
    # Junk here is an injection/differential vector, not a missed tunnel, so it is
    # a 400 -- whereas a clean-but-unknown name routes to a 503 "no tunnel here".
    if any(b < 0x21 or b > 0x7E for b in v):
        raise _BadRequest("bad-host-char")
    host = _strip_port(v.decode("ascii")).lower()
    if not host or "@" in host:
        raise _BadRequest("bad-host")
    if host.startswith("["):
        return host
    if ":" in host:
        raise _BadRequest("bad-host")
    rootless = host[:-1] if host.endswith(".") else host
    if not rootless or any(not names.valid_label(part) for part in rootless.split(".")):
        raise _BadRequest("bad-host")
    return host


def _strip_port(host: str) -> str:
    """Return the host with any ``:port`` removed, rejecting (400) a malformed port.
    The port is irrelevant to routing, but a junk port (``:notaport``, ``:-1``,
    ``:99999999``, empty) is an invalid Host value (RFC 9110 §7.2), so we refuse it
    rather than silently dropping a bad suffix and routing anyway."""
    if host.startswith("["):  # IPv6 literal: "[::1]" or "[::1]:443"
        end = host.find("]")
        if end == -1:
            raise _BadRequest("bad-host")  # unterminated literal
        literal = host[1:end]
        try:
            ipaddress.IPv6Address(literal)
        except ValueError as exc:
            raise _BadRequest("bad-host") from exc
        rest = host[end + 1 :]
        if rest:
            if rest[0] != ":":
                raise _BadRequest("bad-host")
            _check_port(rest[1:])
        return host[: end + 1]
    name, sep, port = host.rpartition(":")
    if not sep:
        return host  # no port present
    if not name or ":" in name:
        raise _BadRequest("bad-host")
    _check_port(port)
    return name


def _check_port(port: str) -> None:
    # A present port must be 1-5 digits in 0..65535 (len<=5 keeps int() bounded and
    # sidesteps Python's int-str conversion limit). Empty / non-numeric / out-of-range
    # means the Host is invalid, not just oddly suffixed.
    if not (port.isdigit() and len(port) <= 5 and int(port) <= 65535):
        raise _BadRequest("bad-port")
