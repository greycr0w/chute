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
import html
import json
import logging
import signal
import socket
import ssl
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import websockets

from . import certs, names, protocol
from .auth import Authorizer, AuthResult, Budget, StaticTokenAuthorizer
from .mux import Mux, Stream

log = logging.getLogger("chute.server")

# Cap any single control-channel WebSocket message. chute's own frames are a
# 5-byte prefix + at most one 64 KiB pump read (see _pump_reader_to_stream and
# the agent side), so the largest legitimate frame is ~64 KiB; 256 KiB leaves
# headroom while closing the pre-auth unbounded-buffer / deflate-bomb OOM. This
# bounds chute's OWN framing envelope only -- proxied HTTP rides inside DATA
# frames as <=64 KiB chunks, untouched, so byte-transparency is preserved.
_MAX_WS_MESSAGE = 256 * 1024

# Backstops for the pre-auth control surface and the relay.
_DEFAULT_MAX_CONTROL_CONNS = 256  # concurrent in-flight (pre-auth) handshakes
_DEFAULT_MAX_VISITORS = 2048  # concurrent public connections
_DEFAULT_HELLO_TIMEOUT = 5.0  # seconds an unauthenticated peer may squat
_DEFAULT_AUTH_TIMEOUT = 5.0  # bound authorizer I/O after a valid hello
_VISITOR_ACQUIRE_TIMEOUT = 5.0  # wait for a visitor slot before 503
_FIRST_BYTE_TIMEOUT = 30.0  # visitor must send a complete HTTP request head within this
_DRAIN_TIMEOUT = 120.0  # no-progress write timeout on the relay
_GRACEFUL_DRAIN_TIMEOUT = 10.0  # SIGTERM: max wait for in-flight streams before close
_STATS_LOG_INTERVAL = 300.0  # seconds between data-path summary log lines
_DEFAULT_LABEL = "default"

# Per-IP failed-auth limiter: an IP gets _AUTH_FAIL_MAX bad handshakes per
# _AUTH_FAIL_WINDOW seconds before further connects are turned away (close 1013).
# Only failures count, so a legitimate agent on a clean IP is never throttled.
_AUTH_FAIL_MAX = 5
_AUTH_FAIL_WINDOW = 60.0
# Keep the per-IP failure map bounded under any input: opportunistically sweep stale
# buckets past _SWEEP_AT, and hard-cap the total distinct IPs (evicting oldest-inserted)
# so a flood of FRESH addresses (e.g. a spoofed IPv6 /64) can't grow it without bound.
_AUTH_FAIL_SWEEP_AT = 4096
_AUTH_FAIL_MAX_IPS = 65536


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


@dataclass(slots=True)
class TunnelRegistration:
    mux: Mux
    account_id: str
    budget: Budget


@dataclass(frozen=True, slots=True)
class RequestHead:
    host: str | None


# Strong refs to fire-and-forget close tasks: the event loop keeps only a weak
# reference, so an untracked task could be garbage-collected before it runs.
_pending_closes: set[asyncio.Task[None]] = set()


def _schedule_ws_close(mux: Mux, code: int, reason: str) -> None:
    """Tear down a superseded connection without blocking on a hung peer."""

    async def _close() -> None:
        try:
            await mux.aclose(code=code, reason=reason)
        except Exception:
            pass

    task = asyncio.ensure_future(_close())
    _pending_closes.add(task)
    task.add_done_callback(_pending_closes.discard)


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
        max_visitors: int = _DEFAULT_MAX_VISITORS,
        hello_timeout: float = _DEFAULT_HELLO_TIMEOUT,
        auth_timeout: float = _DEFAULT_AUTH_TIMEOUT,
        max_auth_conns: int | None = None,
        authorizer: Authorizer | None = None,
    ) -> None:
        self.token = token
        # The authorization seam. Default preserves the original single-shared-token
        # behavior; an alternative authorizer (e.g. database-backed) can be injected
        # via the CHUTE_AUTHORIZER knob (see cli.py).
        self.authorizer: Authorizer = authorizer or StaticTokenAuthorizer(token)
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
        # Reverse index account id -> live labels, for per-account caps and same-account
        # reclaim. Single-tenant uses the same registry under _DEFAULT_LABEL.
        self._account_labels: dict[str, set[str]] = {}
        # Per-IP failed-auth timestamps (monotonic), pruned opportunistically.
        self._auth_fails: dict[str, list[float]] = {}

        # Pre-auth / concurrency backstops (framing & rate only; never payload).
        self.hello_timeout = hello_timeout
        self.auth_timeout = auth_timeout
        self._control_sem = asyncio.Semaphore(max_control_conns)
        self._auth_sem = asyncio.Semaphore(max_auth_conns or max_control_conns)
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
        if self.tls_cert and self.tls_key:
            self._public_tls_context = certs.server_ssl_context(self.tls_cert, self.tls_key)

    @property
    def _https_available(self) -> bool:
        """Can we hand out https:// URLs? Either we terminate TLS at the edge,
        or something upstream (nginx) does it for us."""
        return self._public_tls_context is not None or self.upstream_tls

    async def serve(self) -> None:
        control = await websockets.serve(
            self._handle_agent,
            self.control_host,
            self.control_port,
            ssl=self.ssl_context,
            ping_interval=20,
            ping_timeout=20,
            # Bound the pre-auth surface: a finite per-message cap (vs None) stops
            # unbounded buffering, and compression=None removes the permessage-
            # deflate decompression-bomb vector. Both limit ONLY chute's framing.
            max_size=_MAX_WS_MESSAGE,
            compression=None,
        )
        public = await asyncio.start_server(
            self._handle_visitor, self.public_host, self.public_port
        )
        public_tls = None
        if self._public_tls_context is not None:
            public_tls = await asyncio.start_server(
                self._handle_visitor,
                self.public_host,
                self.public_tls_port,
                ssl=self._public_tls_context,
            )
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

        background = [asyncio.ensure_future(self._log_stats())]
        if public_tls is not None:
            background.append(asyncio.ensure_future(self._watch_cert()))

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
            # Stop NEW connections. close_connections=False keeps the live agent control
            # channels up so we can drain them gracefully below; the public listener's
            # in-flight visitor sockets keep flowing until their stream ends.
            with contextlib.suppress(Exception):
                control.close(close_connections=False)
            public.close()
            if public_tls is not None:
                public_tls.close()
            for task in background:
                task.cancel()
            # GOAWAY each agent and wait (bounded) for its in-flight visitor streams to
            # finish, then close. A permanent SSE/WS stream is force-closed at the deadline.
            await asyncio.gather(*(mux.drain(timeout) for mux in muxes), return_exceptions=True)
            for srv in (public, public_tls):
                if srv is not None:
                    with contextlib.suppress(Exception):
                        await asyncio.wait_for(srv.wait_closed(), timeout=5.0)
            with contextlib.suppress(Exception):
                await asyncio.wait_for(control.wait_closed(), timeout=5.0)

    def _live_muxes(self) -> list[Mux]:
        """Every currently-registered agent mux."""
        return [registration.mux for registration in self._agents.values()]

    async def _log_stats(self) -> None:
        """Periodically log a one-line data-path summary so the operator isn't blind to
        live tunnel/stream count, buffer pressure, and reset/stall rates. The mux tracks
        these (Mux.stats); this surfaces them without standing up a metrics server."""
        while True:
            await asyncio.sleep(_STATS_LOG_INTERVAL)
            muxes = self._live_muxes()
            if not muxes:
                continue
            agg: dict[str, int] = {}
            for mux in muxes:
                for key, value in mux.stats().items():
                    agg[key] = agg.get(key, 0) + value
            log.info(
                "stats | agents=%d streams=%d buffered=%dKiB opened=%d "
                "reset=%d(peer=%d) credit_stall=%d write_stall=%d",
                len(muxes),
                agg.get("active_streams", 0),
                agg.get("buffered_bytes", 0) // 1024,
                agg.get("opened", 0),
                agg.get("reset_local", 0) + agg.get("reset_peer", 0),
                agg.get("reset_peer", 0),
                agg.get("credit_stall", 0),
                agg.get("write_stall", 0),
            )

    async def _watch_cert(self) -> None:
        """Hot-reload the public TLS cert when the files change on disk.

        An external ACME client (dehydrated/lego/certbot via a systemd timer)
        owns issuance + renewal; we just notice the new files and load them into
        the live SSLContext, so renewals apply to new connections with no restart.
        """
        assert self._public_tls_context is not None
        paths = [self.tls_cert, self.tls_key]

        def _mtimes() -> tuple[float, ...] | None:
            try:
                return tuple(p.stat().st_mtime for p in paths)  # type: ignore[union-attr]
            except OSError:
                return None

        last = _mtimes()
        while True:
            await asyncio.sleep(self.cert_reload_interval)
            current = _mtimes()
            if current is None or current == last:
                continue
            try:
                self._public_tls_context.load_cert_chain(
                    certfile=str(self.tls_cert), keyfile=str(self.tls_key)
                )
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
            with contextlib.suppress(Exception):
                await ws.close(code=1013, reason="server busy")
            return
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
            self._control_sem.release()

        # Refuse a peer that doesn't speak our exact protocol version, before any
        # further work. Flow control requires BOTH ends to honor credit windows; a
        # version-mismatched agent would stall or overflow later, so fail it cleanly
        # now with a reason. Fatal on the agent side (it won't retry-spin).
        if hello.get("v") != protocol.VERSION:
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

        # Exactly one authorization call per connect, outside the pre-auth semaphore
        # but inside its own cap/timeout, so a slow database-backed authorizer cannot
        # become the new unbounded pre-auth resource.
        try:
            await asyncio.wait_for(self._auth_sem.acquire(), timeout=self.auth_timeout)
        except TimeoutError:
            with contextlib.suppress(Exception):
                await ws.close(code=1013, reason="server busy")
            return
        try:
            try:
                auth = await asyncio.wait_for(
                    self.authorizer.authenticate(
                        str(hello.get("token", "")), requested_subdomain, agent_ip
                    ),
                    timeout=self.auth_timeout,
                )
            except TimeoutError:
                log.warning("authorizer unavailable for agent from %s", ws.remote_address)
                with contextlib.suppress(Exception):
                    await ws.close(code=1013, reason="try again later")
                return
            except Exception:
                log.warning("authorizer unavailable for agent from %s", ws.remote_address)
                with contextlib.suppress(Exception):
                    await ws.close(code=1013, reason="try again later")
                return
        finally:
            self._auth_sem.release()
        if auth is None:
            self._record_auth_fail(agent_ip)
            await ws.send(json.dumps({"type": "error", "reason": "unauthorized"}))
            await ws.close(code=4001, reason="unauthorized")
            log.warning("rejected agent (unauthorized) from %s", ws.remote_address)
            return

        await self._serve_agent(ws, requested_subdomain, scheme, auth)

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

    async def _serve_agent(
        self, ws: Any, requested_subdomain: str | None, scheme: str, auth: AuthResult
    ) -> None:
        try:
            if self.base_domain:
                label = self._assign_label(requested_subdomain)
            else:
                if requested_subdomain is not None:
                    raise _LabelError("subdomain_unsupported")
                label = _DEFAULT_LABEL
            self._authorize_claim(auth, label)
            public_url = self._public_url_for(label, scheme)
        except _LabelError as exc:
            await ws.send(json.dumps({"type": "error", "reason": str(exc)}))
            await ws.close(code=4002, reason=str(exc))
            log.warning("rejected agent label %r: %s", requested_subdomain, exc)
            return

        def _on_agent_goaway() -> None:
            self._deregister_if_current(label, mux)
            log.info("agent %r going away; deregistered while it drains", label)

        mux = Mux(ws, on_goaway=_on_agent_goaway)
        previous = self._agents.get(label)
        self._agents[label] = TunnelRegistration(mux, auth.account_id, auth.budget)
        self._account_labels.setdefault(auth.account_id, set()).add(label)
        if previous is not None:
            log.info("replacing previous agent for label %r (newest wins)", label)
            _schedule_ws_close(previous.mux, 4003, "superseded")

        ready = {
            "type": "ready",
            "public_url": public_url,
            "subdomain": None if label == _DEFAULT_LABEL else label,
            "v": protocol.VERSION,
        }
        await ws.send(json.dumps(ready))
        log.info("agent %r connected from %s -> %s", label, ws.remote_address, public_url)
        try:
            await mux.run()
        finally:
            self._deregister_if_current(label, mux)
            log.info("agent %r disconnected", label)

    def _deregister_if_current(self, label: str, mux: Mux) -> None:
        current = self._agents.get(label)
        if current is None or current.mux is not mux:
            return
        del self._agents[label]
        labels = self._account_labels.get(current.account_id)
        if labels is not None:
            labels.discard(label)
            if not labels:
                del self._account_labels[current.account_id]

    def _assign_label(self, requested: str | None) -> str:
        if requested is not None:
            if not names.valid_label(requested):
                raise _LabelError("invalid_subdomain")
            return requested
        for _ in range(100):  # auto-assign: pick a free, friendly random label
            label = names.random_phrase()
            if label not in self._agents:
                return label
        raise _LabelError("no_free_subdomain")  # astronomically unlikely

    def _public_url_for(self, label: str, scheme: str) -> str:
        if scheme == "http":
            return (
                f"http://{label}.{self.base_domain}/"
                if self.base_domain
                else _with_url_scheme(self.public_url, "http")
            )
        if self.base_domain and self._https_available:
            return f"https://{label}.{self.base_domain}/"
        if not self.base_domain and self.public_https_url:
            return self.public_https_url
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
        owned = self._account_labels.get(auth.account_id, ())
        if label not in owned and len(owned) >= auth.max_tunnels:
            raise _LabelError("tunnel_limit")

    def _auth_rate_ok(self, ip: str | None) -> bool:
        """True if *ip* is under its failed-auth budget; prunes this IP's expired
        failures as a side effect."""
        if ip is None:
            return True  # no usable peer address to key a bucket on; don't block
        fails = self._auth_fails.get(ip)
        if not fails:
            return True
        now = time.monotonic()
        fresh = [t for t in fails if now - t < _AUTH_FAIL_WINDOW]
        if fresh:
            self._auth_fails[ip] = fresh
        else:
            del self._auth_fails[ip]
        return len(fresh) < _AUTH_FAIL_MAX

    def _record_auth_fail(self, ip: str | None) -> None:
        """Note a failed auth from *ip*, keeping the map bounded under any input."""
        if ip is None:
            return
        now = time.monotonic()
        self._auth_fails.setdefault(ip, []).append(now)
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

    # -- public side -----------------------------------------------------------
    async def _handle_visitor(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        # OS-level keepalive so a vanished visitor (half-open TCP) is reaped without
        # inspecting bytes -- SSE/WebSocket-safe, unlike an idle-data timeout.
        _enable_keepalive(writer)
        # Cap concurrent public connections so a flood can't exhaust FDs / open
        # an unbounded number of mux streams against the agent.
        try:
            await asyncio.wait_for(self._visitor_sem.acquire(), timeout=_VISITOR_ACQUIRE_TIMEOUT)
        except TimeoutError:
            writer.write(_BUSY_RESPONSE)
            await _safe_drain(writer)
            _safe_close(writer)
            return
        try:
            await self._handle_visitor_registered(reader, writer)
        finally:
            self._visitor_sem.release()

    async def _handle_visitor_registered(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            head = await self._read_request_head(reader)
        except asyncio.IncompleteReadError:
            _safe_close(writer)
            return
        except Exception:
            writer.write(_BAD_REQUEST_RESPONSE)
            await _safe_drain(writer)
            _safe_close(writer)
            return

        try:
            selection = self._select_agent_for_visitor(head)
        except _BadRequest as exc:
            log.info("rejected request from %s: %s", writer.get_extra_info("peername"), exc)
            writer.write(_BAD_REQUEST_RESPONSE)
            await _safe_drain(writer)
            _safe_close(writer)
            return
        if selection is None:
            if self.base_domain:
                host = _host_from_head(head)
                writer.write(_no_tunnel_response(host))
            else:
                writer.write(_OFFLINE_RESPONSE)
            await _safe_drain(writer)
            _safe_close(writer)
            return
        _label, registration = selection

        if self._visitor_budget_exceeded(registration):
            writer.write(_BUSY_RESPONSE)
            await _safe_drain(writer)
            _safe_close(writer)
            return

        try:
            stream = await registration.mux.open()
        except Exception:
            writer.write(_OFFLINE_RESPONSE)
            await _safe_drain(writer)
            _safe_close(writer)
            return
        await self._relay(reader, writer, stream, head)

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
        return (label, registration) if registration is not None else None

    async def _relay(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        stream: Stream,
        initial: bytes,
    ) -> None:
        try:
            await stream.send(initial)
            reader_task = asyncio.ensure_future(_pump_reader_to_stream(reader, stream))
            writer_task = asyncio.ensure_future(_pump_stream_to_writer(stream, writer))
            try:
                done, _pending = await asyncio.wait(
                    {reader_task, writer_task}, return_when=asyncio.FIRST_COMPLETED
                )
                if writer_task in done:
                    await writer_task
                    reader_task.cancel()
                    with contextlib.suppress(Exception):
                        await stream.send_eof()
                else:
                    await reader_task
                    await writer_task
            finally:
                for task in (reader_task, writer_task):
                    task.cancel()
                    with contextlib.suppress(asyncio.CancelledError, Exception):
                        await task
        except Exception:
            await _safe_reset(stream)
        finally:
            stream.close()
            _safe_close(writer)

    def _account_active_streams(self, account_id: str) -> int:
        """Concurrent visitor streams across all of the account's live tunnels. Derived
        from live mux state, so it cannot drift the way a hand-kept counter would."""
        total = 0
        for lbl in self._account_labels.get(account_id, ()):
            entry = self._agents.get(lbl)
            if entry is not None:
                total += entry.mux.active_streams
        return total

    def _visitor_budget_exceeded(self, registration: TunnelRegistration) -> bool:
        """True if admitting another visitor would exceed the account's enforced
        ``Budget.max_visitors``. No budget / unlimited -> never exceeded."""
        budget = registration.budget
        if budget is None or budget.max_visitors is None:
            return False
        return self._account_active_streams(registration.account_id) >= budget.max_visitors

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


def _enable_keepalive(writer: asyncio.StreamWriter) -> None:
    """Turn on TCP keepalive for a visitor socket so the OS detects and reaps a peer
    that vanished (half-open connection) without us inspecting any bytes -- the SSE /
    WebSocket-safe way to reclaim a slot held by a dead client. On Linux we tune the
    timers for detection in ~90s; elsewhere SO_KEEPALIVE applies the platform default."""
    sock = writer.get_extra_info("socket")
    if sock is None:
        return
    with contextlib.suppress(OSError):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        if hasattr(socket, "TCP_KEEPIDLE"):  # Linux-only knobs
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)


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
    return _strip_port(v.decode("ascii"))


def _strip_port(host: str) -> str:
    """Return the host with any ``:port`` removed, rejecting (400) a malformed port.
    The port is irrelevant to routing, but a junk port (``:notaport``, ``:-1``,
    ``:99999999``, empty) is an invalid Host value (RFC 9110 §7.2), so we refuse it
    rather than silently dropping a bad suffix and routing anyway."""
    if host.startswith("["):  # IPv6 literal: "[::1]" or "[::1]:443"
        end = host.find("]")
        if end == -1:
            raise _BadRequest("bad-host")  # unterminated literal
        rest = host[end + 1 :]
        if rest:
            if rest[0] != ":":
                raise _BadRequest("bad-host")
            _check_port(rest[1:])
        return host[: end + 1]
    name, sep, port = host.rpartition(":")
    if not sep:
        return host  # no port present
    _check_port(port)
    return name


def _check_port(port: str) -> None:
    # A present port must be 1-5 digits in 0..65535 (len<=5 keeps int() bounded and
    # sidesteps Python's int-str conversion limit). Empty / non-numeric / out-of-range
    # means the Host is invalid, not just oddly suffixed.
    if not (port.isdigit() and len(port) <= 5 and int(port) <= 65535):
        raise _BadRequest("bad-port")


# -- shared relay pumps -------------------------------------------------------
async def _pump_reader_to_stream(reader: asyncio.StreamReader, stream: Stream) -> None:
    while True:
        data = await reader.read(65536)
        if not data:
            await stream.send_eof()
            return
        await stream.send(data)


async def _pump_stream_to_writer(stream: Stream, writer: asyncio.StreamWriter) -> None:
    while True:
        chunk = await stream.read()
        if chunk is None:
            if stream.reset_by_peer:
                # The response was aborted/truncated (peer RESET, overflow, teardown),
                # not cleanly finished. RST the visitor so a close-delimited body is
                # NOT mistaken for a complete one, and so the sibling reader pump
                # unblocks. (F22)
                _safe_abort(writer)
            elif writer.can_write_eof():
                # Clean half-close: propagate it so the visitor sees end-of-response.
                with contextlib.suppress(Exception):
                    writer.write_eof()
            else:
                # SSL transports can't half-close (can_write_eof() is False), so a
                # close-delimited response (HTTP/1.0, no Content-Length, SSE, a
                # wss:// upgrade terminated at our edge :443) would reach the visitor
                # with no FIN and hang. A full close is the correct end-of-response
                # here, and unblocks the sibling reader pump. (F20)
                _safe_close(writer)
            return
        writer.write(chunk)
        # Bound a stalled write: a dead/slow visitor that never drains would
        # otherwise pin the stream and its buffer. Legit slow-but-progressing
        # clients flush well within this window; idle SSE blocks on read(), not
        # drain(), so it is unaffected.
        await asyncio.wait_for(writer.drain(), timeout=_DRAIN_TIMEOUT)
        # Bytes are now flushed to the visitor: return that much flow-control credit
        # to the agent so it may send more (this is the backpressure signal).
        await stream.ack(len(chunk))


def _safe_close(writer: asyncio.StreamWriter) -> None:
    try:
        writer.close()
    except Exception:
        pass


def _safe_abort(writer: asyncio.StreamWriter) -> None:
    # RST the connection (asyncio-native, discards buffered data): the right
    # signal for an aborted/truncated relay, and it instantly unblocks a peer or
    # sibling pump that won't otherwise notice the teardown.
    try:
        writer.transport.abort()
    except Exception:
        pass


async def _safe_drain(writer: asyncio.StreamWriter) -> None:
    try:
        await writer.drain()
    except Exception:
        pass


async def _safe_reset(stream: Stream) -> None:
    try:
        await stream.reset()
    except Exception:
        pass
