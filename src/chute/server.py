"""chute server -- runs on the public VPS.

Two listeners:

* **control** (WSS): accepts agents. Each agent dials *out* to here, which is
  what lets the whole thing traverse NAT/firewalls.
* **public** (plain TCP): accepts visitor connections and relays each one, as a
  multiplexed stream, to the right agent -- which forwards it to the local app
  and pipes the response back.

**Single-tenant** (default): one token == one tunnel, newest agent wins. The
public side is a pure L4 relay that never parses HTTP, so it transparently
carries keep-alive, chunked, SSE and WebSocket upgrades.

**Multi-tenant** (when ``base_domain`` is set): many agents, each owning a
subdomain label. The public side peeks *only* the request line + Host header to
choose the agent, then forwards every byte it peeked plus the rest verbatim --
it still never alters the request or the response. The multi-tenant public port
MUST sit behind a normalizing reverse proxy (nginx, one request per upstream
connection) when exposed to untrusted networks; the CLI defaults that bind to
loopback for exactly this reason.

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
import ssl
import time
from pathlib import Path
from typing import Any

import websockets

from . import certs, names
from .auth import Authorizer, AuthResult, StaticTokenAuthorizer
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
_VISITOR_ACQUIRE_TIMEOUT = 5.0  # wait for a visitor slot before 503
_DRAIN_TIMEOUT = 120.0  # no-progress write timeout on the relay

# Per-IP failed-auth limiter: an IP gets _AUTH_FAIL_MAX bad handshakes per
# _AUTH_FAIL_WINDOW seconds before further connects are turned away (close 1013).
# Only failures count, so a legitimate agent on a clean IP is never throttled.
_AUTH_FAIL_MAX = 5
_AUTH_FAIL_WINDOW = 60.0


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

        # Multi-tenant routing. With base_domain set, the public side routes by
        # Host header to one of many agents; otherwise it stays the single-tenant
        # pure-L4 relay (one agent, newest wins).
        self.base_domain = base_domain.lower().strip(".") if base_domain else None
        self.upstream_tls = upstream_tls
        self._agent: Mux | None = None  # single-tenant: the one agent
        # Multi-tenant routing: label -> (agent mux, owning account id), plus the
        # reverse index account id -> its live labels (for the concurrency cap and
        # same-account reclaim). Visitor routing only ever reads the mux.
        self._agents: dict[str, tuple[Mux, str]] = {}
        self._account_labels: dict[str, set[str]] = {}
        # Per-IP failed-auth timestamps (monotonic), pruned opportunistically.
        self._auth_fails: dict[str, list[float]] = {}

        # Pre-auth / concurrency backstops (framing & rate only; never payload).
        self.hello_timeout = hello_timeout
        self._control_sem = asyncio.Semaphore(max_control_conns)
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
        if self.base_domain and not _is_loopback(self.public_host):
            log.warning(
                "multi-tenant public port bound to %s (not loopback): put a "
                "normalizing reverse proxy in front, or it is exposed to request "
                "smuggling/desync from untrusted clients",
                self.public_host,
            )
        log.info(
            "chute up | %s | http %s:%s | %s | control %s:%s | %s",
            f"multi-tenant *.{self.base_domain}" if self.base_domain else "single-tenant",
            self.public_host,
            self.public_port,
            f"https {self.public_host}:{self.public_tls_port}" if public_tls else "edge-https off",
            self.control_host,
            self.control_port,
            "wss" if self.ssl_context else "ws (NO TLS)",
        )
        async with contextlib.AsyncExitStack() as stack:
            await stack.enter_async_context(control)
            await stack.enter_async_context(public)
            coros = [control.wait_closed(), public.serve_forever()]
            if public_tls is not None:
                await stack.enter_async_context(public_tls)
                coros.append(public_tls.serve_forever())
                coros.append(self._watch_cert())
            await asyncio.gather(*coros)

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
            except (TimeoutError, ValueError, TypeError):
                await ws.close(code=4000, reason="bad handshake")
                return
            if not isinstance(hello, dict):
                # non-object JSON (list/int/str/...) -- route through the benign
                # close path instead of raising an AttributeError traceback.
                await ws.close(code=4000, reason="bad handshake")
                return
        finally:
            # Release the pre-auth handshake slot BEFORE authorizing. The semaphore
            # bounds half-open handshakes -- which are over once we have the hello --
            # not the authorize call, which may do slow I/O (e.g. a database lookup)
            # in an alternative authorizer. Holding it across a slow authorize would
            # turn the concurrency cap into a DoS amplifier.
            self._control_sem.release()

        # Per-IP failed-auth limiter: an IP that has burned its budget of bad
        # handshakes is turned away before we spend an authorize call on it. Only
        # failures consume budget, so a good token from a clean IP never waits.
        agent_ip = ws.remote_address[0] if ws.remote_address else None
        if not self._auth_rate_ok(agent_ip):
            with contextlib.suppress(Exception):
                await ws.close(code=1013, reason="too many auth failures")
            log.warning("rate-limited agent handshakes from %s", ws.remote_address)
            return

        # Exactly one authorization call per connect, OUTSIDE the pre-auth
        # semaphore. A *raised* exception means the authorizer is unavailable (e.g.
        # a database blip) -- RETRYABLE, so we close 1013 with no error frame and
        # the agent backs off and reconnects. A *None* return is a genuine rejection
        # (bad/revoked token) -- fatal, closed 4001 with an error frame.
        try:
            auth = await self.authorizer.authenticate(
                str(hello.get("token", "")), hello.get("subdomain"), agent_ip
            )
        except Exception:
            log.warning("authorizer unavailable for agent from %s", ws.remote_address)
            with contextlib.suppress(Exception):
                await ws.close(code=1013, reason="try again later")
            return
        if auth is None:
            self._record_auth_fail(agent_ip)
            await ws.send(json.dumps({"type": "error", "reason": "unauthorized"}))
            await ws.close(code=4001, reason="unauthorized")
            log.warning("rejected agent (unauthorized) from %s", ws.remote_address)
            return

        scheme = str(hello.get("scheme", "http"))
        if self.base_domain:
            await self._serve_agent_multi(ws, hello, scheme, auth)
        else:
            await self._serve_agent_single(ws, scheme)

    async def _serve_agent_single(self, ws: Any, scheme: str) -> None:
        if scheme == "https" and self._public_tls_context is not None and self.public_https_url:
            public_url = self.public_https_url
        else:
            if scheme == "https":
                log.warning("agent requested https but no public TLS configured; serving http")
            public_url = self.public_url
        await ws.send(json.dumps({"type": "ready", "public_url": public_url}))
        mux = Mux(ws)  # server never accepts peer-opened streams
        previous, self._agent = self._agent, mux
        if previous is not None:
            log.info("replacing previous agent (newest wins)")
            _schedule_ws_close(previous, 4003, "superseded")
        log.info("agent connected from %s", ws.remote_address)
        try:
            await mux.run()
        finally:
            if self._agent is mux:
                self._agent = None
            log.info("agent disconnected")

    async def _serve_agent_multi(
        self, ws: Any, hello: dict[str, Any], scheme: str, auth: AuthResult
    ) -> None:
        account_id = auth.account_id
        try:
            label = self._assign_label(hello.get("subdomain"))
            self._authorize_claim(account_id, label, auth.max_tunnels)
        except _LabelError as exc:
            await ws.send(json.dumps({"type": "error", "reason": str(exc)}))
            await ws.close(code=4002, reason=str(exc))
            log.warning("rejected agent subdomain %r: %s", hello.get("subdomain"), exc)
            return

        public_url = self._public_url_for(label, scheme)
        mux = Mux(ws)
        # Newest wins for a label, but only the SAME account may reclaim it
        # (_authorize_claim already rejected a different account). This keeps
        # reconnection (laptop sleep, Wi-Fi flap) seamless: a re-dialing agent
        # reclaims its own label instead of being locked out by its stale conn.
        previous = self._agents.get(label)
        self._agents[label] = (mux, account_id)
        self._account_labels.setdefault(account_id, set()).add(label)
        if previous is not None:
            log.warning("agent reclaimed busy label %r (newest wins)", label)
            _schedule_ws_close(previous[0], 4003, "superseded")
        await ws.send(json.dumps({"type": "ready", "public_url": public_url, "subdomain": label}))
        log.info("agent %r connected from %s -> %s", label, ws.remote_address, public_url)
        try:
            await mux.run()
        finally:
            # Only clear if we're still the registered agent (a newer same-account
            # agent that replaced us must keep its slot and its account-label entry).
            current = self._agents.get(label)
            if current is not None and current[0] is mux:
                del self._agents[label]
                labels = self._account_labels.get(account_id)
                if labels is not None:
                    labels.discard(label)
                    if not labels:
                        del self._account_labels[account_id]
            log.info("agent %r disconnected", label)

    def _assign_label(self, requested: object) -> str:
        if requested is not None:
            label = str(requested).lower()
            if not names.valid_label(label):
                raise _LabelError("invalid_subdomain")
            return label
        for _ in range(100):  # auto-assign: pick a free, friendly random label
            label = names.random_phrase()
            if label not in self._agents:
                return label
        raise _LabelError("no_free_subdomain")  # astronomically unlikely

    def _public_url_for(self, label: str, scheme: str) -> str:
        assert self.base_domain
        if scheme == "https" and self._https_available:
            return f"https://{label}.{self.base_domain}/"
        if scheme == "https":
            log.warning("agent %r requested https but https is unavailable; serving http", label)
        return f"http://{label}.{self.base_domain}/"

    def _authorize_claim(self, account_id: str, label: str, max_tunnels: int) -> None:
        """Decide whether *account_id* may claim *label*; raise _LabelError with a
        client-facing reason otherwise. Synchronous and await-free, so check-and-claim
        is atomic on the single-threaded event loop -- no lock needed."""
        held = self._agents.get(label)
        if held is not None and held[1] != account_id:
            raise _LabelError("subdomain_taken")  # a different account holds it now
        owned = self._account_labels.get(account_id, ())
        # Reclaiming a label this account already holds is a replacement, not a new
        # tunnel, so it never counts against the cap (keeps reconnect seamless).
        if label not in owned and len(owned) >= max_tunnels:
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
        """Note a failed auth from *ip*, sweeping stale buckets to stay bounded."""
        if ip is None:
            return
        now = time.monotonic()
        self._auth_fails.setdefault(ip, []).append(now)
        if len(self._auth_fails) > 4096:  # opportunistic global sweep
            stale = [
                k
                for k, v in self._auth_fails.items()
                if all(now - t >= _AUTH_FAIL_WINDOW for t in v)
            ]
            for k in stale:
                del self._auth_fails[k]

    # -- public side -----------------------------------------------------------
    async def _handle_visitor(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
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
            if self.base_domain:
                await self._handle_visitor_routed(reader, writer)
            else:
                await self._handle_visitor_single(reader, writer)
        finally:
            self._visitor_sem.release()

    async def _handle_visitor_single(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        agent = self._agent
        if agent is None:
            writer.write(_OFFLINE_RESPONSE)
            await _safe_drain(writer)
            _safe_close(writer)
            return

        try:
            stream = await agent.open()
        except Exception:  # agent gone or at its stream ceiling
            writer.write(_OFFLINE_RESPONSE)
            await _safe_drain(writer)
            _safe_close(writer)
            return
        try:
            async with asyncio.TaskGroup() as tg:
                tg.create_task(_pump_reader_to_stream(reader, stream))
                tg.create_task(_pump_stream_to_writer(stream, writer))
        except* Exception:  # visitor or tunnel died mid-flight
            await _safe_reset(stream)
        finally:
            stream.close()
            _safe_close(writer)

    async def _handle_visitor_routed(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        # Peek the request head (request line + headers, through the blank line)
        # to find Host. We forward every peeked byte plus the rest untouched, so
        # the relay stays byte-transparent -- we only *read* Host, never edit.
        # nginx normalizes to CRLF and sends one request per upstream connection.
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=30)
        except asyncio.IncompleteReadError:
            _safe_close(writer)  # visitor closed before sending a full request
            return
        except Exception:  # timeout, header block over the buffer limit, reset
            writer.write(_BAD_REQUEST_RESPONSE)
            await _safe_drain(writer)
            _safe_close(writer)
            return

        host = _host_from_head(head)
        label = self._label_from_host(host)
        entry = self._agents.get(label) if label else None
        agent = entry[0] if entry is not None else None
        if agent is None:
            writer.write(_no_tunnel_response(host or "?"))
            await _safe_drain(writer)
            _safe_close(writer)
            return

        try:
            stream = await agent.open()
        except Exception:
            writer.write(_OFFLINE_RESPONSE)
            await _safe_drain(writer)
            _safe_close(writer)
            return
        try:
            await stream.send(head)  # the bytes we peeked, forwarded verbatim
            async with asyncio.TaskGroup() as tg:
                tg.create_task(_pump_reader_to_stream(reader, stream))
                tg.create_task(_pump_stream_to_writer(stream, writer))
        except* Exception:
            await _safe_reset(stream)
        finally:
            stream.close()
            _safe_close(writer)

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


# -- request-head parsing (multi-tenant routing only) -------------------------
def _host_from_head(head: bytes) -> str | None:
    """Pull the Host header value (port stripped) out of a buffered request head."""
    lines = head.split(b"\r\n")
    for line in lines[1:]:  # skip the request line
        name, sep, value = line.partition(b":")
        if not sep:
            continue
        if name.strip().lower() == b"host":
            return _strip_port(value.strip().decode("latin-1", "replace"))
    return None


def _strip_port(host: str) -> str:
    # "label.dom" / "label.dom:443" -> "label.dom"; leave IPv6 literals alone.
    if host.startswith("["):
        return host
    return host.rsplit(":", 1)[0] if ":" in host else host


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
            # Propagate the peer's half-close so the visitor sees the response
            # end instead of the connection hanging until some other timeout.
            if writer.can_write_eof():
                with contextlib.suppress(Exception):
                    writer.write_eof()
            return
        writer.write(chunk)
        # Bound a stalled write: a dead/slow visitor that never drains would
        # otherwise pin the stream and its buffer. Legit slow-but-progressing
        # clients flush well within this window; idle SSE blocks on read(), not
        # drain(), so it is unaffected.
        await asyncio.wait_for(writer.drain(), timeout=_DRAIN_TIMEOUT)


def _safe_close(writer: asyncio.StreamWriter) -> None:
    try:
        writer.close()
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
