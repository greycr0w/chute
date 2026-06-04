# chute — Reviewer Benchmark Brief

Dense reference for reviewing the chute tunnel against authoritative library/protocol behavior. Five areas. Each: verified key facts, then a measurement checklist. `[VERIFIED]` = confirmed against installed source/this repo on 2026-06-01. `[FIX]` = real gap. `[OK]` = correct, lock it with a test. Line numbers are current-tree.

**Single most load-bearing fact:** chute runs **websockets 16.0** (uv.lock:637). At 16.0 top-level `websockets.serve`/`connect` ARE the **new `websockets.asyncio`** impl — legacy stopped being the top-level default at **14.0**. `[VERIFIED]` live: `serve.__module__ == 'websockets.asyncio.server'`, `connect.__module__ == 'websockets.asyncio.client'`. Every websockets fact below is the NEW impl; legacy numbers (max_queue=32 messages, write_limit 64KiB, `4*max_size*max_queue` memory) do **not** apply.

---

## 1. websockets library behavior (new asyncio impl, v16.0)

chute config now sets `max_size=256KiB`, `max_queue=16 frames`, `write_limit=32KiB`, `compression=None`, `ping_interval=20`, `ping_timeout=20`; client also sets `open_timeout=15`. These match websockets 16 defaults but are explicit so production behavior does not drift with library defaults.

### Key facts
- **Inbound queue = BACKPRESSURE, never drop.** `asyncio/messages.py` `Assembler` is an **unbounded `collections.deque`**; `max_queue` is a **high-water mark on FRAME COUNT** (default **16**, low = high//4 = **4**). Over high-water → `transport.pause_reading()` (shrinks peer's TCP recv window); drain below low → `resume_reading()`. Nothing dropped at the WS layer; the *peer's sender* is throttled. (docs: memory.html — "max_queue defaults to 16 frames"; "max_size*max_queue" ≈ 16 MiB inbound cap vs legacy 128 MiB.)
- **New impl is PUSH-based.** `data_received()` parses all available frames synchronously and `put`s each into the deque (gated only by pause_reading). No separate read task; **`read_limit` was REMOVED**.
- **`await ws.send()` backpressures a fast sender** via the transport write buffer: `send() → send_data() (transport.write) → await drain()`; `drain()` blocks only while `paused`, toggled by `pause_writing()/resume_writing()` at the `write_limit` high/low-water marks (32 KiB default). The "no backpressure, piles until ping timeout" warning applies **only to `broadcast()`**, which chute does not use.
- **Keepalive:** `keepalive()` sleeps `ping_interval`, pings, waits `ping_timeout` for the pong; on miss → `fail(1011, 'keepalive ping timeout')` + abort. At 20/20 a half-open/dead TCP surfaces in **up to ~40 s** (idle interval already elapsed + full timeout). Interval is measured from pong receipt; high latency lengthens the period by design.
- **Close hierarchy:** `ConnectionClosed(WebSocketException)` base; `ConnectionClosedOK` (1000/1001/none) and `ConnectionClosedError` (any other code / incomplete handshake) subclass it. `async for` swallows OK, propagates Error. Codes/reasons live on `exc.rcvd`/`exc.sent` (`frames.Close.code/.reason`); **`exc.code`/`exc.reason` are DEPRECATED since 13.1** (emit DeprecationWarning).
- `[OK]` client.py:163-164 reads `close = exc.rcvd or exc.sent; code = close.code` — the correct non-deprecated pattern. `[VERIFIED]` grep: the only `.code` access in src/ is this site (off `frames.Close`, not the exception). `_FATAL_CLOSE_CODES` excludes 1011/1013 so a keepalive-timeout/`server busy` close is correctly retryable.

### THE PRODUCTION ASSURANCE GAP (cross-cuts §5)
`[RESOLVED]` pyproject.toml now requires **`websockets>=16,<17`**, matching uv.lock and the implementation assumptions in this brief. Runtime tests assert top-level `websockets.serve/connect` resolve to `websockets.asyncio.*`.

### Checklist
- [x] **Pin floor to the tested impl.** pyproject.toml requires `websockets>=16,<17`; uv.lock resolves 16.0.
- [x] **Impl-assertion regression test:** `tests/test_security_limits.py` asserts `websockets.serve/connect` resolve to `websockets.asyncio.*`.
- [x] **Decide & document `max_queue=16 frames`.** The value is explicit on server/client and documented in `docs/PROTOCOL.md`; mux/account budgets bound post-demux queues.
- [x] **Decide & document `write_limit=32 KiB`.** The value is explicit on server/client and documented in `docs/PROTOCOL.md`.
- [x] `[VERIFIED]` **No deprecated WebSocket exception attrs:** source now has a regression guard that rejects `exc.code` / `exc.reason`; the agent uses `exc.rcvd or exc.sent` and then reads the close frame's `code` / `reason`. Coverage: `tests/test_security_limits.py::test_source_avoids_deprecated_websocket_exception_close_attrs`.
- [x] `[VERIFIED]` **Control `recv()` sequencing is single-consumer:** the pre-auth hello `await ws.recv()` completes before `Mux.run()` starts iterating the same WebSocket, preserving the websockets new-impl single-consumer contract. Coverage: `tests/test_security_limits.py::test_agent_hello_recv_completes_before_mux_run`.
- [x] `[RESOLVED]` **Half-open detection window documented:** `docs/PROTOCOL.md` now states that 20s/20s WebSocket keepalive can take up to about 40s to surface a silent peer before agent reconnect backoff is added. Coverage: `tests/test_control.py::test_protocol_docs_state_keepalive_detection_window`.

*Sources: installed `websockets/asyncio/{messages,connection,server,client}.py` v16.0; docs memory.html & howto/upgrade.html (top-level→new since 14.0, write_limit 64→32 KiB, max_queue "32 messages"→"16 frames", read_limit removed). Repo: pyproject.toml:33, uv.lock:637, ci.yml `uv sync --locked`, deploy.sh:55.*

---

## 2. asyncio idioms & footguns (CPython 3.11+)

chute targets 3.11+ (pyproject:10 `requires-python>=3.11`). Relay = `TaskGroup` pumps; sole consumer per WS.

### Key facts
- **TaskGroup:** first non-`CancelledError` failure cancels remaining children; **a child that RETURNS NORMALLY does NOT cancel siblings.** On exit, non-cancel failures combine into `(Base)ExceptionGroup`; plain `CancelledError` is filtered out. `KeyboardInterrupt`/`SystemExit` are re-raised **un-grouped** → `except* Exception` does NOT catch them (they're `BaseException`).
- `[OK]` **Half-close invariant** (server.py:528-535/574-581; client.py:195-202): the request pump calls `send_eof()` and **returns** on visitor EOF; the sibling response pump keeps running so the HTTP response still flows. Relies on the doc-confirmed normal-return-doesn't-cancel-sibling semantic — but it is an **undocumented invariant in code**.
- **create_task/ensure_future strong-ref:** loop keeps only weak refs; an unreferenced task "may get garbage collected … even before it's done" → "Task was destroyed but it is pending!". Fix = hold in a set + `add_done_callback(set.discard)` (Ruff RUF006).
- `[OK]` Discipline correct at both hot spots: server.py `_pending_closes` set; mux.py:107/135-138 `_spawn` → `_tasks` + discard. cli.py holds `task` across `await task`.
- **Streams:** `write()` buffers (sync); pair with `await drain()` for backpressure. `close()` only **schedules** close next tick; **`await wait_closed()`** actually flushes FIN. `write_eof()`/`can_write_eof()` → **SSL has no half-close** (`can_write_eof()` is False on TLS; `write_eof()` raises `NotImplementedError`). `start_server(..., limit=)` default StreamReader buffer = **64 KiB**; `readuntil(sep)` raises `LimitOverrunError` if the scanned run exceeds `limit` (data left in buffer).
- **`transport.abort()` vs `close()`:** `abort()` = immediate close, **buffered data LOST** → this is the asyncio-native **TCP RST** (no manual `SO_LINGER`). `close()` flushes async then `connection_lost`. No public `StreamWriter.abort()`; reach via `writer.transport.abort()`.
- **Signals:** `asyncio.run()` (3.11+) maps SIGINT→KeyboardInterrupt but installs **no SIGTERM handler** → under systemd/Docker, `stop` = abrupt kill, no drain. `loop.add_signal_handler` is Unix-only, main-thread-only.
- `wait_for`: on timeout it cancels AND awaits the inner (total time can exceed timeout). Historical 3.8–3.11 race could swallow inner `CancelledError`; rewritten on `asyncio.timeout()` in 3.12.
- **SSL drain deadlock** (cpython#102792, 3.11+): forcing write-buffer high-water to **0** on an SSL writer deadlocks for payloads >~1 KiB in a relay loop. `[VERIFIED]` chute never calls `set_write_buffer_limits` — not exposed.

### Real gaps & checklist
- [x] `[RESOLVED]` **SIGTERM reaches graceful stop/drain:** the agent CLI registers SIGINT/SIGTERM callbacks that call `Tunnel.request_stop()`, and `Server.serve()` registers SIGINT/SIGTERM callbacks that stop accepting and drain live muxes with `_GRACEFUL_DRAIN_TIMEOUT`. Regression coverage: `tests/test_cli.py::test_agent_main_registers_sigterm_for_graceful_stop`, `tests/test_security_limits.py::test_server_sigterm_stops_accepting_and_drains_live_muxes`.
- [x] `[RESOLVED]` **TCP RST exists for abort/truncation paths:** `_pump_stream_to_writer()` calls `_safe_abort()` on peer RESET, and `_safe_abort()` uses `writer.transport.abort()`. Mux write-stall also aborts the WebSocket transport. Regression coverage: `tests/test_multitenant_authz.py::test_relay_stream_reset_aborts_writer_not_clean_eof`, `tests/test_protocol_hardening.py::test_send_aborts_transport_on_write_stall`.
- [x] `[CLARIFIED]` **No hot-path writer `wait_closed()`:** relay/error-page teardown uses `_safe_close()` / `_safe_abort()` without awaiting a potentially half-dead peer. The only `wait_closed()` calls in `src/` are bounded listener-shutdown waits in `Server.serve()` after accepting has stopped.
- [x] `[RESOLVED]` **SSL `can_write_eof()` guard is covered:** `_pump_stream_to_writer()` falls back to a full close when `can_write_eof()` is false, and the edge-TLS listener has a close-delimited response regression. Coverage: `tests/test_https.py::test_edge_tls_close_delimited_response_does_not_hang`.
- [x] `[RESOLVED]` **64 KiB request-head cap is explicit:** public listeners pass `limit=_MAX_REQUEST_HEAD`, `_handle_visitor_registered()` handles `LimitOverrunError` directly, and `tests/test_security_limits.py::test_oversized_request_head_returns_400_before_routing` proves an oversized head returns 400 before routing or agent stream admission.
- [x] `[RESOLVED]` **Half-close keeps the opposite pump alive:** server relay now documents the request-EOF branch that keeps the mux-to-visitor writer alive, and the agent TaskGroup site documents that normal pump return is a half-close, not sibling cancellation. Regression coverage: `tests/test_security_limits.py::test_request_eof_does_not_cancel_delayed_response_body`.
- [x] `[RESOLVED]` **Startup/shutdown cleanup is bounded and cancellation-safe:** `Server.serve()` closes partially-started listeners if a later bind fails, performs listener/mux cleanup in `finally`, uses a zero drain timeout for plain task cancellation and `_GRACEFUL_DRAIN_TIMEOUT` only for signal-driven shutdown, bounds listener `wait_closed()` with `wait_for(5)`, awaits canceled background tasks, and `Mux.drain()` bounds the WebSocket close phase with `_CLOSE_TIMEOUT` before aborting the transport. Regression coverage: `tests/test_security_limits.py::test_server_startup_failure_closes_partial_listeners`, `tests/test_security_limits.py::test_server_sigterm_stops_accepting_and_drains_live_muxes`, `tests/test_drain.py::test_drain_close_timeout_aborts_transport`.
- [x] `[CLARIFIED]` **No top-level listener `gather()` remains:** `Server.serve()` creates the control/public listeners, waits on a shutdown event, and closes listeners in `finally`; the only remaining server-side `asyncio.gather()` is the bounded mux-drain call with `return_exceptions=True`. There is no listener-sibling `gather(*serve_forever())` site to replace with `TaskGroup`.
- [x] `[RESOLVED]` **Mux.run() finally cancellation:** `Mux.run()` aborts live streams, cancels spawned handlers, and awaits them with `return_exceptions=True`; cancelled agent-side `_handle_stream` still reaches `finally` and closes both local writer and stream after connect. Regression coverage: `tests/test_drain.py::test_run_awaits_owned_task_cleanup_on_cancel`, `tests/test_client.py::test_stream_handler_cancellation_after_connect_closes_writer_and_stream`.
- [x] `[ACCEPTED]` **`wait_for` on 3.11:** keep the package floor at `>=3.11` for now. The remaining `wait_for` sites are explicit resource/readiness/dial/write bounds with regression coverage, production deploys pin Python 3.13 via `.python-version`, and CI still exercises 3.11/3.12/3.13. Raising the public floor to 3.12 only for the historical rare cancellation race is a compatibility cost without a demonstrated chute failure; revisit when dropping 3.11 from the CI matrix.
- [x] `[RESOLVED]` **Strong-ref lint:** Ruff **RUF006** is selected in `pyproject.toml`, and `tests/test_deploy_config.py::test_ci_lint_uses_locked_project_ruff` asserts the rule stays enabled so fire-and-forget tasks cannot sneak in without strong refs.
- [x] `[RESOLVED]` **Defense-in-depth comment:** server and agent `_WS_WRITE_LIMIT` constants now warn not to force SSL transport write-buffer high-water to 0 (cpython#102792); chute bounds wedged writes with explicit timeouts instead.

*Sources: CPython docs asyncio-task / -stream / -protocol / -eventloop; cpython#102792, #95704, #116720, #115957, #91887; Tribler#7570; Ruff RUF006. Repo: server.py:256-261/528-535/574-581/621-645, client.py:195-202/265-283, mux.py:107/135-138/run-finally, cli.py.*

---

## 3. Stream state machine — legal/illegal transitions

Benchmarked against HTTP/2 (RFC 9113 §5.1, the fully-named normative FSM), yamux (const.go/stream.go/session.go), smux. chute's `_streams: dict[int, Stream]` tracks the live stream object while `_RecvState` tracks the receive terminal (`OPEN`, `EOF`, `RESET`); it still avoids a full bidirectional HTTP/2-style state matrix. Dispatch is a plain `dict.get(sid)` (mux.py run()). Mapping: OPEN≈HEADERS/SYN, DATA≈DATA, EOF≈END_STREAM/FIN, RESET≈RST_STREAM/RST. No ACK/SYN-ACK (server-only ids, no establishment race); protocol v4 uses `WINDOW_UPDATE` plus a negotiated per-connection flow window.

### What chute gets RIGHT by construction `[OK]`
- [x] `[RESOLVED]` **Server ignores ALL peer OPENs** (`on_open=None` → `continue`, mux.py run()). Strongest possible; a malicious agent cannot rapid-open against the server. Regression coverage: `tests/test_flow_control.py::test_server_mux_ignores_peer_open_without_materializing_streams`.
- [x] `[RESOLVED]` **DATA/EOF/RESET for unknown/closed sid → silent drop** (`dict.get` is None). Spec-compatible (HTTP/2 lenient-ignore; yamux/smux drop). WS message framing means no byte-stream desync risk (unlike yamux, which must `io.CopyN(io.Discard)` to stay synced). Regression coverage: `tests/test_protocol_hardening.py::test_unknown_frame_churn_is_capped_without_stream_or_task_growth`.
- **Never answers RESET with RESET** (`_abort()` then `_remove`, no reply) → no reset amplification.
- **Frame-after-RESET dropped** (stream removed on reset) → HTTP/2 grace-window ignore.
- [x] `[RESOLVED]` **At `_max_streams`, inbound OPEN → single RESET for that sid, mux stays up** (mux.py run()). Stream-error not connection-error — correct §5.4 split. Regression coverage: `tests/test_flow_control.py::test_inbound_open_over_max_streams_is_reset_without_closing_mux`.
- **Malformed/short frame → drop, mux survives** (`except ValueError: continue`). Does NOT escalate one bad frame to tearing down the session (contrast yamux, which GOAWAYs on a single recvWindow violation).

### REAL, TESTABLE GAPS
- [x] `[RESOLVED]` **Stream-id exhaustion refuses instead of wrapping**: `Mux.open()` now treats stream ids as monotonic and never reused within a connection; id exhaustion raises instead of wrapping onto a live id. Regression coverage: `tests/test_flow_control.py::test_open_refuses_at_id_exhaustion`.
- [x] `[RESOLVED]` **Double-EOF is idempotent**: `_RecvState` is write-once (`OPEN -> EOF | RESET`), so duplicate EOF frames do not enqueue duplicate terminals. Regression coverage: `tests/test_flow_control.py::test_eof_idempotent_and_data_after_eof_dropped`, `tests/test_protocol_hardening.py::test_recv_state_is_write_once`.
- [x] `[RESOLVED]` **DATA-after-EOF is dropped**: `Stream._feed()` refuses payload once the receive side is terminal, preserving frame-order semantics after a clean half-close. Regression coverage: `tests/test_flow_control.py::test_eof_idempotent_and_data_after_eof_dropped`.
- [x] `[RESOLVED]` **Duplicate OPEN is reset, not overwritten**: `Mux.run()` checks `sid in self._streams` before registering a peer-opened stream and sends one deduplicated RESET for duplicate live ids. Regression coverage: `tests/test_flow_control.py::test_duplicate_open_is_reset`, `tests/test_flow_control.py::test_duplicate_open_reset_send_is_deduplicated`.
- [x] `[RESOLVED]` **Inbound ignored-frame churn is capped:** `Mux.run()` now counts non-actionable frames (malformed frames, unknown stream ids, duplicate GOAWAY, server-side peer `OPEN`, zero grants, etc.) and aborts the connection after `_MAX_IGNORED_FRAMES = 65_536`, while preserving normal late-frame races below that threshold. Regression coverage proves an unknown DATA/EOF/RESET/WINDOW_UPDATE/OPEN flood creates no streams/tasks/resets and aborts at the cap: `tests/test_protocol_hardening.py::test_unknown_frame_churn_is_capped_without_stream_or_task_growth`. `docs/PROTOCOL.md` documents the limit.

### Design-substitution notes (document, don't "fix")
- [x] `[CURRENT]` **Credit-window flow control exists, but stays intentionally simpler
  than HTTP/2.** Chute v4 negotiates one per-stream byte window (`flow_window`) in
  the JSON handshake, sends `WINDOW_UPDATE` only after downstream drain, and derives
  per-stream byte/frame backstops from the negotiated value. It does **not** add a
  full HTTP/2-style per-connection flow-control window; instead, relay memory is
  bounded by `_MAX_CONN_BUFFERED` and `_MAX_CONN_FRAMES`, with per-account
  `Budget.max_buffered_bytes` available for cloud/multi-tenant policy. Coverage:
  `tests/test_flow_control.py`, `tests/test_protocol_hardening.py`,
  `tests/test_multitenant_authz.py::test_flow_window_negotiates_lower_preference_and_configures_mux`.
- [x] `[CURRENT]` **GOAWAY graceful drain exists, but it is single-node HA, not
  failover.** `Mux.drain()` sends `GOAWAY`, refuses new opens, waits for in-flight
  streams up to `_DRAIN_GRACE`, then closes `1001`; server `SIGTERM`/`SIGINT`,
  finite-lease expiry, lease revocation, and agent Ctrl-C/`aclose()` use that path.
  There is still no cross-node state transfer, so long-lived streams are force-closed
  at the drain deadline and reconnect at the application/client layer. Coverage:
  `tests/test_drain.py`, `tests/test_security_limits.py::test_server_sigterm_stops_accepting_and_drains_live_muxes`,
  `tests/test_multitenant_authz.py::test_expired_lease_stops_new_visitors_and_drains_tunnel`.
- [x] `[CURRENT]` **Liveness remains a layered policy, not a mux-level ping
  feature.** The control WebSocket keeps its 20s/20s ping/pong half-open detection,
  accepted/local TCP sockets enable OS keepalive where supported, and operators can
  opt into `CHUTE_RELAY_IDLE_TIMEOUT` for byte-idle relay streams. Chute still does
  not add a mux-frame NOP/ping like yamux/smux; that remains a deliberate simplicity
  choice unless measurements show WebSocket keepalive plus socket keepalive is
  insufficient.

### Cheapest high-value fix
- [x] `[RESOLVED]` **3-state receive lifecycle**: `_RecvState` (`OPEN`, `EOF`, `RESET`) is now the authoritative receive-side terminal state. DATA drops after terminal, EOF is idempotent, RESET cannot rewrite a prior clean EOF, and stream ids never wrap. Regression coverage: `tests/test_flow_control.py`, `tests/test_protocol_hardening.py`.

*Sources: RFC 9113 §5.1/§5.4/§5.5/§6.8/§6.9; yamux spec.md+const.go/stream.go/session.go; smux stream.go/session.go; Cloudflare/Google CVE-2023-44487 writeups. Repo: docs/PROTOCOL.md §5-§10/§15, mux.py (`WINDOW_UPDATE`, `GOAWAY`, `drain`, stream-id monotonicity), server.py (`SIGTERM` drain, lease expiry/revocation drain), client.py (`request_stop`, `aclose`, local connect), tests/test_flow_control.py, tests/test_protocol_hardening.py, tests/test_drain.py, tests/test_multitenant_authz.py, tests/test_security_limits.py.*

---

## 4. TLS hardening

**Headline:** bare `ssl.SSLContext(PROTOCOL_TLS_SERVER)` is **SAFE BY DEFAULT** for protocol floor + ciphers on **Python 3.11+** (chute's floor). The control channel needs almost nothing. Real gaps concentrate in the **edge-TLS path** (unrotated session-ticket key) and missing-but-mostly-inapplicable hardening.

### What PROTOCOL_TLS_SERVER already gives you (3.11+, no code) `[VERIFIED]`
- `minimum_version` = **TLS 1.2** already (`PY_SSL_MIN_PROTOCOL = TLS1_2_VERSION` in `_ssl.c`). Setting `minimum_version=TLSv1_2` is **redundant**. (Pre-3.10 it was NOT — chute is 3.11+.)
- Default `options |= NO_SSLv2|NO_SSLv3|NO_COMPRESSION|CIPHER_SERVER_PREFERENCE|SINGLE_DH_USE|SINGLE_ECDH_USE`.
- Cipher list = OpenSSL `HIGH`@seclevel2 (3.10+): forward-secret AES-GCM/ChaCha20 only; RSA/DH<2048, ECC<224 banned; no NULL/MD5/RC4/3DES. `set_ciphers()` is **redundant** and **cannot touch TLS 1.3 suites** anyway.
- TLS 1.3 enabled; **renegotiation impossible by spec** (no CVE-2009-3555 class); RFC 5746 secure-reneg on by default for 1.2 (`OP_LEGACY_SERVER_CONNECT` not set).

### Real gaps & checklist
- [x] `[RESOLVED]` **Session-ticket FS regression on edge-TLS** (certs.py `server_ssl_context`, reused for the public :443 listener). `server_ssl_context()` now sets `OP_NO_TICKET` and `num_tickets = 0`, matching the documented nginx `ssl_session_tickets off` posture for both control TLS and standalone edge TLS. Regression coverage: `tests/test_security_limits.py`.
- [x] `[CLARIFIED]` **Ticket regression test:** the actionable invariant is "no tickets issued"; Python's stdlib does not expose `SSL_SESS_CACHE_OFF`, and live TLS 1.2 probes can still resume through OpenSSL's stateful session-id cache. If zero TLS 1.2 resumption becomes a product requirement, the decision is TLS-1.3-only or a lower-level OpenSSL binding, not another stdlib flag.
- [x] `[RESOLVED]` **Key-file write race**: `certs.generate()` writes the control private key through `os.open(..., O_CREAT|O_TRUNC, 0o600)` and calls `fchmod(0600)` before bytes are written, so both first creation under a permissive umask and regeneration from a loosened existing mode end at 0600. Regression coverage: `tests/test_security_limits.py`.
- [x] `[RESOLVED]` **Runtime key-file fallback**: `deploy/chuted.service` sets `UMask=0077`; the control key file itself is 0600 and the install tree is not made world-writable. Regression coverage: `tests/test_deploy_config.py`.
- [x] `[RESOLVED]` **`_watch_cert` reload**: the edge listener keeps a stable SNI-dispatch context; reload validates cert+key in a fresh `SSLContext` and replaces only the active context used by new handshakes. Torn cert/key writes leave the last-good cert serving. Regression coverage: `tests/test_https.py`.
- [x] `[RESOLVED]` **Require atomic cert install:** README and PROTOCOL now require renewal hooks for watched public cert/key paths to publish by same-directory atomic rename, not by truncating live PEMs in place.
- [x] `[RESOLVED]` **Pinned-leaf expiry monitoring**: `chuted run` now warns when the manually pinned control cert is within 90 days of `notAfter` (or already expired), and README/PROTOCOL document the coordinated rotation runbook plus the fact that there is no backup-pin overlap. Regression coverage: `tests/test_security_limits.py`, `tests/test_cli.py`.
- [x] `[RESOLVED]` **Cert pinning construction is CORRECT and SAFE** (certs.py `client_ssl_context`: `load_verify_locations(cafile=leaf)` + `CERT_REQUIRED` + `check_hostname=False`). `check_hostname=False` is required here because identity is bound to the pinned cert, not DNS SAN matching; `CA:FALSE` shrinks blast radius. Regression coverage now rejects both a child cert signed by the pinned leaf and a replacement self-signed leaf reminted with the pinned private key.
- [x] `[RESOLVED]` **Client fallback trust-mode visibility**: `Tunnel._build_ssl()` logs whether the control channel is using a pinned server cert or the system trust store before returning either `certs.client_ssl_context()` or `ssl.create_default_context()`. Regression coverage: `tests/test_client.py::test_build_ssl_logs_pinned_trust_mode`, `tests/test_client.py::test_build_ssl_logs_system_trust_mode`.
- [x] `[RESOLVED]` **Assert, don't add config:** `tests/test_security_limits.py::test_server_ssl_context_negotiates_modern_tls_and_pfs_cipher` now verifies a live TLS handshake negotiates TLS 1.2+ and that the TLS 1.2 fallback cipher is forward-secret (`ECDHE`/`DHE`). Optional self-documenting `ctx.minimum_version = TLSVersion.TLSv1_2` remains a clarity call, not a fix.
- [x] `[RESOLVED]` **ALPN absent is intentional and documented:** README and PROTOCOL now state the built-in public TLS listener is HTTP/1.1-only, does not advertise ALPN, and should be fronted by nginx when browser HTTP/2 is required. No ALPN was added to the control channel.
- [x] `[RESOLVED]` **No OCSP stapling / Must-Staple on pinned leaf:** README and PROTOCOL now state the pinned control cert is a self-signed leaf with no responder and certificate pinning is the revocation model; OCSP stapling is only an optional nginx/ACME policy.
- [x] `[RESOLVED]` **nginx-chute.conf** `[OK]`: `ssl_protocols TLSv1.2 TLSv1.3` + explicit Intermediate cipher list + `ssl_prefer_server_ciphers off` + `ssl_session_tickets off` + `http2 on` match Mozilla Intermediate. The deliberate **NO-HSTS / NO-:80→:443-redirect** product decision is documented in the template and pinned by `tests/test_deploy_config.py::test_nginx_template_keeps_http_and_https_without_forced_upgrade` so a reviewer cannot silently "fix" away the iframe/postMessage HTTP workflow.
- [x] `[RESOLVED]` `server_ssl_context()` sets `OP_NO_RENEGOTIATION` where OpenSSL exposes it (defense-in-depth for TLS 1.2; chute never renegotiates). Regression coverage: `tests/test_security_limits.py`.

*Sources: CPython 3.11 `Modules/_ssl.c` (`PY_SSL_MIN_PROTOCOL=TLS1_2_VERSION`; default options; `OP_NO_TICKET`/`OP_NO_RENEGOTIATION`/`OP_LEGACY_SERVER_CONNECT` NOT set), `Lib/ssl.py` `create_default_context`; docs.python.org ssl; Mozilla SSTLS wiki + ssl-config.mozilla.org; filippo.io "We need to talk about Session Tickets" (STEK never rotated for process lifetime); OpenSSL TLS1.3 wiki. Repo: certs.py, server.py:201-203/225-235/263-292, client.py:181-184, deploy/nginx-chute.conf.*

---

## 5. Supply-chain / CI / deploy

**Posture is unusually strong for a hobby project:** CI top-level `permissions: contents: read`; `uv sync --locked` (drift fails CI); fully-hashed uv.lock resolved exclusively from `pypi.org/simple`; deploy reads secrets into env (not inlined — no script-injection); host key pinned; CD gated behind `CD_ENABLED` + a GitHub production Environment, run via a server-side forced-command shell-less user with a 3-command NOPASSWD sudoers allowlist; `chuted.service` genuinely hardened (`NoNewPrivileges`, `ProtectSystem=strict` with NO `ReadWritePaths`, empty `CapabilityBoundingSet`, `SystemCallFilter=@system-service`, `MemoryMax`/`TasksMax`); release attaches wheels to GitHub Releases (no long-lived PyPI token).

### THREE STANDOUT FINDINGS
- [x] `[CLARIFIED]` **mypy lock graph is current PyPI metadata, not a phantom lock entry:** PyPI metadata for `mypy 2.1.0` now exists and declares `ast-serialize` and `librt`; `uv tree --locked --package mypy` matches that graph. Residual lesson remains: resolver output is only trustworthy with source/hash provenance and advisory scanning, both covered below.
- [x] `[RESOLVED]` **Prod installs hash-pinned deps instead of floating:** `deploy/deploy.sh` and `deploy/deploy-pull.sh` install `deploy/requirements.txt` and `deploy/build-requirements.txt` with `pip install --require-hashes`, then install chute itself with `--no-build-isolation --no-deps`. CI regenerates the runtime export with `uv export --frozen --no-dev --no-emit-project` and fails on drift.
- [x] `[RESOLVED]` **GitHub Actions are SHA-pinned:** every `uses:` reference in `.github/workflows/*.yml` resolves to a 40-character commit SHA with a trailing version comment; Dependabot covers `github-actions` updates.

### Other findings & checklist
- [x] `[RESOLVED]` **cryptography CVE floor:** `pyproject.toml` now requires `cryptography>=44.0.1,<49`, excluding the GHSA-79v4-65xg-pq4g / CVE-2024-12797 vulnerable wheel range. `uv.lock` records the same runtime spec and currently resolves `cryptography 48.0.0`; `uv tree --locked --package cryptography` and `uv tree --locked --package websockets` both pass.
- [x] `[RESOLVED]` **release.yml provenance/SBOM:** release workflow has top-level `contents: read`, job-scoped `{ contents: write, id-token: write, attestations: write }`, builds with locked tooling, generates a runtime CycloneDX SBOM, attests build provenance, attests the SBOM, and publishes via SHA-pinned `softprops/action-gh-release`.
- [x] `[RESOLVED]` **CI vulnerability scanning:** CI exports the locked production runtime requirements and runs `uv run --no-sync pip-audit -r deploy/requirements.txt --disable-pip`; local verification with `uv run --locked --extra dev pip-audit` reports no known vulnerabilities.
- [x] `[RESOLVED]` **Dependabot configured:** `.github/dependabot.yml` covers `github-actions`, `uv`, and `pre-commit` on a weekly cadence.
- [x] `[VERIFIED]` **Lock source/hash provenance:** structured `uv.lock` parse shows the only registry is `https://pypi.org/simple` and every sdist/wheel URL has a `sha256:` hash. Repo grep finds no alternate index knobs (`index-url`, `extra-index`, `find-links`, `[tool.uv.index]`, `default-index`, `PIP_INDEX`, `UV_INDEX`) in tracked config/docs/deploy files.
- [x] `[RESOLVED]` **No unpinned deploy-time pip upgrade:** deploy scripts no longer run `pip install --upgrade pip`; runtime/build dependencies are installed from hash-pinned requirement exports.
- [x] `[RESOLVED]` **Pinned deploy interpreter/tooling:** `.python-version` pins Python `3.13`, `[tool.uv] required-version` pins the minimum uv version, and both deploy scripts provision the venv through `uv python install` / `uv venv --python` before hash-pinned installs.
- [x] `[RESOLVED]` **launchd plist secret handling:** the agent supports `--token-file` / `CHUTE_TOKEN_FILE` with a regular-file and owner-only mode check; the sample plist stores only the token-file path, has no `EnvironmentVariables`, logs under `~/Library/Logs/chute`, and documents creating `~/.config/chute/token` with `chmod 600`. Regression coverage: `tests/test_cli.py::test_agent_token_file_is_passed_to_tunnel`, `tests/test_cli.py::test_agent_token_file_rejects_permissive_mode`, `tests/test_deploy_config.py::test_launchd_agent_sample_keeps_token_out_of_plist_and_tmp_logs`.
- [x] `[VERIFIED]` **CI trigger posture:** PR workflows use `pull_request`, not `pull_request_target`, with top-level `contents: read`; no `run:` block interpolates untrusted `${{ github.event.* }}`. Deploy is push-to-main only, uses a production Environment, deliberately checks out nothing, and routes secrets through `env:` before shell use. The PR fuzz jobs do call SHA-pinned ClusterFuzzLite actions with the read-only `GITHUB_TOKEN`, which is acceptable for this posture; do not migrate these workflows to `pull_request_target` unless the job never checks out untrusted head code while holding elevated token/secrets.
- [x] `[VERIFIED]` **`chuted.service` hardening is pinned:** `NoNewPrivileges`, `ProtectSystem=strict` with no `ReadWritePaths`, empty `CapabilityBoundingSet`/`AmbientCapabilities`, `RestrictAddressFamilies=AF_INET AF_INET6`, `SystemCallFilter=@system-service`, and `MemoryMax`/`TasksMax`/`LimitNOFILE` are present and now covered by `tests/test_deploy_config.py::test_chuted_service_preserves_runtime_sandbox_and_resource_caps`. These are the backstop that keeps a single-process blowup from taking down the shared VPS.
- [x] **Runtime-hardening adjacency (ties §1):** explicit `max_queue`+`write_limit` on `websockets.serve/connect`, explicit `limit=` on public `asyncio.start_server`, and explicit local-app `open_connection(limit=...)`; regression tests cover the configured kwargs.
- [x] `[RESOLVED]` **Hygiene:** `SECURITY.md` now gives a private GitHub Security Advisory reporting path plus scope/supply-chain expectations; `deploy/CD-SETUP.md` no longer carries live-test breadcrumbs, and `tests/test_deploy_config.py::test_operator_docs_do_not_include_live_test_breadcrumbs` pins that cleanup.

*Sources: uv.lock (mypy 2.1.0:416 + deps:419-425, ast-serialize:9, librt:343; 22 deps all pypi.org/simple, all sha256), pyproject.toml:33-34, ci.yml:9-10/21-53, release.yml:10/17-22, deploy/deploy.sh:54-55, deploy/deploy-pull.sh:19, deploy/chuted.service, deploy/com.chute.agent.plist, deploy/CD-SETUP.md. External: GHSA-79v4-65xg-pq4g (CVE-2024-12797, cryptography wheels 42.0.0–44.0.0, fixed 44.0.1); CVE-2025-30066 (tj-actions); OpenSSF Scorecard Pinned-Deps + GitHub Aug-2025 SHA-pin policy; uv docs (`--locked` vs `--frozen`, `uv export`); actions/attest-build-provenance (SLSA L2); websockets security.html.*

---

## Priority rollup (current)

The original top-ten rollup is closed. Keeping it as an action list would now
send review effort back into fixed code, so treat this as the current decision
surface: what was closed, and what still deserves engineering attention.

### Closed original top risks

| Original risk | Current status | Evidence |
|---|---|---|
| Suspect `uv.lock` graph / missing vulnerability scan | Clarified and guarded | Lock graph source/hash provenance is verified; CI exports prod requirements and audits them with locked `pip-audit`. |
| Prod dependency and runtime-buffer drift | Resolved | `websockets>=16,<17`, locked CI/dev tooling, hash-pinned prod requirements, and explicit websocket/stream limits are tested. |
| Mutable GitHub Actions and broad release permissions | Resolved | Actions are 40-hex SHA-pinned; release permissions are job-scoped; provenance and SBOM attestations are emitted. |
| Stream-id wrap / duplicate live stream hijack | Resolved | Stream ids are monotonic and exhaustion refuses; regression coverage in `tests/test_flow_control.py`. |
| Double-EOF, DATA-after-EOF, duplicate OPEN | Resolved | `_RecvState` is write-once; duplicate live `OPEN` is reset; post-terminal DATA drops. |
| Missing SIGTERM drain | Resolved | Server and agent signal paths drain with `GOAWAY`; covered by CLI, security-limit, and drain tests. |
| Edge-TLS session-ticket forward-secrecy regression | Resolved | `OP_NO_TICKET` and `num_tickets = 0` are set and tested. |
| Vulnerable `cryptography` floor | Resolved | Runtime floor excludes the vulnerable wheel range; lock resolves `cryptography 48.0.0`. |
| No abortive RST path | Resolved | Relay RESET/truncation paths use `transport.abort()`; mux write stalls abort the WebSocket transport. |
| Pinned control leaf expiry invisibility | Resolved | Startup expiry warnings and rotation documentation are covered by CLI/security tests. |

### Current highest-leverage work

| Priority | Area | What to do next | Why |
|---|---|---|---|
| 1 | Measured performance | Run `scripts/benchmark_remote_e2e.py --output-json ...` against the deployed VPS/nginx/TLS path and compare the saved report with the mux-only plus loopback baselines in `docs/PERFORMANCE.md` before changing the default `flow_window`. | The knob exists; raising the default without remote end-to-end measurements trades memory for theoretical throughput. |
| 2 | Product policy seams | Continue adding paid/cloud policy only where relay-local behavior can be enforced and tested (`Budget`, finite leases, queued lifecycle/stat events). | Chute is a pipe, not a WAF; advertising app-level policy the relay cannot enforce would be dishonest. |
| 3 | Drift prevention | Keep cross-cutting facts in lockstep across code, tests, README, PROTOCOL, deploy scripts, and CI. | Most late misses came from stale surfaces after the implementation was correct. |
| 4 | Runtime evidence | Use the loopback metrics endpoint and periodic stats, including pool pressure, event queue health, policy update outcomes, and lease renewal/retirement outcomes, to decide whether tuning or new limits are needed. | Observability should drive changes to defaults; otherwise hardening becomes guesswork. |
| 5 | Future FSM complexity | Add a full bidirectional stream-state model only if new protocol features need it. | The current `_RecvState` is sufficient for EOF/RESET/teardown invariants and keeps the mux auditable. |

*Current rollup sources: RFC 9113 stream/flow-control/GOAWAY model; GitHub Actions security and artifact-attestation docs; uv locked/export docs; repo evidence in pyproject.toml, uv.lock, .github/workflows, deploy scripts, docs/PROTOCOL.md, tests/test_deploy_config.py, tests/test_flow_control.py, tests/test_protocol_hardening.py, tests/test_drain.py, tests/test_security_limits.py, and tests/test_multitenant_authz.py.*
