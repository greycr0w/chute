# chute Protocol Specification

**Protocol version:** 4 &nbsp;·&nbsp; **Status:** stable &nbsp;·&nbsp; **Wire/behaviour source of truth:** `src/chute/protocol.py`, `src/chute/mux.py`, the handshake in `src/chute/server.py` / `src/chute/client.py`.

This document specifies, end to end, the protocol two chute peers speak: how the
connection is established, how bytes are framed and multiplexed, how flow control
paces them, how streams are torn down, and what limits each peer enforces against a
misbehaving or wedged counterpart. It is written to be implementable from scratch and
to be auditable against the code.

The key words **MUST**, **MUST NOT**, **SHOULD**, **MAY** are used as in RFC 2119.

---

## Table of contents

1. [Overview](#1-overview)
2. [Roles and terminology](#2-roles-and-terminology)
3. [Transport](#3-transport)
4. [Connection establishment (handshake)](#4-connection-establishment-handshake)
5. [Frame format](#5-frame-format)
6. [Streams and the receive state machine](#6-streams-and-the-receive-state-machine)
7. [Flow control](#7-flow-control)
8. [Frame semantics (reference)](#8-frame-semantics-reference)
9. [Teardown and half-close](#9-teardown-and-half-close)
10. [Limits and enforcement](#10-limits-and-enforcement)
11. [Close codes](#11-close-codes)
12. [Versioning and compatibility](#12-versioning-and-compatibility)
13. [Security considerations](#13-security-considerations)
14. [Design rationale and non-goals](#14-design-rationale-and-non-goals)
15. [Known limitations](#15-known-limitations)
- [Appendix A: constants](#appendix-a-constants)
- [Appendix B: a request, end to end](#appendix-b-a-request-end-to-end)

---

## 1. Overview

chute relays public traffic to a local app over **one** persistent, authenticated,
TLS connection that the local side dials **outbound** (so it traverses NAT/firewalls
with no inbound ports). That single connection is a **stream multiplexer**: every
public connection becomes one logical, bidirectional byte stream inside it, the same
idea as HTTP/2 streams or yamux/muxado.

```
            visitor TCP conn  ─┐
            visitor TCP conn  ─┤   (one stream each)
                               ▼
   visitor ──▶  chute server ══════ one WSS connection ══════ chute agent ──▶ 127.0.0.1:app
                  (VPS, public)        (binary frames)        (your machine)
```

The protocol has two planes over the one connection:

- A short **control plane**: a JSON request/response handshake (auth, scheme,
  protocol-version negotiation, the assigned public URL).
- A **data plane**: a binary, length-implicit frame protocol that opens streams,
  carries their bytes, paces them with a credit window, and tears them down.

Visitor admission is HTTP-specific: the server reads a complete HTTP request head
before opening an agent stream. After admission, the buffered head is forwarded
verbatim and everything in the data plane is **byte-transparent**: chute never
rewrites or reframes the payload it relays. Frames carry opaque bytes; flow
control only *paces* them.

---

## 2. Roles and terminology

| Term | Meaning |
|---|---|
| **Server** | The public host (VPS). Accepts agents on the control port (WSS) and visitors on the public port(s). It is the stream **initiator**: it opens exactly one stream per visitor connection. |
| **Agent** | The local side. Dials *out* to the server, authenticates, then acts as the stream **responder**: for each stream the server opens, it connects to the local app and pipes bytes both ways. |
| **Visitor** | An end user hitting the public URL. Not a protocol participant — an ordinary TCP/HTTP client whose bytes are relayed verbatim. |
| **Stream** | One logical, bidirectional, flow-controlled byte channel inside the connection, identified by a 32-bit id. One per visitor connection. |
| **Initiator / Responder** | The server initiates (opens) streams; the agent responds (accepts + dials local). This asymmetry is fixed and load-bearing (see §6, §13). |
| **Peer** | Either end of the multiplexer, when a rule applies symmetrically. |

Both ends run the same multiplexer (`Mux`); the only asymmetry is who may open
streams.

---

## 3. Transport

- **One WebSocket-over-TLS (WSS) connection per agent**, dialed agent → server. It is
  long-lived; all control and data frames ride inside it.
- **Framing comes from WebSocket.** Each chute frame is exactly one WebSocket
  **binary** message; the message boundary delimits the frame. There is no length
  prefix. Handshake messages (§4) are WebSocket **text** messages (JSON). After the
  handshake a peer **MUST** ignore any non-binary (text) message on the data plane.
- **TLS.** The control channel uses a pinned, self-signed certificate by default: the
  agent pins the server's exact certificate (`server_cert`), giving strong MITM
  protection with no CA or ACME dependency. The pinned leaf is long-lived but not
  auto-renewed; `chuted run` warns within 90 days of `notAfter`, and rotation is a
  coordinated pin redistribution because there is no backup-pin overlap. If no
  certificate is pinned, the agent falls back to the system trust store (and logs
  which mode is in use). Public HTTPS (a separate `:443` edge listener) is
  independent of the control channel; when enabled, public cert reload validates a
  fresh `SSLContext` and switches new handshakes only after a cert/key pair loads
  successfully. Renewal hooks for the watched public cert/key paths must publish by
  same-directory atomic rename, not by truncating the live PEMs in place. The built-in
  public TLS listener is HTTP/1.1-only and does not advertise ALPN; front with nginx
  when browser HTTP/2 is required. Server TLS contexts disable session tickets and
  TLS 1.2 renegotiation where Python/OpenSSL expose those controls; Python's `ssl`
  module does not expose a switch for OpenSSL's stateful TLS 1.2 session-id cache, so
  "no TLS 1.2 resumption of any kind" would require a TLS-1.3-only product decision
  rather than another stdlib flag. OCSP Must-Staple does not belong on the pinned
  control leaf because it is self-signed, has no responder, and certificate pinning is
  the revocation model for that channel; stapling is only an optional nginx/ACME
  policy.
- **Keepalive.** Both ends run WebSocket ping/pong with `ping_interval = 20s` and
  `ping_timeout = 20s`. A peer that fails to pong within the timeout has the
  connection closed. A silent or half-open peer can therefore take up to about
  40s to surface before the agent's reconnect backoff is added. (Note: this
  detects a *silent/dead* peer, **not** a peer that keeps the socket open but
  stops reading — that case is handled by the write-stall timeout in §10.)
- **Message size cap.** Any single WebSocket message is capped at
  `_MAX_WS_MESSAGE = 256 KiB`. A larger message closes the connection. Legitimate
  chute frames are ≤ ~64 KiB + 5 (one pump read; §7), so this is pure headroom that
  bounds the pre-auth buffer.
- **WebSocket buffer caps.** Both ends set `max_queue = 16` frames and
  `write_limit = 32 KiB` explicitly. The frame queue applies TCP backpressure
  before the mux sees frames; mux stream/account budgets then bound post-demux
  payload queues.
- **Request-head cap.** Public visitor listeners use
  `_MAX_REQUEST_HEAD = 64 KiB` as the `asyncio` stream reader limit. `readuntil()`
  rejects a larger header block before chute routes the visitor or opens an agent
  stream.
- **Compression is disabled** (`permessage-deflate` off) on both ends. Security first
  — it removes the decompression-bomb vector — and the cost is near zero: the bytes
  chute relays are usually already compressed by the app (gzip/br on text & JSON) or
  are media, so deflating them again is double work for ~no gain (the same reason
  reverse proxies skip already-encoded responses). An app serving *uncompressed* text
  should set its own `Content-Encoding`, which chute forwards verbatim.
- **Connect timeout.** The agent bounds the WSS open at 15s.

---

## 4. Connection establishment (handshake)

The handshake is a single JSON request/response over WebSocket **text** messages,
completed before any binary frame flows.

### 4.1 Agent → server: `auth`

The agent's first message **MUST** be a JSON object:

```json
{
  "type": "auth",
  "token": "<shared secret>",
  "scheme": "http" | "https",
  "flow_window": 262144,
  "v": 4,
  "subdomain": "<label>"
}
```

- `token` (**required**) — the shared secret. Compared in constant time, as bytes.
- `scheme` (optional, default `"http"`) — which scheme the *public* endpoint should
  serve. `"http"` is always an explicit plaintext request. `"https"` asks the
  server to advertise HTTPS and fails closed if HTTPS is not truthfully available.
- `flow_window` (optional, positive integer, bytes) — the agent's preferred mux
  flow-control window. Omitted means the default 256 KiB.
- `v` (**required**) — the protocol version the agent speaks. **MUST** equal `4`.
- `subdomain` (optional, Host-routed deployments only) — a requested DNS label
  (`a–z`, `0–9`, hyphen). Omitted with `base_domain` → the server auto-assigns a
  random label. Omitted without `base_domain` → the reserved internal `default`
  label is used.

### 4.2 Server validation order

The server applies these checks **in order**, each with its own failure (§11):

1. **Failed-auth limiter** — if the source bucket has exceeded its budget (5
   failures / 60s; exact IPv4 address or IPv6 `/64`), close `1013` (too many
   auth failures) before spending a semaphore slot or authorize call.
2. **Concurrency gate** — acquire a pre-auth handshake slot within `hello_timeout`
   (5s), else close `1013` (busy). Released as soon as the hello is read (before
   authorization), so a slow authorizer can't turn the cap into an amplifier.
3. **Read + parse hello** within `hello_timeout`. Timeout, non-JSON, non-object, or
   pathologically nested JSON → close `4000` (bad handshake).
4. **Version** — if `v != 4`, send `{"type":"error","reason":...}` then close `4004`.
   Checked *before* auth so a stale agent fails fast and clearly.
5. **Subdomain syntax** — a non-string `subdomain` closes `4000`; an invalid DNS
   label sends an error and closes `4002` before the control plane is called.
   A malformed `flow_window` closes `4000`; an omitted value means the default
   256 KiB preference.
6. **Tunnel admission** under its own concurrency cap and timeout. The relay passes
   a structured `TunnelAdmissionRequest` (token, requested subdomain, scheme,
   agent IP, protocol version) to the configured `ControlPlane`. A custom
   implementation can be loaded with `CHUTE_CONTROL_PLANE=module:attr`; the built-in
   file-backed implementation is loaded with `--policy-file` / `CHUTE_POLICY_FILE`.
   The default control plane wraps the static-token `Authorizer`; `CHUTE_AUTHORIZER`
   remains a compatibility hook. A *raised* exception or timeout (control plane
   unavailable, e.g. a DB blip) → close `1013` (retryable). A `None` return
   (bad/revoked token) → record the failure, emit an auth-rejected event if
   configured (§4.6), send `{"type":"error","reason":"unauthorized"}`, close `4001`.
   A malformed
   `TunnelAdmission` return is treated as unavailable policy and closes `1013`.
   A returned finite lease that is already expired closes `1013` before `ready`.
7. **Registration claim** — select the label (`default` without `base_domain`, a
   requested/random label with `base_domain`), enforce the `TunnelAdmission`
   allowed-label policy, same-account ownership, and the account tunnel limit. On
   failure send
   `{"type":"error","reason":<code>}` and close `4002` (reasons:
   `subdomain_unsupported`, `subdomain_not_allowed`, `subdomain_taken`,
   `tunnel_limit`, `https_unavailable`, `no_free_subdomain`).

### 4.3 Server → agent: `ready`

On success the server replies:

```json
{
  "type": "ready",
  "public_url": "http://...",
  "subdomain": "<label>",
  "flow_window": 262144,
  "v": 4
}
```

- `public_url` (**required**, string) — the live public URL.
- `subdomain` — the assigned DNS label when `base_domain` is configured; `null`
  for the internal `default` route.
- `flow_window` (**required**, positive integer, bytes) — the negotiated mux
  flow-control window for this connection. It is the lower of the agent and
  server preferences, capped at 16 MiB.
- `v` (**required**) — the server's protocol version.

### 4.4 Agent validation of `ready`

The agent **MUST** treat each of these as fatal (no reconnect): a reply that is not an
object, whose `type != "ready"`, whose `v != 4`, whose `public_url` is not a
string, whose `flow_window` is missing/malformed, or whose `flow_window` is larger
than the agent advertised. A fatal handshake error surfaces a reason and exits; a
transient close (`1013`, network drop) backs off and retries. The agent's fatal
close-code set is `{4001, 4002, 4004}`.

### 4.5 Supersession

A second successful agent for the same label (`default` included, **same account
only**) takes over: **newest wins**. The previous connection is closed `4003`
(superseded). This keeps reconnects (sleep/wake, Wi-Fi flap) seamless.

After `ready`, both peers switch to the binary data plane and run the multiplexer.

Finite `TunnelLease.expires_at` values are enforced locally before the relay opens
a visitor stream. Expiry removes the route, stops new visitors, sends `GOAWAY` to
the agent, and drains in-flight streams before closing the mux connection.
Standalone/static-token chute returns a non-expiring lease.

Finite leases are renewed out-of-band between the relay and its configured
`ControlPlane`, never through agent frames and never through visitor requests. A
successful renewal must preserve the lease id, account id, credential id, and a
non-decreasing integer generation, and it must return a finite timezone-aware
`expires_at` that is still in the future. A transient or malformed renewal keeps
the existing local lease until expiry; a `None` renewal result is an explicit
revocation and drains immediately. Renewal timers are jittered by lease
identity/generation so large relay fleets do not synchronize control-plane calls.

`Budget.max_visitors` is enforced by a relay-local per-account visitor reservation
counter. The slot is reserved before mux `OPEN` and released when the visitor relay
closes, so this limit is not an external authorization call and does not scan every
tunnel owned by the account.

`Budget.max_reconnects_per_min` is enforced after tunnel admission identifies the
account and before the relay sends `ready`. It limits successful control-channel
connect attempts per account per relay over a 60-second local window. Exceeding the
limit closes `1013`, so the agent backs off and retries instead of treating the
token or label as permanently invalid.

`Budget.max_bytes_per_sec` is enforced as a relay-local per-account byte-rate
schedule. Both `DATA` directions share the same schedule; the relay delays
visitor-to-agent chunks before sending `DATA` and delays agent-to-visitor chunks
before writing to the visitor and returning credit. This is local behavior only,
not a wire change.

`Budget.max_buffered_bytes` is enforced as a relay-local per-account unread mux
payload budget. The relay reserves account bytes before queueing an inbound
`DATA` frame and releases them when the downstream consumer reads or abandons the
chunk. Exceeding the limit resets only the offending stream. This caps
chute-owned stream-buffer payload memory; kernel socket buffers, WebSocket
library buffers, and downstream application memory remain outside this budget.

Dynamic policy updates are also out-of-band between the relay and its configured
`ControlPlane`; they are not WebSocket frames and are never visible to the agent.
The relay polls with its current accepted policy version and active lease count.
Full active lease-id snapshots are opt-in for control planes that explicitly need
them; custom/cloud control planes should usually return revocations by lease id
without asking the relay to send every live id each poll. A valid update must
have a strictly newer version and may revoke lease ids, revoke leases with a
`drain` or `close` action, or replace the current local account budget used by
live tunnels and detached in-flight relay work. Legacy
lease-id-only revocations drain. Structured `LeaseRevocation(action="drain")`
stops new visitors and gives in-flight streams the relay drain window; `close`
stops new visitors and closes the mux connection immediately. Stale or malformed
updates are rejected as a whole and the relay keeps last-good local policy.

`StaticPolicyControlPlane` is the built-in local policy-file implementation. It
is configured by `--policy-file` / `CHUTE_POLICY_FILE` and reads a non-symlink
chmod-600 JSON file owned by the user running `chuted` (`chute` in the bundled
systemd unit) from a parent directory owned by that user or root and not group- or
world-writable. Token verifiers inside the file use `token_sha256`; `chuted
gen-token --token-file` creates and flushes a new private token file without
printing the secret, and `chuted hash-token
--token-file` reads that token file under the same current-user-owned,
non-symlink owner-only rule.
Reserved `allowed_label` values are normalized to lowercase and cannot be assigned
to multiple accounts.
The initial file must be valid. After startup, unchanged files reuse the cached
parsed policy, and malformed live edits keep last-good local policy until a valid
replacement lands. `chuted validate-policy --policy-file <path>` runs the same
private-file and schema validation without starting the daemon.

### 4.6 Local extension events (not wire frames)

The relay may be configured with an optional local `EventSink`. This is the
telemetry half of the open-core extension boundary; it is not part of the
WebSocket protocol and no event is sent to the agent.

Events emitted by core:

- `tunnel_opened` / `tunnel_closed` — includes a relay-generated `connection_id`,
  label, account id, optional credential id, scheme, public URL, agent IP, and
  timestamp.
- `visitor_opened` / `visitor_closed` — includes the tunnel `connection_id`,
  stream id, label, account id, optional credential id, visitor IP, Host, and
  timestamp.
- `auth_rejected` — includes reason, agent IP, requested subdomain, scheme, and
  any authenticated account/credential context available.
- `visitor_rejected` — includes reason (`no_tunnel`, `visitor_limit`), Host,
  visitor IP, and any account/credential context available.
- `relay_stats` — includes process-local active tunnel/account/stream gauges,
  control/auth/visitor pool usage and capacity, direct visitor source-bucket
  count, fixed busy/limit shed counters for those pools, aggregate mux
  buffering/reset/stall counters, cumulative bytes forwarded to the agent and
  visitor sides, fixed generated lifecycle/audit event counters, best-effort event
  queue depth/capacity and enqueue/deliver/retry/drop counters, current policy
  version, policy update applied/rejected/poll-failure counters, lease renewal
  outcome counters, lease revocation/expiration counters, and timestamp.

The default sink is a no-op. If `CHUTE_REQUIRE_EVENT_SINK=1` is set, the
`tunnel_opened` event is load-bearing: it must complete successfully before the
server sends `ready`; failure closes `1013` so the agent retries. All other event
failures are handled by a bounded best-effort queue: exporter/database latency and
transient failures are retried outside visitor hot paths, queue overflow drops the
event with a log line, and relay behavior does not change. Queue health is
reported through `relay_stats` and the loopback `/metrics` endpoint, alongside
fixed generated-event counters, so operators can distinguish local activity from
exporter overload without adding a visitor-path dependency.

The built-in local sink is enabled with `--event-log-file` /
`CHUTE_EVENT_LOG_FILE`. It writes owner-only JSONL and should be
handled as metadata-sensitive output: no proxied payload bytes are written, but
account ids, credential ids, labels, Hosts, public URLs, and source IPs are
present. Existing log files must be owned by the user running `chuted` (`chute` in
the bundled systemd unit), and the parent directory must be owned by that user and
not group- or world-writable because default rotation renames files there. The
file rotates by size by default through
`CHUTE_EVENT_LOG_MAX_BYTES` (100 MiB) and `CHUTE_EVENT_LOG_BACKUPS` (5 rotated
owner-only files); disable those only when an external retention system owns the
log lifecycle.

The built-in logs follow the same boundary: data-path failures are rate-limited
and metadata-only (reason, label/account, validated Host, visitor IP, stream id,
and aggregate mux gauges). The periodic stats log carries the same aggregate
pool, shed, policy/lease, event-queue, mux, and byte counters as the
low-cardinality relay snapshot. Chute never logs request targets, arbitrary
headers, or body bytes.

---

## 5. Frame format

Every data-plane frame is one WebSocket binary message: a fixed 5-byte prefix plus an
opaque payload.

```
 0       1                       5                        N
 +-------+-----------------------+------------------------+
 | type  |      stream_id        |        payload         |
 | u8    |   u32, big-endian     |     0 .. N bytes       |
 +-------+-----------------------+------------------------+
```

- `type` — one of the frame types below.
- `stream_id` — the stream this frame belongs to (big-endian `u32`; `struct` format
  `"!BI"`).
- `payload` — frame-type-dependent, possibly empty.

A receiver **MUST** drop (ignore, keep the connection alive) any frame shorter than
the 5-byte prefix.

| Type | Value | Direction | Payload | Purpose |
|---|---|---|---|---|
| `OPEN` | `0x01` | server → agent | empty | Open a stream; the agent dials the local target. |
| `DATA` | `0x02` | both | opaque bytes | Stream payload. The only flow-controlled frame. |
| `EOF` | `0x03` | both | empty | Half-close: the sender will write no more on this stream. |
| `RESET` | `0x04` | both | empty | Abort this stream immediately, both directions. |
| `WINDOW_UPDATE` | `0x05` | both | `u32` BE | Grant the peer N more bytes of send credit. |
| `GOAWAY` | `0x06` | both | empty (id `0`) | Sender is draining: it will open no new streams and closes once in-flight ones finish. |

There is **no length field** (WebSocket gives the boundary) and **no flags byte**: each
concern is its own frame type. This keeps the parser trivial and the wire
self-delimiting.

---

## 6. Streams and the receive state machine

### 6.1 Who opens, and stream ids

- **Only the server opens streams.** It allocates every `stream_id`, so there is no
  id-collision negotiation. The agent **MUST NOT** open streams; the server **MUST**
  ignore any `OPEN` it receives (this denies a malicious agent a way to grow the
  server's stream table).
- Ids are **monotonic and never reused** within a connection: `1 .. 0xFFFFFFFF`. At
  exhaustion the initiator **MUST** refuse to open rather than wrap, because a wrapped
  id could collide with a still-live stream and hijack it. (Exhaustion is a
  reconnect-scale event; see §15.)
- A `DATA`/`EOF`/`RESET`/`WINDOW_UPDATE` for an unknown id is silently ignored.
- A duplicate `OPEN` for a live id **MUST** be answered with `RESET` (not silently
  overwritten).

### 6.2 Half-close is real

A stream's two directions are independent. The **receive** direction ends when the
peer sends `EOF` (clean) or `RESET` (abort); the **send** direction ends when this
side sends its own `EOF`. A stream stays alive until *both* directions are done (or
either side `RESET`s / the connection drops). This is what lets a relayed connection
hold one direction open (e.g. an HTTP keep-alive idle between requests, an SSE stream,
a WebSocket upgrade) while the other has finished.

### 6.3 The receive state machine

Each stream's receive direction is a single, **write-once** state — the one
authoritative "sign" for the lane:

```
                 EOF frame received
        ┌────────────────────────────────▶  EOF   (clean half-close → FIN downstream)
        │
   ┌────────┐
   │  OPEN  │
   └────────┘
        │   RESET received,  OR  connection death,  OR  a local
        │   limit breached (§10)
        └────────────────────────────────▶  RESET (abort → RST downstream)
```

**Only `OPEN` may transition.** Once a stream reaches `EOF` or `RESET` that terminal is
permanent:

- A `RESET` arriving **after** a clean `EOF` does **not** rewrite the terminal — the
  receive direction already ended cleanly; the `RESET` aborts only the still-open send
  direction. (Without this rule, a late abort could turn a fully-delivered response
  into a truncation signal downstream.)
- Likewise a stray `EOF` after a `RESET` does not soften the abort.

The terminal's nature is the **only** thing the consumer needs to choose the
downstream signal at end-of-stream (§9): `EOF → FIN`, `RESET → RST`. The send
direction is tracked separately (credit window + an "EOF sent" flag); the lifecycle
flag `closed` marks full teardown + deregistration.

---

## 7. Flow control

Flow control is the core of the data plane. Without it, one slow consumer behind the relay forces
the other end to buffer without bound; with it, backpressure propagates end to end
across the WebSocket hop. None of it touches payload bytes — it only decides *when* a
sender may transmit.

### 7.1 The credit window

- Each **direction** of each stream has a **credit window**, initially the
  negotiated `flow_window` for that control connection. The default preference is
  `_FLOW_WINDOW = 256 KiB` (matching yamux's default), and both server and agent
  cap configured preferences at 16 MiB.
- The server chooses the negotiated value as
  `min(agent flow_window preference, server flow_window preference)`. This is a
  receiver-resource policy, not a unilateral throughput wish: raising throughput
  over a high-bandwidth/high-RTT path requires both ends to advertise a larger
  value.
- A sender **MUST NOT** transmit more `DATA` payload bytes than its remaining credit.
  When the window reaches 0 the sender **blocks** — which propagates TCP backpressure
  all the way back to whatever produces the bytes (the visitor socket, or the local
  app).
- **Only `DATA` consumes credit**, by its payload byte count. `OPEN`, `EOF`, `RESET`,
  and `WINDOW_UPDATE` are not flow-controlled.

### 7.2 Returning credit (`WINDOW_UPDATE`)

- The receiver returns credit by sending `WINDOW_UPDATE` with a 4-byte big-endian
  `u32` delta of bytes.
- **Credit is returned on *consumption*, not on *arrival*.** The receiver grants
  credit only after the bytes have been drained **downstream** (handed to the visitor
  or local-app socket and `drain()`-ed) — never merely on receipt into the queue. This
  is the rule that makes backpressure real: a slow downstream stops credit, which
  stops the sender. (Granting on arrival, the deprecated `OnReceive` strategy in other
  muxers, silently loses backpressure and lets the buffer grow unbounded.)
- **Batched.** A `WINDOW_UPDATE` is emitted once the receiver has drained half the
  negotiated window since its last update, carrying the whole accumulated amount.
  This sends ~one update per half-window rather than one per frame, while keeping
  the sender from stalling a full round-trip each cycle.

### 7.3 Validation of incoming `WINDOW_UPDATE`

A receiver of `WINDOW_UPDATE` **MUST**:

- treat a payload whose length is not exactly 4 bytes as malformed and **RESET** the
  stream;
- ignore a `delta == 0` (a no-op grant) **without** waking a blocked sender — otherwise
  a flood of zero-grants resets the sender's stall clock (§7.5) and pins it forever;
- cap the resulting window at `_MAX_SEND_WINDOW = 2^31 − 1`, so a flood of large grants
  cannot grow it without bound.

A compliant peer never triggers any of these.

### 7.4 Deadlock freedom

The multiplexer's frame reader (the demux loop) **never blocks on sending** — it only
enqueues received `DATA`, applies a grant, or spawns a teardown. Because the reader
cannot be parked on a backpressured send, a stalled stream can neither wedge the demux
loop nor head-of-line-block other streams: each peer always keeps draining its socket.

This yields the liveness property: *if the receiver keeps draining downstream, the
sender cannot stay blocked.* Sketch — when a sender is blocked its window is exactly 0,
i.e. it has one full window (256 KiB) of unacknowledged bytes in flight; when the
receiver has drained all of them, its un-credited total is ≥ 256 KiB, which exceeds the
128 KiB threshold, so a `WINDOW_UPDATE` is necessarily owed and the sender unblocks.
The only way a sender stays blocked is a downstream that genuinely will not accept more
data — which is correct backpressure, bounded by the timeouts below.

> This covers a *cooperative-but-slow* peer. A *malicious or wedged* peer — one that
> stops reading the socket, or refuses to return credit — is not a flow-control
> problem; it is handled by enforcement (§10).

### 7.5 Credit-stall timeout

A sender parked on zero credit for `_CREDIT_STALL_TIMEOUT = 120s` without receiving a
(nonzero) grant gives up: it aborts the stream rather than pin a slot/FD forever. The
clock is **per wait**, so any real grant resets it — a slow-but-progressing consumer
keeps the stream alive.

---

## 8. Frame semantics (reference)

### `OPEN` (0x01) — server → agent

The server allocates a fresh id, sends `OPEN`, and **MUST** order it strictly before
any `DATA` for that id. On receipt the agent creates the stream and dials the local
app; if the registry is full it answers `RESET`, and a duplicate live id gets `RESET`.
A dial failure (refused, blackholed within a 10s connect timeout) is answered with
`RESET`.

### `DATA` (0x02) — both directions

Carries opaque payload. The sender **MUST** respect the credit window (§7.1); the
receiver enqueues it for its consumer and later returns credit (§7.2). A receiver
**MUST** drop `DATA` whose receive direction is not `OPEN` (data after `EOF`/`RESET`),
and **MUST** drop an **empty** `DATA` frame (it delivers nothing, is never sent by a
compliant peer, and is otherwise a backstop-evasion vector; §10).

### `EOF` (0x03) — both directions

A clean half-close of the sender's direction. `OPEN → EOF` on the receiver; idempotent
(a second `EOF`, or `EOF` after a terminal, is a no-op). The receiver eventually
signals end-of-stream downstream with a clean FIN (§9).

### `RESET` (0x04) — both directions

Abort the stream immediately, both directions. `OPEN → RESET` (unless already
terminal; §6.3). The receiver tears down and signals downstream with a hard RST. The
peer that initiates a reset sends exactly one `RESET` frame.

### `WINDOW_UPDATE` (0x05) — both directions

Grants the peer `delta` more bytes of send credit. Sent by a receiver after draining
downstream (§7.2); validated on receipt (§7.3). Not flow-controlled itself.

### `GOAWAY` (0x06) — both directions

Connection-level (stream id `0`, empty payload): the sender is **draining**. After
sending `GOAWAY` it opens no new streams; it keeps servicing in-flight streams, then
closes the connection (`1001`) once they finish or a bounded grace elapses
(`_DRAIN_GRACE`). A receiver **MUST** stop directing new work at the peer while letting
in-flight streams complete: the server deregisters a draining agent from routing (new
visitors get `503`), and the agent — which never opens streams — simply lets its
reconnect loop handle the close that follows. This is the zero-drop restart path: the
server drains on `SIGTERM`/`SIGINT`, the agent on Ctrl-C / `aclose()`. It carries no
last-stream id (only the server opens streams, and it just stops); unknown ids or extra
payload are ignored.

---

## 9. Teardown and half-close

When the consumer of a stream reaches end-of-stream (its read returns the terminal),
it maps the receive state to a downstream socket action:

| Receive terminal | Cause | Downstream action |
|---|---|---|
| `EOF` | peer sent `EOF` | **FIN** — `write_eof()`, or a full `close()` on transports that can't half-close (e.g. the SSL edge: a close-delimited HTTP/1.0 / SSE response must still produce an observable end). |
| `RESET` | peer `RESET`, a local limit breach, or connection death | **RST** — `transport.abort()`, so a partial/aborted body is *not* mistaken for a complete one, and a sibling pump blocked on read unblocks immediately. |

This `EOF → FIN` / `RESET → RST` distinction is why the receive terminal is write-once
(§6.3): a complete response that ended in `EOF` must never be re-signalled as a
truncation because a `RESET` arrived a moment later.

When the **connection** drops, every live stream is moved to its terminal (a clean
`EOF` is preserved; an open receive direction becomes `RESET`), every blocked sender is
woken to bail, and all per-stream handlers are cancelled — so no socket or slot leaks
across a reconnect.

---

## 10. Limits and enforcement

**Threat model.** The agent is authenticated but only *semi-trusted*: a leaked token,
a compromised agent, or simply a buggy/wedged peer is in scope (and in multi-tenant
mode one bad tenant must not be able to harm the others). Flow control alone assumes a
cooperative peer; these limits enforce good behaviour against one that isn't. A
compliant peer never approaches any of them.

| Limit | Value | Defends against |
|---|---|---|
| `_MAX_WS_MESSAGE` | 256 KiB | Pre-auth unbounded buffering; oversized frames. |
| Per-stream byte backstop | 2× negotiated window (512 KiB by default) | A peer flooding `DATA` past its granted credit (per-stream **byte** buffer). |
| Per-stream frame-count backstop | negotiated window in frames (262 144 by default) | An **empty/tiny-frame flood** the byte cap is blind to (per-stream **frame-count** buffer). |
| `_MAX_CONN_BUFFERED` | 64 MiB | Aggregate buffering across *all* streams on one connection (the shared budget per-stream windows alone don't bound). |
| `_MAX_CONN_FRAMES` | 1 048 576 | A **tiny-frame flood across many streams** the byte cap is blind to (per-frame object overhead; connection **frame-count** buffer). |
| `_MAX_STREAMS` | 4096 | A peer growing the stream registry without bound. |
| `_MAX_IGNORED_FRAMES` | 65 536 | Authenticated-peer churn: malformed frames, unknown stream ids, duplicate GOAWAY, and other non-actionable frames are tolerated for normal races, then the connection is aborted if the flood continues. |
| Mux flow-window preference | 256 KiB default; 16 MiB configured max | Per-connection throughput/memory tradeoff; `CHUTE_MUX_FLOW_WINDOW` / `--mux-flow-window` set each endpoint's preference, and the negotiated value is the lower preference. |
| `_WRITE_STALL_TIMEOUT` | 30s | A peer that stops reading its socket (pauses our writes) — the connection is aborted, since the WS keepalive can't detect this (its ping blocks on the same paused write). |
| `_CREDIT_STALL_TIMEOUT` | 120s | A peer that drains but never returns credit — the stream is reset. |
| `WINDOW_UPDATE` validation | len == 4; `delta != 0`; cap 2³¹−1 | Malformed/zero/overflowing credit frames (the zero-grant stall-clock bypass). |
| Empty `DATA` dropped | — | The unbounded queue-growth vector that ignores the byte cap. |
| Server ignores peer `OPEN` | — | A malicious agent growing the server's stream table. |
| Failed-auth limiter | 5 / 60s per exact IPv4 address or IPv6 `/64` | Pre-auth token guessing. |
| Pre-auth concurrency | 256 in-flight handshakes | Half-open handshake floods (FD/CPU); `CHUTE_MAX_CONTROL_CONNS=0` rejects all. |
| Auth concurrency | defaults to pre-auth concurrency | Slow/unavailable control-plane calls pinning handshake work; `CHUTE_MAX_AUTH_CONNS=0` rejects all auth/admission work. |
| `hello_timeout` | 5s | An unauthenticated peer squatting a slot; `CHUTE_HELLO_TIMEOUT` tunes this. |
| `auth_timeout` | 5s | Control-plane/auth I/O squatting an auth slot; `CHUTE_AUTH_TIMEOUT` tunes this. |
| Agent registry | 1024 labels | Relay-local cap on registered agent labels; replacements of an existing label are allowed, but new labels over `CHUTE_MAX_AGENTS` close retryably (`1013`). |
| Visitor concurrency | 2048 global; 64 per direct non-loopback exact IPv4 or IPv6 `/64` | Public-side FD exhaustion / unbounded stream creation; `CHUTE_MAX_VISITORS=0` rejects all visitors. |
| Relay idle timeout | disabled | Optional no-progress visitor stream policy; `CHUTE_RELAY_IDLE_TIMEOUT=N` resets a stream after N seconds with no relayed bytes in either direction, while `0/off/none/false/unlimited` disables it. |
| Relay drain timeout | 120s | A stalled downstream pinning a stream's buffer. |
| Local connect timeout | 10s | A blackholed local port pinning a stream. |
| Metrics listener | disabled | Optional loopback-only `/healthz` and `/metrics`; `CHUTE_METRICS_PORT=N` enables it, `CHUTE_METRICS_HOST` defaults to `127.0.0.1`, and a routable metrics host is refused. |
| systemd watchdog | `WatchdogSec=30s` | A wedged daemon event loop: `READY=1` is sent after listeners bind, then `WATCHDOG=1` is emitted at half of `$WATCHDOG_USEC`. |

Breaching a per-stream or connection buffer limit **RESET**s the offending stream
(load-shed). Breaching the write-stall timeout aborts the whole connection (the
deadlock breaker). The buffer counters reconcile on teardown, so they never drift.

---

## 11. Close codes

WebSocket close codes used on the control channel:

| Code | Meaning | Agent reaction |
|---|---|---|
| `1000` | Normal closure. | — |
| `1011` | Internal error (incl. keepalive ping timeout). | Retry (backoff). |
| `1013` | Try again later — busy, control plane unavailable, auth/reconnect-rate-limited. | Retry (backoff). |
| `4000` | Bad handshake (malformed / timed-out / non-object hello). | Retry. |
| `4001` | Unauthorized (bad/revoked token). | **Fatal — no retry.** |
| `4002` | Subdomain rejected / tunnel limit (`reason` carries the code). | **Fatal — no retry.** |
| `4003` | Superseded by a newer connection. | Retry. |
| `4004` | Protocol-version mismatch. | **Fatal — no retry.** |

Fatal codes (`4001`, `4002`, `4004`) make the agent surface a reason and stop; all
other closes are treated as transient and trigger reconnect with exponential backoff +
jitter.

---

## 12. Versioning and compatibility

- The protocol version is negotiated **out of band**, in the JSON handshake (`v` in
  both `auth` and `ready`), **not** in the binary prefix. Both ends **MUST** agree on
  the exact version before any binary frame flows; a mismatch fails closed (`4004` /
  fatal) rather than letting a half-speaking pair stall or overflow.
- Negotiating in the handshake (not the prefix) means a new frame type — e.g.
  `WINDOW_UPDATE` in v2 — can be added without an older peer silently no-op'ing it.
- **v2** introduced credit-based flow control (`WINDOW_UPDATE`). The hardening that
  followed (frame-count and connection buffer caps, the write-stall and credit-stall
  timeouts, `WINDOW_UPDATE` validation, the receive state machine) changed
  **enforcement and local behaviour only** — no wire change — so it stayed v2.
- **v3** added the `GOAWAY` frame (graceful drain). Adding a frame type is a wire
  change, so the version bumped and v3 peers refused mismatched handshakes with
  `4004`. This is exactly why the version is negotiated in the handshake — so a
  new frame can't be silently dropped.
- **v4** added `flow_window` negotiation in the JSON handshake. This is a protocol
  semantic change because the initial send credit and receive-side backstops are no
  longer a single fixed constant; a v4 peer refuses any peer whose handshake
  `v != 4` with `4004`.

Bump the version when the frame set or framing semantics change incompatibly.

---

## 13. Security considerations

- **Authentication & transport.** The control channel is the only internet-facing
  pre-auth surface. It is gated by a constant-time token compare over a pinned-cert TLS
  channel, with compression off, finite WebSocket message/queue/write caps, bounded
  handshake concurrency, a hello timeout, and a per-IP failed-auth limiter (§4,
  §10). The token is the trust boundary; treat its leak as the primary residual
  risk.
- **Enforcement is per-connection.** Every quantity one connection's peer can grow is
  bounded — per-stream bytes and frame count, per-connection aggregate buffer and frame
  count, stream count, send-window growth (§10) — and every way it can stall is timed out
  (credit return, downstream drain, transport write, handshake). So a single malicious or
  wedged connection cannot wedge itself or grow its memory without bound. Cross-agent
  growth is bounded by the relay-global agent registry cap plus the visitor pool, and
  tenant containment is only as strong as the per-account `Budget` the control plane sets
  (`max_visitors`, `max_reconnects_per_min`, `max_bytes_per_sec`, and
  `max_buffered_bytes` enforced locally; §4) plus the host limits the operator imposes.
- **Byte transparency is deliberate** (§14): chute does not sanitise payloads. It is a
  pipe, not a WAF. Exposure of the local app is the operator's responsibility.
- **Visitor routing.** The server always reads and validates a complete HTTP/1.x
  request head before opening an agent stream. Without `base_domain`, a valid head
  selects the reserved internal `default` label; HTTP/1.0 may omit `Host`, HTTP/1.1
  may not. With `base_domain`, the public port validates the request line and
  strictly parses `Host` to choose a label, then forwards the accepted head verbatim
  — it never rewrites, only refuses. It answers `400` and closes the connection on a
  head it cannot unambiguously route: malformed request line; a missing, duplicate,
  or invalid `Host` (RFC 9110 §7.2); whitespace before a field-name colon (RFC 9112
  §5.1); an obsolete line fold (§5.2); a bare CR or LF; or a non-origin-form
  request-target (§3.2.2). The Host-routed port is loopback-only and sits behind
  nginx, which owns public parser and one-request-per-upstream-connection assurance.
  chute's parser is a reject-only backstop. *Why* — the threat model (parser
  differentials, the connection-level pipelining desync, the one-request-per-
  connection requirement) — is the README's "Security model", not restated here.
- **Visitor concurrency accounting.** Standalone/direct edge mode caps concurrent
  public connections both globally and per non-loopback peer IP. Host-routed mode
  binds chute to loopback, so chute only sees the reverse proxy as the TCP peer;
  true client-IP concurrency must be enforced in nginx (`limit_conn`) or the
  equivalent front proxy.

---

## 14. Design rationale and non-goals

- **One connection, many streams.** Avoids connection-per-request pool exhaustion and
  gives clean concurrency, at the cost of sharing one ordered transport (see the HOL
  note below).
- **Server-only stream opening.** Eliminates id-collision negotiation and denies a
  malicious agent any way to grow server state by opening streams. The price is that
  the agent is purely reactive.
- **WebSocket message = frame.** Free, unambiguous framing with no length parsing; the
  256 KiB message cap doubles as the pre-auth buffer bound.
- **HTTP-head admission, then byte transparency.** Requiring a valid request head
  before `OPEN` makes chute an HTTP tunnel rather than an arbitrary TCP relay. Once a
  stream is admitted, no payload parsing means keep-alive, chunked, SSE, and
  WebSocket upgrades pass through verbatim. Host routing peeks only the request head
  and only on the visitor socket, never the relayed stream.
- **Credit returned on consume, not arrival.** The single most important flow-control
  choice; it is what makes backpressure end-to-end (§7.2).
- **No connection-level *fairness* window.** chute bounds aggregate **memory**
  (`_MAX_CONN_BUFFERED`) but, like yamux and unlike HTTP/2, has no connection-level
  window that throttles bandwidth across streams. A congested shared link slows all
  streams together; per-stream windows isolate *buffering*, not *bandwidth*. For a
  personal/small tunnel where the internet link is the bottleneck this is the right
  trade.
- **64 KiB frames, not split to 16 KiB.** A `DATA` frame is at most one pump read
  (~64 KiB). yamux splits at 16 KiB for finer interleaving on a congested link; chute's
  coarser frame trades a little interleaving latency for simplicity, fine at tunnel
  concurrency.

Non-goals: per-tunnel tokens / accounts / dashboard, request inspection, payload
sanitisation, and bandwidth fairness across streams.

---

## 15. Known limitations

These are tracked, accepted residuals — documented here so they are not mistaken for
guarantees:

- **Application-idle policy is explicit, not implicit.** Visitor admission reads a
  complete HTTP request head under `_FIRST_BYTE_TIMEOUT`, so a connect-and-send-nothing
  peer is closed before it opens an agent stream; `SO_KEEPALIVE` reaps a *vanished*
  peer. A *live* stream that keeps the socket open but sends no bytes is allowed by
  default for byte transparency and quiet SSE/WebSocket tunnels. Operators that need a
  hard no-progress deadline can set `CHUTE_RELAY_IDLE_TIMEOUT=N`; the timer resets on
  relayed bytes in either direction, so long-lived streams need heartbeat traffic or a
  disabled/high timeout.
- **Proxy-mode per-IP accounting is not automatic.** chute caps direct non-loopback
  peers by exact IPv4 address or IPv6 `/64`, but Host-routed deployments intentionally
  put chute behind loopback nginx.
  In that shape nginx sees the real client IP and chute sees `127.0.0.1`, so operators
  must keep a front-proxy client-IP cap such as the bundled `limit_conn` config.
- **Stream-id exhaustion is a hard stop, not a recycle.** After ~4.29 billion streams
  on one connection (≈ 50 days at 1000 req/s) the initiator refuses new streams until
  the connection is re-established; nothing auto-reconnects on exhaustion.
- **Graceful drain, but no HA.** `SIGTERM`/Ctrl-C drains in-flight streams before closing
  (`GOAWAY`, §8), so a restart no longer hard-drops active requests. Control-plane
  revocation can also choose an immediate close action for a live lease. State is
  still in-RAM and single-node: long-lived streams are force-closed at the drain
  deadline (`_DRAIN_GRACE`) unless a policy closes sooner, tunnel registrations are
  lost across a restart, and URL stability still depends on a fixed subdomain.
  Multi-node failover is future work.
- **Memory caps are relay-local, not host-global.** `Budget.max_buffered_bytes`
  caps unread mux payload queued inside chute per account, and each connection
  still has `_MAX_CONN_BUFFERED` / `_MAX_CONN_FRAMES` backstops. It does not cap
  kernel socket buffers, WebSocket library internals, downstream app memory, or
  memory on other relay nodes, so host limits and account tunnel caps still matter.

---

## Appendix A: constants

All from `src/chute/mux.py` unless noted. Values are defaults; several are tunable.

| Constant | Value | Meaning |
|---|---|---|
| `protocol.VERSION` | `4` | Negotiated protocol version. |
| `_DRAIN_GRACE` | 10 s | Graceful-drain wait for in-flight streams before close. |
| `_FLOW_WINDOW` | 256 KiB | Default preferred per-stream send credit, each direction. |
| Negotiated flow window | 1 byte to 16 MiB | Per-connection initial send credit; chosen as the lower of server and agent preferences (`CHUTE_MUX_FLOW_WINDOW` / `--mux-flow-window`). |
| Window update threshold | half the negotiated window | Drained bytes that trigger a `WINDOW_UPDATE`. |
| `_MAX_SEND_WINDOW` | 2³¹−1 | Hard ceiling on accumulated credit. |
| Per-stream byte backstop | 2× negotiated window | Per-stream buffered-**byte** backstop. |
| Per-stream frame-count backstop | negotiated window in frames | Per-stream queued-**frame** backstop. |
| `_MAX_CONN_BUFFERED` | 64 MiB | Connection-wide aggregate buffer cap. |
| `_MAX_CONN_FRAMES` | 1 048 576 | Connection-wide queued-frame cap (per-frame overhead). |
| `_MAX_STREAMS` | 4096 | Concurrent streams per connection. |
| `_MAX_IGNORED_FRAMES` | 65 536 | Non-actionable inbound frames tolerated before aborting the connection. |
| `_CREDIT_STALL_TIMEOUT` | 120s | Sender gives up if no credit returns. |
| `_WRITE_STALL_TIMEOUT` | 30s | Connection aborted if a send can't drain. |
| `_MAX_WS_MESSAGE` | 256 KiB | Max WebSocket message (server.py / client.py). |
| `ping_interval` / `ping_timeout` | 20s / 20s | WebSocket keepalive (both ends). |
| `hello_timeout` | 5s | Handshake read budget (server.py); `CHUTE_HELLO_TIMEOUT`. |
| `auth_timeout` | 5s | Control-plane/auth call budget (server.py); `CHUTE_AUTH_TIMEOUT`. |
| Control concurrency | 256 | Max concurrent pre-auth handshakes (server.py); `CHUTE_MAX_CONTROL_CONNS=0` rejects all. |
| Auth concurrency | same as control concurrency | Max concurrent control-plane/auth calls (server.py); `CHUTE_MAX_AUTH_CONNS=default` follows control, `0` rejects all. |
| Agent registry | 1024 labels | Max registered agent labels on one relay (server.py); `CHUTE_MAX_AGENTS=0` rejects new labels, existing-label replacement still works. |
| Visitor concurrency | 2048 global; 64 per direct non-loopback exact IPv4 or IPv6 `/64` | Max concurrent public connections (server.py); `CHUTE_MAX_VISITORS=0` rejects all, and `CHUTE_MAX_VISITORS_PER_IP=0/off/none/false/unlimited` disables the per-IP cap. |
| Relay idle timeout | disabled | Optional no-progress visitor stream timeout (server.py); `CHUTE_RELAY_IDLE_TIMEOUT=N`, disabled by `0/off/none/false/unlimited`. |
| Metrics listener | disabled | Optional loopback health/metrics listener (server.py); `CHUTE_METRICS_PORT=N`, `CHUTE_METRICS_HOST=127.0.0.1` by default. |
| Relay drain timeout | 120s | No-progress downstream write (server.py / client.py). |
| Local connect timeout | 10s | Agent dial to the local app (client.py). |

---

## Appendix B: a request, end to end

A single HTTP request through a default-route tunnel:

1. **Visitor connects** to the server's public port and sends a valid HTTP request
   head.
2. The server selects the agent registration: `default` without `base_domain`, or the
   validated `Host` label with `base_domain`.
3. The server **opens a stream** (`OPEN`, fresh id) to the agent, forwards the
   buffered request head as the first `DATA`, and starts two pumps: visitor→stream and
   stream→visitor.
4. The remaining visitor bytes are read in ≤64 KiB chunks and sent as `DATA`, each
   debiting the stream's send window. If the window hits 0 (the agent/local app is
   slow to drain) the pump blocks — the visitor's TCP backpressures.
5. The **agent** receives `OPEN`, dials `127.0.0.1:app`, and pipes: `DATA` → local
   socket; as it drains the local socket it returns credit with `WINDOW_UPDATE`.
6. The local app's response flows back the same way: agent `DATA` → server, server
   drains it to the visitor and returns credit to the agent.
7. When the visitor finishes its request body it sends nothing more; when the app's
   response completes the local socket closes → the agent sends `EOF`. The server's
   stream→visitor pump reads the terminal and writes a clean FIN to the visitor.
8. When both directions are done (or the visitor closes), both pumps finish, the stream
   is closed and deregistered, and its credit/buffer accounting is reconciled.

If anything aborts mid-flight — the visitor disconnects, the local app dies, a limit is
breached — the affected side sends `RESET`, the peer maps it to an RST downstream, and
the stream tears down without leaking a socket or a slot.
