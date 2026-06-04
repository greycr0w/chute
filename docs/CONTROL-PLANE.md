# Chute control plane

This document defines the boundary between chute's data plane and policy/control
plane. The goal is not to copy Envoy or Contour. The useful lesson from those
systems is narrower: keep the runtime that moves traffic small and locally
enforcing, while policy, ownership, and observability are supplied through a
separate contract.

## Design premise

chute has two different jobs:

- **Data plane**: accept agent control connections, admit visitor HTTP requests,
  select a tunnel, open mux streams, relay bytes, apply local limits, and drain or
  close live streams.
- **Control plane**: decide who may create a tunnel, who owns a label/hostname,
  what local budget applies, when a tunnel should be revoked or drained, and where
  lifecycle events and stats should be exported or persisted.

The control plane decides. The relay enforces. The visitor hot path must not call
a remote service by default.

## Current implemented boundary

The first implemented boundary is tunnel admission:

```text
Agent hello
  -> relay validates syntax/protocol version
  -> ControlPlane.admit_tunnel(TunnelAdmissionRequest)
  -> TunnelAdmission or reject
  -> relay installs local registration
  -> ready
  -> relay renews finite leases in the background
  -> relay polls versioned policy deltas in the background
  -> mux data plane
```

The Python API is in `src/chute/control.py`:

- `TunnelAdmissionRequest` carries pre-admission facts the relay knows: token,
  requested label, agent IP, scheme, and protocol version.
- `TunnelAdmission` carries local policy for the relay: account, credential,
  tunnel cap, allowed label, budget, and a `TunnelLease`.
- `TunnelLease` is the control-plane handle for an admitted tunnel. The current
  static implementation returns non-expiring leases; hosted/sidecar control
  planes can return finite expirations.
- `ControlPlane.admit_tunnel()` is the admission policy seam.
- `ControlPlane.renew_lease()` refreshes finite leases. Returning `None` revokes
  the lease; raising or timing out is treated as transient and retried until local
  expiry.
- `ControlPlane.poll_policy_updates()` returns optional versioned deltas for live
  relays: lease revocations, lease revocation actions, and account budget
  replacements. Invalid or stale updates are rejected as a whole and the relay
  keeps last-good local policy.
- `AuthorizerControlPlane` adapts the existing `Authorizer` hook.
- `StaticTokenControlPlane` preserves standalone chute: one token, one bootstrap
  account, no database, no policy polling task unless explicitly configured.
- `StaticPolicyControlPlane` loads a local JSON policy file for self-hosted
  account/credential/budget policy without writing Python glue.
- `EventSink` emits lifecycle events, rejection audit events, and periodic
  low-cardinality `RelayStatsEvent` snapshots. The default sink is no-op.
- `JsonlEventSink` persists those events to a local owner-only JSONL file for
  self-hosted audit trails without writing Python glue.

`chuted` can load the built-in file-backed policy with `--policy-file` or
`CHUTE_POLICY_FILE`. It can also load a custom implementation with
`CHUTE_CONTROL_PLANE=module:attr`; the value may point at an instance or a
zero-argument factory. Set only one of `CHUTE_POLICY_FILE`,
`CHUTE_CONTROL_PLANE`, or `CHUTE_AUTHORIZER`.

`CHUTE_AUTHORIZER` is the simple admission-only extension hook: it answers
"which account may this token open, and with what label/budget?" It is not
deprecated. `CHUTE_CONTROL_PLANE` is the full lifecycle hook: admission plus
finite lease renewal, revocation, and policy-budget updates. Structurally,
`AuthorizerControlPlane` adapts an `Authorizer` into that wider seam.

## Visitor hot path

The visitor path stays local:

```text
visitor TCP
  -> read bounded HTTP request head
  -> parse Host / select label
  -> local route/registration lookup
  -> local lease check / account visitor-slot reservation
  -> mux OPEN
  -> relay bytes
```

This is the performance rule. Control-plane I/O can add latency to agent startup
or reconnect, but it must not add a remote round trip to every visitor request in
normal tunnel mode.

Control-plane return objects are validated at runtime before they mutate local
relay state. A malformed admission is treated like unavailable policy: the control
connection closes `1013` and no tunnel is registered. Malformed finite renewals are
ignored until local expiry, and malformed policy updates are rejected as a whole.
`None` remains the explicit unauthorized or lease-revoked result where the API
defines it.

## Guarantees matrix

Use this table as the boundary for product claims. If a guarantee is not listed
here, either add code/tests and update the table or describe it as operator-owned
or not guaranteed.

| Area | Guaranteed by chute core | Owned outside chute core | Not guaranteed |
|---|---|---|---|
| Admission and ownership | Syntax/protocol validation, token/control-plane admission, local label ownership, pending-label reservation, local tunnel caps, and finite lease expiry/revocation. | Token secrecy, credential lifecycle, custom or managed control-plane availability, and the policy file contents a self-hosted operator writes. | OAuth, SSO, billing identity, global account state, or a dashboard. |
| Visitor routing | Bounded HTTP/1.x request-head admission, strict Host parsing in host-routed mode, reject-only parser behavior, loopback-only host routing, and byte-transparent relay after admission. | The front proxy must normalize public HTTP, avoid upstream keepalive, and provide one request per upstream connection. | WAF behavior, payload sanitization, request rewriting, or protection for the local app beyond refusing ambiguous request heads. |
| Local resource budgets | Per-relay account budgets for visitor slots, reconnect rate, byte rate, and unread mux payload bytes, including detached in-flight streams after a policy update. | The control plane chooses meaningful account budgets; the host/operator sets process, file descriptor, memory, network, and account tunnel limits. | Host-global memory caps, kernel socket buffer limits, downstream app memory limits, bandwidth fairness across streams, or fleet-wide budget accounting. |
| Events and audit | Bounded best-effort event delivery by default, queue/drop/retry counters, owner-only JSONL local event files, and fail-closed `tunnel_opened` admission when `CHUTE_REQUIRE_EVENT_SINK=1`. | Durable storage, retention, alerting, compliance reports, and exporter/database availability. | Compliance-grade audit by default, replayable event logs, or guaranteed delivery for non-required events. |
| Performance | No remote control-plane call on the visitor hot path; mux flow-window negotiation with a conservative default and explicit memory/throughput tradeoff. | Operators must run remote VPS/nginx/TLS/local-app benchmarks before changing defaults for their deployment. | WAN throughput, latency SLOs, bandwidth fairness, or a universal best flow-window default. |
| Deploy and edge | Bundled deploy config binds host routing to loopback, renders nginx without upstream keepalive, validates nginx before restart, and fails closed on an unrestricted control port unless the operator explicitly acknowledges an external firewall. | Public ACME certs, DNS, VPS firewall state, cloud firewall rules, and OS/package availability. | Proof that an external firewall is correct, automatic ACME management, or live host-state verification from unit tests. |
| Availability and fleet | Local graceful drain, local lease renewal/expiry, local revocation, and single-node last-good policy behavior. | Multi-node routing, global failover, DNS automation, fleet placement, persistent state, and sidecar/managed control-plane rollout. | HA, multi-node seamless failover, or preserving in-RAM tunnel registrations across restart. |

Finite leases are enforced in this local path. `expires_at=None` means static
standalone policy and never expires. If `expires_at` is in the past, the relay
removes the route, stops accepting new visitors for that tunnel, and drains the
mux connection in the background. Existing in-flight streams get the drain window;
new visitors see the normal offline/no-tunnel response.

Finite leases are renewed by a relay background task, not by visitor requests. The
task wakes in a deterministic jittered window of the lease lifetime, calls
`renew_lease()`, and applies only a renewed lease that matches the current lease id,
account, credential, a real non-decreasing integer generation, and a finite
timezone-aware `expires_at` still in the future. `expires_at=None` is valid for
static standalone admission, not for renewing an already-finite lease. Transient or
malformed renewal results do not immediately drop traffic; the relay retries at a
bounded jittered cadence until the current local expiry, then drains if renewal
never succeeds. An explicit `None` renewal result revokes immediately.

The relay also enforces a host-level registered-agent ceiling
(`CHUTE_MAX_AGENTS`) before installing a new label. This is deliberately separate
from `TunnelAdmission.max_tunnels`: the control plane owns account policy, while
the relay still protects its local registry, FDs, and memory if a static token or
buggy policy grants too many labels. Replacing an existing label does not consume
another slot.

Visitor budgets are also enforced locally. The relay reserves one per-account
visitor slot before it awaits mux `OPEN`, then releases that slot when the visitor
relay closes. This keeps the hot-path decision constant-time and prevents concurrent
visitors from racing past `Budget.max_visitors`.

Reconnect budgets are enforced locally on the control channel after admission
identifies the account and before the relay sends `ready`. A
`Budget.max_reconnects_per_min` value limits successful control-channel connects per
account per relay over a 60-second window. Exceeding it closes `1013`, preserving
agent backoff behavior without marking the credential or label permanently invalid.

Bandwidth budgets are enforced locally in the relay data path.
`Budget.max_bytes_per_sec` is an aggregate per-account, per-relay byte-rate
budget shared by visitor-to-agent and agent-to-visitor forwarding. The relay
delays chunks before forwarding; zero or malformed values fail closed. This does
not call the control plane and does not change mux framing.

Memory budgets are enforced locally at the mux queue boundary.
`Budget.max_buffered_bytes` is an aggregate per-account, per-relay cap on unread
mux payload bytes held by chute. The mux asks the relay to reserve account bytes
before queueing inbound `DATA` and releases the same bytes when the consumer reads
or abandons them. Exceeding the cap resets the offending stream without a
control-plane call.

Dynamic policy updates are polled by a relay background task for custom control
planes. The request always contains the relay's current accepted policy version
and active-plus-pending lease count. It contains the full active lease-id snapshot
only when the control-plane object explicitly sets
`include_active_lease_ids_in_policy_poll = True`; the built-in
`StaticPolicyControlPlane` opts in because it uses the snapshot to prune its local
finite-lease cache. Cloud/custom control planes should usually leave this off and
return revocations by lease id; the relay treats absent lease ids as no-ops. A
returned update must have a strictly newer version and structurally valid bounded
payloads; otherwise the relay applies none of it and does not advance its local
version. Valid updates are local operations: legacy `revoke_lease_ids` entries
call the same drain path as lease expiry, structured `LeaseRevocation` entries
can choose `drain` or `close`, and budget updates replace the current local account
budget used by live tunnels and detached in-flight relay work for that account.
Revocations are applied through relay lease-id indexes rather than by
scanning every active or pending tunnel for each revoked lease. `drain` stops new
visitors and gives in-flight streams the relay drain window. `close` stops new
visitors and closes the mux connection immediately.

Relay stats are emitted from a relay background task, not from the visitor hot
path. The snapshot aggregates process-local mux gauges/counters and cumulative
relay byte counters across all live tunnels. It also reports control/auth/visitor
pool usage/capacity, direct visitor source-bucket count, fixed busy/limit shed
counters for those pools, fixed generated lifecycle/audit event counters, and
best-effort event queue depth/capacity plus enqueue/deliver/retry/drop counters,
policy update applied/rejected/poll-failure counters, lease renewal outcome
counters, and lease revocation/expiration counters, so exporter overload, pool
saturation, and control-plane drift are visible without blocking the relay. The
same aggregate snapshot is available through the loopback metrics endpoint, the
periodic stats log, and the optional `relay_stats` event. It deliberately avoids
per-label, per-reason, or per-stream metric cardinality in core; exporters can
attach richer dimensions outside the relay.

Best-effort lifecycle/stat events are delivered through a bounded relay-local
queue with bounded retry. A slow or transiently failing sink can delay or drop its
own exported events, but it does not add a database/exporter round trip to visitor
admission or byte relay. The only synchronous event gate is `tunnel_opened` when
`CHUTE_REQUIRE_EVENT_SINK=1`, because that mode explicitly asks the relay to fail
closed before advertising a tunnel.

`JsonlEventSink` is the local, no-database implementation of the event side of the
same contract. Enable it with `--event-log-file` / `CHUTE_EVENT_LOG_FILE`. Tunnel
open/close events include the lease id, which is the operator-visible handle for
static-file `lease_revocations`. The file is created with owner-only permissions
and any existing file must be a non-symlink
regular file owned by the user running `chuted` (`chute` in the bundled systemd
unit) and readable only by its owner (`chmod 600` on POSIX); the parent directory
must be owned by that user and must not be group- or world-writable because
default rotation renames files in that directory. To keep this local path from
becoming a disk-fill footgun, it rotates by size by default:
`CHUTE_EVENT_LOG_MAX_BYTES` defaults to 100 MiB and `CHUTE_EVENT_LOG_BACKUPS`
defaults to 5. Rotated files use the same owner-only checks, and setting
`CHUTE_EVENT_LOG_MAX_BYTES=off` or `CHUTE_EVENT_LOG_BACKUPS=0` should be reserved
for deployments where external logrotate/journald/cloud shipping owns retention.
Treat it as metadata-sensitive: it never contains proxied payload bytes, but it
does contain account ids, credential ids, labels, Hosts, public URLs, and source
IPs.

## Static policy file

`StaticPolicyControlPlane` is the local, no-database implementation of the same
contract. The file must be a non-symlink regular JSON file readable only by its
owner (`chmod 600` on POSIX) and owned by the user running `chuted` (`chute` in
the bundled systemd unit). Its parent directory must be owned by that user or
root and must not be group- or world-writable. It is validated at daemon startup,
then reloaded only when the
private-file fingerprint changes. Credential, budget, and revocation changes can
apply without a restart, unchanged files reuse the cached parsed policy, and
malformed live edits keep the last-good policy until a valid replacement appears.
An invalid initial file still fails closed because there is no last-good policy to
enforce. The file is capped at 1 MiB; policy files and returned policy deltas also
cap credential, revocation, and budget-update counts so malformed local config or
buggy imported control planes cannot monopolize the relay event loop with
unbounded policy work.

Tokens are not stored in plaintext. Each credential contains a SHA-256 token
digest. This is still sensitive configuration: use high-entropy random tokens and
protect the file because a leaked verifier enables offline guessing of weak
tokens.

Generate the token and verifier without putting the token in a process argument.
The private token file must be owned by the user reading it, follows the same
non-symlink owner-only rule, and token generation flushes the file before
returning:

```bash
install -d -m 700 /etc/chute
chuted gen-token --token-file /etc/chute/dev-laptop.token
chuted hash-token --token-file /etc/chute/dev-laptop.token
```

Use the printed `sha256:<digest>` as `token_sha256`, and give the token file to
the agent as `--token-file` / `CHUTE_TOKEN_FILE`.

```json
{
  "schema_version": 1,
  "credentials": [
    {
      "credential_id": "dev-laptop",
      "token_sha256": "sha256:<64 hex chars>",
      "account_id": "acct-dev",
      "allowed_label": "dev",
      "max_tunnels": 2,
      "lease_seconds": 300,
      "budget": {
        "max_visitors": 32,
        "max_reconnects_per_min": 10,
        "max_bytes_per_sec": 10485760,
        "max_buffered_bytes": 4194304
      }
    }
  ],
  "policy_version": 1,
  "lease_revocations": [
    {"lease_id": "lease-to-close", "action": "close"}
  ],
  "account_budgets": [
    {"account_id": "acct-dev", "budget": {"max_visitors": 16}}
  ]
}
```

`lease_seconds` is optional. Omit it for a non-expiring local lease; set it to a
positive integer when the relay should renew the lease from the file-backed
policy. Removing a finite-lease credential or changing it to a non-renewable
credential revokes that lease on the next renewal attempt. Dynamic policy fields
are optional, but if any are present `policy_version` must be present and positive.
Unknown keys are rejected so typos do not silently widen policy. Duplicate
revocations and duplicate account budget updates are rejected at the file boundary.
`allowed_label` values are normalized to lowercase and must be valid hostname
labels. Multiple credentials may reserve the same label for one account, which is
useful during token rotation, but one label cannot be assigned to multiple accounts
in the same policy file.

Validate edits before restart or before replacing a live policy file:

```bash
chuted validate-policy --policy-file /etc/chute/policy.json
```

The command uses the same private-file checks and parser as the daemon, but it
does not read daemon-only run defaults such as `CHUTE_PUBLIC_PORT`.

## Deployment modes

The same data plane should support these modes:

```text
standalone token        StaticTokenControlPlane
local custom auth       AuthorizerControlPlane
local policy file       StaticPolicyControlPlane
sidecar service         future HTTP/gRPC ControlPlane
chute-cloud             hosted implementation of the same contract
```

Open-source users should get the same primitives as cloud users. The commercial
boundary is operations and management, not a private tunnel protocol.

## Core resource boundary

The control-plane resources in chute core are intentionally small and
relay-enforceable:

- `TunnelLease`: admitted tunnel identity, owner, expiry, and generation.
- `Budget` / `AccountBudgetUpdate`: local visitor, reconnect, byte-rate, and mux
  buffer limits the relay can enforce without a visitor-path control-plane call.
- `LeaseRevocation`: lease id plus `drain` or `close` action.
- `PolicyUpdate`: versioned revocation or account budget delta.
- `RelayEvent`: tunnel and visitor lifecycle plus rejection audit events.
- `RelayStats`: active tunnels, streams, bytes, buffers, resets, stalls, limiter
  state, policy counters, and event queue health.

Durable route ownership, fleet placement, global account state, edge gateway
configuration, and any cloud-to-relay watch protocol remain outside chute core.
Core's job is to validate the local objects it receives, apply only newer valid
updates, reject invalid updates, and continue with last-good local state where
doing so is safe.

## Failure rules

Default failure behavior should be explicit:

- If tunnel admission cannot reach a required managed control plane, reject with a
  retryable close code.
- If an admitted tunnel has a finite lease and renewal fails transiently, continue
  until local lease expiry, then stop new visitors and drain existing streams.
- If lease renewal returns `None`, treat it as an explicit revocation and drain
  immediately.
- If a policy update is invalid, reject it and keep last-good policy.
- If a revocation arrives, stop new visitors immediately and either drain or close
  existing streams according to the revocation action.
- If event/stat reporting fails, retry from a bounded queue and do not block visitor
  traffic by default.

## Non-goals

For core completion, cloud compatibility means preserving these local semantics
and extension points. It does not mean shipping a cloud network protocol, edge
gateway, database schema, or fleet scheduler in the core package.

chute core should not own billing, OAuth, SSO, dashboards, cloud databases, DNS
automation, compliance reporting, or fleet placement UI.

chute core should own the protocol, mux, HTTP admission, route lookup, local
registry, local budget enforcement, drain/revocation behavior, public event/stat
schemas, and the control-plane interface.
