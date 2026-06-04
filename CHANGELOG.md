# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Breaking

- The pluggable `Authorizer` seam now receives a structured `AuthRequest`
  object instead of three positional arguments. This makes the open-core policy
  boundary explicit and extensible before cloud integrations depend on it.

### Security

- Hardened the multi-tenant relay foundation: protocol v3 graceful drain
  (`GOAWAY`), stricter Host validation, bounded mux frame/message behavior,
  safer malformed auth handling, hash-pinned build-backend installs in deploy,
  a forced-command CD runner that verifies signed commits before deploy or
  rollback, release provenance plus runtime-SBOM attestations, SHA-frozen
  pre-commit hooks, and control-port deployment that fails closed unless
  explicitly allowlisted or externally firewalled.

### Added

- `Budget.max_visitors`, `Budget.max_reconnects_per_min`,
  `Budget.max_bytes_per_sec`, and `Budget.max_buffered_bytes`, enforced per
  account on each relay.
- Relay-global `CHUTE_MAX_AGENTS` / `--max-agents` cap for registered agent
  labels, with existing-label replacement allowed.
- Optional lifecycle `EventSink` seam, loadable through `CHUTE_EVENT_SINK`, for
  tunnel/visitor open/close events and admission rejection audit events. The
  default sink is a no-op, so self-hosted chute stays cloud-free.
- Optional `CHUTE_RELAY_IDLE_TIMEOUT` / `--relay-idle-timeout` no-progress
  policy for visitor streams. It is disabled by default to preserve quiet
  SSE/WebSocket tunnels, and resets streams only when explicitly configured.
- Inline type information is now distributed with the package via a `py.typed`
  marker (PEP 561), so downstream code is type-checked against chute's public
  API. The package is fully annotated and checked under `mypy --strict`.
- Package metadata: trove classifiers, project URLs, and keywords.

### Fixed

- `chute.__version__` is now read from the installed package metadata instead of
  a hardcoded string, so it can no longer drift from the version in
  `pyproject.toml`.
- Default-route tunnels with `upstream_tls=True` now advertise `https://` from
  the server resolver itself, instead of relying on the CLI to precompute a
  separate HTTPS URL.
- `chuted run` now fails closed with a clean config-error exit for malformed
  control cert/key files and partial, missing, or invalid explicit public TLS
  cert/key configuration, instead of tracebacking or silently disabling a
  requested HTTPS edge.

### Changed

- CI installs dependencies from the committed `uv.lock` (`uv sync --locked`) for
  reproducible runs across the Python 3.11–3.13 matrix, and adds a `mypy --strict`
  gate plus a test-coverage report.
- Shared relay pump mechanics now live in `_relay.py`, so server and agent use
  the same EOF, RESET, bounded-drain, and flow-control credit behavior.
- Server startup diagnostics (missing token, missing/invalid control-channel
  cert, missing/invalid public TLS cert) are emitted through the logger instead
  of `print`.

## [0.3.0] - 2026-05-31

First tagged release.

### Added

- Pluggable authorization seam for the control channel: an `Authorizer` protocol
  with a `StaticTokenAuthorizer` default, selectable at runtime via the
  `CHUTE_AUTHORIZER` environment variable. The default single-shared-token
  behavior is unchanged.
- Account-aware relay primitives: per-account concurrent-tunnel limits and a
  per-IP failed-authentication rate limiter on the control port.

## [0.2.0] - 2026-05-31

Initial development release.

### Added

- Stream-multiplexed tunnel over a single outbound WSS control connection
  (custom 5-byte binary frame protocol), traversing NAT with no inbound ports.
- Pinned self-signed control-channel certificate (10-year validity) for
  zero-maintenance, MITM-resistant agent↔server TLS.
- Fully transparent L4 public relay: HTTP keep-alive, chunked transfer, SSE, and
  WebSocket upgrades pass through verbatim, never inspected or rewritten.
- Multi-tenant subdomain routing (`--base-domain`) with friendly auto-assigned
  labels (e.g. `swift-amber-otter`), plus client-requested subdomains.
- Per-tunnel HTTPS (`chute https <port>`): TLS terminates at the server edge with
  hot-reloaded certificates; the agent still speaks plaintext to the local app.
- Auto-reconnect with exponential backoff and jitter; blocking, async, and
  background-thread consumption modes for the `Tunnel` SDK.

[Unreleased]: https://github.com/greycr0w/chute/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/greycr0w/chute/releases/tag/v0.3.0
