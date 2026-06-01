# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- `chute.__version__` is now read from the installed package metadata instead of
  a hardcoded string, so it can no longer drift from the version in
  `pyproject.toml`.

### Added

- Inline type information is now distributed with the package via a `py.typed`
  marker (PEP 561), so downstream code is type-checked against chute's public
  API. The package is fully annotated and checked under `mypy --strict`.
- Package metadata: trove classifiers, project URLs, and keywords.

### Changed

- CI installs dependencies from the committed `uv.lock` (`uv sync --locked`) for
  reproducible runs across the Python 3.11–3.13 matrix, and adds a `mypy --strict`
  gate plus a test-coverage report.
- Server startup diagnostics (missing token, missing control-channel cert,
  missing public TLS cert) are emitted through the logger instead of `print`.

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
