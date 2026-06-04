# Security policy

## Reporting a vulnerability

Please report security issues **privately** — use GitHub's *Report a vulnerability*
(the repository's **Security → Advisories** tab), not a public issue, for anything
unpatched. We aim to acknowledge within a few days and will coordinate a fix and
disclosure with you.

## Trust model (what to report against)

chute is a self-hosted HTTP(S) tunnel. Its security model is documented in the
README's **Security model** section and in `docs/PROTOCOL.md`:

The exact guarantee boundary is the
[`docs/CONTROL-PLANE.md` guarantees matrix](docs/CONTROL-PLANE.md#guarantees-matrix):
what chute core enforces locally, what the proxy/operator/control plane owns, and
what is explicitly not guaranteed.

- The **shared token is the trust boundary** — anyone holding it can open tunnels.
  Reports assuming an attacker already has the token are out of scope.
- The **control port** is the only internet-facing pre-auth surface; it caps message
  size, WebSocket frame queueing, and write buffering, disables compression, bounds
  concurrent handshakes, rate-limits failed auth, and times out the hello.
- **Multi-tenant routing is loopback-only** and must sit behind a normalizing reverse
  proxy that gives chute one request per connection and enforces client-IP visitor
  concurrency before forwarding to chute.
- The **public visitor port** has global and direct non-loopback per-IP concurrency
  caps. In loopback proxy mode, chute sees the proxy's address; true client-IP caps
  belong to the front proxy. The bundled nginx config keys exact
  `$binary_remote_addr`, so proxy-mode IPv6 limits are not grouped by `/64`.
- The relay is **byte-transparent** — it is a pipe, not a WAF. Exposure of the local
  app is the operator's responsibility.

In scope: pre-auth DoS/memory-exhaustion on the control or public ports, cross-tenant
routing/desync, parser differentials, TLS/cert handling, and supply-chain integrity.

## Supply chain

Releases are built in CI with third-party actions **pinned to commit SHAs** and
carry build-provenance and CycloneDX runtime-SBOM attestations. The release also
publishes `chute-runtime-sbom.cdx.json`, generated from the built wheel installed
with the same hash-pinned runtime requirements production deploys consume.

```
gh attestation verify <artifact> \
  --repo greycr0w/chute \
  --signer-workflow greycr0w/chute/.github/workflows/release.yml \
  --source-ref refs/tags/<tag>

gh attestation verify <artifact> \
  --repo greycr0w/chute \
  --signer-workflow greycr0w/chute/.github/workflows/release.yml \
  --source-ref refs/tags/<tag> \
  --predicate-type https://cyclonedx.org/bom
```

Production installs runtime dependencies from a **hash-pinned export of the committed
`uv.lock`** (`deploy/requirements.txt`) and build-backend dependencies from
`deploy/build-requirements.txt`, then installs chute with pip build isolation disabled.
That keeps both runtime and local-project build inputs explicit on the production box.

Local pre-commit uses the locked dev runner (`pre-commit==4.6.0`) and freezes
third-party hook repos to commit SHAs with `# frozen: <tag>` comments. Install
hooks with `uv run --no-sync pre-commit install`; refresh hook pins with
`uv run --no-sync pre-commit autoupdate --freeze` or review Dependabot's weekly
pre-commit updates.
