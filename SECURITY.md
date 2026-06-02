# Security policy

## Reporting a vulnerability

Please report security issues **privately** — use GitHub's *Report a vulnerability*
(the repository's **Security → Advisories** tab), not a public issue, for anything
unpatched. We aim to acknowledge within a few days and will coordinate a fix and
disclosure with you.

## Trust model (what to report against)

chute is a self-hosted HTTP(S) tunnel. Its security model is documented in the
README's **Security model** section and in `docs/PROTOCOL.md`:

- The **shared token is the trust boundary** — anyone holding it can open tunnels.
  Reports assuming an attacker already has the token are out of scope.
- The **control port** is the only internet-facing pre-auth surface; it caps message
  size, disables compression, bounds concurrent handshakes, rate-limits failed auth,
  and times out the hello.
- **Multi-tenant routing is loopback-only** and must sit behind a normalizing reverse
  proxy that gives chute one request per connection.
- The relay is **byte-transparent** — it is a pipe, not a WAF. Exposure of the local
  app is the operator's responsibility.

In scope: pre-auth DoS/memory-exhaustion on the control or public ports, cross-tenant
routing/desync, parser differentials, TLS/cert handling, and supply-chain integrity.

## Supply chain

Releases are built in CI with third-party actions **pinned to commit SHAs** and carry
a **build-provenance attestation**; verify a downloaded artifact with:

```
gh attestation verify <file> --repo <owner>/chute
```

Production installs runtime dependencies from a **hash-pinned export of the committed
`uv.lock`** (`deploy/requirements.txt`), so the deployed versions match what CI tested.
