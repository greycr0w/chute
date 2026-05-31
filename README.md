# chute

A tiny, self-hosted, zero-maintenance HTTP(S) tunnel — your own ngrok, with no
third parties. Your VPS gets a stable public URL; traffic is relayed over a
single authenticated, TLS-pinned connection to a local app on your Mac.

```
visitor ──▶ chute server (VPS, public)
                 │  one persistent WSS control connection (agent dials OUT)
                 ▼
            chute agent (your Mac)  ──▶  127.0.0.1:8000  (your app)
```

## Why this design

- **Agent dials out** over a single connection → traverses NAT/firewalls, no
  inbound ports on your Mac.
- **Stream multiplexing** over that one connection (like HTTP/2 / yamux) →
  no connection-pool exhaustion, clean concurrency.
- **Pinned self-signed cert** for the control channel → strong MITM protection,
  **no certbot, no ACME, no renewals** (10-year cert = fire-and-forget).
- **Token auth** (constant-time compare) gates the control channel.
- **Raw L4 relay** on the public side → transparently carries keep-alive,
  chunked, SSE and WebSocket upgrades; the public side stays plain HTTP so
  there is no mixed-content surprise for embedded iframes / Selenium.
- **Auto-reconnect** with backoff + jitter → survives sleep/wake, Wi-Fi
  changes and server restarts.

## Staying HTTP (the whole point)

chute is a **transparent byte pipe**. It never adds TLS, never redirects to
HTTPS, never sends HSTS — and, just as deliberately, never *strips or rewrites*
what your app sends. Headers, keep-alive, chunked bodies, SSE and WebSocket
upgrades all pass through verbatim. If your app serves it, the browser sees it.
(There is intentionally no response sanitiser; a tunnel that mangles headers
isn't a tunnel.)

That transparency is exactly what makes the embedded-iframe + `postMessage`
flow work:

- The parent page is served over `http://` through chute, so embedding an
  `http://` iframe (localhost or a public IP) is **same-scheme — no mixed-content
  block**, and nothing tries to upgrade it.
- `window.postMessage` across those HTTP origins is fine; pass the iframe's
  exact origin as `targetOrigin` (e.g. `"http://203.0.113.10:32588"`).
- Heads up: `http://localhost:PORT` inside an iframe resolves on the **bot's**
  machine, not the server's — use a public IP if the target isn't co-located
  with the headless Chrome.

Since the client is a throwaway headless Chrome (`client.quit()` per run) there
is no persistent HSTS cache to worry about. If you ever point a *real* browser
at it, two browser-side settings still matter (no server can override them):
reach it by **IP** (browsers don't apply HSTS to IP literals), and for Selenium
add `--disable-features=HttpsUpgrades,HttpsFirstBalancedModeAutoEnable`.

## HTTPS for other apps

The HTTP transparency above is one *workflow*; chute also serves **HTTPS per
tunnel** for normal web apps. You pick the scheme when you start the agent:

```bash
chute http  8000     # transparent plain-HTTP pipe (default; the iframe case)
chute https 3000     # public endpoint is HTTPS
chute 8000           # bare form == http (backward compatible)
```

How it works: **TLS terminates at the server edge** (a `:443` listener on the
VPS). After the handshake the decrypted bytes flow through the *same* relay the
HTTP path uses, so the agent still speaks plain HTTP to your local app and the
public cert's private key **never leaves the VPS**. The control channel keeps
its own independent pinned self-signed cert — unaffected.

Two requirements for HTTPS (don't apply to the HTTP workflow):

- **A real DNS hostname** pointed at the VPS. No bare-IP HTTPS — browsers can't
  get a trusted cert for an IP.
- **A browser-trusted cert.** Self-signed won't do for real browsers. chute
  does **not** run an ACME client itself (that's the certbot maintenance you're
  avoiding *inside* chute); instead an external tool owns issuance/renewal and
  chute **hot-reloads** the PEM when it changes — zero downtime, zero restart.

```bash
# one-time on the VPS: let an external ACME client own renewal (systemd timer)
lego --email you@example.com --domains app.example.com --http run     # or certbot

chuted run --token "$CHUTE_TOKEN" --domain app.example.com \
  --cert chute-cert.pem --key chute-key.pem \           # control channel (pinned)
  --tls-cert /etc/lego/certificates/app.example.com.crt \ # public, browser-trusted
  --tls-key  /etc/lego/certificates/app.example.com.key   # auto-reloaded on renewal
```

The `--tls-cert/--tls-key` files are watched; when the ACME timer renews them,
chute swaps the cert for new connections on its own. If `--tls-cert` is absent,
the server is HTTP-only exactly as before, and an agent that asks for `https`
gets a logged warning + an `http://` URL rather than a failure.

## Install

chute is **one package** that ships both the importable SDK (`from chute
import Tunnel`) and two CLIs (`chute`, `chuted`). There's no second
"client" package to install — splitting them would only buy a shared-core
package and a second release to keep in sync, and importing the SDK never pulls
the server into your process anyway. Pick the install that matches how you're
consuming it:

```bash
# 1. CLI on your Mac — pipx is the Pythonic way to install a CLI tool
#    (its own isolated venv, on your PATH). Build once, then:
python -m build                       # -> dist/chute-*.whl  (no PyPI needed)
pipx install dist/chute-*.whl
chute http 8000 ...

# 2. Embedding the SDK in another app — install the wheel into that app's venv
pip install dist/chute-*.whl
#   then:  from chute import Tunnel

# 3. Hacking on chute itself
pip install -e ".[dev]"
```

No PyPI required (it's a third party you're avoiding): build the wheel and
install it straight, or `pip install git+ssh://…` from your own repo. The VPS
side is handled for you by `deploy/deploy.sh` (see below) — it builds an
isolated venv at `/opt/chute` and installs the package there.

## Quick start

**On the VPS (once):**

```bash
chuted gen-token                       # -> copy this secret
chuted gen-cert --host tunnel.example.com   # -> chute-cert.pem / chute-key.pem
# copy chute-cert.pem down to your Mac
CHUTE_TOKEN=<secret> chuted run --public-port 80 --public-url http://tunnel.example.com/
```

**On your Mac:**

```bash
export CHUTE_SERVER=tunnel.example.com
export CHUTE_TOKEN=<secret>
export CHUTE_SERVER_CERT=./chute-cert.pem
chute 8000
#   chute  http://tunnel.example.com/  ->  127.0.0.1:8000
```

## Use as an SDK

```python
from chute import Tunnel

with Tunnel(server="tunnel.example.com", token="...", local_port=8000,
            server_cert="chute-cert.pem") as t:
    print(t.public_url)
    t.wait()           # block until Ctrl-C; reconnects automatically
```

For an HTTPS tunnel, add `scheme="https"` (the server must have a public cert
configured); everything else is identical:

```python
with Tunnel(server="vps.example.com", token="...", local_port=3000,
            server_cert="chute-cert.pem", scheme="https") as t:
    print(t.public_url)        # -> https://app.example.com/
    t.wait()
```

### Subdomains (multi-tenant)

If the server runs with a base domain (`--base-domain chute.sh`), every
tunnel gets its own `<label>.<base-domain>` URL — so you can run many tunnels at
once through one server. Request a label, or let the server pick one:

```python
with Tunnel(server="chute.sh", token="...", local_port=8000,
            server_cert="chute-cert.pem", subdomain="myapp") as t:
    print(t.public_url)        # -> http://myapp.chute.sh/
    print(t.subdomain)         # -> "myapp"  (the label the server assigned)
```

Omit `subdomain=` and the server auto-assigns a short random label
(`http://k7m2pq9w.chute.sh/`). Add `scheme="https"` for
`https://myapp.chute.sh/`. The label is a single DNS label (a–z, 0–9,
hyphen); a bad one is rejected immediately, client-side. On the CLI it's
`--subdomain myapp`. If you re-request a label your own tunnel already holds
(e.g. after a reconnect), you reclaim it — newest connection wins.

Or fully async:

```python
tunnel = Tunnel(server="...", token="...", local_port=8000, server_cert="...")
await tunnel.serve_forever()
```

## Testing

```bash
pytest                      # unit + loopback E2E (no VPS needed)
./scripts/smoke_test.sh     # final gate against the real server
```

## Deploy fire-and-forget

One command from your Mac sets up (or updates) the whole server — venv, systemd
service, nginx wildcard vhost, a generated token and control cert:

```bash
./deploy/deploy.sh root@your-vps
```

It's idempotent: re-run it to ship new code (the token and cert are generated
once and preserved). It prints the token + the path to the pinned client cert to
copy down, and reminds you to open the control port in the firewall. nginx owns
`:80`/`:443` for `*.<base-domain>` and proxies plain HTTP to chute on
`127.0.0.1:8080`, so the daemon needs no root and no privileged ports.

Under the hood it installs:

- `deploy/chuted.service` — systemd, `Restart=always`, config from
  `/etc/chute/chute.env`.
- `deploy/nginx-chute.conf` — the `*.<base-domain>` vhost (TLS + HTTP, no
  forced upgrade).

On the Mac, `deploy/com.chute.agent.plist` (launchd, `KeepAlive`) keeps an
agent running across reboots.

## Scope / non-goals

Multi-tenant subdomains **are** supported (route by `Host` under a base domain;
auto or requested labels). One shared token still gates all tunnels — there are
no per-tunnel tokens, no accounts, no dashboard, no request inspection, no OAuth.
Single-tenant mode (no base domain → one token = one tunnel, pure-L4 relay) is
still the default and still the path the transparency guarantees are tested on.
