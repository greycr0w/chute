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
  no connection-pool exhaustion, clean concurrency, with **per-stream
  credit-window flow control** so a slow consumer can't make the other end
  buffer without bound. Full spec: [docs/PROTOCOL.md](docs/PROTOCOL.md).
- **Pinned self-signed cert** for the control channel → strong MITM protection,
  **no certbot, no ACME, no renewals** (10-year cert = fire-and-forget).
- **Token auth** (constant-time compare) gates the control channel.
- **One HTTP tunnel foundation** on the public side → every visitor must send a
  complete HTTP request head before chute opens an agent stream; after that,
  the request head and body, response headers, chunked bodies, SSE and WebSocket
  upgrades pass through verbatim.
- **Auto-reconnect** with backoff + jitter → survives sleep/wake, Wi-Fi
  changes and server restarts.

## Protocol

The control connection is a binary **stream multiplexer** with credit-window flow
control — the same family as HTTP/2 / yamux — specified in full at
**[docs/PROTOCOL.md](docs/PROTOCOL.md)**: the JSON handshake, frame format, the stream
state machine, flow control, teardown, the limits each end enforces against a
misbehaving peer, and the close codes.

The protocol is **versioned and negotiated in the handshake**; the current version is
**3** (credit-window flow control + `GOAWAY` graceful drain). Server and agent must be
upgraded **together** — a version mismatch fails fast with a clear "upgrade" close
rather than silently stalling, and v3 is not interoperable with older builds.

## Staying HTTP (the whole point)

chute is an **HTTP tunnel**. A visitor must send a complete HTTP request head
before chute opens a stream to the agent; that makes admission explicit and
prevents partial requests from pinning agent streams. Once admitted, chute
forwards the request head verbatim and never redirects to HTTPS, never sends
HSTS, and never strips or rewrites what your app sends. Headers, keep-alive,
chunked bodies, SSE and WebSocket upgrades pass through as the app emits them.

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
chute https 3000     # public endpoint is HTTPS (the default)
chute http  8000     # plaintext pipe — bare IP, no public cert, or the iframe case
chute 8000           # bare form == https
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
chute swaps the cert for new connections on its own. If HTTPS cannot be
truthfully advertised, an agent that asks for `https` fails closed with
`https_unavailable`; pass `http` explicitly when you want plaintext.

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
chute http 8000      # `http` since this server has no public TLS (https is the default)
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

The SDK default asks for HTTPS. If the server cannot truthfully advertise HTTPS,
startup fails with `https_unavailable`. For an explicit plaintext tunnel, pass
`scheme="http"`:

```python
with Tunnel(server="vps.example.com", token="...", local_port=3000,
            server_cert="chute-cert.pem", scheme="http") as t:
    print(t.public_url)        # -> http://app.example.com/
    t.wait()
```

### Host-routed labels

If the server runs with a base domain (`--base-domain chute.sh`), every
tunnel gets its own `<label>.<base-domain>` URL — so you can run many tunnels at
once through one server. Request a label, or let the server pick one:

```python
with Tunnel(server="chute.sh", token="...", local_port=8000,
            server_cert="chute-cert.pem", subdomain="myapp") as t:
    print(t.public_url)        # -> https://myapp.chute.sh/
    print(t.subdomain)         # -> "myapp"  (the label the server assigned)
```

Omit `subdomain=` and the server auto-assigns a short random label
(`https://k7m2pq9w.chute.sh/`). Pass `scheme="http"` when you deliberately want
`http://myapp.chute.sh/`. The label is a single DNS label (a–z, 0–9, hyphen); a
bad one is rejected immediately, client-side. On the CLI it's `--subdomain
myapp`. If you re-request a label your own tunnel already holds (e.g. after a
reconnect), you reclaim it — newest connection wins.

> **Host-routed labels are loopback-only.** The router commits a whole connection
> to one agent on that connection's first request, so the public port refuses to
> bind a routable address and must sit behind a reverse proxy that gives it one
> request per connection — the bundled
> [`deploy/nginx-chute.conf`](deploy/nginx-chute.conf) does. See
> [Security model](#security-model) for why Host routing needs that edge shape.

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

## Security model

chute has one tunnel foundation: one authenticated agent registry, one admission
path, one mux, and one relay. The only difference is how a visitor selects the
registered tunnel:

|                                  | No `--base-domain`             | With `--base-domain`                        |
| -------------------------------- | ------------------------------ | ------------------------------------------- |
| Internal label                   | reserved `default`             | DNS label from `Host`                       |
| Visitor admission                | strictly validated HTTP request head | strictly validated HTTP request head with Host |
| Routing decision                 | always `default`               | pick the agent by `Host`, per connection    |
| Public bind                      | can be exposed directly        | loopback-only; put nginx in front           |
| nginx upstream `keepalive`       | unnecessary                    | **dangerous** — re-creates the desync       |

The default route has no tenant-selection input: any valid HTTP/1.x request goes
to the reserved `default` label. HTTP/1.0 may omit `Host`; HTTP/1.1 and Host-routed
requests may not. You are still publishing your local app; chute is not a WAF.

Host-routed labels must choose *which* agent gets a connection, and the only
place the target tenant is named is the `Host` header. nginx is the authoritative
public parser and connection manager; chute's parser is only a reject-only
backstop before it opens a mux stream. That introduces exactly two failure modes,
with two different owners:

1. **Parser differential — one *ambiguous* request.** Malformed request lines, two
   `Host` headers, `Host :` with a space before the colon, an obs-folded line, a
   bare LF, an absolute-form request line, or a missing/invalid `Host` — anything
   chute might read one way and a downstream hop another.
   chute **closes this itself**: it does not guess, it answers `400` and drops the
   connection (it never rewrites the bytes it forwards, so refusing is its only safe
   move). This is the strict "back-end rejects what the front-end didn't normalize"
   half of the standard request-smuggling defense.

2. **Connection-level pipelining desync — many *clean* requests.** HTTP/1.1 reuses one
   connection for many requests, but chute commits the whole connection to one agent
   on the **first** request and relays the rest blind (that blind relay is what lets
   WebSocket/SSE/chunked pass through untouched). So a second, perfectly valid request
   for a *different* tenant on the same connection still lands in the first tenant's
   agent. chute **cannot** close this without becoming a full HTTP parser — which
   would destroy transparency and re-open the smuggling surface. It is closed
   *operationally*, by guaranteeing **one request per connection** into chute.

Because of #2, the Host-routed public port is **loopback-only** — chute refuses to
bind a routable address when `--base-domain` is set. It must sit behind a reverse
proxy that opens one upstream connection per request. The bundled
[`deploy/nginx-chute.conf`](deploy/nginx-chute.conf) does this by default: it has no
`upstream {}` keepalive block — **don't add one**, that single line re-creates the
desync. (Routing `Host` → a dynamic, runtime-assigned agent is the one job chute
can't hand to nginx, which is why the router lives in chute while the
one-request-per-connection guarantee lives in the proxy.)

## Scope / non-goals

Host-routed labels **are** supported (route by `Host` under a base domain; auto
or requested labels). The default no-domain route uses the same registry and
relay path under the reserved internal `default` label. One shared token still
gates all tunnels by default — there are no dashboards, no request inspection,
and no OAuth.
