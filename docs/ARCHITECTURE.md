# chute — Multi-Tenant Architecture

> Status: **design / proposed**. This document is the reference for evolving chute
> from a single-user tunnel into a multi-tenant service with a self-serve website
> (`chute.sh`) where users sign up, mint tokens, and manage their tunnels and
> reserved domains. No code in this PR — it sets the direction the implementation
> phases follow.

## 1. Guiding principle: split the data plane from the control plane

The single most important decision. Two independently deployable halves that share
**one source of truth (PostgreSQL)**:

- **Data plane — `chuted`.** A dumb, fast byte-relay. Stays as lean and auditable
  as it is today. Its *only* new responsibility is an **authorization lookup at
  connect time**: "which account is this token, and what may it do?" It never
  touches the database on the hot path — visitor bytes never hit Postgres.
- **Control plane — `chute-api` + website.** Owns all business logic: signup,
  minting/revoking tokens, reserving subdomains, plans, usage, billing, the
  dashboard. Changes weekly. Redeploys without touching the relay.
- **PostgreSQL — the contract between them.** The relay mostly *reads* it; the
  control plane *writes* it.

```
                  ┌──────────────── PostgreSQL  (source of truth) ───────────────┐
                  │ accounts · tokens(hashed) · reserved_subdomains ·             │
                  │ reserved_labels · tunnel_sessions · (plans/usage later)       │
                  └─────▲────────────────────────────────────────▲───────────────┘
            authz reads │ + session writes        CRUD reads/writes│
                        │                                          │
 agent(Mac) ═WSS:7000═▶ chuted  (DATA PLANE)        chute-api (CONTROL PLANE, FastAPI)
 visitor ──HTTP──▶ nginx ─▶ chuted :8080            signup · mint/revoke token ·
                                                    reserve name · list live tunnels ·
                                                    usage · billing
                                                              ▲ JSON API
                                                    chute.sh website (Next.js SPA)
```

**Why this split (vs. cramming logic into `chuted`):**

- The relay stays small, auditable, and fast — the part on the pre-auth internet
  surface changes rarely.
- The website/API team iterates independently and redeploys freely.
- **Graceful degradation:** if the API is down, existing tunnels keep relaying and
  new agents can still authenticate (the relay's path to Postgres is read-mostly).
- **Blast-radius containment:** an API/website compromise doesn't sit in the byte
  path; a DB compromise yields only *hashed* tokens.

## 2. Identity model

```
account ──< token        (one account, many tokens: laptop, CI, bot, …)
account ──< reserved_subdomain
account ──< tunnel_session
```

The unit of identity is the **account**, not the token. This is the key reframe
that answers "what if someone runs chute twice with the same key": it's the same
*account* running two tunnels; per-tunnel identity is the **label** (subdomain),
not the token. An account holds many tokens so a user can revoke one device
without disrupting others.

## 3. Database schema (v1)

PostgreSQL (the cluster already on the box, currently empty). Database `chute`.
Managed by **Alembic migrations** so the schema is versioned and the web team can
evolve it safely.

| Table | Columns (essentials) | Notes |
|---|---|---|
| `accounts` | `id`, `email` (unique, citext), `plan`, `status`, `created_at` | `plan` drives limits; `status` = active/suspended |
| `tokens` | `id`, `account_id` FK, `token_hash` (unique), `name`, `created_at`, `last_used_at`, `revoked_at` | **Only the SHA-256 hash is stored — never plaintext.** `revoked_at NULL` = active |
| `reserved_subdomains` | `id`, `account_id` FK, `label` (unique citext), `created_at` | Paid/owned names. Empty in v1; the table exists so the website can fill it later |
| `reserved_labels` | `label` (PK) | System denylist: `www app api admin dashboard chute …` so no one tunnels `app.chute.sh` |
| `tunnel_sessions` | `id`, `account_id` FK, `token_id` FK, `label`, `scheme`, `agent_ip`, `started_at`, `ended_at` | `ended_at NULL` = live. Powers dashboard "active tunnels" + usage history |

Design choices:
- **Hash, don't encrypt, tokens.** Auth needs only equality; a DB leak yields no
  usable credential. Lookup is `WHERE token_hash = sha256($presented)`, indexed.
- **`tunnel_sessions` is append-style** (open row on connect, stamp `ended_at` on
  disconnect) — gives free usage history and a live-tunnels view without extra
  state.
- **citext** for emails/labels — case-insensitive uniqueness without app-side
  normalization drift.

### Least-privilege DB roles

- `chute_relay` — `SELECT` on `tokens`, `reserved_subdomains`, `reserved_labels`,
  `accounts`; `INSERT`/`UPDATE` on `tunnel_sessions`. Nothing else.
- `chute_api` — full DML on its tables. **No superuser.**
- Migrations run as a third, owner-level role used only by Alembic.

## 4. Authorization flow (the new bit in `chuted`)

At agent connect (after the existing TLS-pin + token framing checks):

1. `sha256(presented_token)` → `SELECT account_id, token_id FROM tokens WHERE
   token_hash=$1 AND revoked_at IS NULL` (also check `accounts.status='active'`).
   No row → reject `unauthorized` (same close code as today).
2. Resolve the label:
   - **Requested name:** allowed only if it's the account's own
     `reserved_subdomain`, or (policy) an unreserved free label. A name reserved by
     *another* account → reject.
   - **No name:** auto-assign `random_phrase()` (today's word-word-word), retry on
     collision (already implemented).
3. Enforce **concurrency**: `COUNT(tunnel_sessions WHERE account_id=$me AND
   ended_at IS NULL)` against `plan.max_tunnels`.
4. **Smart reclaim** on label collision — the routing map becomes
   `label → {mux, account_id}`:
   - Same account reclaiming its own (stale/sleep-dropped) connection → newest
     wins (today's seamless-reconnect behavior).
   - A *different* account → reject.
   - A genuinely concurrent second tunnel of the *same reserved name* by the same
     account → reject (don't silently knock your own live site offline).
5. `INSERT` a `tunnel_sessions` row; `UPDATE last_used_at`. On disconnect, stamp
   `ended_at`.

**Hot-path note:** steps 1–5 happen **once per tunnel connect**, never per visitor
request. Visitor traffic continues to route purely through the in-memory
`label → mux` map. A tiny asyncpg pool over a local socket; the relay caches the
authz result for the life of the connection.

### Product answers encoded
- **Token → account by hash lookup** (not one shared secret).
- **Smart reclaim** = same-account-stale only; cross-account stealing impossible.
- **Generous free tier** = `plan.max_tunnels` random names; `reserved_subdomains`
  stays empty until reserved names become a paid feature. No billing logic in v1.

## 5. Security posture

- **No secrets in the repo** (verified): the codebase is the *protocol*, never the
  *credentials*. Tokens + the pinned cert live only on the machines
  (`/etc/chute/chute.env` chmod 600; client copy chmod 600). Cloning the repo is
  like having ngrok's source — useless without an account/token.
- **Control port 7000 is the pre-auth internet surface.** Today it gates one shared
  secret; multi-tenant makes it the front door for *all* users. Hardening:
  - keep `hmac.compare_digest`, the pre-auth connection cap, and the hello-timeout
    that already exist;
  - 256-bit tokens → brute force is infeasible; lookup is by hash;
  - add **per-IP rate-limiting** on failed auths + a **fail2ban jail** for 7000;
  - **bootstrap escape hatch:** one env-token always maps to account 0 (you), so a
    DB outage never locks you out of your own box.
- **Defense in depth:** least-privilege DB roles mean a compromised relay can't
  mint tokens or read other tables; a compromised API isn't in the byte path.
- **Abuse vector (phishing/malware over tunnels)** is a *control-plane* concern:
  account status + the ability to revoke a token/kill sessions live in the API, not
  the relay. Out of scope for v1 mechanics but the schema (`status`, `revoked_at`)
  is ready for it.

## 6. Technology choices

| Layer | Choice | Why |
|---|---|---|
| Database | **PostgreSQL** (existing, empty) | Already installed; your pick for custom apps; great for this relational shape |
| Relay DB access | **asyncpg**, hand-written SQL, no ORM | Keep the data plane lean; tiny query set; local socket + small pool |
| Control API | **FastAPI + SQLAlchemy 2.0 + Alembic** | Async, typed, OpenAPI for free; Alembic = versioned migrations the web team evolves |
| Website | **Next.js / React SPA** (separate app) | Richer dashboard UX; consumes the JSON API; its own build/deploy |
| Repo | **Monorepo**: `src/chute/` (relay), `src/chute_api/` (control), `migrations/`, `web/` (SPA) | One CD pipeline ships relay+API; split later if needed |
| Deploy | existing forced-command CD + branch protection | Already wired; each phase ships through it |

The **SPA ↔ API boundary is a versioned JSON contract** (`/api/v1/…`,
OpenAPI-documented). The website is just one client of it; the same API could back
a CLI `chute login` or Terraform provider later. This is why the API is designed
front-end-agnostic even though we've chosen Next.js for the first site.

### Indicative API surface (v1)
```
POST   /api/v1/auth/signup            email → account (+ verification later)
POST   /api/v1/tokens                 mint a token (returns plaintext ONCE)
GET    /api/v1/tokens                 list (names + last_used, never the secret)
DELETE /api/v1/tokens/{id}            revoke
GET    /api/v1/tunnels                live + recent sessions (dashboard)
POST   /api/v1/subdomains             reserve a name (plan-gated)
GET    /api/v1/usage                  per-account usage (later)
```

## 7. Build order (each phase independently shippable via existing CD)

1. **Schema only.** Create DB `chute` + roles + Alembic migrations; seed
   **account 0** with the *current* token (hashed). `chuted` behavior unchanged.
   Invisible and reversible.
2. **Relay reads the DB.** Replace the single-token compare with hash lookup +
   account identity + smart-reclaim + concurrency rules. Heavy tests. DB-down →
   bootstrap-token fallback (account 0).
3. **Control-plane API.** FastAPI endpoints above; localhost; driven by curl. No
   website yet.
4. **Website.** `chute.sh` Next.js SPA: sign up → mint token → copy the `chute`
   command; dashboard shows live tunnels/usage from the API.
5. **Monetization.** Plans, enforced limits, reserved names as a paid feature,
   billing.

Nothing is thrown away: today's single token becomes "account 0's first token,"
and the relay keeps relaying throughout every phase.

## 8. Open questions (decide before the phase that needs them)

- **Account auth for the website**: email+password vs. magic-link vs. OAuth
  (GitHub/Google). Needed at Phase 4, not before.
- **Free-tier policy specifics**: exact `max_tunnels`, idle-timeout, anonymous
  (tokenless) tunnels yes/no.
- **Billing provider** (Phase 5): the no-third-party ethos may not extend to
  payments — Stripe vs. self-hosted is a deliberate later call.
- **Custom domains** (bring-your-own, not just `*.chute.sh`): schema-compatible
  later via a `domains` table; explicitly out of v1.
