# Continuous deploy (push to `main` → VPS)

This wires `.github/workflows/deploy.yml` so a push to `main` deploys to the box.
It ships **dormant** and stays off until you finish every step here and flip the
master switch. Read the threat note at the bottom first.

The design, in one line: GitHub Actions makes **one** SSH call whose key is
locked server-side to a **single forced command** (`deploy/deploy-pull.sh`), run
by a **dedicated non-root user** with a **three-command sudo allowlist**. A
leaked key can only *trigger a deploy* — never open a shell, never run anything
else.

## Prerequisites

You've already done the initial install once from your Mac:

```bash
./deploy/deploy.sh root@your-vps
```

That created `/opt/chute` (venv) and installed the service + nginx vhost. CD
only handles **subsequent code deploys**.

## One-time bootstrap on the VPS

```bash
# 1. Make /opt/chute/src a git clone of the PUBLIC repo (CD pulls into it).
#    (Back up the rsync'd copy first if you want.)
rm -rf /opt/chute/src
git clone https://github.com/greycr0w/chute.git /opt/chute/src

# 2. Dedicated, shell-less deploy user.
useradd --system --create-home --shell /usr/sbin/nologin chute-deploy

# 3. Let it pull + own the source and run the venv.
chown -R chute-deploy:chute-deploy /opt/chute/src
#    (the venv at /opt/chute/.venv stays owned by the `chute` service user;
#     pip install --upgrade only writes site-packages, group-writable is fine —
#     or run the pip step under sudo -u chute if you keep venv perms tight.)

# 4. Tight sudo allowlist — the ONLY privileged things deploy-pull.sh may do.
cat >/etc/sudoers.d/chute-deploy <<'EOF'
chute-deploy ALL=(root) NOPASSWD: /usr/bin/systemctl restart chuted, \
  /usr/bin/systemctl reload nginx, /usr/sbin/nginx -t
EOF
chmod 440 /etc/sudoers.d/chute-deploy
visudo -cf /etc/sudoers.d/chute-deploy     # validate

# 5. Generate the deploy keypair (no passphrase; it's a machine credential).
sudo -u chute-deploy ssh-keygen -t ed25519 -N '' \
  -f /home/chute-deploy/.ssh/id_ed25519 -C github-actions-deploy

# 6. Authorize it as a FORCED COMMAND (this is the whole security model):
mkdir -p /home/chute-deploy/.ssh
cat >/home/chute-deploy/.ssh/authorized_keys <<EOF
command="/opt/chute/src/deploy/deploy-pull.sh",no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-pty $(cat /home/chute-deploy/.ssh/id_ed25519.pub)
EOF
chown -R chute-deploy:chute-deploy /home/chute-deploy/.ssh
chmod 700 /home/chute-deploy/.ssh
chmod 600 /home/chute-deploy/.ssh/authorized_keys
```

## GitHub side

Set these as **repository secrets** (Settings → Secrets and variables → Actions):

| Secret | Value |
| --- | --- |
| `DEPLOY_SSH_KEY` | contents of `/home/chute-deploy/.ssh/id_ed25519` (the **private** key) |
| `DEPLOY_SSH_USER` | `chute-deploy` |
| `DEPLOY_SSH_HOST` | `your-vps` (or `chute.sh`) |
| `DEPLOY_KNOWN_HOSTS` | output of `ssh-keyscan -t ed25519 your-vps` — pins the host key |

Then **arm it**: add a repository **variable** `CD_ENABLED = true`.

Strongly recommended for a box this important: create a **`production`
Environment** (Settings → Environments) and add yourself as a **required
reviewer**. Then every deploy waits for your one-click approval — push-to-main
convenience, with a human gate on the privileged step.

Delete the private key from the VPS once it's in GitHub: `shred -u
/home/chute-deploy/.ssh/id_ed25519` (keep `.pub` + `authorized_keys`).

## Verify

```bash
# from your Mac, prove the forced command works and is locked down:
ssh -i <the-private-key> chute-deploy@your-vps anything-here   # runs deploy-pull.sh, ignores the arg
ssh -i <the-private-key> chute-deploy@your-vps "rm -rf /"      # MUST be refused (forced command)
```

Then push a trivial change to `main` and watch the **Deploy** workflow.

## Threat note (why the gate matters)

Push-to-main CD means **whatever lands on `main` runs on this production box**.
The forced-command key contains the blast radius of a *leaked key*, but it does
**not** protect against a malicious or buggy commit reaching `main` — that code
is what gets deployed and executed. On a box that also runs your mail MX and DNS,
mitigate with: branch protection on `main` (require PR + review + green CI before
merge), the `production` Environment approval gate above, and pinned dependencies.
If you'd rather not give GitHub any standing path to the box, switch
`deploy.yml`'s trigger to tags only, or set `CD_ENABLED=false` and deploy
manually with `./deploy/deploy.sh` from your Mac.

# CD pipeline verified live 2026-05-31

# branch-protection live-test 1780272243
