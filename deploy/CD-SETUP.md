# Continuous deploy (push to `main` → VPS)

This wires `.github/workflows/deploy.yml` so a push to `main` deploys to the box.
It ships **dormant** and stays off until you finish every step here and flip the
master switch. Read the threat note at the bottom first.

The design, in one line: GitHub Actions makes **one** SSH call whose key is
locked server-side to a **single forced command**
(`/usr/local/sbin/chute-deploy-pull`), run by a **dedicated non-root user** with
a **three-command sudo allowlist**. A
leaked key can only *trigger the deploy script* — never open a shell, never run
anything else. The forced command points at `/usr/local/sbin/chute-deploy-pull`,
a stable root-installed copy of the deploy runner, so a test ref cannot replace
the rollback mechanism itself. The deploy script accepts only `deploy`,
`rollback [last|sha]`, and `status`, and it verifies the target commit signature
before resetting the checkout.

## Prerequisites

You've already done the initial install once from your Mac:

```bash
CHUTE_AGENT_CIDRS="1.2.3.4/32" ./deploy/deploy.sh root@your-vps
```

That created `/opt/chute` (venv) and installed the service + nginx vhost. If an
external firewall or private network already restricts the control port, use
`CHUTE_ALLOW_OPEN_CONTROL=1` instead of `CHUTE_AGENT_CIDRS`. CD only handles
**subsequent code deploys**. Re-run it once after deploy-runner changes so
`/usr/local/sbin/chute-deploy-pull` is refreshed.

The VPS must have `uv` on `PATH` for both the initial install and forced-command
deploys. The deploy runner reads `.python-version`, runs `uv python install`,
and recreates `/opt/chute/.venv` with that pinned Python minor before installing
the hash-pinned requirements.

## One-time bootstrap on the VPS

```bash
# 1. Make /opt/chute/src a git clone of the PUBLIC repo (CD pulls into it).
#    (Back up the rsync'd copy first if you want.)
rm -rf /opt/chute/src
git clone https://github.com/greycr0w/chute.git /opt/chute/src

# 2. Dedicated forced-command deploy user. OpenSSH invokes forced commands via
#    the user's login shell, so use a real shell and rely on authorized_keys
#    restrictions below to prevent interactive access.
useradd --system --create-home --shell /bin/sh chute-deploy

# 3. Let it pull the source, and let the shared chute group update the venv.
chown -R chute-deploy:chute-deploy /opt/chute/src
install -d -m 700 -o chute-deploy -g chute-deploy \
  /opt/chute/uv /opt/chute/uv/cache /opt/chute/uv/python
usermod -aG chute chute-deploy
chgrp -R chute /opt/chute/.venv
chmod -R g+rwX /opt/chute/.venv
find /opt/chute/.venv -type d -exec chmod g+s {} +
#    Log out and back in, or restart sshd sessions, before testing the deploy key
#    so the chute-deploy user's new group membership is visible.

# 4. Tight sudo allowlist — the ONLY privileged things deploy-pull.sh may do.
cat >/etc/sudoers.d/chute-deploy <<'EOF'
chute-deploy ALL=(root) NOPASSWD: /usr/bin/systemctl restart chuted, \
  /usr/bin/systemctl reload nginx, /usr/sbin/nginx -t
EOF
chmod 440 /etc/sudoers.d/chute-deploy
visudo -cf /etc/sudoers.d/chute-deploy     # validate

# 5. Configure the signing trust store used by the forced deploy runner.
#    Default mode verifies SSH commit signatures. Put the public signing key,
#    not the GitHub deploy SSH key, in this file. Keep this outside /opt/chute/src
#    and /etc/chute so deploys cannot mutate it.
install -d -m 755 -o root -g root /etc/chute-deploy
cat >/etc/chute-deploy/allowed-signers <<'EOF'
you@example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... signing-key
EOF
chmod 644 /etc/chute-deploy/allowed-signers
cat >/etc/chute-deploy/verify.env <<'EOF'
CHUTE_DEPLOY_VERIFY_SIGNATURE=1
CHUTE_DEPLOY_SIGNING_FORMAT=ssh
CHUTE_DEPLOY_ALLOWED_SIGNERS=/etc/chute-deploy/allowed-signers
EOF
chmod 644 /etc/chute-deploy/verify.env

# 6. Generate the deploy keypair (no passphrase; it's a machine credential).
install -d -m 700 -o chute-deploy -g chute-deploy /home/chute-deploy/.ssh
sudo -u chute-deploy ssh-keygen -t ed25519 -N '' \
  -f /home/chute-deploy/.ssh/id_ed25519 -C github-actions-deploy

# 7. Authorize it as a FORCED COMMAND (this is the whole security model).
#    SSH_ORIGINAL_COMMAND is still visible to deploy-pull.sh, which lets the
#    same forced command safely distinguish deploy, rollback, and status.
cat >/home/chute-deploy/.ssh/authorized_keys <<EOF
restrict,command="/usr/local/sbin/chute-deploy-pull" $(cat /home/chute-deploy/.ssh/id_ed25519.pub)
EOF
chown root:root /home/chute-deploy /home/chute-deploy/.ssh /home/chute-deploy/.ssh/authorized_keys
chmod 755 /home/chute-deploy
chmod 755 /home/chute-deploy/.ssh
chmod 644 /home/chute-deploy/.ssh/authorized_keys
chown chute-deploy:chute-deploy /home/chute-deploy/.ssh/id_ed25519 /home/chute-deploy/.ssh/id_ed25519.pub
chmod 600 /home/chute-deploy/.ssh/id_ed25519
chmod 644 /home/chute-deploy/.ssh/id_ed25519.pub
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

## Signed deploy refs

The forced deploy runner verifies every deployed commit, including `rollback
last` and explicit rollback SHAs, before `git reset --hard`. The default is SSH
commit signing with Git's `gpg.format=ssh` and
`gpg.ssh.allowedSignersFile=/etc/chute-deploy/allowed-signers`. Operators choose
the trusted signing keys by editing `/etc/chute-deploy/allowed-signers`; keep
that file root-owned and outside the mutable checkout.

To sign commits with SSH from your workstation:

```bash
git config --global gpg.format ssh
git config --global user.signingKey ~/.ssh/id_ed25519.pub
git commit -S
```

If you use OpenPGP or X.509 instead, set
`CHUTE_DEPLOY_SIGNING_FORMAT=openpgp` or `CHUTE_DEPLOY_SIGNING_FORMAT=x509` in
`/etc/chute-deploy/verify.env` and configure the deploy user's Git/GPG trust
store accordingly. `CHUTE_DEPLOY_SIGNING_FORMAT=auto` delegates to Git's normal
config and keyring lookup.

The deliberate escape hatch is:

```bash
CHUTE_DEPLOY_VERIFY_SIGNATURE=0
```

Use that only for a local or investigative box. It re-opens the exact risk this
CD setup is meant to close: a branch or rollback target can be deployed without
cryptographic proof that an approved key signed it.

## Verify

```bash
# from your Mac, prove the forced command works and is locked down:
ssh -i <the-private-key> chute-deploy@your-vps status          # prints current + saved rollback commit
ssh -i <the-private-key> chute-deploy@your-vps "rm -rf /"      # MUST be refused by deploy-pull.sh
```

Then push a trivial change to `main` and watch the **Deploy** workflow.

## Existing CD installs

If the box was bootstrapped before the stable forced-command runner existed,
configure `/etc/chute-deploy/allowed-signers`, refresh the runner, and repoint
the existing deploy key once:

```bash
CHUTE_AGENT_CIDRS="1.2.3.4/32" ./deploy/deploy.sh root@your-vps
ssh root@your-vps '
  old=/opt/chute/src/deploy/deploy-pull.sh
  new=/usr/local/sbin/chute-deploy-pull
  test -x "$new"
  pub="$(cat /home/chute-deploy/.ssh/id_ed25519.pub)"
  printf "restrict,command=\"%s\" %s\n" "$new" "$pub" >/home/chute-deploy/.ssh/authorized_keys
  chown root:root /home/chute-deploy /home/chute-deploy/.ssh /home/chute-deploy/.ssh/authorized_keys
  chmod 755 /home/chute-deploy
  chmod 755 /home/chute-deploy/.ssh
  chmod 644 /home/chute-deploy/.ssh/authorized_keys
  install -d -m 700 -o chute-deploy -g chute-deploy /opt/chute/uv /opt/chute/uv/cache /opt/chute/uv/python
'
```

After that, code deploys can change files under `/opt/chute/src` without
changing the forced command used by CD and break-glass rollback.

## Break-glass rollback

The normal path stays unchanged: push to `main`, approve the `production`
environment, and the workflow runs `deploy`.

The GitHub workflow intentionally does **not** accept arbitrary refs. If you need
to roll back a bad production deploy, use the same forced-command key directly
from an operator machine:

```bash
ssh -i <the-private-key> chute-deploy@your-vps status
ssh -i <the-private-key> chute-deploy@your-vps rollback last
ssh -i <the-private-key> chute-deploy@your-vps deploy
```

`rollback last` uses the previous commit recorded in the repo's git metadata.
The forced deploy runner is outside the mutable checkout, so rollback still works
if files under `/opt/chute/src` are broken. This is deliberately not a fuzzing or
staging system; fuzzing runs in its own secret-free workflow.

## Threat note (why the gate matters)

Push-to-main CD means **whatever lands on `main` runs on this production box**.
The forced-command key contains the blast radius of a *leaked key*, and signed
commit verification prevents unsigned or untrusted commits from being deployed
by that key. It still does **not** prove the code is correct: a malicious or
buggy commit signed by an allowed key is still production code. On a box that
also runs your mail MX and DNS, mitigate with: branch protection on `main`
(require PR + review + green CI before merge), the `production` Environment
approval gate above, signed commits from approved keys, and pinned dependencies.
If you'd rather not give GitHub any standing path to the box, switch
`deploy.yml`'s trigger to tags only, or set `CD_ENABLED=false` and deploy
manually with `./deploy/deploy.sh` from your Mac.
