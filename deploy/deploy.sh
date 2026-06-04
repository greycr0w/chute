#!/usr/bin/env bash
# Frictionless deploy of the chute SERVER to your VPS. Idempotent: the first run
# sets everything up; later runs just ship new code and restart. Secrets (token,
# control cert) are generated ONCE and preserved across re-runs.
#
#   ./deploy/deploy.sh root@your-vps          # host or IP of your server
#
# Override defaults via env, e.g.:
#   CHUTE_BASE_DOMAIN=chute.sh CHUTE_PUBLIC_PORT=8080 ./deploy/deploy.sh root@host
#   CHUTE_AGENT_CIDRS="1.2.3.4/32" ./deploy/deploy.sh root@host
#
# What it does on the box:
#   1. rsync this repo to /opt/chute/src   (no .git / venv / caches)
#   2. build a pinned-Python venv at /opt/chute/.venv and install the package
#   3. ensure the `chute` service user
#   4. write /etc/chute/chute.env  (token generated once; chmod 600)
#   5. ensure the control-channel pinned cert (generated once)
#   6. install + (re)start the systemd unit
#   7. install the nginx wildcard vhost, `nginx -t`, reload
#   8. print the token + cert path you need on the client
set -euo pipefail

REMOTE="${1:?usage: deploy.sh user@host}"
BASE_DOMAIN="${CHUTE_BASE_DOMAIN:-chute.sh}"
PUBLIC_PORT="${CHUTE_PUBLIC_PORT:-8080}"
CONTROL_PORT="${CHUTE_CONTROL_PORT:-7000}"
CERT_ROOT="${CHUTE_CERT_ROOT:-/home/letsencrypt/chute/certs}"
# Optional: space-separated CIDRs allowed to reach the control port. When set
# (and ufw is already active on the box) the deploy restricts the port to these.
# Without active ufw, set CHUTE_ALLOW_OPEN_CONTROL=1 only if an external firewall
# or private network already enforces the same restriction.
AGENT_CIDRS="${CHUTE_AGENT_CIDRS:-}"
ALLOW_OPEN_CONTROL="${CHUTE_ALLOW_OPEN_CONTROL:-0}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
SOURCE_GIT_HEAD="$(git -C "$HERE" rev-parse --verify HEAD 2>/dev/null || true)"

echo "==> [1/2] syncing source to $REMOTE:/opt/chute/src"
ssh "$REMOTE" 'mkdir -p /opt/chute/src /etc/chute'
rsync -az --delete \
  --exclude '.git' --exclude '.venv' --exclude '__pycache__' \
  --exclude 'dist' --exclude '*.egg-info' --exclude '.pytest_cache' \
  "$HERE/" "$REMOTE:/opt/chute/src/"

echo "==> [2/2] installing on the box (venv + systemd + nginx)"
ssh "$REMOTE" \
  BASE_DOMAIN="$BASE_DOMAIN" PUBLIC_PORT="$PUBLIC_PORT" CONTROL_PORT="$CONTROL_PORT" \
  CERT_ROOT="$CERT_ROOT" AGENT_CIDRS="$AGENT_CIDRS" ALLOW_OPEN_CONTROL="$ALLOW_OPEN_CONTROL" \
  SOURCE_GIT_HEAD="$SOURCE_GIT_HEAD" \
  'bash -s' <<'REMOTE_SCRIPT'
set -euo pipefail
: "${BASE_DOMAIN:?}" "${PUBLIC_PORT:?}" "${CONTROL_PORT:?}" "${CERT_ROOT:?}"

# If /opt/chute/src is also the git checkout used by CD, keep its HEAD aligned
# with the source commit this manual deploy is refreshing. That prevents the
# next forced-command deploy from re-detecting already-applied config changes.
if [ -n "${SOURCE_GIT_HEAD:-}" ] && git -C /opt/chute/src rev-parse --git-dir >/dev/null 2>&1; then
  if ! git -C /opt/chute/src cat-file -e "$SOURCE_GIT_HEAD^{commit}" 2>/dev/null; then
    git -C /opt/chute/src fetch --quiet origin "+refs/heads/main:refs/remotes/origin/main" || true
  fi
  if git -C /opt/chute/src cat-file -e "$SOURCE_GIT_HEAD^{commit}" 2>/dev/null; then
    git -C /opt/chute/src reset --hard --quiet "$SOURCE_GIT_HEAD"
  else
    echo "    NOTE: source git commit $SOURCE_GIT_HEAD is not present in /opt/chute/src; leaving remote git metadata unchanged" >&2
  fi
fi

# 1) dedicated service user (no shell, no home churn)
id -u chute >/dev/null 2>&1 || \
  useradd --system --home-dir /opt/chute --shell /usr/sbin/nologin chute

# 2) venv + install. Runtime deps and build deps come from HASH-PINNED exports, so
# prod runs the exact versions CI tested instead of resolving fresh on the box.
# The interpreter version comes from the repo pin; uv can install it if the OS
# image doesn't already have that Python minor.
PYTHON_VERSION="$(tr -d '[:space:]' </opt/chute/src/.python-version)"
[ -n "$PYTHON_VERSION" ] || { echo "missing /opt/chute/src/.python-version" >&2; exit 1; }
command -v uv >/dev/null 2>&1 || {
  echo "uv is required on the VPS to provision pinned Python $PYTHON_VERSION" >&2
  echo "install uv once, then rerun deploy/deploy.sh" >&2
  exit 1
}
uv python install "$PYTHON_VERSION"
uv venv --clear --seed --python "$PYTHON_VERSION" /opt/chute/.venv
# chute itself is then installed without dependency resolution or build isolation.
/opt/chute/.venv/bin/pip install --quiet --require-hashes -r /opt/chute/src/deploy/requirements.txt
/opt/chute/.venv/bin/pip install --quiet --require-hashes -r /opt/chute/src/deploy/build-requirements.txt
/opt/chute/.venv/bin/pip install --quiet --no-build-isolation --no-deps /opt/chute/src

# 3) control-channel pinned cert (generated ONCE; the client pins this exact file)
if [ ! -f /opt/chute/chute-cert.pem ]; then
  echo "    generating control-channel cert (one time)"
  /opt/chute/.venv/bin/chuted gen-cert --host "$BASE_DOMAIN" \
    --cert /opt/chute/chute-cert.pem --key /opt/chute/chute-key.pem
fi

PUBLIC_CERT="$CERT_ROOT/$BASE_DOMAIN/fullchain.pem"
PUBLIC_KEY="$CERT_ROOT/$BASE_DOMAIN/privkey.pem"
if [ ! -f "$PUBLIC_CERT" ] || [ ! -f "$PUBLIC_KEY" ]; then
  echo "missing wildcard public TLS cert/key for nginx:" >&2
  echo "  $PUBLIC_CERT" >&2
  echo "  $PUBLIC_KEY" >&2
  echo "Set CHUTE_CERT_ROOT or provision the wildcard cert before running deploy.sh." >&2
  exit 1
fi

# 4) candidate env with the shared token preserved, but runtime values regenerated
# on every deploy. nginx is rendered from these same effective values below; the
# candidate is committed only after nginx validates.
if [ -f /etc/chute/chute.env ] && grep -q '^CHUTE_TOKEN=' /etc/chute/chute.env; then
  TOKEN="$(grep '^CHUTE_TOKEN=' /etc/chute/chute.env | cut -d= -f2-)"
else
  echo "    generating shared token (one time)"
  TOKEN="$(/opt/chute/.venv/bin/chuted gen-token)"
fi
cat > /etc/chute/chute.env.new <<EOF
CHUTE_TOKEN=$TOKEN
CHUTE_BASE_DOMAIN=$BASE_DOMAIN
CHUTE_UPSTREAM_TLS=1
CHUTE_PUBLIC_HOST=127.0.0.1
CHUTE_PUBLIC_PORT=$PUBLIC_PORT
CHUTE_CONTROL_HOST=0.0.0.0
CHUTE_CONTROL_PORT=$CONTROL_PORT
CHUTE_CERT=/opt/chute/chute-cert.pem
CHUTE_KEY=/opt/chute/chute-key.pem
EOF
chmod 600 /etc/chute/chute.env.new
chown chute:chute /etc/chute/chute.env.new
chown -R chute:chute /opt/chute /etc/chute
if id -u chute-deploy >/dev/null 2>&1; then
  chown -R chute-deploy:chute-deploy /opt/chute/src
  install -d -m 700 -o chute-deploy -g chute-deploy \
    /opt/chute/uv /opt/chute/uv/cache /opt/chute/uv/python
fi
chgrp -R chute /opt/chute/.venv
chmod -R g+rwX /opt/chute/.venv
find /opt/chute/.venv -type d -exec chmod g+s {} +

# 5) nginx wildcard vhost (specific server_name => other vhosts untouched).
# Install the candidate config, validate it, and restore the old file on failure.
# chuted is not restarted until this succeeds, so it cannot advertise HTTPS before
# nginx can truthfully serve it.
_sed_escape() { printf '%s' "$1" | sed 's/[\/&]/\\&/g'; }
BASE_DOMAIN_ESC="$(_sed_escape "$BASE_DOMAIN")"
PUBLIC_PORT_ESC="$(_sed_escape "$PUBLIC_PORT")"
CERT_ROOT_ESC="$(_sed_escape "$CERT_ROOT")"
NGINX_CONF=/etc/nginx/sites-available/chute.conf
NGINX_LINK=/etc/nginx/sites-enabled/chute.conf
NGINX_BACKUP="$(mktemp)"
NGINX_HAD_CONF=0
NGINX_HAD_LINK=0
if [ -f "$NGINX_CONF" ]; then
  cp "$NGINX_CONF" "$NGINX_BACKUP"
  NGINX_HAD_CONF=1
fi
if [ -e "$NGINX_LINK" ] || [ -L "$NGINX_LINK" ]; then
  NGINX_HAD_LINK=1
fi
_restore_nginx_candidate() {
  if [ "$NGINX_HAD_CONF" = "1" ]; then
    cp "$NGINX_BACKUP" "$NGINX_CONF"
  else
    rm -f "$NGINX_CONF"
  fi
  if [ "$NGINX_HAD_LINK" = "0" ]; then
    rm -f "$NGINX_LINK"
  fi
  rm -f "$NGINX_BACKUP"
}
sed \
  -e "s/__BASE_DOMAIN__/$BASE_DOMAIN_ESC/g" \
  -e "s/__PUBLIC_PORT__/$PUBLIC_PORT_ESC/g" \
  -e "s/__CERT_ROOT__/$CERT_ROOT_ESC/g" \
  /opt/chute/src/deploy/nginx-chute.conf > "$NGINX_CONF"
ln -sf "$NGINX_CONF" "$NGINX_LINK"
if nginx -t; then
  :
else
  echo "!!! nginx -t FAILED -- left the running config untouched, fix and re-run" >&2
  _restore_nginx_candidate
  rm -f /etc/chute/chute.env.new
  exit 1
fi

# 6) restrict the pre-auth control port before the daemon is restarted. If this
# deploy cannot enforce the restriction itself, require an explicit override.
if [ -n "${AGENT_CIDRS:-}" ]; then
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi '^Status: active'; then
    ufw --force delete allow "$CONTROL_PORT"/tcp >/dev/null 2>&1 || true
    ufw --force delete deny "$CONTROL_PORT"/tcp >/dev/null 2>&1 || true
    ufw insert 1 deny "$CONTROL_PORT"/tcp >/dev/null
    for cidr in $AGENT_CIDRS; do
      ufw insert 1 allow from "$cidr" to any port "$CONTROL_PORT" proto tcp >/dev/null
    done
    echo "    restricted control port $CONTROL_PORT/tcp to: $AGENT_CIDRS"
  elif [ "${ALLOW_OPEN_CONTROL:-0}" != "1" ]; then
    echo "!!! CHUTE_AGENT_CIDRS is set but ufw is not active; restrict $CONTROL_PORT/tcp yourself or set CHUTE_ALLOW_OPEN_CONTROL=1 to acknowledge an external firewall" >&2
    _restore_nginx_candidate
    rm -f /etc/chute/chute.env.new
    exit 1
  else
    echo "    NOTE: ufw not active -- relying on your external firewall for $CONTROL_PORT/tcp"
  fi
elif [ "${ALLOW_OPEN_CONTROL:-0}" != "1" ]; then
  echo "!!! CHUTE_AGENT_CIDRS is empty. Refusing to expose control port $CONTROL_PORT/tcp without an allowlist." >&2
  echo "    Set CHUTE_AGENT_CIDRS=\"1.2.3.4/32\" or CHUTE_ALLOW_OPEN_CONTROL=1 if an external firewall already restricts it." >&2
  _restore_nginx_candidate
  rm -f /etc/chute/chute.env.new
  exit 1
fi
rm -f "$NGINX_BACKUP"

# 7) commit daemon env + systemd unit only after nginx validates, then restart.
mv /etc/chute/chute.env.new /etc/chute/chute.env
chmod 600 /etc/chute/chute.env
chown chute:chute /etc/chute/chute.env
cp /opt/chute/src/deploy/chuted.service /etc/systemd/system/chuted.service
install -m 0755 -o root -g root /opt/chute/src/deploy/deploy-pull.sh /usr/local/sbin/chute-deploy-pull
systemctl daemon-reload
systemctl enable chuted >/dev/null 2>&1 || true
systemctl restart chuted
systemctl is-active --quiet chuted
systemctl reload nginx

TOKEN="$(grep '^CHUTE_TOKEN=' /etc/chute/chute.env | cut -d= -f2-)"
echo
echo "===================== chute deployed ====================="
echo "  base domain : *.$BASE_DOMAIN"
echo "  control     : wss://$BASE_DOMAIN:$CONTROL_PORT"
echo "                RESTRICT $CONTROL_PORT/tcp to your agent's source IP(s) -- it must NOT be open to 0.0.0.0/0."
echo "                (set CHUTE_AGENT_CIDRS=\"1.2.3.4/32\" for ufw, or CHUTE_ALLOW_OPEN_CONTROL=1 when an external firewall already enforces this.)"
echo "  token       : $TOKEN"
echo "  client cert : /opt/chute/chute-cert.pem"
echo "==========================================================="
systemctl --no-pager status chuted | sed -n '1,5p' || true
REMOTE_SCRIPT

echo
echo "==> pull the pinned client cert down to your Mac:"
echo "    scp $REMOTE:/opt/chute/chute-cert.pem ./chute-cert.pem"
echo
echo "==> save the token locally for --token-file:"
echo "    install -d -m 700 ~/.config/chute"
echo "    printf '%s\\n' '<token-above>' > ~/.config/chute/token && chmod 600 ~/.config/chute/token"
echo
echo "==> then start a tunnel:"
echo "    chute 8000 --server $BASE_DOMAIN --control-port $CONTROL_PORT \\"
echo "      --token-file ~/.config/chute/token --server-cert ./chute-cert.pem --subdomain myapp"
