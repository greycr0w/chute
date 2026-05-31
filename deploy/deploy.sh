#!/usr/bin/env bash
# Frictionless deploy of the chute SERVER to your VPS. Idempotent: the first run
# sets everything up; later runs just ship new code and restart. Secrets (token,
# control cert) are generated ONCE and preserved across re-runs.
#
#   ./deploy/deploy.sh root@your-vps          # host or IP of your server
#
# Override defaults via env, e.g.:
#   CHUTE_BASE_DOMAIN=chute.sh CHUTE_PUBLIC_PORT=8080 ./deploy/deploy.sh root@host
#
# What it does on the box:
#   1. rsync this repo to /opt/chute/src   (no .git / venv / caches)
#   2. build a venv at /opt/chute/.venv and `pip install` the package
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
# Optional: space-separated CIDRs allowed to reach the control port. When set
# (and ufw is already active on the box) the deploy restricts the port to these;
# otherwise it just prints the commands. The agent dials OUT, so the control
# port rarely needs to be open to the whole internet.
AGENT_CIDRS="${CHUTE_AGENT_CIDRS:-}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"

echo "==> [1/2] syncing source to $REMOTE:/opt/chute/src"
ssh "$REMOTE" 'mkdir -p /opt/chute/src /etc/chute'
rsync -az --delete \
  --exclude '.git' --exclude '.venv' --exclude '__pycache__' \
  --exclude 'dist' --exclude '*.egg-info' --exclude '.pytest_cache' \
  "$HERE/" "$REMOTE:/opt/chute/src/"

echo "==> [2/2] installing on the box (venv + systemd + nginx)"
ssh "$REMOTE" \
  BASE_DOMAIN="$BASE_DOMAIN" PUBLIC_PORT="$PUBLIC_PORT" CONTROL_PORT="$CONTROL_PORT" \
  AGENT_CIDRS="$AGENT_CIDRS" \
  'bash -s' <<'REMOTE_SCRIPT'
set -euo pipefail
: "${BASE_DOMAIN:?}" "${PUBLIC_PORT:?}" "${CONTROL_PORT:?}"

# 1) dedicated service user (no shell, no home churn)
id -u chute >/dev/null 2>&1 || \
  useradd --system --home-dir /opt/chute --shell /usr/sbin/nologin chute

# 2) venv + install (re-installs on every deploy => picks up new code)
python3 -m venv /opt/chute/.venv
/opt/chute/.venv/bin/pip install --quiet --upgrade pip
/opt/chute/.venv/bin/pip install --quiet --upgrade /opt/chute/src

# 3) control-channel pinned cert (generated ONCE; the client pins this exact file)
if [ ! -f /opt/chute/chute-cert.pem ]; then
  echo "    generating control-channel cert (one time)"
  /opt/chute/.venv/bin/chuted gen-cert --host "$BASE_DOMAIN" \
    --cert /opt/chute/chute-cert.pem --key /opt/chute/chute-key.pem
fi

# 4) env file with the shared token (generated ONCE, preserved on re-runs)
if [ ! -f /etc/chute/chute.env ]; then
  echo "    generating shared token (one time)"
  TOKEN="$(/opt/chute/.venv/bin/chuted gen-token)"
  cat > /etc/chute/chute.env <<EOF
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
fi
chmod 600 /etc/chute/chute.env
chown -R chute:chute /opt/chute /etc/chute

# 5) systemd unit
cp /opt/chute/src/deploy/chuted.service /etc/systemd/system/chuted.service
systemctl daemon-reload
systemctl enable chuted >/dev/null 2>&1 || true
systemctl restart chuted

# 6) nginx wildcard vhost (specific server_name => other vhosts untouched)
cp /opt/chute/src/deploy/nginx-chute.conf /etc/nginx/sites-available/chute.conf
ln -sf /etc/nginx/sites-available/chute.conf /etc/nginx/sites-enabled/chute.conf
if nginx -t; then
  systemctl reload nginx
else
  echo "!!! nginx -t FAILED -- left the running config untouched, fix and re-run" >&2
  exit 1
fi

# 7) optionally restrict the pre-auth control port to known agent source IP(s)
if [ -n "${AGENT_CIDRS:-}" ]; then
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi '^Status: active'; then
    for cidr in $AGENT_CIDRS; do
      ufw allow from "$cidr" to any port "$CONTROL_PORT" proto tcp >/dev/null
    done
    ufw deny "$CONTROL_PORT"/tcp >/dev/null || true
    echo "    restricted control port $CONTROL_PORT/tcp to: $AGENT_CIDRS"
  else
    echo "    NOTE: ufw not active -- restrict $CONTROL_PORT/tcp yourself, e.g.:"
    for cidr in $AGENT_CIDRS; do
      echo "      ufw allow from $cidr to any port $CONTROL_PORT proto tcp"
    done
    echo "      ufw deny $CONTROL_PORT/tcp"
  fi
fi

TOKEN="$(grep '^CHUTE_TOKEN=' /etc/chute/chute.env | cut -d= -f2-)"
echo
echo "===================== chute deployed ====================="
echo "  base domain : *.$BASE_DOMAIN"
echo "  control     : wss://$BASE_DOMAIN:$CONTROL_PORT"
echo "                RESTRICT $CONTROL_PORT/tcp to your agent's source IP(s) -- it must NOT be open to 0.0.0.0/0."
echo "                (set CHUTE_AGENT_CIDRS=\"1.2.3.4/32\" to have this script do it via ufw, or front it with WireGuard/Tailscale.)"
echo "  token       : $TOKEN"
echo "  client cert : /opt/chute/chute-cert.pem"
echo "==========================================================="
systemctl --no-pager status chuted | sed -n '1,5p' || true
REMOTE_SCRIPT

echo
echo "==> pull the pinned client cert down to your Mac:"
echo "    scp $REMOTE:/opt/chute/chute-cert.pem ./chute-cert.pem"
echo
echo "==> then start a tunnel:"
echo "    chute http 8000 --server $BASE_DOMAIN --control-port $CONTROL_PORT \\"
echo "      --token <token-above> --server-cert ./chute-cert.pem --subdomain myapp"
