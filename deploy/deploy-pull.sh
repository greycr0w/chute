#!/usr/bin/env bash
# Runs ON THE VPS, invoked only by the GitHub Actions deploy through a
# forced-command SSH key (see deploy/CD-SETUP.md). It pulls main, reinstalls the
# package, and restarts the service. It never needs a root shell: the three
# privileged actions go through a tight NOPASSWD sudoers allowlist.
#
# It deliberately does NOT re-copy the systemd unit or the nginx vhost. Those
# change rarely and doing so would widen the sudoers allowlist; when they DO
# change, run ./deploy/deploy.sh from your Mac once. Day-to-day code deploys ride
# this path.
set -euo pipefail

REPO=/opt/chute/src
VENV=/opt/chute/.venv

cd "$REPO"
git fetch --quiet origin main
git reset --hard --quiet origin/main          # deploy exactly what is on main
"$VENV/bin/pip" install --quiet --upgrade "$REPO"

sudo /usr/bin/systemctl restart chuted
sudo /usr/sbin/nginx -t
sudo /usr/bin/systemctl reload nginx

echo "chute deployed @ $(git rev-parse --short HEAD)"
