#!/usr/bin/env bash
# Runs ON THE VPS from /usr/local/sbin/chute-deploy-pull, invoked only by the
# GitHub Actions deploy through a forced-command SSH key (see deploy/CD-SETUP.md).
# It pulls an explicitly requested ref, reinstalls the package, and restarts the
# service. It never needs a root shell: the privileged actions go through a tight
# NOPASSWD sudoers allowlist.
#
# It deliberately does NOT re-copy the systemd unit or the nginx vhost. Those
# change rarely and doing so would widen the sudoers allowlist; when they DO
# change, run ./deploy/deploy.sh from your Mac once. Day-to-day code deploys and
# test-ref rollbacks ride this path.
set -euo pipefail
umask 0002

REPO=/opt/chute/src
VENV=/opt/chute/.venv

cd "$REPO"
LAST_GOOD="$(git rev-parse --git-path chute-last-good-rev)"

usage() {
  cat >&2 <<'EOF'
usage:
  deploy [ref]          deploy main, a branch, tag, or reachable commit
  rollback [last|sha]   deploy the saved previous commit, or an explicit commit
  status                print current and saved rollback commits
EOF
}

die() {
  echo "deploy-pull: $*" >&2
  exit 1
}

original_command() {
  if [ "$#" -gt 0 ]; then
    printf '%s\n' "$*"
  elif [ -n "${SSH_ORIGINAL_COMMAND:-}" ]; then
    printf '%s\n' "$SSH_ORIGINAL_COMMAND"
  else
    printf '%s\n' "deploy main"
  fi
}

parse_command() {
  local command action arg extra
  command="$(original_command "$@")"
  read -r action arg extra <<<"$command"
  [ -z "${extra:-}" ] || die "expected at most one argument"

  case "${action:-deploy}" in
    deploy)
      printf '%s\t%s\n' deploy "${arg:-main}"
      ;;
    rollback)
      printf '%s\t%s\n' rollback "${arg:-last}"
      ;;
    status)
      [ -z "${arg:-}" ] || die "status takes no arguments"
      printf '%s\t\n' status
      ;;
    *)
      usage
      exit 64
      ;;
  esac
}

fetch_refs() {
  git fetch --quiet origin \
    "+refs/heads/*:refs/remotes/origin/*" \
    "+refs/tags/*:refs/tags/*"
}

validate_ref_arg() {
  local ref=$1
  [ -n "$ref" ] || return 1
  case "$ref" in
    -*|*..*|*@{*|*\\*|*~*|*^*|*:*|*\?*|*\[*|*\]*|*" "*|*"	"*)
      return 1
      ;;
  esac
  if [[ "$ref" =~ ^[0-9a-fA-F]{7,40}$ ]]; then
    return 0
  fi
  git check-ref-format --allow-onelevel "$ref"
}

resolve_ref() {
  local ref=$1 candidate

  validate_ref_arg "$ref" || die "unsafe ref: $ref"
  if [ "$ref" = "main" ]; then
    candidate=origin/main
  elif git rev-parse --verify --quiet "origin/$ref^{commit}" >/dev/null; then
    candidate=origin/$ref
  else
    candidate=$ref
  fi
  git rev-parse --verify "$candidate^{commit}" 2>/dev/null || die "unknown ref: $ref"
}

resolve_rollback_ref() {
  local ref=$1
  if [ "$ref" = "last" ]; then
    [ -s "$LAST_GOOD" ] || die "no saved rollback commit at $LAST_GOOD"
    ref="$(tr -d '[:space:]' <"$LAST_GOOD")"
  fi
  resolve_ref "$ref"
}

install_and_restart() {
  # Hash-pinned runtime deps from the committed lock export, then chute itself (no-deps).
  "$VENV/bin/pip" install --quiet --require-hashes -r "$REPO/deploy/requirements.txt"
  "$VENV/bin/pip" install --quiet --no-deps "$REPO"

  sudo /usr/sbin/nginx -t
  sudo /usr/bin/systemctl restart chuted
  sudo /usr/bin/systemctl reload nginx
}

deploy_commit() {
  local target_sha=$1 record_previous=$2 previous_sha=
  previous_sha="$(git rev-parse --verify HEAD 2>/dev/null || true)"

  if [ "$record_previous" = "yes" ] && [ -n "$previous_sha" ] && [ "$previous_sha" != "$target_sha" ]; then
    printf '%s\n' "$previous_sha" >"$LAST_GOOD.tmp"
    mv "$LAST_GOOD.tmp" "$LAST_GOOD"
  fi

  git reset --hard --quiet "$target_sha"
  if install_and_restart; then
    echo "chute deployed @ $(git rev-parse --short HEAD)"
    return 0
  fi

  if [ "$record_previous" = "yes" ] && [ -n "$previous_sha" ] && [ "$previous_sha" != "$target_sha" ]; then
    echo "deploy failed; attempting automatic rollback to $(git rev-parse --short "$previous_sha")" >&2
    git reset --hard --quiet "$previous_sha"
    install_and_restart || true
  fi
  exit 1
}

print_status() {
  printf 'current=%s\n' "$(git rev-parse HEAD)"
  if [ -s "$LAST_GOOD" ]; then
    printf 'last_good=%s\n' "$(tr -d '[:space:]' <"$LAST_GOOD")"
  else
    printf 'last_good=\n'
  fi
}

main() {
  local parsed action arg target_sha
  parsed="$(parse_command "$@")"
  action="${parsed%%	*}"
  arg="${parsed#*	}"

  case "$action" in
    status)
      print_status
      ;;
    deploy)
      fetch_refs
      target_sha="$(resolve_ref "$arg")"
      deploy_commit "$target_sha" yes
      ;;
    rollback)
      fetch_refs
      target_sha="$(resolve_rollback_ref "$arg")"
      deploy_commit "$target_sha" no
      ;;
  esac
}

main "$@"
