#!/usr/bin/env bash
# Runs ON THE VPS from /usr/local/sbin/chute-deploy-pull, invoked only by the
# GitHub Actions deploy through a forced-command SSH key (see deploy/CD-SETUP.md).
# It pulls origin/main, reinstalls the package, and restarts the service. It never
# needs a root shell: the privileged actions go through a tight NOPASSWD sudoers
# allowlist.
#
# It deliberately does NOT re-copy the systemd unit or the nginx vhost. Those
# change rarely and doing so would widen the sudoers allowlist; when they DO
# change, run ./deploy/deploy.sh from your Mac once. Day-to-day code deploys and
# break-glass commit rollbacks ride this path.
set -euo pipefail
umask 0002

REPO=/opt/chute/src
VENV=/opt/chute/.venv
UV_STATE_ROOT="${CHUTE_UV_STATE_ROOT:-/opt/chute/uv}"
export UV_CACHE_DIR="${UV_CACHE_DIR:-$UV_STATE_ROOT/cache}"
export UV_PYTHON_INSTALL_DIR="${UV_PYTHON_INSTALL_DIR:-$UV_STATE_ROOT/python}"
DEPLOY_VERIFY_CONFIG="${CHUTE_DEPLOY_VERIFY_CONFIG:-/etc/chute-deploy/verify.env}"

cd "$REPO"
LAST_GOOD="$(git rev-parse --git-path chute-last-good-rev)"

usage() {
  cat >&2 <<'EOF'
usage:
  deploy                deploy origin/main
  rollback [last|sha]   deploy the saved previous commit, or an explicit commit
  status                print current and saved rollback commits
EOF
}

die() {
  echo "deploy-pull: $*" >&2
  exit 1
}

load_verify_config() {
  local line key value
  [ -e "$DEPLOY_VERIFY_CONFIG" ] || return
  [ -r "$DEPLOY_VERIFY_CONFIG" ] || die "cannot read deploy verification config: $DEPLOY_VERIFY_CONFIG"

  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
      ""|\#*)
        continue
        ;;
    esac
    key="${line%%=*}"
    value="${line#*=}"
    [ "$key" != "$line" ] || die "bad deploy verification config line: $line"
    case "$key" in
      CHUTE_DEPLOY_VERIFY_SIGNATURE|CHUTE_DEPLOY_SIGNING_FORMAT|CHUTE_DEPLOY_ALLOWED_SIGNERS|CHUTE_DEPLOY_REVOCATION_FILE)
        printf -v "$key" '%s' "$value"
        export "$key"
        ;;
      *)
        die "unknown deploy verification config key: $key"
        ;;
    esac
  done <"$DEPLOY_VERIFY_CONFIG"
}

original_command() {
  if [ "$#" -gt 0 ]; then
    printf '%s\n' "$*"
  elif [ -n "${SSH_ORIGINAL_COMMAND:-}" ]; then
    printf '%s\n' "$SSH_ORIGINAL_COMMAND"
  else
    printf '%s\n' "deploy"
  fi
}

parse_command() {
  local command action arg extra
  command="$(original_command "$@")"
  read -r action arg extra <<<"$command"
  [ -z "${extra:-}" ] || die "expected at most one argument"

  case "${action:-deploy}" in
    deploy)
      [ -z "${arg:-}" ] || die "deploy does not accept a ref; use rollback last|sha"
      printf '%s\t\n' deploy
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
  git fetch --quiet origin "+refs/heads/main:refs/remotes/origin/main"
}

validate_sha_arg() {
  local ref=$1
  [ -n "$ref" ] || return 1
  [ "${#ref}" -ge 7 ] && [ "${#ref}" -le 40 ] || return 1
  [[ "$ref" =~ ^[0-9a-fA-F]+$ ]]
}

resolve_deploy_ref() {
  git rev-parse --verify "origin/main^{commit}" 2>/dev/null || die "unknown ref: origin/main"
}

resolve_rollback_ref() {
  local ref=$1
  if [ "$ref" = "last" ]; then
    [ -s "$LAST_GOOD" ] || die "no saved rollback commit at $LAST_GOOD"
    ref="$(tr -d '[:space:]' <"$LAST_GOOD")"
  fi
  validate_sha_arg "$ref" || die "rollback requires last or a commit SHA"
  git rev-parse --verify "$ref^{commit}" 2>/dev/null || die "unknown rollback commit: $ref"
}

signature_verification_enabled() {
  case "${CHUTE_DEPLOY_VERIFY_SIGNATURE,,}" in
    1|true|yes|on)
      return 0
      ;;
    0|false|no|off)
      return 1
      ;;
    *)
      die "CHUTE_DEPLOY_VERIFY_SIGNATURE must be true/false, got $CHUTE_DEPLOY_VERIFY_SIGNATURE"
      ;;
  esac
}

verify_target_signature() {
  local target_sha=$1 format=${CHUTE_DEPLOY_SIGNING_FORMAT,,}

  if ! signature_verification_enabled; then
    echo "deploy-pull: WARNING: signature verification disabled by CHUTE_DEPLOY_VERIFY_SIGNATURE" >&2
    return
  fi

  case "$format" in
    ssh)
      [ -s "$CHUTE_DEPLOY_ALLOWED_SIGNERS" ] || \
        die "missing SSH allowed signers file: $CHUTE_DEPLOY_ALLOWED_SIGNERS"
      local git_verify=(
        git
        -c gpg.format=ssh
        -c "gpg.ssh.allowedSignersFile=$CHUTE_DEPLOY_ALLOWED_SIGNERS"
      )
      if [ -n "${CHUTE_DEPLOY_REVOCATION_FILE:-}" ]; then
        [ -s "$CHUTE_DEPLOY_REVOCATION_FILE" ] || \
          die "missing SSH revocation file: $CHUTE_DEPLOY_REVOCATION_FILE"
        git_verify+=(-c "gpg.ssh.revocationFile=$CHUTE_DEPLOY_REVOCATION_FILE")
      fi
      "${git_verify[@]}" verify-commit "$target_sha" >/dev/null || \
        die "commit signature verification failed: $target_sha"
      ;;
    openpgp|x509)
      git -c "gpg.format=$format" verify-commit "$target_sha" >/dev/null || \
        die "commit signature verification failed: $target_sha"
      ;;
    auto)
      git verify-commit "$target_sha" >/dev/null || \
        die "commit signature verification failed: $target_sha"
      ;;
    *)
      die "CHUTE_DEPLOY_SIGNING_FORMAT must be ssh, openpgp, x509, or auto"
      ;;
  esac
}

require_manual_deploy_for_config_changes() {
  local previous_sha=$1 target_sha=$2 changed
  [ -n "$previous_sha" ] || return
  [ "$previous_sha" != "$target_sha" ] || return
  changed="$(git diff --name-only "$previous_sha" "$target_sha" -- \
    deploy/chuted.service deploy/nginx-chute.conf deploy/deploy-pull.sh)"
  if [ -z "$changed" ]; then
    return
  fi
  echo "deploy-pull: deployment-owned files changed and require ./deploy/deploy.sh:" >&2
  printf '%s\n' "$changed" >&2
  exit 1
}

ensure_pinned_venv() {
  local python_version
  python_version="$(tr -d '[:space:]' <"$REPO/.python-version")"
  [ -n "$python_version" ] || die "missing $REPO/.python-version"
  command -v uv >/dev/null 2>&1 || die "uv is required to provision pinned Python $python_version"
  mkdir -p "$UV_CACHE_DIR" "$UV_PYTHON_INSTALL_DIR"
  chgrp -R chute "$UV_STATE_ROOT" 2>/dev/null || true
  chmod -R g+rwX "$UV_STATE_ROOT"
  find "$UV_STATE_ROOT" -type d -exec chmod g+s {} +
  uv python install "$python_version"
  uv venv --clear --seed --python "$python_version" "$VENV"
}

install_and_restart() {
  ensure_pinned_venv

  # Hash-pinned runtime/build deps, then chute itself without dependency resolution.
  "$VENV/bin/pip" install --quiet --require-hashes -r "$REPO/deploy/requirements.txt"
  "$VENV/bin/pip" install --quiet --require-hashes -r "$REPO/deploy/build-requirements.txt"
  "$VENV/bin/pip" install --quiet --no-build-isolation --no-deps "$REPO"

  sudo /usr/sbin/nginx -t
  sudo /usr/bin/systemctl restart chuted
  /usr/bin/systemctl is-active --quiet chuted
  sudo /usr/bin/systemctl reload nginx
}

deploy_commit() {
  local target_sha=$1 record_previous=$2 previous_sha=
  previous_sha="$(git rev-parse --verify HEAD 2>/dev/null || true)"
  verify_target_signature "$target_sha"

  if [ "$record_previous" = "yes" ]; then
    require_manual_deploy_for_config_changes "$previous_sha" "$target_sha"
  fi

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
    verify_target_signature "$previous_sha"
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
  load_verify_config
  CHUTE_DEPLOY_VERIFY_SIGNATURE="${CHUTE_DEPLOY_VERIFY_SIGNATURE:-1}"
  CHUTE_DEPLOY_SIGNING_FORMAT="${CHUTE_DEPLOY_SIGNING_FORMAT:-ssh}"
  CHUTE_DEPLOY_ALLOWED_SIGNERS="${CHUTE_DEPLOY_ALLOWED_SIGNERS:-/etc/chute-deploy/allowed-signers}"
  CHUTE_DEPLOY_REVOCATION_FILE="${CHUTE_DEPLOY_REVOCATION_FILE:-}"

  parsed="$(parse_command "$@")"
  action="${parsed%%	*}"
  arg="${parsed#*	}"

  case "$action" in
    status)
      print_status
      ;;
    deploy)
      fetch_refs
      target_sha="$(resolve_deploy_ref)"
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
