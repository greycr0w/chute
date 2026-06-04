from __future__ import annotations

import plistlib
import re
import shutil
import subprocess
import tomllib
from pathlib import Path

import pytest

from chute import certs

ROOT = Path(__file__).resolve().parents[1]


def _render_nginx(base_domain: str, public_port: int, cert_root: str) -> str:
    conf = (ROOT / "deploy" / "nginx-chute.conf").read_text()
    return (
        conf.replace("__BASE_DOMAIN__", base_domain)
        .replace("__PUBLIC_PORT__", str(public_port))
        .replace("__CERT_ROOT__", cert_root)
    )


def _without_comments(conf: str) -> str:
    return "\n".join(line.split("#", 1)[0] for line in conf.splitlines())


def test_nginx_template_renders_non_chute_domain() -> None:
    rendered = _render_nginx("example.net", 18080, "/srv/acme/certs")

    assert "*.example.net" in rendered
    assert "chute.sh" not in rendered
    assert "http://127.0.0.1:18080" in rendered
    assert "/srv/acme/certs/example.net/fullchain.pem" in rendered
    assert "/srv/acme/certs/example.net/privkey.pem" in rendered


def test_nginx_template_keeps_http_and_https_without_forced_upgrade() -> None:
    rendered = _render_nginx("example.net", 18080, "/srv/acme/certs")
    active_config = _without_comments(rendered).lower()

    assert re.search(r"listen\s+80;", rendered)
    assert re.search(r"listen\s+443\s+ssl\s+http2;", rendered)
    assert "return 301" not in active_config
    assert "return 308" not in active_config
    assert "rewrite " not in active_config
    assert "strict-transport-security" not in active_config
    assert "NO HSTS and NO :80->:443 redirect" in rendered
    assert "iframe/postMessage workflow" in rendered


def test_nginx_template_preserves_one_request_per_upstream_connection() -> None:
    rendered = _render_nginx("example.net", 18080, "/srv/acme/certs")
    active_config = _without_comments(rendered)

    assert re.search(r"\bupstream\b", active_config) is None
    assert re.search(r"\bkeepalive\b", active_config) is None
    assert active_config.count("proxy_pass http://127.0.0.1:18080;") == 2
    assert active_config.count("proxy_set_header Connection $chute_connection_upgrade;") == 2
    assert active_config.count("proxy_request_buffering off;") == 2
    assert re.search(
        r"map\s+\$http_upgrade\s+\$chute_connection_upgrade\s*\{[^}]*''\s+close;",
        active_config,
        flags=re.S,
    )


def test_nginx_template_caps_true_client_ip_concurrency() -> None:
    rendered = _render_nginx("example.net", 18080, "/srv/acme/certs")
    active_config = _without_comments(rendered)

    assert "limit_conn_zone $binary_remote_addr zone=chute_per_ip:10m;" in active_config
    assert "limit_conn_status 503;" in active_config
    assert active_config.count("limit_conn chute_per_ip 64;") == 2


def test_deploy_commits_daemon_env_only_after_nginx_validates() -> None:
    script = (ROOT / "deploy" / "deploy.sh").read_text()

    assert "chute.env.new" in script
    assert "CHUTE_BASE_DOMAIN=$BASE_DOMAIN" in script
    assert "CHUTE_PUBLIC_PORT=$PUBLIC_PORT" in script
    assert "CHUTE_UPSTREAM_TLS=1" in script
    assert "if [ ! -f /etc/chute/chute.env ]; then" not in script

    cert_check = script.index("missing wildcard public TLS cert/key for nginx")
    write_env = script.index("cat > /etc/chute/chute.env.new")
    render_nginx = script.index('/opt/chute/src/deploy/nginx-chute.conf > "$NGINX_CONF"')
    nginx_test = script.index("if nginx -t; then")
    commit_env = script.index("mv /etc/chute/chute.env.new /etc/chute/chute.env")
    restart_chuted = script.index("systemctl restart chuted")
    active_check = script.index("systemctl is-active --quiet chuted")
    reload_nginx = script.index("systemctl reload nginx")
    assert (
        cert_check
        < write_env
        < render_nginx
        < nginx_test
        < commit_env
        < restart_chuted
        < active_check
        < reload_nginx
    )


def test_deploy_prints_https_default_agent_command() -> None:
    script = (ROOT / "deploy" / "deploy.sh").read_text()

    assert "chute 8000 --server $BASE_DOMAIN" in script
    assert "chute http 8000 --server $BASE_DOMAIN" not in script
    assert "--token-file ~/.config/chute/token" in script
    assert "--token <token-above>" not in script


def test_readme_states_deploy_public_tls_cert_prerequisite() -> None:
    readme = (ROOT / "README.md").read_text()

    assert "CHUTE_CERT_ROOT" in readme
    assert "fullchain.pem" in readme
    assert "privkey.pem" in readme


def test_docs_name_actual_runtime_user_for_private_files() -> None:
    docs = "\n".join(
        [
            (ROOT / "README.md").read_text(),
            (ROOT / "docs" / "CONTROL-PLANE.md").read_text(),
            (ROOT / "docs" / "PROTOCOL.md").read_text(),
        ]
    )

    assert "user running `chuted` (`chute` in" in docs
    assert "bundled systemd" in docs
    assert "owned by the `chuted` user" not in docs
    assert "owned by `chuted`" not in docs


def test_docs_call_out_proxy_ipv6_limit_keying() -> None:
    readme = (ROOT / "README.md").read_text()
    security = (ROOT / "SECURITY.md").read_text()

    assert "exact `$binary_remote_addr`" in readme
    assert "does not group IPv6 privacy addresses by `/64`" in readme
    assert "proxy-mode IPv6 limits are not grouped by `/64`" in security


def test_deploy_installs_hash_pinned_build_requirements_without_isolation() -> None:
    script = (ROOT / "deploy" / "deploy.sh").read_text()
    pull = (ROOT / "deploy" / "deploy-pull.sh").read_text()
    build_requirements = (ROOT / "deploy" / "build-requirements.txt").read_text()
    pyproject = (ROOT / "pyproject.toml").read_text()

    assert 'requires = ["hatchling==1.27.0"]' in pyproject
    assert "hatchling==1.27.0" in build_requirements
    assert "--hash=sha256:" in build_requirements
    assert "deploy/build-requirements.in" in build_requirements
    assert "pip install --quiet --upgrade pip" not in script
    assert (
        "pip install --quiet --require-hashes -r /opt/chute/src/deploy/build-requirements.txt"
        in script
    )
    assert 'pip" install --quiet --require-hashes -r "$REPO/deploy/build-requirements.txt"' in pull
    assert "pip install --quiet --no-build-isolation --no-deps /opt/chute/src" in script
    assert 'pip" install --quiet --no-build-isolation --no-deps "$REPO"' in pull


def test_deploy_requires_control_port_allowlist_or_explicit_override() -> None:
    script = (ROOT / "deploy" / "deploy.sh").read_text()

    assert 'ALLOW_OPEN_CONTROL="${CHUTE_ALLOW_OPEN_CONTROL:-0}"' in script
    assert "CHUTE_AGENT_CIDRS is empty. Refusing to expose control port" in script
    assert "CHUTE_ALLOW_OPEN_CONTROL=1" in script
    assert 'ufw --force delete allow "$CONTROL_PORT"/tcp' in script
    assert 'ufw insert 1 deny "$CONTROL_PORT"/tcp' in script
    assert 'ufw insert 1 allow from "$cidr" to any port "$CONTROL_PORT" proto tcp' in script

    delete_allow = script.index('ufw --force delete allow "$CONTROL_PORT"/tcp')
    insert_deny = script.index('ufw insert 1 deny "$CONTROL_PORT"/tcp')
    insert_allow = script.index(
        'ufw insert 1 allow from "$cidr" to any port "$CONTROL_PORT" proto tcp'
    )
    assert delete_allow < insert_deny < insert_allow


def test_deploy_restores_candidate_nginx_on_firewall_refusal() -> None:
    script = (ROOT / "deploy" / "deploy.sh").read_text()

    inactive_ufw = script.index("CHUTE_AGENT_CIDRS is set but ufw is not active")
    missing_allowlist = script.index("CHUTE_AGENT_CIDRS is empty. Refusing")
    restore_inactive = script.index("_restore_nginx_candidate", inactive_ufw)
    restore_missing = script.index("_restore_nginx_candidate", missing_allowlist)
    commit_env = script.index("mv /etc/chute/chute.env.new /etc/chute/chute.env")

    assert restore_inactive < commit_env
    assert restore_missing < commit_env


def test_chuted_service_rate_limits_crash_loops() -> None:
    unit = (ROOT / "deploy" / "chuted.service").read_text()
    unit_section, service_and_rest = unit.split("[Service]", 1)
    service_section = service_and_rest.split("[Install]", 1)[0]

    assert "StartLimitIntervalSec=60" in unit_section
    assert "StartLimitBurst=5" in unit_section
    assert "Restart=always" in service_section
    assert "RestartSec=2" in service_section


def test_chuted_service_uses_notify_watchdog() -> None:
    unit = (ROOT / "deploy" / "chuted.service").read_text()
    service_section = unit.split("[Service]", 1)[1].split("[Install]", 1)[0]

    assert "Type=notify" in service_section
    assert "NotifyAccess=main" in service_section
    assert "WatchdogSec=30s" in service_section


def test_chuted_service_uses_restrictive_runtime_umask() -> None:
    unit = (ROOT / "deploy" / "chuted.service").read_text()
    service_section = unit.split("[Service]", 1)[1].split("[Install]", 1)[0]

    assert "UMask=0077" in service_section


def test_chuted_service_provisions_private_log_directory_without_broad_write() -> None:
    unit = (ROOT / "deploy" / "chuted.service").read_text()
    service_section = unit.split("[Service]", 1)[1].split("[Install]", 1)[0]

    assert "LogsDirectory=chute" in service_section
    assert "LogsDirectoryMode=0700" in service_section


def test_chuted_service_preserves_runtime_sandbox_and_resource_caps() -> None:
    unit = (ROOT / "deploy" / "chuted.service").read_text()
    service_section = _without_comments(unit.split("[Service]", 1)[1].split("[Install]", 1)[0])

    assert "NoNewPrivileges=true" in service_section
    assert "ProtectSystem=strict" in service_section
    assert "ReadWritePaths=" not in service_section
    assert "CapabilityBoundingSet=" in service_section
    assert "AmbientCapabilities=" in service_section
    assert "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6" in service_section
    assert "Type=notify" in service_section
    assert "WatchdogSec=30s" in service_section
    assert "SystemCallFilter=@system-service" in service_section
    assert "MemoryMax=512M" in service_section
    assert "TasksMax=256" in service_section
    assert "LimitNOFILE=8192" in service_section


def test_launchd_agent_sample_keeps_token_out_of_plist_and_tmp_logs() -> None:
    plist_path = ROOT / "deploy" / "com.chute.agent.plist"
    text = plist_path.read_text()
    parsed = plistlib.loads(plist_path.read_bytes())

    assert "CHUTE_TOKEN" not in text
    assert "CHANGE_ME_TOKEN" in text  # only in setup comments, not plist keys/values
    assert "chmod 600 ~/.config/chute/token" in text
    assert "/tmp/chute" not in text

    args = parsed["ProgramArguments"]
    assert "--token-file" in args
    assert "/Users/CHANGE_ME/.config/chute/token" in args
    assert "--token" not in args
    assert "EnvironmentVariables" not in parsed
    assert parsed["StandardOutPath"] == "/Users/CHANGE_ME/Library/Logs/chute/agent.log"
    assert parsed["StandardErrorPath"] == "/Users/CHANGE_ME/Library/Logs/chute/agent.err.log"


def test_operator_docs_do_not_include_live_test_breadcrumbs() -> None:
    cd_setup = (ROOT / "deploy" / "CD-SETUP.md").read_text()

    assert "verified live" not in cd_setup
    assert "live-test" not in cd_setup


def test_deploy_installs_stable_forced_command_runner() -> None:
    script = (ROOT / "deploy" / "deploy.sh").read_text()
    cd_setup = (ROOT / "deploy" / "CD-SETUP.md").read_text()

    assert (
        "install -m 0755 -o root -g root /opt/chute/src/deploy/deploy-pull.sh "
        "/usr/local/sbin/chute-deploy-pull"
    ) in script
    assert "chown -R chute-deploy:chute-deploy /opt/chute/src" in script
    assert "install -d -m 700 -o chute-deploy -g chute-deploy \\" in script
    assert "/opt/chute/uv /opt/chute/uv/cache /opt/chute/uv/python" in script
    assert "useradd --system --create-home --shell /bin/sh chute-deploy" in cd_setup
    assert "install -d -m 700 -o chute-deploy -g chute-deploy /home/chute-deploy/.ssh" in cd_setup
    assert cd_setup.index("install -d -m 700") < cd_setup.index("ssh-keygen -t ed25519")
    assert 'restrict,command="/usr/local/sbin/chute-deploy-pull"' in cd_setup
    assert (
        "chown root:root /home/chute-deploy /home/chute-deploy/.ssh "
        "/home/chute-deploy/.ssh/authorized_keys"
    ) in cd_setup
    assert "chmod 755 /home/chute-deploy" in cd_setup
    assert 'command="/opt/chute/src/deploy/deploy-pull.sh"' not in cd_setup


def test_cd_workflow_keeps_production_deploy_simple() -> None:
    workflow = (ROOT / ".github" / "workflows" / "deploy.yml").read_text()

    assert "workflow_dispatch:" not in workflow
    assert "rollback_to:" not in workflow
    assert "DEPLOY_REF" not in workflow
    assert "validate_remote_arg()" not in workflow
    assert "remote_command=(" not in workflow
    assert '"$SSH_USER@$SSH_HOST" deploy' in workflow


def test_ci_lint_uses_locked_project_ruff() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text())
    lock = (ROOT / "uv.lock").read_text()

    dev_deps = pyproject["project"]["optional-dependencies"]["dev"]
    lint_select = pyproject["tool"]["ruff"]["lint"]["select"]
    assert "ruff==0.15.15" in dev_deps
    assert 'name = "ruff"' in lock
    assert 'version = "0.15.15"' in lock
    assert "RUF006" in lint_select

    assert "uvx ruff" not in workflow
    assert "uv sync --locked --extra dev" in workflow
    assert "uv run --no-sync ruff check --output-format=github ." in workflow
    assert "uv run --no-sync ruff format --check ." in workflow


def test_ci_audits_locked_production_dependencies() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
    dependabot = (ROOT / ".github" / "dependabot.yml").read_text()
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text())
    lock = (ROOT / "uv.lock").read_text()

    dev_deps = pyproject["project"]["optional-dependencies"]["dev"]
    assert "pip-audit==2.10.0" in dev_deps
    assert 'name = "pip-audit"' in lock
    assert 'version = "2.10.0"' in lock

    assert 'package-ecosystem: "github-actions"' in dependabot
    assert 'package-ecosystem: "uv"' in dependabot
    assert "uvx pip-audit" not in workflow
    assert "pip install pip-audit" not in workflow
    assert "uv run --no-sync pip-audit -r deploy/requirements.txt --disable-pip" in workflow
    assert "uv export --frozen --no-dev --no-emit-project -o deploy/requirements.txt" in workflow
    assert workflow.index("deploy/requirements.txt matches the lock") < workflow.index(
        "Audit production dependencies"
    )


def test_release_workflow_uses_pinned_actions_and_sbom_attestations() -> None:
    release = (ROOT / ".github" / "workflows" / "release.yml").read_text()
    script = (ROOT / "scripts" / "generate_release_sbom.sh").read_text()
    security = (ROOT / "SECURITY.md").read_text()
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text())
    lock = (ROOT / "uv.lock").read_text()

    dev_deps = pyproject["project"]["optional-dependencies"]["dev"]
    assert "cyclonedx-bom==7.3.0" in dev_deps
    assert 'name = "cyclonedx-bom"' in lock
    assert 'version = "7.3.0"' in lock

    assert "permissions:\n  contents: read" in release
    assert "contents: write # create the Release" in release
    assert "id-token: write # OIDC, for the build-provenance attestation" in release
    assert "attestations: write # record the provenance attestation" in release
    assert "uv sync --locked --extra dev" in release
    assert "Generate runtime SBOM" in release
    assert "scripts/generate_release_sbom.sh" in release
    assert "Attest build provenance" in release
    assert "actions/attest-build-provenance@" in release
    assert "Attest runtime SBOM" in release
    assert "actions/attest@" in release
    assert "subject-path: |\n            dist/*.whl\n            dist/*.tar.gz" in release
    assert "dist/chute-runtime-sbom.cdx.json" in release
    assert "sbom-path: dist/chute-runtime-sbom.cdx.json" in release

    assert (
        'uv pip install --python "$python_bin" --require-hashes -r deploy/requirements.txt'
        in script
    )
    assert "--no-build-isolation --no-deps" in script
    assert "cyclonedx-py environment" in script
    assert "--pyproject pyproject.toml" in script
    assert "--mc-type library" in script
    assert "--output-reproducible" in script

    assert "chute-runtime-sbom.cdx.json" in security
    assert "--predicate-type https://cyclonedx.org/bom" in security
    assert "--source-ref refs/tags/<tag>" in security

    action_refs = re.findall(r"uses:\s+[^@\s]+@([0-9a-f]{40})\b", release)
    assert len(action_refs) == 5
    assert "@v" not in release


def test_github_actions_are_sha_pinned() -> None:
    workflow_dir = ROOT / ".github" / "workflows"
    workflows = sorted(workflow_dir.glob("*.yml"))
    assert workflows

    unpinned: list[str] = []
    for workflow in workflows:
        for lineno, line in enumerate(workflow.read_text().splitlines(), start=1):
            match = re.search(r"uses:\s+[^@\s]+@([^\s#]+)", line)
            if match and not re.fullmatch(r"[0-9a-f]{40}", match.group(1)):
                unpinned.append(f"{workflow.name}:{lineno}:{line.strip()}")
    assert unpinned == []


def test_pre_commit_hooks_are_sha_pinned() -> None:
    config = (ROOT / ".pre-commit-config.yaml").read_text()
    dependabot = (ROOT / ".github" / "dependabot.yml").read_text()
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text())
    lock = (ROOT / "uv.lock").read_text()

    dev_deps = pyproject["project"]["optional-dependencies"]["dev"]
    assert "pre-commit==4.6.0" in dev_deps
    assert 'name = "pre-commit"' in lock
    assert 'version = "4.6.0"' in lock

    assert "uv run --no-sync pre-commit install" in config
    assert "uv run --no-sync pre-commit autoupdate --freeze" in config
    assert 'minimum_pre_commit_version: "4.6.0"' in config
    assert 'package-ecosystem: "pre-commit"' in dependabot

    rev_lines = re.findall(r"^\s*rev:\s*(\S+)(?:\s+#\s*frozen:\s*(\S+))?", config, flags=re.M)
    assert rev_lines
    unpinned: list[str] = []
    missing_frozen_comment: list[str] = []
    for rev, frozen_tag in rev_lines:
        if not re.fullmatch(r"[0-9a-f]{40}", rev):
            unpinned.append(rev)
        if not frozen_tag or not frozen_tag.startswith("v"):
            missing_frozen_comment.append(rev)
    assert unpinned == []
    assert missing_frozen_comment == []
    assert "rev: v" not in config


def test_python_and_uv_toolchain_are_pinned_for_ci_and_deploy() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
    fuzz_workflow = (ROOT / ".github" / "workflows" / "fuzz.yml").read_text()
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text())
    python_version = (ROOT / ".python-version").read_text().strip()
    deploy = (ROOT / "deploy" / "deploy.sh").read_text()
    pull = (ROOT / "deploy" / "deploy-pull.sh").read_text()
    readme = (ROOT / "README.md").read_text()
    cd_setup = (ROOT / "deploy" / "CD-SETUP.md").read_text()

    assert python_version == "3.13"
    assert pyproject["tool"]["uv"]["required-version"] == ">=0.5.26"
    assert pyproject["project"]["requires-python"] == ">=3.11"

    assert 'python-version: ["3.11", "3.12", "3.13"]' in workflow
    assert "uv sync --locked --extra dev --python ${{ matrix.python-version }}" in workflow
    assert "uv sync --locked --extra dev --extra fuzz --python 3.11" in fuzz_workflow
    assert "setup-uv" in workflow

    assert "PYTHON_VERSION=\"$(tr -d '[:space:]' </opt/chute/src/.python-version)\"" in deploy
    assert "command -v uv >/dev/null 2>&1 || {" in deploy
    assert 'uv python install "$PYTHON_VERSION"' in deploy
    assert 'uv venv --python "$PYTHON_VERSION" /opt/chute/.venv' in deploy
    assert "python3 -m venv" not in deploy

    assert "ensure_pinned_venv()" in pull
    assert 'UV_STATE_ROOT="${CHUTE_UV_STATE_ROOT:-/opt/chute/uv}"' in pull
    assert 'export UV_CACHE_DIR="${UV_CACHE_DIR:-$UV_STATE_ROOT/cache}"' in pull
    assert 'export UV_PYTHON_INSTALL_DIR="${UV_PYTHON_INSTALL_DIR:-$UV_STATE_ROOT/python}"' in pull
    assert 'mkdir -p "$UV_CACHE_DIR" "$UV_PYTHON_INSTALL_DIR"' in pull
    assert 'python_version="$(tr -d \'[:space:]\' <"$REPO/.python-version")"' in pull
    assert 'command -v uv >/dev/null 2>&1 || die "uv is required' in pull
    assert 'uv python install "$python_version"' in pull
    assert 'uv venv --python "$python_version" "$VENV"' in pull
    assert "python3 -m venv" not in pull

    assert "install `uv` once" in readme
    assert "same default Python minor pinned in `.python-version`" in readme
    assert "The VPS must have `uv` on `PATH`" in cd_setup
    assert "recreates `/opt/chute/.venv` with that pinned Python minor" in cd_setup
    assert "install -d -m 700 -o chute-deploy -g chute-deploy \\" in cd_setup
    assert "/opt/chute/uv /opt/chute/uv/cache /opt/chute/uv/python" in cd_setup


def test_deploy_pull_supports_forced_command_rollback() -> None:
    script = (ROOT / "deploy" / "deploy-pull.sh").read_text()

    assert "SSH_ORIGINAL_COMMAND" in script
    assert 'LAST_GOOD="$(git rev-parse --git-path chute-last-good-rev)"' in script
    assert "deploy                deploy origin/main" in script
    assert "rollback [last|sha]" in script
    assert "git check-ref-format --allow-onelevel" not in script
    assert '"+refs/heads/main:refs/remotes/origin/main"' in script
    assert '"+refs/tags/*:refs/tags/*"' not in script
    assert "validate_sha_arg()" in script
    assert "resolve_deploy_ref()" in script
    assert "origin/main^{commit}" in script
    assert "require_manual_deploy_for_config_changes" in script
    assert "deploy/nginx-chute.conf deploy/deploy-pull.sh" in script
    assert 'deploy_commit "$target_sha" yes' in script
    assert 'deploy_commit "$target_sha" no' in script


def test_deploy_pull_verifies_signed_commits_before_reset() -> None:
    script = (ROOT / "deploy" / "deploy-pull.sh").read_text()
    cd_setup = (ROOT / "deploy" / "CD-SETUP.md").read_text()
    readme = (ROOT / "README.md").read_text()

    assert (
        'DEPLOY_VERIFY_CONFIG="${CHUTE_DEPLOY_VERIFY_CONFIG:-/etc/chute-deploy/verify.env}"'
        in script
    )
    assert 'CHUTE_DEPLOY_VERIFY_SIGNATURE="${CHUTE_DEPLOY_VERIFY_SIGNATURE:-1}"' in script
    assert 'CHUTE_DEPLOY_SIGNING_FORMAT="${CHUTE_DEPLOY_SIGNING_FORMAT:-ssh}"' in script
    assert (
        'CHUTE_DEPLOY_ALLOWED_SIGNERS="${CHUTE_DEPLOY_ALLOWED_SIGNERS:-/etc/chute-deploy/allowed-signers}"'
        in script
    )
    assert "CHUTE_DEPLOY_REVOCATION_FILE" in script
    assert "source " not in script
    assert "CHUTE_DEPLOY_VERIFY_SIGNATURE|CHUTE_DEPLOY_SIGNING_FORMAT|" in script
    assert "signature_verification_enabled()" in script
    assert "verify_target_signature()" in script
    assert "-c gpg.format=ssh" in script
    assert "gpg.ssh.allowedSignersFile" in script
    assert "gpg.ssh.revocationFile" in script
    assert 'git -c "gpg.format=$format" verify-commit "$target_sha"' in script
    assert 'git verify-commit "$target_sha"' in script
    assert "signature verification disabled by CHUTE_DEPLOY_VERIFY_SIGNATURE" in script

    deploy_commit = script.index("deploy_commit()")
    verify = script.index('verify_target_signature "$target_sha"', deploy_commit)
    save_last_good = script.index("printf '%s\\n' \"$previous_sha\"", deploy_commit)
    reset = script.index('git reset --hard --quiet "$target_sha"', deploy_commit)
    install = script.index("if install_and_restart; then", deploy_commit)
    verify_previous = script.index('verify_target_signature "$previous_sha"', install)
    rollback_reset = script.index('git reset --hard --quiet "$previous_sha"', install)
    assert verify < save_last_good < reset < install
    assert verify_previous < rollback_reset

    assert "/etc/chute-deploy/allowed-signers" in cd_setup
    assert "/etc/chute-deploy/verify.env" in cd_setup
    assert "CHUTE_DEPLOY_VERIFY_SIGNATURE=1" in cd_setup
    assert "CHUTE_DEPLOY_VERIFY_SIGNATURE=0" in cd_setup
    assert "CHUTE_DEPLOY_SIGNING_FORMAT=ssh" in cd_setup
    assert "git commit -S" in cd_setup
    assert "signed commits from approved keys" in cd_setup
    assert "signed commit verification" in readme


def test_deploy_pull_validates_nginx_before_restart() -> None:
    script = (ROOT / "deploy" / "deploy-pull.sh").read_text()
    install_and_restart = script.index("install_and_restart()")
    nginx_test = script.index("sudo /usr/sbin/nginx -t", install_and_restart)
    restart_chuted = script.index("sudo /usr/bin/systemctl restart chuted", install_and_restart)
    active_check = script.index("/usr/bin/systemctl is-active --quiet chuted", install_and_restart)
    reload_nginx = script.index("sudo /usr/bin/systemctl reload nginx", install_and_restart)

    assert nginx_test < restart_chuted < active_check < reload_nginx


def test_shell_scripts_are_valid_bash() -> None:
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is not installed")

    for script in ("deploy/deploy.sh", "deploy/deploy-pull.sh", "scripts/generate_release_sbom.sh"):
        result = subprocess.run(
            [bash, "-n", str(ROOT / script)],
            check=False,
            text=True,
            capture_output=True,
        )
        assert result.returncode == 0, result.stderr


def test_rendered_nginx_validates_when_nginx_available(tmp_path: Path) -> None:
    nginx = shutil.which("nginx")
    if nginx is None:
        pytest.skip("nginx is not installed")

    cert_dir = tmp_path / "certs" / "example.net"
    cert_dir.mkdir(parents=True)
    certs.generate("example.net", cert_dir / "fullchain.pem", cert_dir / "privkey.pem")
    rendered = _render_nginx("example.net", 18080, str(tmp_path / "certs"))

    nginx_root = tmp_path / "nginx"
    nginx_root.mkdir()
    (nginx_root / "logs").mkdir()
    chute_conf = nginx_root / "chute.conf"
    chute_conf.write_text(rendered)
    nginx_conf = nginx_root / "nginx.conf"
    nginx_conf.write_text(
        f"pid {nginx_root / 'nginx.pid'};\n"
        f"error_log {nginx_root / 'logs' / 'error.log'};\n"
        "events {}\n"
        f"http {{ include {chute_conf}; }}\n"
    )

    result = subprocess.run(
        [nginx, "-t", "-c", str(nginx_conf), "-p", str(nginx_root)],
        check=False,
        text=True,
        capture_output=True,
    )
    assert result.returncode == 0, result.stderr
