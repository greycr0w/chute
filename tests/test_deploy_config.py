from __future__ import annotations

import re
import shutil
import subprocess
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


def test_nginx_template_keeps_http_and_https_without_forced_redirect() -> None:
    rendered = _render_nginx("example.net", 18080, "/srv/acme/certs")

    assert re.search(r"listen\s+80;", rendered)
    assert re.search(r"listen\s+443\s+ssl;", rendered)
    assert "return 301" not in rendered
    assert "rewrite " not in rendered


def test_nginx_template_preserves_one_request_per_upstream_connection() -> None:
    rendered = _render_nginx("example.net", 18080, "/srv/acme/certs")
    active_config = _without_comments(rendered)

    assert re.search(r"\bupstream\b", active_config) is None
    assert re.search(r"\bkeepalive\b", active_config) is None
    assert active_config.count("proxy_pass http://127.0.0.1:18080;") == 2
    assert active_config.count("proxy_set_header Connection $chute_connection_upgrade;") == 2
    assert re.search(
        r"map\s+\$http_upgrade\s+\$chute_connection_upgrade\s*\{[^}]*''\s+close;",
        active_config,
        flags=re.S,
    )


def test_deploy_commits_daemon_env_only_after_nginx_validates() -> None:
    script = (ROOT / "deploy" / "deploy.sh").read_text()

    assert "chute.env.new" in script
    assert "CHUTE_BASE_DOMAIN=$BASE_DOMAIN" in script
    assert "CHUTE_PUBLIC_PORT=$PUBLIC_PORT" in script
    assert "CHUTE_UPSTREAM_TLS=1" in script
    assert "if [ ! -f /etc/chute/chute.env ]; then" not in script

    render_nginx = script.index('/opt/chute/src/deploy/nginx-chute.conf > "$NGINX_CONF"')
    nginx_test = script.index("if nginx -t; then")
    commit_env = script.index("mv /etc/chute/chute.env.new /etc/chute/chute.env")
    restart_chuted = script.index("systemctl restart chuted")
    reload_nginx = script.index("systemctl reload nginx")
    assert render_nginx < nginx_test < commit_env < restart_chuted < reload_nginx


def test_deploy_installs_stable_forced_command_runner() -> None:
    script = (ROOT / "deploy" / "deploy.sh").read_text()
    cd_setup = (ROOT / "deploy" / "CD-SETUP.md").read_text()

    assert (
        "install -m 0755 -o root -g root /opt/chute/src/deploy/deploy-pull.sh "
        "/usr/local/sbin/chute-deploy-pull"
    ) in script
    assert 'command="/usr/local/sbin/chute-deploy-pull"' in cd_setup
    assert 'command="/opt/chute/src/deploy/deploy-pull.sh"' not in cd_setup


def test_cd_workflow_keeps_production_deploy_simple() -> None:
    workflow = (ROOT / ".github" / "workflows" / "deploy.yml").read_text()

    assert "workflow_dispatch:" not in workflow
    assert "rollback_to:" not in workflow
    assert "DEPLOY_REF" not in workflow
    assert "validate_remote_arg()" not in workflow
    assert "remote_command=(" not in workflow
    assert '"$SSH_USER@$SSH_HOST" deploy' in workflow


def test_deploy_pull_supports_forced_command_rollback() -> None:
    script = (ROOT / "deploy" / "deploy-pull.sh").read_text()

    assert "SSH_ORIGINAL_COMMAND" in script
    assert 'LAST_GOOD="$(git rev-parse --git-path chute-last-good-rev)"' in script
    assert "deploy [ref]" in script
    assert "rollback [last|sha]" in script
    assert "git check-ref-format --allow-onelevel" in script
    assert '"+refs/heads/*:refs/remotes/origin/*"' in script
    assert '"+refs/tags/*:refs/tags/*"' in script
    assert 'deploy_commit "$target_sha" yes' in script
    assert 'deploy_commit "$target_sha" no' in script


def test_deploy_pull_validates_nginx_before_restart() -> None:
    script = (ROOT / "deploy" / "deploy-pull.sh").read_text()
    install_and_restart = script.index("install_and_restart()")
    nginx_test = script.index("sudo /usr/sbin/nginx -t", install_and_restart)
    restart_chuted = script.index("sudo /usr/bin/systemctl restart chuted", install_and_restart)

    assert nginx_test < restart_chuted


def test_deploy_scripts_are_valid_bash() -> None:
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is not installed")

    for script in ("deploy.sh", "deploy-pull.sh"):
        result = subprocess.run(
            [bash, "-n", str(ROOT / "deploy" / script)],
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
