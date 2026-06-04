"""CLI entry-point behavior: the real `agent_main` path, which the fatal-token
tests elsewhere bypass by awaiting serve_forever() directly.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import signal
import socket
from pathlib import Path

import pytest

import chute.cli
from chute import certs
from chute.cli import (
    _flow_window_env,
    _int_env,
    _nonnegative_int_env,
    _optional_nonnegative_int_env,
    _optional_positive_float_env,
    _optional_positive_int_env,
    _positive_float_env,
    agent_main,
    server_main,
)
from chute.control import StaticPolicyControlPlane
from chute.events import (
    DEFAULT_JSONL_EVENT_LOG_BACKUPS,
    DEFAULT_JSONL_EVENT_LOG_MAX_BYTES,
    JsonlEventSink,
)
from chute.server import Server


class _DummyAuthorizer:
    async def authenticate(self, request):
        return None


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _write_policy_file(path: Path, token: str = "s3cret") -> None:
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "credentials": [
                    {
                        "credential_id": "cred",
                        "token_sha256": hashlib.sha256(token.encode()).hexdigest(),
                        "account_id": "acct",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    path.chmod(0o600)


async def _quiet_cancel(*tasks: asyncio.Future) -> None:
    for t in tasks:
        t.cancel()
    for t in tasks:
        try:
            await t
        except (asyncio.CancelledError, Exception):
            pass


# -- F21: a wrong token must EXIT non-zero, not hang forever -------------------
async def test_agent_main_wrong_token_exits_nonzero(tmp_path: Path, capsys) -> None:
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    certs.generate("127.0.0.1", cert, key)
    cp = _free_port()
    server = Server(
        token="secret",
        public_host="127.0.0.1",
        public_port=_free_port(),
        control_host="127.0.0.1",
        control_port=cp,
        ssl_context=certs.server_ssl_context(cert, key),
    )
    server_task = asyncio.ensure_future(server.serve())
    await asyncio.sleep(0.3)
    argv = [
        "http",
        str(_free_port()),
        "--server",
        "127.0.0.1",
        "--token",
        "WRONG",  # server closes 4001 -> _FatalError -> exit 1 (must not hang)
        "--control-port",
        str(cp),
        "--server-cert",
        str(cert),
    ]
    try:
        # wait_for trips if agent_main hangs (the pre-fix behavior).
        rc = await asyncio.wait_for(asyncio.to_thread(agent_main, argv), timeout=10)
        assert rc == 1
        _out, err = capsys.readouterr()
        assert "Task exception was never retrieved" not in err
    finally:
        await _quiet_cancel(server_task)


def test_agent_token_file_is_passed_to_tunnel(tmp_path: Path, monkeypatch, capsys) -> None:
    token_file = tmp_path / "token"
    token_file.write_text("from-file\n")
    token_file.chmod(0o600)
    captured: dict[str, object] = {}

    class _FakeTunnel:
        def __init__(self, **kwargs: object) -> None:
            captured.update(kwargs)

        async def serve_forever(self) -> None:
            return None

        async def wait_until_ready(self) -> str:
            return "https://example.test/"

        def request_stop(self) -> None:
            return None

    monkeypatch.setattr(chute.cli, "Tunnel", _FakeTunnel)

    rc = agent_main(
        [
            "8000",
            "--server",
            "relay.example",
            "--token-file",
            str(token_file),
            "--mux-flow-window",
            "524288",
        ]
    )

    out, _err = capsys.readouterr()
    assert rc == 0
    assert captured["token"] == "from-file"
    assert captured["mux_flow_window"] == 524288
    assert "https://example.test/" in out


def test_agent_main_registers_sigterm_for_graceful_stop(monkeypatch, capsys) -> None:
    signal_handlers: dict[signal.Signals, object] = {}

    class _FakeLoop:
        def add_signal_handler(self, sig: signal.Signals, callback: object) -> None:
            signal_handlers[sig] = callback

    class _FakeTunnel:
        def __init__(self, **_kwargs: object) -> None:
            self.stopped = False
            instances.append(self)

        async def serve_forever(self) -> None:
            while not self.stopped:
                await asyncio.sleep(0.01)

        async def wait_until_ready(self) -> str:
            while signal.SIGTERM not in signal_handlers:
                await asyncio.sleep(0)
            callback = signal_handlers[signal.SIGTERM]
            assert callable(callback)
            callback()
            return "https://example.test/"

        def request_stop(self) -> None:
            self.stopped = True

    instances: list[_FakeTunnel] = []
    monkeypatch.setattr(chute.cli.asyncio, "get_running_loop", lambda: _FakeLoop())
    monkeypatch.setattr(chute.cli, "Tunnel", _FakeTunnel)

    rc = agent_main(["8000", "--server", "relay.example", "--token", "secret"])

    out, _err = capsys.readouterr()
    assert rc == 0
    assert signal.SIGINT in signal_handlers
    assert signal.SIGTERM in signal_handlers
    assert instances and instances[0].stopped
    assert "https://example.test/" in out


def test_agent_token_file_rejects_permissive_mode(tmp_path: Path, monkeypatch) -> None:
    token_file = tmp_path / "token"
    token_file.write_text("secret\n")
    token_file.chmod(0o644)

    with pytest.raises(SystemExit):
        agent_main(["8000", "--server", "relay.example", "--token-file", str(token_file)])


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink behavior only")
def test_agent_token_file_rejects_symlink(tmp_path: Path) -> None:
    target = tmp_path / "target-token"
    link = tmp_path / "token"
    target.write_text("secret\n")
    target.chmod(0o600)
    link.symlink_to(target)

    with pytest.raises(SystemExit):
        agent_main(["8000", "--server", "relay.example", "--token-file", str(link)])


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode bits only")
def test_agent_token_file_rejects_world_writable_parent(tmp_path: Path) -> None:
    parent = tmp_path / "public"
    parent.mkdir()
    parent.chmod(0o777)
    token_file = parent / "token"
    token_file.write_text("secret\n")
    token_file.chmod(0o600)

    with pytest.raises(SystemExit):
        agent_main(["8000", "--server", "relay.example", "--token-file", str(token_file)])


def test_agent_rejects_ambiguous_token_sources(tmp_path: Path) -> None:
    token_file = tmp_path / "token"
    token_file.write_text("secret\n")
    token_file.chmod(0o600)

    with pytest.raises(SystemExit):
        agent_main(
            [
                "8000",
                "--server",
                "relay.example",
                "--token",
                "inline",
                "--token-file",
                str(token_file),
            ]
        )


# -- F46: _int_env -- blank/unset falls back; non-numeric exits cleanly --------
def test_int_env_unset_and_blank_use_default(monkeypatch) -> None:
    monkeypatch.delenv("CHUTE_X_PORT", raising=False)
    assert _int_env("CHUTE_X_PORT", 8000) == 8000
    monkeypatch.setenv("CHUTE_X_PORT", "   ")
    assert _int_env("CHUTE_X_PORT", 8000) == 8000  # blank == unset, not an error
    monkeypatch.setenv("CHUTE_X_PORT", "9001")
    assert _int_env("CHUTE_X_PORT", 8000) == 9001


def test_int_env_non_numeric_exits_cleanly(monkeypatch) -> None:
    monkeypatch.setenv("CHUTE_X_PORT", "not-a-number")
    with pytest.raises(SystemExit):
        _int_env("CHUTE_X_PORT", 8000)


def test_optional_positive_int_env_supports_off_switch(monkeypatch) -> None:
    monkeypatch.delenv("CHUTE_MAX_VISITORS_PER_IP", raising=False)
    assert _optional_positive_int_env("CHUTE_MAX_VISITORS_PER_IP", 64) == 64
    monkeypatch.setenv("CHUTE_MAX_VISITORS_PER_IP", "128")
    assert _optional_positive_int_env("CHUTE_MAX_VISITORS_PER_IP", 64) == 128
    for value in ("0", "off", "none", "false", "unlimited"):
        monkeypatch.setenv("CHUTE_MAX_VISITORS_PER_IP", value)
        assert _optional_positive_int_env("CHUTE_MAX_VISITORS_PER_IP", 64) is None


def test_optional_positive_int_env_rejects_bad_values(monkeypatch) -> None:
    for value in ("not-a-number", "-1"):
        monkeypatch.setenv("CHUTE_MAX_VISITORS_PER_IP", value)
        with pytest.raises(SystemExit):
            _optional_positive_int_env("CHUTE_MAX_VISITORS_PER_IP", 64)


def test_flow_window_env_defaults_and_rejects_bad_values(monkeypatch) -> None:
    monkeypatch.delenv("CHUTE_MUX_FLOW_WINDOW", raising=False)
    assert _flow_window_env("CHUTE_MUX_FLOW_WINDOW") == chute.cli._FLOW_WINDOW
    monkeypatch.setenv("CHUTE_MUX_FLOW_WINDOW", "1048576")
    assert _flow_window_env("CHUTE_MUX_FLOW_WINDOW") == 1048576
    for value in ("0", "true", str(16 * 1024 * 1024 + 1)):
        monkeypatch.setenv("CHUTE_MUX_FLOW_WINDOW", value)
        with pytest.raises(SystemExit):
            _flow_window_env("CHUTE_MUX_FLOW_WINDOW")


def test_nonnegative_int_env_supports_zero_and_rejects_negative(monkeypatch) -> None:
    monkeypatch.delenv("CHUTE_MAX_CONTROL_CONNS", raising=False)
    assert _nonnegative_int_env("CHUTE_MAX_CONTROL_CONNS", 256) == 256
    monkeypatch.setenv("CHUTE_MAX_CONTROL_CONNS", "0")
    assert _nonnegative_int_env("CHUTE_MAX_CONTROL_CONNS", 256) == 0
    monkeypatch.setenv("CHUTE_MAX_CONTROL_CONNS", "12")
    assert _nonnegative_int_env("CHUTE_MAX_CONTROL_CONNS", 256) == 12
    for value in ("not-a-number", "-1"):
        monkeypatch.setenv("CHUTE_MAX_CONTROL_CONNS", value)
        with pytest.raises(SystemExit):
            _nonnegative_int_env("CHUTE_MAX_CONTROL_CONNS", 256)


def test_optional_nonnegative_int_env_defaults_and_supports_zero(monkeypatch) -> None:
    monkeypatch.delenv("CHUTE_MAX_AUTH_CONNS", raising=False)
    assert _optional_nonnegative_int_env("CHUTE_MAX_AUTH_CONNS") is None
    for value in ("", "none", "default"):
        monkeypatch.setenv("CHUTE_MAX_AUTH_CONNS", value)
        assert _optional_nonnegative_int_env("CHUTE_MAX_AUTH_CONNS") is None
    monkeypatch.setenv("CHUTE_MAX_AUTH_CONNS", "0")
    assert _optional_nonnegative_int_env("CHUTE_MAX_AUTH_CONNS") == 0
    monkeypatch.setenv("CHUTE_MAX_AUTH_CONNS", "4")
    assert _optional_nonnegative_int_env("CHUTE_MAX_AUTH_CONNS") == 4
    for value in ("not-a-number", "-1"):
        monkeypatch.setenv("CHUTE_MAX_AUTH_CONNS", value)
        with pytest.raises(SystemExit):
            _optional_nonnegative_int_env("CHUTE_MAX_AUTH_CONNS")


def test_positive_float_env_rejects_zero_negative_and_nonfinite(monkeypatch) -> None:
    monkeypatch.delenv("CHUTE_HELLO_TIMEOUT", raising=False)
    assert _positive_float_env("CHUTE_HELLO_TIMEOUT", 5.0) == 5.0
    monkeypatch.setenv("CHUTE_HELLO_TIMEOUT", "0.25")
    assert _positive_float_env("CHUTE_HELLO_TIMEOUT", 5.0) == 0.25
    for value in ("0", "-1", "nan", "inf", "not-a-number"):
        monkeypatch.setenv("CHUTE_HELLO_TIMEOUT", value)
        with pytest.raises(SystemExit):
            _positive_float_env("CHUTE_HELLO_TIMEOUT", 5.0)


def test_optional_positive_float_env_accepts_disable_tokens(monkeypatch) -> None:
    monkeypatch.delenv("CHUTE_RELAY_IDLE_TIMEOUT", raising=False)
    assert _optional_positive_float_env("CHUTE_RELAY_IDLE_TIMEOUT") is None
    assert _optional_positive_float_env("CHUTE_RELAY_IDLE_TIMEOUT", 30.0) == 30.0
    monkeypatch.setenv("CHUTE_RELAY_IDLE_TIMEOUT", "12.5")
    assert _optional_positive_float_env("CHUTE_RELAY_IDLE_TIMEOUT") == 12.5
    for value in ("0", "none", "off", "false", "unlimited"):
        monkeypatch.setenv("CHUTE_RELAY_IDLE_TIMEOUT", value)
        assert _optional_positive_float_env("CHUTE_RELAY_IDLE_TIMEOUT", 30.0) is None
    for value in ("-1", "nan", "inf", "not-a-number"):
        monkeypatch.setenv("CHUTE_RELAY_IDLE_TIMEOUT", value)
        with pytest.raises(SystemExit):
            _optional_positive_float_env("CHUTE_RELAY_IDLE_TIMEOUT")


def test_agent_bad_local_port_env_exits_cleanly(monkeypatch) -> None:
    # The bad value must surface as a SystemExit while argparse builds, not a raw
    # ValueError traceback from int("not-a-number").
    monkeypatch.setenv("CHUTE_LOCAL_PORT", "not-a-number")
    with pytest.raises(SystemExit):
        agent_main(["--server", "x", "--token", "y"])


def test_agent_bad_subdomain_exits_cleanly() -> None:
    with pytest.raises(SystemExit):
        agent_main(["http", "8000", "--server", "x", "--token", "y", "--subdomain", "bad_label"])


def test_server_bad_public_port_env_exits_cleanly(monkeypatch) -> None:
    monkeypatch.setenv("CHUTE_PUBLIC_PORT", "eighty")
    with pytest.raises(SystemExit):
        server_main(["run", "--token", "t"])


def test_server_utility_subcommands_ignore_bad_run_env(monkeypatch, capsys) -> None:
    monkeypatch.setenv("CHUTE_PUBLIC_PORT", "eighty")

    assert server_main(["gen-token"]) == 0

    out, _err = capsys.readouterr()
    assert out.strip()


def test_server_gen_token_writes_private_token_file(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.setenv("CHUTE_PUBLIC_PORT", "eighty")
    token_file = tmp_path / "token"

    assert server_main(["gen-token", "--token-file", str(token_file)]) == 0

    out, err = capsys.readouterr()
    assert err == ""
    assert "wrote token file:" in out
    token = token_file.read_text(encoding="utf-8").strip()
    assert token
    assert token not in out
    if os.name != "nt":
        assert token_file.stat().st_mode & 0o077 == 0


def test_server_gen_token_rejects_existing_token_file(tmp_path: Path, capsys) -> None:
    token_file = tmp_path / "token"
    token_file.write_text("existing\n")
    token_file.chmod(0o600)

    assert server_main(["gen-token", "--token-file", str(token_file)]) == 2

    out, err = capsys.readouterr()
    assert out == ""
    assert "already exists" in err
    assert token_file.read_text(encoding="utf-8") == "existing\n"


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink behavior only")
def test_server_gen_token_rejects_symlink_token_file(tmp_path: Path, capsys) -> None:
    target = tmp_path / "target-token"
    link = tmp_path / "token"
    target.write_text("existing\n")
    target.chmod(0o600)
    link.symlink_to(target)

    assert server_main(["gen-token", "--token-file", str(link)]) == 2

    out, err = capsys.readouterr()
    assert out == ""
    assert "already exists" in err or "symlink" in err
    assert target.read_text(encoding="utf-8") == "existing\n"


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode bits only")
def test_server_gen_token_rejects_world_writable_parent(tmp_path: Path, capsys) -> None:
    parent = tmp_path / "public"
    parent.mkdir()
    parent.chmod(0o777)
    token_file = parent / "token"

    assert server_main(["gen-token", "--token-file", str(token_file)]) == 2

    out, err = capsys.readouterr()
    assert out == ""
    assert "world-writable" in err
    assert not token_file.exists()


def test_server_hash_token_reads_private_token_file(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.setenv("CHUTE_PUBLIC_PORT", "eighty")
    token_file = tmp_path / "token"
    token_file.write_text("secret-token\n")
    token_file.chmod(0o600)

    assert server_main(["hash-token", "--token-file", str(token_file)]) == 0

    out = capsys.readouterr().out.strip()
    assert out == f"sha256:{hashlib.sha256(b'secret-token').hexdigest()}"


def test_server_hash_token_rejects_permissive_token_file(tmp_path: Path, capsys) -> None:
    token_file = tmp_path / "token"
    token_file.write_text("secret-token\n")
    token_file.chmod(0o644)

    assert server_main(["hash-token", "--token-file", str(token_file)]) == 2

    out, err = capsys.readouterr()
    assert out == ""
    assert "chmod 600" in err
    assert "secret-token" not in err


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink behavior only")
def test_server_hash_token_rejects_symlink_token_file(tmp_path: Path, capsys) -> None:
    target = tmp_path / "target-token"
    link = tmp_path / "token"
    target.write_text("secret-token\n")
    target.chmod(0o600)
    link.symlink_to(target)

    assert server_main(["hash-token", "--token-file", str(link)]) == 2

    out, err = capsys.readouterr()
    assert out == ""
    assert "symlink" in err
    assert "secret-token" not in err


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode bits only")
def test_server_hash_token_rejects_world_writable_parent(tmp_path: Path, capsys) -> None:
    parent = tmp_path / "public"
    parent.mkdir()
    parent.chmod(0o777)
    token_file = parent / "token"
    token_file.write_text("secret-token\n")
    token_file.chmod(0o600)

    assert server_main(["hash-token", "--token-file", str(token_file)]) == 2

    out, err = capsys.readouterr()
    assert out == ""
    assert "world-writable" in err
    assert "secret-token" not in err


def test_server_validate_policy_accepts_valid_private_policy(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    monkeypatch.setenv("CHUTE_PUBLIC_PORT", "eighty")
    policy_file = tmp_path / "policy.json"
    _write_policy_file(policy_file)

    assert server_main(["validate-policy", "--policy-file", str(policy_file)]) == 0

    out, err = capsys.readouterr()
    assert err == ""
    assert "policy file ok:" in out
    assert str(policy_file) in out


def test_server_validate_policy_uses_env_policy_file(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    policy_file = tmp_path / "policy.json"
    _write_policy_file(policy_file)
    monkeypatch.setenv("CHUTE_POLICY_FILE", str(policy_file))

    assert server_main(["validate-policy"]) == 0

    out, err = capsys.readouterr()
    assert err == ""
    assert "policy file ok:" in out


def test_server_validate_policy_requires_policy_file(capsys) -> None:
    assert server_main(["validate-policy"]) == 2

    out, err = capsys.readouterr()
    assert out == ""
    assert "--policy-file is required" in err


def test_server_validate_policy_rejects_invalid_policy_file(
    tmp_path: Path,
    capsys,
) -> None:
    policy_file = tmp_path / "policy.json"
    policy_file.write_text('{"schema_version": 1, "token": "secret"}', encoding="utf-8")
    policy_file.chmod(0o600)

    assert server_main(["validate-policy", "--policy-file", str(policy_file)]) == 2

    out, err = capsys.readouterr()
    assert out == ""
    assert "unknown keys" in err
    assert "secret" not in err


def test_server_run_help_ignores_bad_run_env(monkeypatch, capsys) -> None:
    monkeypatch.setenv("CHUTE_PUBLIC_PORT", "eighty")

    with pytest.raises(SystemExit) as excinfo:
        server_main(["run", "--help"])

    assert excinfo.value.code == 0
    out, _err = capsys.readouterr()
    assert "--public-port" in out


def test_server_cli_arg_overrides_bad_env_default(tmp_path: Path, monkeypatch) -> None:
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    cert.write_text("cert")
    key.write_text("key")
    captured: dict[str, object] = {}

    class _FakeServer:
        def __init__(self, **kwargs: object) -> None:
            captured.update(kwargs)

        async def serve(self) -> None:
            return None

    monkeypatch.setenv("CHUTE_PUBLIC_PORT", "eighty")
    monkeypatch.setattr(chute.cli.certs, "server_ssl_context", lambda *_args: object())
    monkeypatch.setattr(chute.cli.certs, "warn_if_control_cert_expiring", lambda *_args: None)
    monkeypatch.setattr(chute.cli, "Server", _FakeServer)

    rc = server_main(
        [
            "run",
            "--token",
            "t",
            "--cert",
            str(cert),
            "--key",
            str(key),
            "--public-port",
            "8080",
        ]
    )

    assert rc == 0
    assert captured["public_port"] == 8080


def test_server_no_subcommand_defaults_to_run(tmp_path: Path, monkeypatch) -> None:
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    cert.write_text("cert")
    key.write_text("key")
    captured: dict[str, object] = {}

    class _FakeServer:
        def __init__(self, **kwargs: object) -> None:
            captured.update(kwargs)

        async def serve(self) -> None:
            return None

    monkeypatch.setattr(chute.cli.certs, "server_ssl_context", lambda *_args: object())
    monkeypatch.setattr(chute.cli.certs, "warn_if_control_cert_expiring", lambda *_args: None)
    monkeypatch.setattr(chute.cli, "Server", _FakeServer)

    rc = server_main(
        [
            "--token",
            "t",
            "--cert",
            str(cert),
            "--key",
            str(key),
            "--public-port",
            "8080",
        ]
    )

    assert rc == 0
    assert captured["public_port"] == 8080


def test_server_run_requires_control_cert_and_key(tmp_path: Path) -> None:
    rc = server_main(
        [
            "run",
            "--token",
            "t",
            "--cert",
            str(tmp_path / "missing-cert.pem"),
            "--key",
            str(tmp_path / "missing-key.pem"),
        ]
    )
    assert rc == 2


def test_server_run_rejects_invalid_control_cert_and_key(tmp_path: Path, caplog) -> None:
    cert, key = tmp_path / "bad-cert.pem", tmp_path / "bad-key.pem"
    cert.write_text("not a certificate")
    key.write_text("not a key")
    caplog.set_level(logging.ERROR, logger="chute")

    rc = server_main(["run", "--token", "t", "--cert", str(cert), "--key", str(key)])

    assert rc == 2
    assert "control TLS cert/key invalid" in caplog.text


def test_server_run_rejects_partial_public_tls_config(tmp_path: Path, caplog) -> None:
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    certs.generate("127.0.0.1", cert, key)
    caplog.set_level(logging.ERROR, logger="chute")

    rc = server_main(
        [
            "run",
            "--token",
            "t",
            "--cert",
            str(cert),
            "--key",
            str(key),
            "--tls-cert",
            str(tmp_path / "edge-cert.pem"),
        ]
    )

    assert rc == 2
    assert "set both --tls-cert and --tls-key" in caplog.text


def test_server_run_rejects_missing_explicit_public_tls_files(tmp_path: Path, caplog) -> None:
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    certs.generate("127.0.0.1", cert, key)
    caplog.set_level(logging.ERROR, logger="chute")

    rc = server_main(
        [
            "run",
            "--token",
            "t",
            "--cert",
            str(cert),
            "--key",
            str(key),
            "--tls-cert",
            str(tmp_path / "missing-edge-cert.pem"),
            "--tls-key",
            str(tmp_path / "missing-edge-key.pem"),
            "--domain",
            "edge.example",
        ]
    )

    assert rc == 2
    assert "public TLS cert/key not found" in caplog.text


def test_server_run_rejects_invalid_public_tls_files(tmp_path: Path, caplog) -> None:
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    tls_cert, tls_key = tmp_path / "edge-cert.pem", tmp_path / "edge-key.pem"
    certs.generate("127.0.0.1", cert, key)
    tls_cert.write_text("not a certificate")
    tls_key.write_text("not a key")
    caplog.set_level(logging.ERROR, logger="chute")

    rc = server_main(
        [
            "run",
            "--token",
            "t",
            "--cert",
            str(cert),
            "--key",
            str(key),
            "--tls-cert",
            str(tls_cert),
            "--tls-key",
            str(tls_key),
            "--domain",
            "edge.example",
        ]
    )

    assert rc == 2
    assert "server configuration invalid" in caplog.text


def test_server_resource_limit_args_are_passed_to_server(tmp_path: Path, monkeypatch) -> None:
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    cert.write_text("cert")
    key.write_text("key")
    captured: dict[str, object] = {}
    expiry_checks: list[Path] = []

    class _FakeServer:
        def __init__(self, **kwargs: object) -> None:
            captured.update(kwargs)

        async def serve(self) -> None:
            return None

    monkeypatch.setattr(chute.cli.certs, "server_ssl_context", lambda *_args: object())
    monkeypatch.setattr(
        chute.cli.certs, "warn_if_control_cert_expiring", lambda path: expiry_checks.append(path)
    )
    monkeypatch.setattr(chute.cli, "Server", _FakeServer)

    rc = server_main(
        [
            "run",
            "--token",
            "t",
            "--cert",
            str(cert),
            "--key",
            str(key),
            "--max-control-conns",
            "3",
            "--max-auth-conns",
            "0",
            "--max-agents",
            "4",
            "--max-visitors",
            "5",
            "--max-visitors-per-ip",
            "7",
            "--hello-timeout",
            "0.25",
            "--auth-timeout",
            "0.75",
            "--relay-idle-timeout",
            "12.5",
            "--mux-flow-window",
            "1048576",
            "--metrics-host",
            "127.0.0.1",
            "--metrics-port",
            "9100",
        ]
    )

    assert rc == 0
    assert expiry_checks == [cert]
    assert captured["max_control_conns"] == 3
    assert captured["max_auth_conns"] == 0
    assert captured["max_agents"] == 4
    assert captured["max_visitors"] == 5
    assert captured["max_visitors_per_ip"] == 7
    assert captured["hello_timeout"] == 0.25
    assert captured["auth_timeout"] == 0.75
    assert captured["relay_idle_timeout"] == 12.5
    assert captured["mux_flow_window"] == 1048576
    assert captured["metrics_host"] == "127.0.0.1"
    assert captured["metrics_port"] == 9100


def test_server_policy_file_builds_static_control_plane_without_shared_token(
    tmp_path: Path,
    monkeypatch,
) -> None:
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    cert.write_text("cert")
    key.write_text("key")
    policy_file = tmp_path / "policy.json"
    _write_policy_file(policy_file)
    captured: dict[str, object] = {}

    class _FakeServer:
        def __init__(self, **kwargs: object) -> None:
            captured.update(kwargs)

        async def serve(self) -> None:
            return None

    monkeypatch.delenv("CHUTE_TOKEN", raising=False)
    monkeypatch.delenv("CHUTE_CONTROL_PLANE", raising=False)
    monkeypatch.delenv("CHUTE_AUTHORIZER", raising=False)
    monkeypatch.setattr(chute.cli.certs, "server_ssl_context", lambda *_args: object())
    monkeypatch.setattr(chute.cli.certs, "warn_if_control_cert_expiring", lambda *_args: None)
    monkeypatch.setattr(chute.cli, "Server", _FakeServer)

    rc = server_main(
        [
            "run",
            "--cert",
            str(cert),
            "--key",
            str(key),
            "--policy-file",
            str(policy_file),
        ]
    )

    assert rc == 0
    assert captured["token"] == ""
    assert isinstance(captured["control_plane"], StaticPolicyControlPlane)
    assert captured["authorizer"] is None


def test_server_authorizer_builds_without_shared_token(
    tmp_path: Path,
    monkeypatch,
) -> None:
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    cert.write_text("cert")
    key.write_text("key")
    captured: dict[str, object] = {}

    class _FakeServer:
        def __init__(self, **kwargs: object) -> None:
            captured.update(kwargs)

        async def serve(self) -> None:
            return None

    monkeypatch.delenv("CHUTE_TOKEN", raising=False)
    monkeypatch.delenv("CHUTE_CONTROL_PLANE", raising=False)
    monkeypatch.setenv("CHUTE_AUTHORIZER", "test_cli:_DummyAuthorizer")
    monkeypatch.setattr(chute.cli.certs, "server_ssl_context", lambda *_args: object())
    monkeypatch.setattr(chute.cli.certs, "warn_if_control_cert_expiring", lambda *_args: None)
    monkeypatch.setattr(chute.cli, "Server", _FakeServer)

    rc = server_main(
        [
            "run",
            "--cert",
            str(cert),
            "--key",
            str(key),
        ]
    )

    assert rc == 0
    assert captured["token"] == ""
    assert captured["control_plane"] is None
    assert isinstance(captured["authorizer"], _DummyAuthorizer)


def test_server_event_log_file_builds_jsonl_event_sink(
    tmp_path: Path,
    monkeypatch,
) -> None:
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    cert.write_text("cert")
    key.write_text("key")
    event_log = tmp_path / "events.jsonl"
    captured: dict[str, object] = {}

    class _FakeServer:
        def __init__(self, **kwargs: object) -> None:
            captured.update(kwargs)

        async def serve(self) -> None:
            return None

    monkeypatch.delenv("CHUTE_EVENT_SINK", raising=False)
    monkeypatch.setattr(chute.cli.certs, "server_ssl_context", lambda *_args: object())
    monkeypatch.setattr(chute.cli.certs, "warn_if_control_cert_expiring", lambda *_args: None)
    monkeypatch.setattr(chute.cli, "Server", _FakeServer)

    rc = server_main(
        [
            "run",
            "--token",
            "t",
            "--cert",
            str(cert),
            "--key",
            str(key),
            "--event-log-file",
            str(event_log),
        ]
    )

    assert rc == 0
    assert isinstance(captured["event_sink"], JsonlEventSink)
    sink = captured["event_sink"]
    assert isinstance(sink, JsonlEventSink)
    assert sink.max_bytes == DEFAULT_JSONL_EVENT_LOG_MAX_BYTES
    assert sink.backup_count == DEFAULT_JSONL_EVENT_LOG_BACKUPS
    if os.name != "nt":
        assert event_log.stat().st_mode & 0o077 == 0


def test_server_event_log_rotation_args_are_passed_to_sink(
    tmp_path: Path,
    monkeypatch,
) -> None:
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    cert.write_text("cert")
    key.write_text("key")
    event_log = tmp_path / "events.jsonl"
    captured: dict[str, object] = {}

    class _FakeServer:
        def __init__(self, **kwargs: object) -> None:
            captured.update(kwargs)

        async def serve(self) -> None:
            return None

    monkeypatch.delenv("CHUTE_EVENT_SINK", raising=False)
    monkeypatch.setattr(chute.cli.certs, "server_ssl_context", lambda *_args: object())
    monkeypatch.setattr(chute.cli.certs, "warn_if_control_cert_expiring", lambda *_args: None)
    monkeypatch.setattr(chute.cli, "Server", _FakeServer)

    rc = server_main(
        [
            "run",
            "--token",
            "t",
            "--cert",
            str(cert),
            "--key",
            str(key),
            "--event-log-file",
            str(event_log),
            "--event-log-max-bytes",
            "2048",
            "--event-log-backups",
            "3",
        ]
    )

    assert rc == 0
    sink = captured["event_sink"]
    assert isinstance(sink, JsonlEventSink)
    assert sink.max_bytes == 2048
    assert sink.backup_count == 3


def test_server_event_log_rotation_can_be_disabled(
    tmp_path: Path,
    monkeypatch,
) -> None:
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    cert.write_text("cert")
    key.write_text("key")
    event_log = tmp_path / "events.jsonl"
    captured: dict[str, object] = {}

    class _FakeServer:
        def __init__(self, **kwargs: object) -> None:
            captured.update(kwargs)

        async def serve(self) -> None:
            return None

    monkeypatch.delenv("CHUTE_EVENT_SINK", raising=False)
    monkeypatch.setattr(chute.cli.certs, "server_ssl_context", lambda *_args: object())
    monkeypatch.setattr(chute.cli.certs, "warn_if_control_cert_expiring", lambda *_args: None)
    monkeypatch.setattr(chute.cli, "Server", _FakeServer)

    rc = server_main(
        [
            "run",
            "--token",
            "t",
            "--cert",
            str(cert),
            "--key",
            str(key),
            "--event-log-file",
            str(event_log),
            "--event-log-max-bytes",
            "off",
        ]
    )

    assert rc == 0
    sink = captured["event_sink"]
    assert isinstance(sink, JsonlEventSink)
    assert sink.max_bytes is None


def test_server_resource_limit_env_is_passed_to_server(tmp_path: Path, monkeypatch) -> None:
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    cert.write_text("cert")
    key.write_text("key")
    captured: dict[str, object] = {}

    class _FakeServer:
        def __init__(self, **kwargs: object) -> None:
            captured.update(kwargs)

        async def serve(self) -> None:
            return None

    monkeypatch.setenv("CHUTE_MAX_CONTROL_CONNS", "11")
    monkeypatch.setenv("CHUTE_MAX_AUTH_CONNS", "default")
    monkeypatch.setenv("CHUTE_MAX_AGENTS", "12")
    monkeypatch.setenv("CHUTE_MAX_VISITORS", "13")
    monkeypatch.setenv("CHUTE_HELLO_TIMEOUT", "1.25")
    monkeypatch.setenv("CHUTE_AUTH_TIMEOUT", "2.5")
    monkeypatch.setenv("CHUTE_RELAY_IDLE_TIMEOUT", "off")
    monkeypatch.setenv("CHUTE_MUX_FLOW_WINDOW", "2097152")
    monkeypatch.setenv("CHUTE_METRICS_HOST", "localhost")
    monkeypatch.setenv("CHUTE_METRICS_PORT", "9101")
    monkeypatch.setattr(chute.cli.certs, "server_ssl_context", lambda *_args: object())
    monkeypatch.setattr(chute.cli.certs, "warn_if_control_cert_expiring", lambda *_args: None)
    monkeypatch.setattr(chute.cli, "Server", _FakeServer)

    rc = server_main(
        [
            "run",
            "--token",
            "t",
            "--cert",
            str(cert),
            "--key",
            str(key),
        ]
    )

    assert rc == 0
    assert captured["max_control_conns"] == 11
    assert captured["max_auth_conns"] is None
    assert captured["max_agents"] == 12
    assert captured["max_visitors"] == 13
    assert captured["hello_timeout"] == 1.25
    assert captured["auth_timeout"] == 2.5
    assert captured["relay_idle_timeout"] is None
    assert captured["mux_flow_window"] == 2097152
    assert captured["metrics_host"] == "localhost"
    assert captured["metrics_port"] == 9101
