"""CLI entry-point behavior: the real `agent_main` path, which the fatal-token
tests elsewhere bypass by awaiting serve_forever() directly.
"""

from __future__ import annotations

import asyncio
import socket
from pathlib import Path

import pytest

from chute import certs
from chute.cli import _int_env, agent_main, server_main
from chute.server import Server


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


async def _quiet_cancel(*tasks: asyncio.Future) -> None:
    for t in tasks:
        t.cancel()
    for t in tasks:
        try:
            await t
        except (asyncio.CancelledError, Exception):
            pass


# -- F21: a wrong token must EXIT non-zero, not hang forever -------------------
async def test_agent_main_wrong_token_exits_nonzero(tmp_path: Path) -> None:
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
    finally:
        await _quiet_cancel(server_task)


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
