from __future__ import annotations

import asyncio
import contextlib
import importlib.util
import json
import socket
import sys
from pathlib import Path

import pytest

from chute import certs
from chute import mux as chute_mux
from chute.server import Server

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "benchmark_remote_e2e.py"
_ROOT = Path(__file__).resolve().parents[1]
_BASELINE_FLOW_WINDOW = 256 * 1024
sys.path.insert(0, str(_SCRIPT.parent))
_SPEC = importlib.util.spec_from_file_location("benchmark_remote_e2e", _SCRIPT)
assert _SPEC is not None and _SPEC.loader is not None
benchmark_remote_e2e = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = benchmark_remote_e2e
_SPEC.loader.exec_module(benchmark_remote_e2e)


def _free_port() -> int:
    sock = socket.socket()
    try:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])
    finally:
        sock.close()


async def _quiet_cancel(*tasks: asyncio.Future) -> None:
    for task in tasks:
        task.cancel()
    for task in tasks:
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await task


def test_remote_e2e_benchmark_resolves_token_file_securely(tmp_path: Path) -> None:
    token_file = tmp_path / "token"
    token_file.write_text("from-file\n")
    token_file.chmod(0o600)

    assert (
        benchmark_remote_e2e._resolve_token(token=None, token_file=str(token_file)) == "from-file"
    )
    assert benchmark_remote_e2e._resolve_token(token="inline", token_file=None) == "inline"
    with pytest.raises(ValueError, match="only one"):
        benchmark_remote_e2e._resolve_token(token="inline", token_file=str(token_file))
    with pytest.raises(ValueError, match="CHUTE_TOKEN"):
        benchmark_remote_e2e._resolve_token(token=None, token_file=None)


def test_remote_e2e_benchmark_public_url_target_validation() -> None:
    assert benchmark_remote_e2e._public_target("https://example.test/base/", "/payload") == (
        "https",
        "example.test",
        None,
        "/base/payload",
    )
    assert benchmark_remote_e2e._public_target("http://example.test:8080", "/upload") == (
        "http",
        "example.test",
        8080,
        "/upload",
    )
    with pytest.raises(ValueError, match="http or https"):
        benchmark_remote_e2e._public_target("ftp://example.test/", "/payload")
    with pytest.raises(ValueError, match="query"):
        benchmark_remote_e2e._public_target("https://example.test/?x=1", "/payload")


def test_remote_e2e_benchmark_writes_self_describing_report_without_secrets(
    tmp_path: Path,
) -> None:
    sample = benchmark_remote_e2e.E2ESample(
        direction="download",
        window_bytes=1024,
        negotiated_window_bytes=1024,
        payload_bytes=4096,
        chunk_bytes=512,
        elapsed_s=1,
        throughput_mib_s=4,
        transferred_bytes=4096,
    )
    result = benchmark_remote_e2e.aggregate_samples((sample,))
    report = benchmark_remote_e2e.build_report(
        results=[result],
        server="relay.example",
        control_port=7000,
        scheme="https",
        subdomain="bench",
        windows=[1024],
        directions=["download"],
        payload_bytes=4096,
        chunk_bytes=512,
        runs=1,
        warmup_runs=0,
        request_timeout=10,
        ready_timeout=5,
        insecure_public_tls=False,
    )
    output = tmp_path / "reports" / "remote.json"

    benchmark_remote_e2e.write_report(output, report)

    data = json.loads(output.read_text())
    assert data["schema_version"] == 1
    assert data["benchmark"] == "chute_remote_e2e"
    assert data["server"] == "relay.example"
    assert data["chute_protocol_version"] > 0
    assert data["results"][0]["direction"] == "download"
    serialized = output.read_text()
    assert "token" not in serialized.lower()
    assert "secret" not in serialized.lower()


async def test_remote_e2e_benchmark_tiny_real_tunnel_run_against_local_relay(
    tmp_path: Path,
) -> None:
    cert, key = tmp_path / "control-cert.pem", tmp_path / "control-key.pem"
    certs.generate("127.0.0.1", cert, key)
    public_port = _free_port()
    control_port = _free_port()
    server = Server(
        token="secret",
        public_host="127.0.0.1",
        public_port=public_port,
        control_host="127.0.0.1",
        control_port=control_port,
        public_url=f"http://127.0.0.1:{public_port}/",
        ssl_context=certs.server_ssl_context(cert, key),
        mux_flow_window=8192,
    )
    server_task = asyncio.create_task(server.serve())
    await asyncio.sleep(0.2)
    try:
        results = await benchmark_remote_e2e.run_matrix(
            server="127.0.0.1",
            token="secret",
            control_port=control_port,
            server_cert=str(cert),
            scheme="http",
            subdomain=None,
            windows=[8192],
            directions=["download", "upload"],
            payload_bytes=16 * 1024,
            chunk_bytes=1024,
            runs=1,
            warmup_runs=0,
            request_timeout=10,
            ready_timeout=5,
            insecure_public_tls=False,
        )
    finally:
        await _quiet_cancel(server_task)

    assert [result.direction for result in results] == ["download", "upload"]
    for result in results:
        assert result.runs == 1
        assert result.window_bytes == 8192
        assert result.negotiated_window_bytes == 8192
        assert result.transferred_bytes == 16 * 1024
        assert result.throughput_mib_s_median > 0


async def test_remote_e2e_benchmark_rejects_invalid_matrix_args() -> None:
    kwargs = {
        "server": "relay.example",
        "token": "secret",
        "control_port": 7000,
        "server_cert": None,
        "scheme": "https",
        "subdomain": None,
        "windows": [1024],
        "directions": ["download"],
        "payload_bytes": 1024,
        "chunk_bytes": 1024,
        "runs": 1,
        "warmup_runs": 0,
        "request_timeout": 10,
        "ready_timeout": 5,
        "insecure_public_tls": False,
    }
    with pytest.raises(ValueError, match="scheme"):
        await benchmark_remote_e2e.run_matrix(**{**kwargs, "scheme": "ftp"})
    with pytest.raises(ValueError, match="runs"):
        await benchmark_remote_e2e.run_matrix(**{**kwargs, "runs": 0})
    with pytest.raises(ValueError, match="request_timeout"):
        await benchmark_remote_e2e.run_matrix(**{**kwargs, "request_timeout": 0})


def test_performance_doc_mentions_remote_benchmark_secret_and_scope() -> None:
    text = (_ROOT / "docs" / "PERFORMANCE.md").read_text()

    assert "scripts/benchmark_remote_e2e.py" in text
    assert "CHUTE_TOKEN_FILE" in text
    assert "--output-json" in text
    assert "token values and token-file paths are intentionally omitted" in text
    assert "real VPS/nginx/TLS" in text
    assert "remote end-to-end evidence" in text


def _remote_reports_covering(window_bytes: int) -> list[Path]:
    reports: list[Path] = []
    for path in sorted((_ROOT / "docs" / "perf").glob("remote-*.json")):
        try:
            report = json.loads(path.read_text())
        except json.JSONDecodeError:
            continue
        if report.get("schema_version") != 1:
            continue
        if report.get("benchmark") != "chute_remote_e2e":
            continue
        if not isinstance(report.get("chute_protocol_version"), int):
            continue
        results = report.get("results")
        if not isinstance(results, list) or not results:
            continue
        for result in results:
            if not isinstance(result, dict):
                continue
            if result.get("window_bytes") == window_bytes:
                samples = result.get("samples")
                if isinstance(samples, list) and samples:
                    reports.append(path)
                    break
    return reports


def test_flow_window_default_change_requires_remote_report_artifact() -> None:
    perf_doc = (_ROOT / "docs" / "PERFORMANCE.md").read_text()
    perf_report_readme = (_ROOT / "docs" / "perf" / "README.md").read_text()

    assert "remote end-to-end evidence" in perf_doc
    assert "--output-json docs/perf/" in perf_doc
    assert "256 KiB" in perf_report_readme

    if chute_mux._FLOW_WINDOW == _BASELINE_FLOW_WINDOW:
        assert "256 KiB default remains a conservative baseline" in perf_doc
        return

    reports = _remote_reports_covering(chute_mux._FLOW_WINDOW)
    assert reports, (
        "Changing chute.mux._FLOW_WINDOW away from 256 KiB requires a saved "
        "docs/perf/remote-*.json report from scripts/benchmark_remote_e2e.py "
        "that includes the candidate default window."
    )
