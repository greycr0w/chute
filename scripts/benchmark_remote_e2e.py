#!/usr/bin/env python3
"""Benchmark a deployed chute relay end-to-end.

This starts a local benchmark HTTP app, opens a real Tunnel agent to an existing
relay, waits for the relay-provided public URL, and measures download/upload
requests against that public URL. It is the step after the loopback benchmark:
the public request crosses whatever VPS, nginx, TLS, and network path your
deployment actually uses.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import datetime as _dt
import http.client
import json
import os
import ssl
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.parse import urlsplit

try:
    from benchmark_e2e_loopback import (
        E2EAggregate,
        E2ESample,
        _format_bytes,
        _parse_directions,
        _parse_size,
        _parse_size_list,
        _positive_int,
        _start_local_app,
        aggregate_samples,
    )
except ModuleNotFoundError:  # pragma: no cover - used when imported as scripts.* in tests
    from scripts.benchmark_e2e_loopback import (
        E2EAggregate,
        E2ESample,
        _format_bytes,
        _parse_directions,
        _parse_size,
        _parse_size_list,
        _positive_int,
        _start_local_app,
        aggregate_samples,
    )

from chute import protocol
from chute.cli import _read_secret_file
from chute.client import Tunnel
from chute.mux import _FLOW_WINDOW


@dataclass(frozen=True)
class RemoteBenchmarkReport:
    schema_version: int
    benchmark: str
    generated_at: str
    python_version: str
    chute_protocol_version: int
    server: str
    control_port: int
    scheme: str
    subdomain: str | None
    windows: list[int]
    directions: list[str]
    payload_bytes: int
    chunk_bytes: int
    runs: int
    warmup_runs: int
    request_timeout: float
    ready_timeout: float
    insecure_public_tls: bool
    results: list[E2EAggregate]


def _env(name: str, default: str | None = None) -> str | None:
    value = os.environ.get(name)
    if value is None or not value.strip():
        return default
    return value


def _int_env(name: str, default: int) -> int:
    raw = _env(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        raise SystemExit(f"{name} must be an integer, got {raw!r}") from None


def _float_env(name: str, default: float) -> float:
    raw = _env(name)
    if raw is None:
        return default
    try:
        return float(raw)
    except ValueError:
        raise SystemExit(f"{name} must be a number, got {raw!r}") from None


def _resolve_token(*, token: str | None, token_file: str | None) -> str:
    if token and token_file:
        raise ValueError("set only one of --token/CHUTE_TOKEN or --token-file/CHUTE_TOKEN_FILE")
    if token_file:
        return _read_secret_file(token_file, "--token-file")
    if token:
        return token
    raise ValueError("set --token-file/CHUTE_TOKEN_FILE or CHUTE_TOKEN")


def _public_target(public_url: str, benchmark_path: str) -> tuple[str, str, int | None, str]:
    parsed = urlsplit(public_url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("public URL must use http or https")
    if not parsed.hostname:
        raise ValueError("public URL must include a host")
    if parsed.query or parsed.fragment:
        raise ValueError("public URL must not include query or fragment")
    base_path = parsed.path.rstrip("/")
    target = f"{base_path}{benchmark_path}"
    return parsed.scheme, parsed.hostname, parsed.port, target


def _connection(
    public_url: str,
    benchmark_path: str,
    *,
    timeout: float,
    insecure_public_tls: bool,
) -> tuple[http.client.HTTPConnection, str]:
    scheme, host, port, target = _public_target(public_url, benchmark_path)
    if scheme == "https":
        context = ssl._create_unverified_context() if insecure_public_tls else None
        return (
            http.client.HTTPSConnection(host, port=port, timeout=timeout, context=context),
            target,
        )
    return http.client.HTTPConnection(host, port=port, timeout=timeout), target


def _measure_download(
    public_url: str,
    *,
    payload_bytes: int,
    timeout: float,
    insecure_public_tls: bool,
) -> tuple[float, int]:
    conn, target = _connection(
        public_url,
        "/payload",
        timeout=timeout,
        insecure_public_tls=insecure_public_tls,
    )
    count = 0
    started = time.perf_counter()
    try:
        conn.request("GET", target, headers={"Connection": "close"})
        response = conn.getresponse()
        while True:
            chunk = response.read(64 * 1024)
            if not chunk:
                break
            count += len(chunk)
        elapsed = time.perf_counter() - started
        if response.status != 200:
            raise RuntimeError(f"download returned HTTP {response.status}")
        if count != payload_bytes:
            raise RuntimeError(f"download received {count} of {payload_bytes} bytes")
        return elapsed, count
    finally:
        conn.close()


def _measure_upload(
    public_url: str,
    *,
    payload_bytes: int,
    chunk_bytes: int,
    timeout: float,
    insecure_public_tls: bool,
) -> tuple[float, int]:
    conn, target = _connection(
        public_url,
        "/upload",
        timeout=timeout,
        insecure_public_tls=insecure_public_tls,
    )
    chunk = b"x" * min(payload_bytes, chunk_bytes)
    remaining = payload_bytes
    started = time.perf_counter()
    try:
        conn.putrequest("POST", target)
        conn.putheader("Content-Length", str(payload_bytes))
        conn.putheader("Connection", "close")
        conn.endheaders()
        while remaining:
            n = min(len(chunk), remaining)
            conn.send(chunk[:n])
            remaining -= n
        response = conn.getresponse()
        body = response.read()
        elapsed = time.perf_counter() - started
        if response.status != 200:
            raise RuntimeError(f"upload returned HTTP {response.status}")
        expected = f"ok {payload_bytes}\n".encode("ascii")
        if body != expected:
            raise RuntimeError(f"upload response mismatch: {body!r}")
        return elapsed, payload_bytes
    finally:
        conn.close()


async def _measure_remote_sample(
    *,
    direction: str,
    public_url: str,
    requested_window: int,
    negotiated_window: int,
    payload_bytes: int,
    chunk_bytes: int,
    timeout: float,
    insecure_public_tls: bool,
) -> E2ESample:
    if direction == "download":
        elapsed, transferred = await asyncio.to_thread(
            _measure_download,
            public_url,
            payload_bytes=payload_bytes,
            timeout=timeout,
            insecure_public_tls=insecure_public_tls,
        )
    elif direction == "upload":
        elapsed, transferred = await asyncio.to_thread(
            _measure_upload,
            public_url,
            payload_bytes=payload_bytes,
            chunk_bytes=chunk_bytes,
            timeout=timeout,
            insecure_public_tls=insecure_public_tls,
        )
    else:
        raise ValueError(f"invalid direction: {direction!r}")
    return E2ESample(
        direction=direction,
        window_bytes=requested_window,
        negotiated_window_bytes=negotiated_window,
        payload_bytes=payload_bytes,
        chunk_bytes=chunk_bytes,
        elapsed_s=elapsed,
        throughput_mib_s=(transferred / 1024**2) / elapsed,
        transferred_bytes=transferred,
    )


async def run_matrix(
    *,
    server: str,
    token: str,
    control_port: int,
    server_cert: str | None,
    scheme: str,
    subdomain: str | None,
    windows: list[int],
    directions: list[str],
    payload_bytes: int,
    chunk_bytes: int,
    runs: int,
    warmup_runs: int,
    request_timeout: float,
    ready_timeout: float,
    insecure_public_tls: bool,
) -> list[E2EAggregate]:
    if scheme not in ("http", "https"):
        raise ValueError("scheme must be http or https")
    if payload_bytes < 1:
        raise ValueError("payload_bytes must be >= 1 byte")
    if chunk_bytes < 1:
        raise ValueError("chunk_bytes must be >= 1 byte")
    if runs < 1:
        raise ValueError("runs must be >= 1")
    if warmup_runs < 0:
        raise ValueError("warmup_runs must be >= 0")
    if request_timeout <= 0:
        raise ValueError("request_timeout must be positive")
    if ready_timeout <= 0:
        raise ValueError("ready_timeout must be positive")

    results: list[E2EAggregate] = []
    for window in windows:
        local_port, httpd = _start_local_app(payload_bytes, chunk_bytes)
        tunnel = Tunnel(
            server=server,
            token=token,
            local_port=local_port,
            control_port=control_port,
            server_cert=server_cert,
            scheme=scheme,
            subdomain=subdomain,
            mux_flow_window=window,
        )
        task = asyncio.create_task(tunnel.serve_forever())
        try:
            public_url = await tunnel.wait_until_ready(timeout=ready_timeout)
            negotiated = tunnel.negotiated_mux_flow_window
            if negotiated is None:
                raise RuntimeError("tunnel became ready without a negotiated flow window")
            for direction in directions:
                for _ in range(warmup_runs):
                    await _measure_remote_sample(
                        direction=direction,
                        public_url=public_url,
                        requested_window=window,
                        negotiated_window=negotiated,
                        payload_bytes=payload_bytes,
                        chunk_bytes=chunk_bytes,
                        timeout=request_timeout,
                        insecure_public_tls=insecure_public_tls,
                    )
                samples = [
                    await _measure_remote_sample(
                        direction=direction,
                        public_url=public_url,
                        requested_window=window,
                        negotiated_window=negotiated,
                        payload_bytes=payload_bytes,
                        chunk_bytes=chunk_bytes,
                        timeout=request_timeout,
                        insecure_public_tls=insecure_public_tls,
                    )
                    for _ in range(runs)
                ]
                results.append(aggregate_samples(samples))
        finally:
            await tunnel.aclose()
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
            httpd.shutdown()
            httpd.server_close()
    return results


def _print_table(results: list[E2EAggregate]) -> None:
    headers = [
        "direction",
        "window",
        "negotiated",
        "runs",
        "bytes",
        "elapsed_s med",
        "MiB/s med",
        "MiB/s min..max",
    ]
    print(" | ".join(headers))
    print(" | ".join("-" * len(header) for header in headers))
    for row in results:
        print(
            " | ".join(
                [
                    row.direction,
                    _format_bytes(row.window_bytes),
                    _format_bytes(row.negotiated_window_bytes),
                    str(row.runs),
                    _format_bytes(row.transferred_bytes),
                    f"{row.elapsed_s_median:.3f}",
                    f"{row.throughput_mib_s_median:.2f}",
                    f"{row.throughput_mib_s_min:.2f}..{row.throughput_mib_s_max:.2f}",
                ]
            )
        )


def build_report(
    *,
    results: list[E2EAggregate],
    server: str,
    control_port: int,
    scheme: str,
    subdomain: str | None,
    windows: list[int],
    directions: list[str],
    payload_bytes: int,
    chunk_bytes: int,
    runs: int,
    warmup_runs: int,
    request_timeout: float,
    ready_timeout: float,
    insecure_public_tls: bool,
) -> RemoteBenchmarkReport:
    return RemoteBenchmarkReport(
        schema_version=1,
        benchmark="chute_remote_e2e",
        generated_at=_dt.datetime.now(_dt.UTC).isoformat(),
        python_version=sys.version.split()[0],
        chute_protocol_version=protocol.VERSION,
        server=server,
        control_port=control_port,
        scheme=scheme,
        subdomain=subdomain,
        windows=windows,
        directions=directions,
        payload_bytes=payload_bytes,
        chunk_bytes=chunk_bytes,
        runs=runs,
        warmup_runs=warmup_runs,
        request_timeout=request_timeout,
        ready_timeout=ready_timeout,
        insecure_public_tls=insecure_public_tls,
        results=results,
    )


def write_report(path: str | os.PathLike[str], report: RemoteBenchmarkReport) -> None:
    target = Path(path).expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(asdict(report), indent=2) + "\n", encoding="utf-8")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Benchmark a deployed chute relay end-to-end. Starts a local benchmark "
            "app, opens a Tunnel agent, then measures the relay-provided public URL."
        )
    )
    parser.add_argument("--server", default=_env("CHUTE_SERVER"), help="relay control host")
    parser.add_argument(
        "--token",
        default=_env("CHUTE_TOKEN"),
        help="shared secret; prefer --token-file to avoid shell history/process exposure",
    )
    parser.add_argument(
        "--token-file",
        default=_env("CHUTE_TOKEN_FILE"),
        help="read the shared secret from a chmod 600 file",
    )
    parser.add_argument("--control-port", type=int, default=_int_env("CHUTE_CONTROL_PORT", 7000))
    parser.add_argument("--server-cert", default=_env("CHUTE_SERVER_CERT"))
    parser.add_argument("--scheme", choices=("http", "https"), default="https")
    parser.add_argument("--subdomain", default=_env("CHUTE_SUBDOMAIN"))
    parser.add_argument(
        "--windows",
        type=_parse_size_list,
        default=[_FLOW_WINDOW, 1024 * 1024, 4 * 1024 * 1024],
        help="comma-separated mux flow windows to set on the agent",
    )
    parser.add_argument(
        "--directions",
        type=_parse_directions,
        default=["download", "upload"],
        help="comma-separated directions: download,upload",
    )
    parser.add_argument("--bytes", dest="payload_bytes", type=_parse_size, default=8 * 1024 * 1024)
    parser.add_argument("--chunk-size", type=_parse_size, default=64 * 1024)
    parser.add_argument("--runs", type=_positive_int, default=3)
    parser.add_argument("--warmup-runs", type=int, default=1)
    parser.add_argument(
        "--request-timeout",
        type=float,
        default=_float_env("CHUTE_BENCH_TIMEOUT", 60),
    )
    parser.add_argument("--ready-timeout", type=float, default=20)
    parser.add_argument(
        "--insecure-public-tls",
        action="store_true",
        help="disable public HTTPS certificate verification for lab-only self-signed public certs",
    )
    parser.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    parser.add_argument(
        "--output-json",
        help=(
            "write a self-describing JSON report artifact; secrets and token-file "
            "paths are intentionally omitted"
        ),
    )
    return parser


async def _amain(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        token = _resolve_token(token=args.token, token_file=args.token_file)
    except ValueError as exc:
        raise SystemExit(str(exc)) from None
    if not args.server:
        raise SystemExit("set --server or CHUTE_SERVER")
    results = await run_matrix(
        server=args.server,
        token=token,
        control_port=args.control_port,
        server_cert=args.server_cert,
        scheme=args.scheme,
        subdomain=args.subdomain,
        windows=args.windows,
        directions=args.directions,
        payload_bytes=args.payload_bytes,
        chunk_bytes=args.chunk_size,
        runs=args.runs,
        warmup_runs=args.warmup_runs,
        request_timeout=args.request_timeout,
        ready_timeout=args.ready_timeout,
        insecure_public_tls=args.insecure_public_tls,
    )
    report = build_report(
        results=results,
        server=args.server,
        control_port=args.control_port,
        scheme=args.scheme,
        subdomain=args.subdomain,
        windows=args.windows,
        directions=args.directions,
        payload_bytes=args.payload_bytes,
        chunk_bytes=args.chunk_size,
        runs=args.runs,
        warmup_runs=args.warmup_runs,
        request_timeout=args.request_timeout,
        ready_timeout=args.ready_timeout,
        insecure_public_tls=args.insecure_public_tls,
    )
    if args.output_json:
        write_report(args.output_json, report)
    if args.json:
        print(json.dumps([asdict(result) for result in results], indent=2))
    else:
        _print_table(results)
    return 0


def main(argv: list[str] | None = None) -> int:
    return asyncio.run(_amain(argv))


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
