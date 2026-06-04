#!/usr/bin/env python3
"""Benchmark the full chute tunnel path on loopback.

This launches a real Server, a real Tunnel agent, and a local HTTP app in one
process. It measures the public visitor path through the relay and back to the
local app. It does not simulate WAN RTT, nginx, kernel TCP behavior across a real
network, or a VPS NIC. Use it as an end-to-end loopback baseline before remote
benchmarking, not as production throughput proof.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import socket
import statistics
import tempfile
import threading
import time
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from chute import certs
from chute.client import Tunnel
from chute.mux import _FLOW_WINDOW, validate_flow_window
from chute.server import Server

_UNITS = {
    "b": 1,
    "": 1,
    "k": 1024,
    "kb": 1024,
    "kib": 1024,
    "m": 1024 * 1024,
    "mb": 1024 * 1024,
    "mib": 1024 * 1024,
    "g": 1024 * 1024 * 1024,
    "gb": 1024 * 1024 * 1024,
    "gib": 1024 * 1024 * 1024,
}
_VALID_DIRECTIONS = frozenset({"download", "upload"})
_RESPONSE_HEAD_LIMIT = 64 * 1024


@dataclass(frozen=True)
class E2ESample:
    direction: str
    window_bytes: int
    negotiated_window_bytes: int
    payload_bytes: int
    chunk_bytes: int
    elapsed_s: float
    throughput_mib_s: float
    transferred_bytes: int


@dataclass(frozen=True)
class E2EAggregate:
    direction: str
    window_bytes: int
    negotiated_window_bytes: int
    payload_bytes: int
    chunk_bytes: int
    runs: int
    elapsed_s_median: float
    elapsed_s_min: float
    elapsed_s_max: float
    throughput_mib_s_median: float
    throughput_mib_s_min: float
    throughput_mib_s_max: float
    transferred_bytes: int
    samples: tuple[E2ESample, ...]


def _parse_size(raw: str) -> int:
    value = raw.strip().lower()
    if not value:
        raise argparse.ArgumentTypeError("empty byte size")
    for suffix in sorted(_UNITS, key=len, reverse=True):
        if suffix and value.endswith(suffix):
            number = value[: -len(suffix)]
            break
    else:
        suffix = ""
        number = value
    try:
        parsed = float(number)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid byte size: {raw!r}") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("byte size must be positive")
    byte_count = int(parsed * _UNITS[suffix])
    if byte_count < 1:
        raise argparse.ArgumentTypeError("byte size must be at least 1 byte")
    return byte_count


def _parse_size_list(raw: str) -> list[int]:
    values = [_parse_size(part) for part in raw.split(",") if part.strip()]
    if not values:
        raise argparse.ArgumentTypeError("at least one byte size is required")
    for value in values:
        validate_flow_window(value)
    return values


def _positive_int(raw: str) -> int:
    try:
        value = int(raw)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid integer: {raw!r}") from exc
    if value < 1:
        raise argparse.ArgumentTypeError("value must be >= 1")
    return value


def _parse_directions(raw: str) -> list[str]:
    values = [part.strip().lower() for part in raw.split(",") if part.strip()]
    if not values:
        raise argparse.ArgumentTypeError("at least one direction is required")
    invalid = sorted(set(values) - _VALID_DIRECTIONS)
    if invalid:
        raise argparse.ArgumentTypeError(f"invalid direction(s): {', '.join(invalid)}")
    return values


def _format_bytes(value: int) -> str:
    for suffix, factor in (("GiB", 1024**3), ("MiB", 1024**2), ("KiB", 1024)):
        if value >= factor:
            return f"{value / factor:.2f} {suffix}"
    return f"{value} B"


def _free_port() -> int:
    sock = socket.socket()
    try:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])
    finally:
        sock.close()


def _make_handler(payload_bytes: int, chunk_bytes: int) -> type[BaseHTTPRequestHandler]:
    payload_chunk = b"x" * min(payload_bytes, chunk_bytes)

    class _BenchmarkHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args: object) -> None:
            return None

        def do_GET(self) -> None:
            if self.path != "/payload":
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(payload_bytes))
            self.send_header("Connection", "close")
            self.end_headers()
            remaining = payload_bytes
            while remaining:
                n = min(len(payload_chunk), remaining)
                self.wfile.write(payload_chunk[:n])
                remaining -= n

        def do_POST(self) -> None:
            if self.path != "/upload":
                self.send_error(404)
                return
            remaining = int(self.headers.get("Content-Length", "0"))
            consumed = 0
            while remaining:
                chunk = self.rfile.read(min(64 * 1024, remaining))
                if not chunk:
                    break
                consumed += len(chunk)
                remaining -= len(chunk)
            body = f"ok {consumed}\n".encode("ascii")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

    return _BenchmarkHandler


def _start_local_app(payload_bytes: int, chunk_bytes: int) -> tuple[int, ThreadingHTTPServer]:
    port = _free_port()
    server = ThreadingHTTPServer(("127.0.0.1", port), _make_handler(payload_bytes, chunk_bytes))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return port, server


async def _quiet_cancel(*tasks: asyncio.Task[object]) -> None:
    for task in tasks:
        task.cancel()
    for task in tasks:
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await task


class _LoopbackHarness:
    def __init__(self, *, flow_window: int, payload_bytes: int, chunk_bytes: int) -> None:
        self.flow_window = validate_flow_window(flow_window)
        self.payload_bytes = payload_bytes
        self.chunk_bytes = chunk_bytes
        self.public_port = 0
        self.negotiated_window = 0
        self._tmpdir: tempfile.TemporaryDirectory[str] | None = None
        self._httpd: ThreadingHTTPServer | None = None
        self._tunnel: Tunnel | None = None
        self._tasks: list[asyncio.Task[object]] = []

    async def __aenter__(self) -> _LoopbackHarness:
        self._tmpdir = tempfile.TemporaryDirectory()
        tmp = Path(self._tmpdir.name)
        cert, key = tmp / "control-cert.pem", tmp / "control-key.pem"
        certs.generate("127.0.0.1", cert, key)
        local_port, self._httpd = _start_local_app(self.payload_bytes, self.chunk_bytes)
        self.public_port = _free_port()
        control_port = _free_port()
        server = Server(
            token="secret",
            public_host="127.0.0.1",
            public_port=self.public_port,
            control_host="127.0.0.1",
            control_port=control_port,
            public_url=f"http://127.0.0.1:{self.public_port}/",
            ssl_context=certs.server_ssl_context(cert, key),
            mux_flow_window=self.flow_window,
        )
        self._tasks.append(asyncio.create_task(server.serve()))
        await asyncio.sleep(0.2)
        self._tunnel = Tunnel(
            server="127.0.0.1",
            token="secret",
            local_port=local_port,
            control_port=control_port,
            server_cert=str(cert),
            scheme="http",
            mux_flow_window=self.flow_window,
        )
        self._tasks.append(asyncio.create_task(self._tunnel.serve_forever()))
        await self._tunnel.wait_until_ready(timeout=10)
        self.negotiated_window = server._agents["default"].mux.flow_window
        return self

    async def __aexit__(
        self,
        _exc_type: object,
        _exc: object,
        _traceback: object,
    ) -> None:
        if self._tunnel is not None:
            await self._tunnel.aclose()
        await _quiet_cancel(*self._tasks)
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
        if self._tmpdir is not None:
            self._tmpdir.cleanup()


async def _read_http_response(reader: asyncio.StreamReader) -> tuple[int, bytes]:
    head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=30)
    if len(head) > _RESPONSE_HEAD_LIMIT:
        raise RuntimeError("response head exceeded local benchmark limit")
    status_line = head.split(b"\r\n", 1)[0]
    try:
        status = int(status_line.split(b" ", 2)[1])
    except (IndexError, ValueError) as exc:
        raise RuntimeError(f"invalid response status line: {status_line!r}") from exc
    length = 0
    for line in head.split(b"\r\n")[1:]:
        if line.lower().startswith(b"content-length:"):
            length = int(line.split(b":", 1)[1].strip())
            break
    body = await asyncio.wait_for(reader.readexactly(length), timeout=60)
    return status, body


async def _measure_download(port: int, payload_bytes: int) -> tuple[float, int]:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        request = b"GET /payload HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
        started = time.perf_counter()
        writer.write(request)
        await writer.drain()
        status, body = await _read_http_response(reader)
        elapsed = time.perf_counter() - started
        if status != 200:
            raise RuntimeError(f"download returned HTTP {status}")
        if len(body) != payload_bytes:
            raise RuntimeError(f"download received {len(body)} of {payload_bytes} bytes")
        return elapsed, len(body)
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


async def _measure_upload(port: int, payload_bytes: int, chunk_bytes: int) -> tuple[float, int]:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    payload = b"x" * min(payload_bytes, chunk_bytes)
    try:
        headers = (
            b"POST /upload HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            + f"Content-Length: {payload_bytes}\r\n".encode("ascii")
            + b"Connection: close\r\n"
            b"\r\n"
        )
        remaining = payload_bytes
        started = time.perf_counter()
        writer.write(headers)
        while remaining:
            n = min(len(payload), remaining)
            writer.write(payload[:n])
            remaining -= n
            await writer.drain()
        status, body = await _read_http_response(reader)
        elapsed = time.perf_counter() - started
        if status != 200:
            raise RuntimeError(f"upload returned HTTP {status}")
        expected = f"ok {payload_bytes}\n".encode("ascii")
        if body != expected:
            raise RuntimeError(f"upload response mismatch: {body!r}")
        return elapsed, payload_bytes
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


async def run_sample(
    *,
    harness: _LoopbackHarness,
    direction: str,
) -> E2ESample:
    if direction == "download":
        elapsed, transferred = await _measure_download(harness.public_port, harness.payload_bytes)
    elif direction == "upload":
        elapsed, transferred = await _measure_upload(
            harness.public_port, harness.payload_bytes, harness.chunk_bytes
        )
    else:
        raise ValueError(f"invalid direction: {direction!r}")
    throughput = (transferred / 1024**2) / elapsed
    return E2ESample(
        direction=direction,
        window_bytes=harness.flow_window,
        negotiated_window_bytes=harness.negotiated_window,
        payload_bytes=harness.payload_bytes,
        chunk_bytes=harness.chunk_bytes,
        elapsed_s=elapsed,
        throughput_mib_s=throughput,
        transferred_bytes=transferred,
    )


def aggregate_samples(samples: Iterable[E2ESample]) -> E2EAggregate:
    sample_tuple = tuple(samples)
    if not sample_tuple:
        raise ValueError("at least one benchmark sample is required")
    first = sample_tuple[0]
    for sample in sample_tuple[1:]:
        if (
            sample.direction != first.direction
            or sample.window_bytes != first.window_bytes
            or sample.negotiated_window_bytes != first.negotiated_window_bytes
            or sample.payload_bytes != first.payload_bytes
            or sample.chunk_bytes != first.chunk_bytes
        ):
            raise ValueError("benchmark samples must describe the same scenario")
    elapsed = [sample.elapsed_s for sample in sample_tuple]
    throughputs = [sample.throughput_mib_s for sample in sample_tuple]
    return E2EAggregate(
        direction=first.direction,
        window_bytes=first.window_bytes,
        negotiated_window_bytes=first.negotiated_window_bytes,
        payload_bytes=first.payload_bytes,
        chunk_bytes=first.chunk_bytes,
        runs=len(sample_tuple),
        elapsed_s_median=statistics.median(elapsed),
        elapsed_s_min=min(elapsed),
        elapsed_s_max=max(elapsed),
        throughput_mib_s_median=statistics.median(throughputs),
        throughput_mib_s_min=min(throughputs),
        throughput_mib_s_max=max(throughputs),
        transferred_bytes=first.transferred_bytes,
        samples=sample_tuple,
    )


async def run_matrix(
    *,
    windows: Iterable[int],
    directions: Iterable[str],
    payload_bytes: int,
    chunk_bytes: int,
    runs: int,
    warmup_runs: int,
) -> list[E2EAggregate]:
    if payload_bytes < 1:
        raise ValueError("payload_bytes must be >= 1 byte")
    if chunk_bytes < 1:
        raise ValueError("chunk_bytes must be >= 1 byte")
    if runs < 1:
        raise ValueError("runs must be >= 1")
    if warmup_runs < 0:
        raise ValueError("warmup_runs must be >= 0")
    results: list[E2EAggregate] = []
    for window in windows:
        async with _LoopbackHarness(
            flow_window=window,
            payload_bytes=payload_bytes,
            chunk_bytes=chunk_bytes,
        ) as harness:
            for direction in directions:
                for _ in range(warmup_runs):
                    await run_sample(harness=harness, direction=direction)
                samples = [
                    await run_sample(harness=harness, direction=direction) for _ in range(runs)
                ]
                results.append(aggregate_samples(samples))
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


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Benchmark chute's full loopback tunnel path. This runs a local Server, "
            "Tunnel agent, and HTTP app; it is not a WAN/VPS/nginx benchmark."
        )
    )
    parser.add_argument(
        "--windows",
        type=_parse_size_list,
        default=[_FLOW_WINDOW, 1024 * 1024, 4 * 1024 * 1024],
        help="comma-separated mux flow windows to set on both server and agent",
    )
    parser.add_argument(
        "--directions",
        type=_parse_directions,
        default=["download", "upload"],
        help="comma-separated directions: download,upload",
    )
    parser.add_argument(
        "--bytes",
        dest="payload_bytes",
        type=_parse_size,
        default=8 * 1024 * 1024,
        help="payload size per measured request",
    )
    parser.add_argument(
        "--chunk-size",
        type=_parse_size,
        default=64 * 1024,
        help="local app / visitor write chunk size",
    )
    parser.add_argument(
        "--runs",
        type=_positive_int,
        default=3,
        help="measured runs per scenario",
    )
    parser.add_argument(
        "--warmup-runs",
        type=int,
        default=1,
        help="unreported warmup runs per scenario",
    )
    parser.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    return parser


async def _amain(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.warmup_runs < 0:
        raise SystemExit("--warmup-runs must be >= 0")
    results = await run_matrix(
        windows=args.windows,
        directions=args.directions,
        payload_bytes=args.payload_bytes,
        chunk_bytes=args.chunk_size,
        runs=args.runs,
        warmup_runs=args.warmup_runs,
    )
    if args.json:
        print(json.dumps([asdict(result) for result in results], indent=2))
    else:
        _print_table(results)
    return 0


def main(argv: list[str] | None = None) -> int:
    return asyncio.run(_amain(argv))


if __name__ == "__main__":
    raise SystemExit(main())
