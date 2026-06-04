#!/usr/bin/env python3
"""Benchmark chute's mux flow window under a simulated RTT.

This script measures the mux layer directly with an in-memory WebSocket pair. It
does not benchmark TLS, kernel TCP, nginx, or a local app. That is intentional:
it isolates the application credit window so a default change can start from
data instead of instinct.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import statistics
import time
from collections.abc import Iterable
from dataclasses import asdict, dataclass

from chute.mux import _FLOW_WINDOW, Mux, Stream, validate_flow_window

_CLOSE = object()
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


@dataclass(frozen=True)
class BenchmarkResult:
    rtt_ms: float
    window_bytes: int
    payload_bytes: int
    chunk_bytes: int
    elapsed_s: float
    throughput_mib_s: float
    window_limited_mib_s: float
    delivered_bytes: int
    target_mbps: float | None
    target_bdp_bytes: int | None
    window_to_target_bdp: float | None
    payload_to_window: float


@dataclass(frozen=True)
class BenchmarkAggregate:
    rtt_ms: float
    window_bytes: int
    payload_bytes: int
    chunk_bytes: int
    runs: int
    elapsed_s_median: float
    elapsed_s_min: float
    elapsed_s_max: float
    throughput_mib_s_median: float
    throughput_mib_s_min: float
    throughput_mib_s_max: float
    window_limited_mib_s: float
    delivered_bytes: int
    target_mbps: float | None
    target_bdp_bytes: int | None
    window_to_target_bdp: float | None
    payload_to_window: float
    samples: tuple[BenchmarkResult, ...]


class _MemoryTransport:
    def __init__(self, owner: _MemoryWebSocket) -> None:
        self.owner = owner
        self.aborted = False

    def abort(self) -> None:
        self.aborted = True
        self.owner.abort()


class _MemoryWebSocket:
    def __init__(self, one_way_delay_s: float) -> None:
        self.one_way_delay_s = one_way_delay_s
        self.peer: _MemoryWebSocket | None = None
        self.transport = _MemoryTransport(self)
        self._incoming: asyncio.Queue[bytes | object] = asyncio.Queue()
        self._deliveries: set[asyncio.Task[None]] = set()
        self._pending: dict[int, bytes] = {}
        self._order_lock = asyncio.Lock()
        self._next_send_seq = 0
        self._next_recv_seq = 0
        self._closed = False

    def connect(self, peer: _MemoryWebSocket) -> None:
        self.peer = peer

    def __aiter__(self) -> _MemoryWebSocket:
        return self

    async def __anext__(self) -> bytes:
        item = await self._incoming.get()
        if item is _CLOSE:
            raise StopAsyncIteration
        assert isinstance(item, bytes)
        return item

    async def send(self, data: bytes) -> None:
        if self._closed:
            raise ConnectionError("websocket closed")
        peer = self.peer
        if peer is None:
            raise ConnectionError("websocket peer not connected")
        seq = self._next_send_seq
        self._next_send_seq += 1

        async def _deliver() -> None:
            await asyncio.sleep(self.one_way_delay_s)
            await peer._deliver_ordered(seq, data)

        task = asyncio.create_task(_deliver())
        self._deliveries.add(task)
        task.add_done_callback(self._deliveries.discard)

    async def _deliver_ordered(self, seq: int, data: bytes) -> None:
        async with self._order_lock:
            if self._closed:
                return
            self._pending[seq] = data
            while self._next_recv_seq in self._pending:
                await self._incoming.put(self._pending.pop(self._next_recv_seq))
                self._next_recv_seq += 1

    async def close(self, *, code: int = 1000, reason: str = "") -> None:
        del code, reason
        self._closed = True
        if self._deliveries:
            await asyncio.gather(*self._deliveries, return_exceptions=True)
        await self._incoming.put(_CLOSE)

    def abort(self) -> None:
        self._closed = True
        with contextlib.suppress(asyncio.QueueFull):
            self._incoming.put_nowait(_CLOSE)


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
    return values


def _parse_rtt_list(raw: str) -> list[float]:
    values: list[float] = []
    for part in raw.split(","):
        if not part.strip():
            continue
        try:
            value = float(part)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(f"invalid RTT: {part!r}") from exc
        if value < 0:
            raise argparse.ArgumentTypeError("RTT must be >= 0")
        values.append(value)
    if not values:
        raise argparse.ArgumentTypeError("at least one RTT is required")
    return values


def _format_bytes(value: int) -> str:
    for suffix, factor in (("GiB", 1024**3), ("MiB", 1024**2), ("KiB", 1024)):
        if value >= factor:
            return f"{value / factor:.2f} {suffix}"
    return f"{value} B"


def target_bdp_bytes(target_mbps: float, rtt_ms: float) -> int:
    return int((target_mbps * 1_000_000 / 8) * (rtt_ms / 1000))


def _positive_int(raw: str) -> int:
    try:
        value = int(raw)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid integer: {raw!r}") from exc
    if value < 1:
        raise argparse.ArgumentTypeError("value must be >= 1")
    return value


def aggregate_results(samples: Iterable[BenchmarkResult]) -> BenchmarkAggregate:
    sample_tuple = tuple(samples)
    if not sample_tuple:
        raise ValueError("at least one benchmark sample is required")
    first = sample_tuple[0]
    for sample in sample_tuple[1:]:
        if (
            sample.rtt_ms != first.rtt_ms
            or sample.window_bytes != first.window_bytes
            or sample.payload_bytes != first.payload_bytes
            or sample.chunk_bytes != first.chunk_bytes
            or sample.target_mbps != first.target_mbps
            or sample.target_bdp_bytes != first.target_bdp_bytes
        ):
            raise ValueError("benchmark samples must describe the same scenario")
    elapsed = [sample.elapsed_s for sample in sample_tuple]
    throughputs = [sample.throughput_mib_s for sample in sample_tuple]
    return BenchmarkAggregate(
        rtt_ms=first.rtt_ms,
        window_bytes=first.window_bytes,
        payload_bytes=first.payload_bytes,
        chunk_bytes=first.chunk_bytes,
        runs=len(sample_tuple),
        elapsed_s_median=statistics.median(elapsed),
        elapsed_s_min=min(elapsed),
        elapsed_s_max=max(elapsed),
        throughput_mib_s_median=statistics.median(throughputs),
        throughput_mib_s_min=min(throughputs),
        throughput_mib_s_max=max(throughputs),
        window_limited_mib_s=first.window_limited_mib_s,
        delivered_bytes=first.delivered_bytes,
        target_mbps=first.target_mbps,
        target_bdp_bytes=first.target_bdp_bytes,
        window_to_target_bdp=first.window_to_target_bdp,
        payload_to_window=first.payload_to_window,
        samples=sample_tuple,
    )


async def run_benchmark(
    *,
    flow_window: int,
    rtt_ms: float,
    payload_bytes: int,
    chunk_bytes: int,
    target_mbps: float | None,
) -> BenchmarkResult:
    flow_window = validate_flow_window(flow_window)
    if rtt_ms < 0:
        raise ValueError("rtt_ms must be >= 0")
    if payload_bytes < 1:
        raise ValueError("payload_bytes must be >= 1 byte")
    if chunk_bytes < 1:
        raise ValueError("chunk_bytes must be >= 1 byte")
    if target_mbps is not None and target_mbps <= 0:
        raise ValueError("target_mbps must be positive")
    one_way_delay_s = rtt_ms / 2000
    left_ws = _MemoryWebSocket(one_way_delay_s)
    right_ws = _MemoryWebSocket(one_way_delay_s)
    left_ws.connect(right_ws)
    right_ws.connect(left_ws)

    delivered = 0
    done = asyncio.Event()

    async def _on_open(stream: Stream) -> None:
        nonlocal delivered
        while True:
            data = await stream.read()
            if data is None:
                break
            delivered += len(data)
            await stream.ack(len(data))
        done.set()

    left = Mux(left_ws, flow_window=flow_window)
    right = Mux(right_ws, on_open=_on_open, flow_window=flow_window)
    tasks = [asyncio.create_task(left.run()), asyncio.create_task(right.run())]
    try:
        stream = await left.open()
        payload = b"x" * min(chunk_bytes, payload_bytes)
        remaining = payload_bytes
        started = time.perf_counter()
        while remaining:
            n = min(len(payload), remaining)
            await stream.send(payload[:n])
            remaining -= n
        await stream.send_eof()
        await asyncio.wait_for(done.wait(), timeout=max(5.0, (rtt_ms / 1000) * 20))
        elapsed = time.perf_counter() - started
    finally:
        await asyncio.gather(left.aclose(), right.aclose(), return_exceptions=True)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    if delivered != payload_bytes:
        raise RuntimeError(f"delivered {delivered} of {payload_bytes} bytes")

    throughput_mib_s = (payload_bytes / 1024**2) / elapsed
    if rtt_ms == 0:
        window_limited_mib_s = float("inf")
    else:
        window_limited_mib_s = (flow_window / 1024**2) / (rtt_ms / 1000)
    bdp = target_bdp_bytes(target_mbps, rtt_ms) if target_mbps is not None else None
    return BenchmarkResult(
        rtt_ms=rtt_ms,
        window_bytes=flow_window,
        payload_bytes=payload_bytes,
        chunk_bytes=chunk_bytes,
        elapsed_s=elapsed,
        throughput_mib_s=throughput_mib_s,
        window_limited_mib_s=window_limited_mib_s,
        delivered_bytes=delivered,
        target_mbps=target_mbps,
        target_bdp_bytes=bdp,
        window_to_target_bdp=(flow_window / bdp if bdp else None),
        payload_to_window=payload_bytes / flow_window,
    )


async def run_matrix(
    *,
    windows: Iterable[int],
    rtts_ms: Iterable[float],
    payload_bytes: int,
    chunk_bytes: int,
    target_mbps: float | None,
    runs: int = 1,
) -> list[BenchmarkAggregate]:
    if runs < 1:
        raise ValueError("runs must be >= 1")
    results: list[BenchmarkAggregate] = []
    for rtt_ms in rtts_ms:
        for window in windows:
            samples = [
                await run_benchmark(
                    flow_window=window,
                    rtt_ms=rtt_ms,
                    payload_bytes=payload_bytes,
                    chunk_bytes=chunk_bytes,
                    target_mbps=target_mbps,
                )
                for _ in range(runs)
            ]
            results.append(aggregate_results(samples))
    return results


def _print_table(results: list[BenchmarkAggregate]) -> None:
    headers = [
        "rtt_ms",
        "window",
        "runs",
        "elapsed_s med",
        "MiB/s med",
        "MiB/s min..max",
        "window/RTT MiB/s",
        "target_bdp",
        "window/bdp",
        "payload/window",
    ]
    print(" | ".join(headers))
    print(" | ".join("-" * len(header) for header in headers))
    for row in results:
        print(
            " | ".join(
                [
                    f"{row.rtt_ms:g}",
                    _format_bytes(row.window_bytes),
                    f"{row.runs}",
                    f"{row.elapsed_s_median:.3f}",
                    f"{row.throughput_mib_s_median:.2f}",
                    f"{row.throughput_mib_s_min:.2f}..{row.throughput_mib_s_max:.2f}",
                    (
                        "inf"
                        if row.window_limited_mib_s == float("inf")
                        else f"{row.window_limited_mib_s:.2f}"
                    ),
                    _format_bytes(row.target_bdp_bytes) if row.target_bdp_bytes else "-",
                    f"{row.window_to_target_bdp:.2f}" if row.window_to_target_bdp else "-",
                    f"{row.payload_to_window:.2f}",
                ]
            )
        )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Benchmark chute mux flow windows with simulated RTT. "
            "This isolates mux credit behavior; it is not an end-to-end tunnel "
            "benchmark. Short payloads include the initial-window burst; compare "
            "payload/window before using results as steady-state evidence."
        )
    )
    parser.add_argument(
        "--windows",
        type=_parse_size_list,
        default=[_FLOW_WINDOW, 1024 * 1024, 4 * 1024 * 1024],
        help="comma-separated flow windows, e.g. 256k,1m,4m",
    )
    parser.add_argument(
        "--rtts-ms",
        type=_parse_rtt_list,
        default=[10.0, 50.0],
        help="comma-separated round-trip times in milliseconds, e.g. 10,50,100",
    )
    parser.add_argument(
        "--bytes",
        dest="payload_bytes",
        type=_parse_size,
        default=8 * 1024 * 1024,
        help=(
            "payload per benchmark run, e.g. 8m; use far more than the largest "
            "window for steady-state comparisons"
        ),
    )
    parser.add_argument(
        "--chunk-size",
        type=_parse_size,
        default=64 * 1024,
        help="caller write chunk size, e.g. 64k",
    )
    parser.add_argument(
        "--target-mbps",
        type=float,
        default=None,
        help="optional target link bandwidth for BDP comparison",
    )
    parser.add_argument(
        "--runs",
        type=_positive_int,
        default=1,
        help="repeat each RTT/window scenario and report median/min/max",
    )
    parser.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    return parser


async def _amain(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.target_mbps is not None and args.target_mbps <= 0:
        raise SystemExit("--target-mbps must be positive")
    results = await run_matrix(
        windows=args.windows,
        rtts_ms=args.rtts_ms,
        payload_bytes=args.payload_bytes,
        chunk_bytes=args.chunk_size,
        target_mbps=args.target_mbps,
        runs=args.runs,
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
