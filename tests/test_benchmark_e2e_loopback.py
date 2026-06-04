from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "benchmark_e2e_loopback.py"
_ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location("benchmark_e2e_loopback", _SCRIPT)
assert _SPEC is not None and _SPEC.loader is not None
benchmark_e2e_loopback = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = benchmark_e2e_loopback
_SPEC.loader.exec_module(benchmark_e2e_loopback)


def test_e2e_loopback_benchmark_parses_inputs() -> None:
    assert benchmark_e2e_loopback._parse_size_list("256k,1m") == [256 * 1024, 1024 * 1024]
    assert benchmark_e2e_loopback._parse_directions("download,upload") == [
        "download",
        "upload",
    ]
    with pytest.raises(Exception, match="direction"):
        benchmark_e2e_loopback._parse_directions("download,sideways")
    with pytest.raises(Exception, match="positive"):
        benchmark_e2e_loopback._parse_size("0")


def test_e2e_loopback_benchmark_aggregates_samples() -> None:
    samples = [
        benchmark_e2e_loopback.E2ESample(
            direction="download",
            window_bytes=1024,
            negotiated_window_bytes=1024,
            payload_bytes=4096,
            chunk_bytes=512,
            elapsed_s=elapsed,
            throughput_mib_s=throughput,
            transferred_bytes=4096,
        )
        for elapsed, throughput in ((3.0, 11.0), (1.0, 33.0), (2.0, 22.0))
    ]

    aggregate = benchmark_e2e_loopback.aggregate_samples(samples)

    assert aggregate.runs == 3
    assert aggregate.elapsed_s_median == 2.0
    assert aggregate.elapsed_s_min == 1.0
    assert aggregate.elapsed_s_max == 3.0
    assert aggregate.throughput_mib_s_median == 22.0
    assert aggregate.throughput_mib_s_min == 11.0
    assert aggregate.throughput_mib_s_max == 33.0
    assert aggregate.samples == tuple(samples)


def test_e2e_loopback_benchmark_rejects_mixed_or_empty_samples() -> None:
    first = benchmark_e2e_loopback.E2ESample(
        direction="download",
        window_bytes=1024,
        negotiated_window_bytes=1024,
        payload_bytes=4096,
        chunk_bytes=512,
        elapsed_s=1,
        throughput_mib_s=1,
        transferred_bytes=4096,
    )
    second = benchmark_e2e_loopback.E2ESample(
        direction="upload",
        window_bytes=1024,
        negotiated_window_bytes=1024,
        payload_bytes=4096,
        chunk_bytes=512,
        elapsed_s=1,
        throughput_mib_s=1,
        transferred_bytes=4096,
    )

    with pytest.raises(ValueError, match="at least one"):
        benchmark_e2e_loopback.aggregate_samples(())
    with pytest.raises(ValueError, match="same scenario"):
        benchmark_e2e_loopback.aggregate_samples((first, second))


async def test_e2e_loopback_benchmark_tiny_real_tunnel_run() -> None:
    results = await benchmark_e2e_loopback.run_matrix(
        windows=[8192],
        directions=["download", "upload"],
        payload_bytes=16 * 1024,
        chunk_bytes=1024,
        runs=1,
        warmup_runs=0,
    )

    assert [result.direction for result in results] == ["download", "upload"]
    for result in results:
        assert result.runs == 1
        assert result.window_bytes == 8192
        assert result.negotiated_window_bytes == 8192
        assert result.transferred_bytes == 16 * 1024
        assert result.throughput_mib_s_median > 0


async def test_e2e_loopback_benchmark_rejects_invalid_matrix_args() -> None:
    with pytest.raises(ValueError, match="runs"):
        await benchmark_e2e_loopback.run_matrix(
            windows=[1024],
            directions=["download"],
            payload_bytes=1024,
            chunk_bytes=1024,
            runs=0,
            warmup_runs=0,
        )
    with pytest.raises(ValueError, match="warmup"):
        await benchmark_e2e_loopback.run_matrix(
            windows=[1024],
            directions=["download"],
            payload_bytes=1024,
            chunk_bytes=1024,
            runs=1,
            warmup_runs=-1,
        )


def test_performance_doc_mentions_loopback_and_remote_benchmark_boundary() -> None:
    text = (_ROOT / "docs" / "PERFORMANCE.md").read_text()

    assert "scripts/benchmark_e2e_loopback.py" in text
    for required_scope in ("real Server", "real Tunnel agent", "local HTTP app"):
        assert required_scope in text
    assert "loopback" in text
    assert "not a WAN/VPS/nginx benchmark" in text
    assert "end-to-end evidence before changing the default" in text
