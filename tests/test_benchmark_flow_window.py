from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "benchmark_flow_window.py"
_ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location("benchmark_flow_window", _SCRIPT)
assert _SPEC is not None and _SPEC.loader is not None
benchmark_flow_window = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = benchmark_flow_window
_SPEC.loader.exec_module(benchmark_flow_window)


def test_flow_window_benchmark_parses_byte_and_rtt_lists() -> None:
    assert benchmark_flow_window._parse_size_list("256k,1m,1.5m") == [
        256 * 1024,
        1024 * 1024,
        int(1.5 * 1024 * 1024),
    ]
    assert benchmark_flow_window._parse_rtt_list("0,12.5,100") == [0.0, 12.5, 100.0]
    with pytest.raises(Exception, match="positive"):
        benchmark_flow_window._parse_size("0")
    with pytest.raises(Exception, match="at least 1 byte"):
        benchmark_flow_window._parse_size("0.5")
    with pytest.raises(Exception, match="RTT"):
        benchmark_flow_window._parse_rtt_list("-1")


def test_flow_window_benchmark_bdp_math() -> None:
    # 100 Mbps * 50 ms = 5 Mbit = 625,000 bytes.
    assert benchmark_flow_window.target_bdp_bytes(100, 50) == 625_000


def test_flow_window_benchmark_aggregates_repeated_samples() -> None:
    samples = [
        benchmark_flow_window.BenchmarkResult(
            rtt_ms=50,
            window_bytes=1024,
            payload_bytes=4096,
            chunk_bytes=512,
            elapsed_s=elapsed,
            throughput_mib_s=throughput,
            window_limited_mib_s=1.0,
            delivered_bytes=4096,
            target_mbps=10,
            target_bdp_bytes=62_500,
            window_to_target_bdp=1024 / 62_500,
            payload_to_window=4,
        )
        for elapsed, throughput in ((3.0, 11.0), (1.0, 33.0), (2.0, 22.0))
    ]

    aggregate = benchmark_flow_window.aggregate_results(samples)

    assert aggregate.runs == 3
    assert aggregate.elapsed_s_median == 2.0
    assert aggregate.elapsed_s_min == 1.0
    assert aggregate.elapsed_s_max == 3.0
    assert aggregate.throughput_mib_s_median == 22.0
    assert aggregate.throughput_mib_s_min == 11.0
    assert aggregate.throughput_mib_s_max == 33.0
    assert aggregate.samples == tuple(samples)


def test_flow_window_benchmark_rejects_mixed_or_empty_aggregate_samples() -> None:
    first = benchmark_flow_window.BenchmarkResult(
        rtt_ms=50,
        window_bytes=1024,
        payload_bytes=4096,
        chunk_bytes=512,
        elapsed_s=1,
        throughput_mib_s=1,
        window_limited_mib_s=1,
        delivered_bytes=4096,
        target_mbps=None,
        target_bdp_bytes=None,
        window_to_target_bdp=None,
        payload_to_window=4,
    )
    second = benchmark_flow_window.BenchmarkResult(
        rtt_ms=100,
        window_bytes=1024,
        payload_bytes=4096,
        chunk_bytes=512,
        elapsed_s=1,
        throughput_mib_s=1,
        window_limited_mib_s=1,
        delivered_bytes=4096,
        target_mbps=None,
        target_bdp_bytes=None,
        window_to_target_bdp=None,
        payload_to_window=4,
    )

    with pytest.raises(ValueError, match="at least one"):
        benchmark_flow_window.aggregate_results(())
    with pytest.raises(ValueError, match="same scenario"):
        benchmark_flow_window.aggregate_results((first, second))


async def test_flow_window_benchmark_tiny_run_reports_schema() -> None:
    result = await benchmark_flow_window.run_benchmark(
        flow_window=1024,
        rtt_ms=1,
        payload_bytes=4096,
        chunk_bytes=512,
        target_mbps=10,
    )

    assert result.delivered_bytes == 4096
    assert result.window_bytes == 1024
    assert result.throughput_mib_s > 0
    assert result.window_limited_mib_s > 0
    assert result.target_bdp_bytes == 1250
    assert result.window_to_target_bdp == pytest.approx(1024 / 1250)
    assert result.payload_to_window == pytest.approx(4)


async def test_flow_window_benchmark_matrix_repeats_and_reports_aggregate() -> None:
    results = await benchmark_flow_window.run_matrix(
        windows=[1024],
        rtts_ms=[1],
        payload_bytes=4096,
        chunk_bytes=512,
        target_mbps=10,
        runs=2,
    )

    assert len(results) == 1
    aggregate = results[0]
    assert aggregate.runs == 2
    assert len(aggregate.samples) == 2
    assert aggregate.delivered_bytes == 4096
    assert aggregate.throughput_mib_s_median > 0

    with pytest.raises(ValueError, match="runs"):
        await benchmark_flow_window.run_matrix(
            windows=[1024],
            rtts_ms=[1],
            payload_bytes=4096,
            chunk_bytes=512,
            target_mbps=10,
            runs=0,
        )


def test_flow_window_performance_doc_states_scope_and_default_policy() -> None:
    text = (_ROOT / "docs" / "PERFORMANCE.md").read_text()

    assert "scripts/benchmark_flow_window.py" in text
    assert "--runs 3" in text
    assert "mux-only" in text.lower()
    for omitted_scope in ("TLS", "kernel TCP", "nginx", "real VPS"):
        assert omitted_scope in text
    assert "bandwidth-delay product" in text
    assert "256 KiB default remains a conservative baseline" in text
    assert "end-to-end" in text and "before changing" in text
    assert "CHUTE_MUX_FLOW_WINDOW" in text


@pytest.mark.parametrize(
    ("override", "match"),
    [
        ({"rtt_ms": -1}, "rtt_ms"),
        ({"payload_bytes": 0}, "payload_bytes"),
        ({"chunk_bytes": 0}, "chunk_bytes"),
        ({"target_mbps": 0}, "target_mbps"),
    ],
)
async def test_flow_window_benchmark_rejects_invalid_runtime_inputs(
    override: dict[str, object],
    match: str,
) -> None:
    args = {
        "flow_window": 1024,
        "rtt_ms": 1,
        "payload_bytes": 4096,
        "chunk_bytes": 512,
        "target_mbps": 10,
    }
    args.update(override)

    with pytest.raises(ValueError, match=match):
        await benchmark_flow_window.run_benchmark(**args)
