# Performance Notes

Chute performance changes should start from measurements, not from a bigger
constant. The mux `flow_window` is receiver resource policy: raising it can improve
single-stream throughput on high bandwidth-delay-product paths, but it also raises
per-stream buffering headroom and the memory a stalled peer can pin before local
backstops fire.

The protocol basis is the same tradeoff HTTP/2 documents for flow control: windows
protect receiver resources, but windows that are too small can leave available
bandwidth idle on large-RTT links. The sizing math is bandwidth-delay product
(`bandwidth * RTT`).

## Mux-only flow-window benchmark

`scripts/benchmark_flow_window.py` isolates chute's mux credit behavior with an
in-memory WebSocket pair and simulated RTT. It does not measure TLS, kernel TCP,
nginx, the public HTTP parser, local-app behavior, or a real VPS path. Treat it as
evidence for the application credit window only.

Saved remote benchmark reports that justify a future default change belong in
`docs/perf/`; see `docs/perf/README.md` for the artifact rule.

Representative local run on 2026-06-03:

```bash
.venv/bin/python scripts/benchmark_flow_window.py \
  --windows 256k,1m,4m \
  --rtts-ms 10,50,100 \
  --bytes 16m \
  --target-mbps 1000 \
  --runs 3
```

| rtt_ms | window | runs | MiB/s median | MiB/s min..max | window/RTT MiB/s | target BDP | window/BDP |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 10 | 256 KiB | 3 | 18.08 | 17.36..18.76 | 25.00 | 1.19 MiB | 0.21 |
| 10 | 1 MiB | 3 | 70.94 | 65.70..72.08 | 100.00 | 1.19 MiB | 0.84 |
| 10 | 4 MiB | 3 | 270.45 | 259.25..273.21 | 400.00 | 1.19 MiB | 3.36 |
| 50 | 256 KiB | 3 | 4.54 | 4.53..4.55 | 5.00 | 5.96 MiB | 0.04 |
| 50 | 1 MiB | 3 | 18.37 | 18.18..18.44 | 20.00 | 5.96 MiB | 0.17 |
| 50 | 4 MiB | 3 | 76.57 | 76.42..79.26 | 80.00 | 5.96 MiB | 0.67 |
| 100 | 256 KiB | 3 | 2.39 | 2.39..2.39 | 2.50 | 11.92 MiB | 0.02 |
| 100 | 1 MiB | 3 | 9.69 | 9.69..9.72 | 10.00 | 11.92 MiB | 0.08 |
| 100 | 4 MiB | 3 | 42.06 | 41.69..42.95 | 40.00 | 11.92 MiB | 0.34 |

## Interpretation

The 256 KiB default remains a conservative baseline. It keeps memory policy small
and is adequate for interactive HTTP, webhook, and small-object traffic. It is not
a high-BDP bulk-transfer default: at 100 ms RTT, the mux-only ceiling is about
2.5 MiB/s for one stream, before any real-network overhead.

## Loopback end-to-end tunnel benchmark

`scripts/benchmark_e2e_loopback.py` launches a real Server, a real Tunnel agent,
and a local HTTP app in one process. It measures the full local visitor path
through the public listener, mux, agent, and local app. This is stronger evidence
than the mux-only benchmark for local tunnel overhead, but it is still loopback
only and not a WAN/VPS/nginx benchmark.

Representative local run on 2026-06-03:

```bash
.venv/bin/python scripts/benchmark_e2e_loopback.py \
  --windows 256k,1m,4m \
  --directions download,upload \
  --bytes 8m \
  --runs 3 \
  --warmup-runs 1
```

| direction | window | negotiated | runs | bytes | MiB/s median | MiB/s min..max |
|---|---:|---:|---:|---:|---:|---:|
| download | 256 KiB | 256 KiB | 3 | 8 MiB | 251.49 | 183.86..254.79 |
| upload | 256 KiB | 256 KiB | 3 | 8 MiB | 263.91 | 256.81..266.48 |
| download | 1 MiB | 1 MiB | 3 | 8 MiB | 313.89 | 301.40..329.22 |
| upload | 1 MiB | 1 MiB | 3 | 8 MiB | 284.43 | 266.58..329.64 |
| download | 4 MiB | 4 MiB | 3 | 8 MiB | 323.47 | 150.69..329.50 |
| upload | 4 MiB | 4 MiB | 3 | 8 MiB | 326.95 | 324.42..330.41 |

This loopback run shows the full local relay path moving hundreds of MiB/s on
this machine, and that local CPU/scheduling noise can dominate individual samples.
It is not a WAN/VPS/nginx proof and does not contradict the mux-only RTT matrix:
on a real high-BDP path, the credit window can still be the single-stream ceiling.

## Remote end-to-end tunnel benchmark

`scripts/benchmark_remote_e2e.py` starts the same local benchmark HTTP app, opens
a real Tunnel agent to an existing relay, waits for the relay-provided public URL,
and sends download/upload requests through that URL. This is the benchmark to run
against a real VPS/nginx/TLS deployment before changing the default flow window.

Store the relay token in a private file rather than passing it on the command
line:

```bash
install -m 600 /dev/null ~/.config/chute/token
printf '%s\n' "$CHUTE_TOKEN" > ~/.config/chute/token
unset CHUTE_TOKEN
```

Representative command for a deployed relay:

```bash
CHUTE_TOKEN_FILE=~/.config/chute/token \
.venv/bin/python scripts/benchmark_remote_e2e.py \
  --server tunnel.example.com \
  --server-cert ~/.config/chute/control-cert.pem \
  --scheme https \
  --subdomain bench-$(date +%s) \
  --windows 256k,1m,4m \
  --directions download,upload \
  --bytes 8m \
  --runs 3 \
  --warmup-runs 1 \
  --output-json docs/perf/remote-$(date +%Y%m%dT%H%M%SZ).json
```

This remote run is the first benchmark in the chain that includes the real public
network path. It still reports per-scenario medians and raw samples, so outliers
are visible instead of hidden behind one lucky request. `--output-json` writes a
self-describing report with run parameters, protocol version, aggregate results,
and raw samples; token values and token-file paths are intentionally omitted.
Treat remote end-to-end evidence as required before changing the default.

For high-RTT bulk transfer, set `CHUTE_MUX_FLOW_WINDOW` on both agent and server
and verify with an end-to-end profile. A 4 MiB window materially improves the
mux-only ceiling but still underfills a 1 Gbps, 100 ms path by BDP math. Moving the
global default should wait for real VPS measurements across TLS/nginx/local-app
paths and a memory budget decision for concurrent streams. In other words, collect
end-to-end evidence before changing the default.
