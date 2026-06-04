# Performance Report Artifacts

Remote benchmark reports live here when a performance default changes. Generate
them with `scripts/benchmark_remote_e2e.py --output-json docs/perf/remote-<timestamp>.json`.

Do not hand-write reports. They must be produced by the remote benchmark script so
they include the schema version, protocol version, requested parameters,
negotiated windows, aggregate results, and raw samples. The report writer omits
token values and token-file paths.

The current mux flow-window default stays at 256 KiB unless a remote report in
this directory covers the candidate default window and the docs explain the
memory/throughput tradeoff.
