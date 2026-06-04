# Chute fuzzing

Fuzzing protects chute core where normal examples are weakest: byte parsers,
stateful mux accounting, and self-hosted policy JSON. It is deliberately separate
from deploy and cloud machinery. The fuzz workflow has no deployment privileges,
no production environment, and read-only repository permissions.

## Why this shape

chute is Python, but its risk is mostly protocol-shaped rather than business-logic
shaped:

| Surface | Why it matters | Fuzzing layer |
|---|---|---|
| HTTP request head and `Host` parsing | Public visitor input decides routing and rejection. | Atheris byte fuzzing plus example parser tests. |
| Protocol frame decoder | Agent control input is binary and must fail closed on malformed frames. | Atheris byte fuzzing plus Hypothesis decoder property. |
| Mux frame/state machine | Stream teardown, flow control, and buffer counters are stateful. | Hypothesis stateful/structured fuzzing plus Atheris generated frame sequences. |
| Static policy JSON | OSS self-hosted operators can use this without writing code; parser bugs can weaken admission or revocation policy. | Atheris byte fuzzing with valid/invalid seed corpus. |

The division is intentional:

- **Atheris/libFuzzer** is for coverage-guided mutation of byte inputs. The
  fuzzer contract is simple: expected parser rejects are caught, while any other
  exception is a bug.
- **Hypothesis** is for structured properties and stateful invariants, especially
  mux accounting invariants that random bytes alone do not express well.
- **ClusterFuzzLite** packages the same Atheris entrypoints for PR code-change
  fuzzing and scheduled batch fuzzing with seed corpora.
- **Per-target dictionaries** give libFuzzer useful tokens for HTTP, JSON, Host
  names, and mux/protocol frame bytes. They are used by the local runner and
  copied into ClusterFuzzLite output next to each packaged fuzzer.

This is not a substitute for deterministic regression tests. Fuzzing finds new
weird cases; minimized crashes should be committed back as normal regression tests
and, when useful, as seed corpus files.

## Targets

- `protocol_decode_fuzzer`: arbitrary protocol frame bytes.
- `request_head_fuzzer`: arbitrary HTTP request-head bytes with and without Host
  required.
- `host_label_fuzzer`: arbitrary ASCII/byte host strings against host-routed label
  extraction.
- `mux_frames_fuzzer`: byte-generated mux frame sequences with accounting
  invariants after the mux closes.
- `policy_json_fuzzer`: arbitrary UTF-8 JSON bytes against the static policy parser
  and accepted-policy invariants.

Seed corpora live under `fuzz/corpus/<target>/`; dictionaries live under
`fuzz/dictionaries/<target>.dict`. Keep them small and semantic: one file per
boundary case beats a huge opaque dump, and one token per grammar concept beats a
long generated dictionary.

## Local runs

The normal dev venv follows `.python-version` and currently uses Python 3.13.
Atheris works most reliably through the CI-shaped Python 3.11 fuzz environment.
Use a separate uv environment so local fuzzing does not replace `.venv`.

macOS setup:

```bash
brew install llvm
export CLANG_BIN="$(brew --prefix llvm)/bin/clang"
```

Bounded local Atheris run, all targets:

```bash
UV_PROJECT_ENVIRONMENT=/tmp/chute-fuzz-venv \
CLANG_BIN="${CLANG_BIN:-$(brew --prefix llvm)/bin/clang}" \
uv run --locked --extra dev --extra fuzz --python 3.11 \
  python -m fuzz.run_atheris --runs 1000
```

Apple Clang does not ship libFuzzer; use Homebrew LLVM's clang when building
`atheris`.

Run one target:

```bash
UV_PROJECT_ENVIRONMENT=/tmp/chute-fuzz-venv \
CLANG_BIN="${CLANG_BIN:-$(brew --prefix llvm)/bin/clang}" \
uv run --locked --extra dev --extra fuzz --python 3.11 \
  python -m fuzz.run_atheris --target policy_json --runs 10000
```

Run structured fuzz tests:

```bash
HYPOTHESIS_PROFILE=ci-deep .venv/bin/python -m pytest -q \
  tests/test_fuzz_mux.py tests/test_fuzz_harnesses.py tests/test_host_parsing.py
```

Clean the temporary fuzz venv when done:

```bash
rm -rf /tmp/chute-fuzz-venv
```

## CI

`.github/workflows/fuzz.yml` runs:

- pull request / main push: Hypothesis profile `chute` plus 1,000 Atheris runs
  per target.
- scheduled / manual: Hypothesis profile `ci-deep` plus 10,000 Atheris runs per
  target.
- pull request: ClusterFuzzLite code-change fuzzing for 600 seconds.
- scheduled / manual: ClusterFuzzLite batch fuzzing for 3,600 seconds.

ClusterFuzzLite local container build:

```bash
git clone --depth=1 https://github.com/google/oss-fuzz.git /tmp/oss-fuzz
python3 /tmp/oss-fuzz/infra/helper.py build_image --external --architecture x86_64 --pull "$PWD"
python3 /tmp/oss-fuzz/infra/helper.py build_fuzzers --external --architecture x86_64 --sanitizer address --clean "$PWD" "$PWD"
python3 /tmp/oss-fuzz/infra/helper.py run_fuzzer --external --architecture x86_64 --sanitizer address "$PWD" request_head_fuzzer -- -runs=100
```
