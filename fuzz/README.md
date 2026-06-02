# Chute fuzzing

Fuzzing is CI-only and has no deployment privileges.

Layers:

- `tests/test_fuzz_mux.py`: Hypothesis structure/state fuzzing for mux invariants.
- `fuzz/*_fuzzer.py`: Atheris coverage-guided byte fuzzers for parser and mux targets.
- `.clusterfuzzlite/`: ClusterFuzzLite build integration for managed corpus/batch fuzzing.

macOS setup:

```bash
brew install llvm
export CLANG_BIN="$(brew --prefix llvm)/bin/clang"
uv sync --locked --extra dev --extra fuzz
```

Bounded local Atheris run:

```bash
uv run --extra fuzz python -m fuzz.run_atheris --runs 1000
```

Apple Clang does not ship libFuzzer; use Homebrew LLVM's clang when building
`atheris`.

ClusterFuzzLite local container build:

```bash
git clone --depth=1 https://github.com/google/oss-fuzz.git /tmp/oss-fuzz
python3 /tmp/oss-fuzz/infra/helper.py build_image --external --architecture x86_64 --pull "$PWD"
python3 /tmp/oss-fuzz/infra/helper.py build_fuzzers --external --architecture x86_64 --sanitizer address --clean "$PWD" "$PWD"
python3 /tmp/oss-fuzz/infra/helper.py run_fuzzer --external --architecture x86_64 --sanitizer address "$PWD" request_head_fuzzer -- -runs=100
```

The fuzzer contract is simple: expected parser rejects are caught, while any other
exception is a bug.
