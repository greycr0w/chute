from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FUZZERS = {
    "protocol_decode": "fuzz.protocol_decode_fuzzer",
    "request_head": "fuzz.request_head_fuzzer",
    "host_label": "fuzz.host_label_fuzzer",
    "mux_frames": "fuzz.mux_frames_fuzzer",
    "policy_json": "fuzz.policy_json_fuzzer",
}


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run chute Atheris fuzz targets for bounded CI runs."
    )
    parser.add_argument("--runs", type=int, default=1000)
    parser.add_argument("--target", choices=sorted(FUZZERS) + ["all"], default="all")
    args = parser.parse_args()

    targets = sorted(FUZZERS) if args.target == "all" else [args.target]
    with tempfile.TemporaryDirectory(prefix="chute-fuzz-") as tmp:
        tmp_root = Path(tmp)
        for target in targets:
            seed_dir = ROOT / "fuzz" / "corpus" / target
            corpus_dir = tmp_root / target
            if seed_dir.exists():
                shutil.copytree(seed_dir, corpus_dir)
            else:
                corpus_dir.mkdir()
            cmd = [
                sys.executable,
                "-m",
                FUZZERS[target],
                str(corpus_dir),
                f"-atheris_runs={args.runs}",
            ]
            dictionary = ROOT / "fuzz" / "dictionaries" / f"{target}.dict"
            if dictionary.exists():
                cmd.append(f"-dict={dictionary}")
            subprocess.run(cmd, cwd=ROOT, check=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
