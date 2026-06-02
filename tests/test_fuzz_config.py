from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_fuzz_workflow_is_separate_from_deploy_secrets() -> None:
    workflow = (ROOT / ".github" / "workflows" / "fuzz.yml").read_text()

    assert "pull_request_target" not in workflow
    assert "environment:" not in workflow
    assert "DEPLOY_" not in workflow
    assert "production" not in workflow
    assert "permissions:\n  contents: read" in workflow
    assert "persist-credentials: false" in workflow
    assert "workflow_dispatch:" in workflow
    assert "schedule:" in workflow
    assert (
        "google/clusterfuzzlite/actions/build_fuzzers@884713a6c30a92e5e8544c39945cd7cb630abcd1"
        in workflow
    )
    assert (
        "google/clusterfuzzlite/actions/run_fuzzers@884713a6c30a92e5e8544c39945cd7cb630abcd1"
        in workflow
    )


def test_clusterfuzzlite_build_config_exists() -> None:
    assert (ROOT / ".clusterfuzzlite" / "project.yaml").read_text() == "language: python\n"
    dockerfile = (ROOT / ".clusterfuzzlite" / "Dockerfile").read_text()
    build = (ROOT / ".clusterfuzzlite" / "build.sh").read_text()

    assert "FROM gcr.io/oss-fuzz-base/base-builder-python" in dockerfile
    assert "COPY . $SRC/chute" in dockerfile
    assert "pyinstaller" in build
    assert "*_fuzzer.py" in build
    assert "seed_corpus.zip" in build


def test_clusterfuzzlite_build_script_is_valid_bash() -> None:
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is not installed")

    result = subprocess.run(
        [bash, "-n", str(ROOT / ".clusterfuzzlite" / "build.sh")],
        check=False,
        text=True,
        capture_output=True,
    )
    assert result.returncode == 0, result.stderr
