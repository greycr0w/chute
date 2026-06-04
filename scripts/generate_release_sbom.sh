#!/usr/bin/env bash
# Generate a release runtime SBOM from the built wheel installed with the same
# hash-pinned runtime dependency set production deploys consume.
set -euo pipefail

DIST_DIR="${1:-dist}"
SBOM_OUT="$DIST_DIR/chute-runtime-sbom.cdx.json"
SBOM_VENV="$(mktemp -d "${TMPDIR:-/tmp}/chute-sbom-venv.XXXXXX")"

cleanup() {
  rm -rf "$SBOM_VENV"
}
trap cleanup EXIT

python_bin="$SBOM_VENV/bin/python"

uv venv "$SBOM_VENV"
uv pip install --python "$python_bin" --require-hashes -r deploy/requirements.txt
uv pip install --python "$python_bin" --no-build-isolation --no-deps "$DIST_DIR"/*.whl
uv run --no-sync cyclonedx-py environment "$SBOM_VENV" \
  --pyproject pyproject.toml \
  --mc-type library \
  --output-reproducible \
  --of JSON \
  -o "$SBOM_OUT"

printf 'wrote %s\n' "$SBOM_OUT"
