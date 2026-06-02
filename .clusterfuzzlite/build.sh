#!/bin/bash -eu

PROJECT="$SRC/chute"

python3 -m pip install --upgrade pip
python3 -m pip install --require-hashes -r "$PROJECT/deploy/requirements.txt"
python3 -m pip install --no-deps "$PROJECT"
python3 -m pip install atheris==3.0.0 pyinstaller==6.20.0

for fuzzer in "$PROJECT"/fuzz/*_fuzzer.py; do
  fuzzer_basename="$(basename -s .py "$fuzzer")"
  fuzzer_package="${fuzzer_basename}_pkg"
  target="${fuzzer_basename%_fuzzer}"

  pyinstaller --distpath "$OUT" --onefile --name "$fuzzer_package" "$fuzzer"

  cat >"$OUT/$fuzzer_basename" <<EOF
#!/bin/sh
# LLVMFuzzerTestOneInput
this_dir=\$(dirname "\$0")
exec "\$this_dir/$fuzzer_package" "\$@"
EOF
  chmod +x "$OUT/$fuzzer_basename"

  if [ -d "$PROJECT/fuzz/corpus/$target" ] && command -v zip >/dev/null 2>&1; then
    (cd "$PROJECT/fuzz/corpus/$target" && zip -qr "$OUT/${fuzzer_basename}_seed_corpus.zip" .)
  fi
done
