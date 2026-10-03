#!/usr/bin/env bash
# Public synthetic artifacts only. Two DISTINCT binaries: upstream and reference adoption.
set -euo pipefail
if [[ $# != 1 || $(uname -s) != Linux || $(uname -m) != x86_64 ]]; then
  echo 'usage: build-pii-synthetic.sh NEW-ABSOLUTE-DIRECTORY (Linux x86_64)' >&2
  exit 2
fi
out=$1
[[ $out = /* && ! -e $out ]]
repo_root=$(cd -- "$(dirname -- "$0")/../.." && pwd)
mkdir -m 700 -- "$out"
engine_commit=6157cbc5918b3888c8e84b1884719ea8f3278b36
node_sha=fde6a4bf8d0562f7751d1a2d6cb9b417c4cfe107bbcb0aa3e9a24e125e348f48
if [[ -n ${CUSTODIAN_PII_SOURCE_ARCHIVE:-} ]]; then
  # A byte-pinned git archive avoids any credential in the synthetic runner.
  printf '%s  %s\n' e86756f8a556af326c712f1abdaca3624fdae2f59dd924a497791892c2b0b6e1 "$CUSTODIAN_PII_SOURCE_ARCHIVE" | sha256sum --check --status
  mkdir "$out/source"
  tar -xf "$CUSTODIAN_PII_SOURCE_ARCHIVE" -C "$out/source"
else
  git init -q "$out/source"
  git -C "$out/source" fetch -q --depth 1 https://github.com/redact-secret/pii-eval.git "$engine_commit"
  git -C "$out/source" checkout -q --detach FETCH_HEAD
  [[ $(git -C "$out/source" rev-parse HEAD) = "$engine_commit" ]]
fi
curl --fail --silent --show-error --location \
  https://nodejs.org/dist/v22.23.3/node-v22.23.3-linux-x64.tar.xz -o "$out/node.tar.xz"
tar -xJf "$out/node.tar.xz" -C "$out" node-v22.23.3-linux-x64/bin/node
node_bin="$out/node-v22.23.3-linux-x64/bin/node"
printf '%s  %s\n' "$node_sha" "$node_bin" | sha256sum --check --status
(
  cd "$out/source"
  cargo build --release --locked -p pii-eval-cli --bin pii-eval --target-dir "$out/build"
  cp "$out/build/release/pii-eval" "$out/unadopted-pii-eval"
  git apply --check "$repo_root/tools/engines/pii-adoption.patch"
  git apply "$repo_root/tools/engines/pii-adoption.patch"
  cargo fmt --all --check
  cargo clippy --locked -p pii-eval-cli --all-targets -- -D warnings
  cargo test --locked -p pii-eval-cli --lib --test worker_default
  cargo build --release --locked -p pii-eval-cli --bin pii-eval --target-dir "$out/build"
  cp "$out/build/release/pii-eval" "$out/adopted-pii-eval"
  # The helper ONLY authors public synthetic fixtures; it is never the staged engine.
  cargo build --release --locked -p pii-eval-cli --features worker-test-adapters \
    --example worker_test_engine --target-dir "$out/fixture-build"
)
! LC_ALL=C grep -a -q 'pii-eval-worker-test-adapters' "$out/adopted-pii-eval"
for scenario in normal population-mismatch run-class-mismatch wrong-bundle-digest wrong-tree-digest wrong-runtime-digest scanner-crash; do
  "$out/fixture-build/release/examples/worker_test_engine" stage --out "$out/$scenario" \
    --node "$node_bin" --scenario "$scenario" --entries 75 >/dev/null
  cp "$out/adopted-pii-eval" "$out/$scenario/stage/engine"
  # Bind config to the real CLI, not the fixture builder. This is fixture authoring before sealing.
  python3 - "$out/$scenario" <<'PY'
import hashlib, json, pathlib, sys
p = pathlib.Path(sys.argv[1])
config = p / 'stage/config'
v = json.loads(config.read_bytes())
v['artifacts']['engine']['sha256'] = 'sha256:' + hashlib.sha256((p/'stage/engine').read_bytes()).hexdigest()
config.chmod(0o600)
config.write_text(json.dumps(v, separators=(',', ':')))
config.chmod(0o400)
pins = json.loads((p/'pins.json').read_bytes())
for name in ('engine', 'config'):
    pins['pins'][name] = 'sha256:' + hashlib.sha256((p/'stage'/name).read_bytes()).hexdigest()
(p/'pins.json').write_text(json.dumps(pins, separators=(',', ':')))
PY
done
# Record derivation AND file identities. A patched build never inherits the upstream artifact identity.
python3 - "$out" "$engine_commit" "$repo_root/tools/engines/pii-adoption.patch" "$node_sha" <<'PY'
import hashlib, json, pathlib, sys
p=pathlib.Path(sys.argv[1])
def digest(path): return 'sha256:' + hashlib.sha256(path.read_bytes()).hexdigest()
v={'schema':'custodian-pii-synthetic-build/1','upstream_commit':sys.argv[2],
   'adoption_patch':digest(pathlib.Path(sys.argv[3])), 'node_binary':'sha256:'+sys.argv[4],
   'upstream_binary':digest(p/'unadopted-pii-eval'), 'adopted_binary':digest(p/'adopted-pii-eval'),
   'synthetic_only':True, 'deployed':False}
(p/'provenance.json').write_text(json.dumps(v, sort_keys=True)+'\n')
print(json.dumps(v, sort_keys=True))
PY
