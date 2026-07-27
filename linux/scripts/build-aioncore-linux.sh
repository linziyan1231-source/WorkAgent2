#!/usr/bin/env bash
set -euo pipefail

umask 022

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
component_root="$repo_root/components/aioncore"
source_root="${AIONCORE_SOURCE_DIR:-$repo_root/.tools/sources/aioncore}"
managed_root="${AIONCORE_MANAGED_RESOURCES_DIR:-$repo_root/.tools/materials/aioncore-managed-resources-0.1.42-editfork.10-linux-x64}"
cargo_home="${AIONCORE_CARGO_HOME:-$repo_root/.tools/cargo}"
rustup_home="${AIONCORE_RUSTUP_HOME:-$repo_root/.tools/rustup}"
toolchain="1.95.0-x86_64-unknown-linux-gnu"
version="$(tr -d '\r\n' < "$component_root/VERSION")"
build_root="/tmp/workagent-aioncore-release-v1"
source_dir="$build_root/source"
target_dir="$build_root/target"
stage="$build_root/artifact"
smoke_root="$build_root/bundled-smoke"
executable_list="$build_root/executables"
output_dir="${AIONCORE_OUTPUT_DIR:-$repo_root/.tools/artifacts/aioncore-${version}-linux-x64}"
jobs="${AIONCORE_BUILD_JOBS:-4}"
full_tests="${AIONCORE_FULL_TESTS:-1}"
server_pid=""
source_date_epoch="$(tr -d '\r\n' < "$component_root/SOURCE-DATE-EPOCH")"

expected_source="546ce672233f30e4821723c58d91bf6c868632388a3b55114d47c9d06981f317"
expected_cargo_lock="c8bf59bf858f9ee5db372d127bfb78a6cdedcf837584bf4c9d1ead6cfa1c66c9"
expected_managed="4131c117b99b83d1c36980417ba4f9f1d860500e711ad54fea9ae007d7c9d567"
test_attestation="$component_root/TEST-ATTESTATION.json"
expected_test_attestation="e7f2cd6fde3b3d9a65b820e067c59b33325a400ca8b9a5be1b2201f39572935a"

fail() {
  printf 'build-aioncore-linux: %s\n' "$*" >&2
  exit 1
}

hash_of() {
  sha256sum -- "$1" | cut -d' ' -f1
}

canonical_tree_hash() {
  tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner --format=gnu \
    -cf - -C "$1" . | sha256sum | cut -d' ' -f1
}

cleanup() {
  if [[ -n "$server_pid" ]] && kill -0 "$server_pid" 2>/dev/null; then
    kill -TERM "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  for path in "$source_dir" "$target_dir" "$stage" "$smoke_root" "$executable_list"; do
    case "$path" in
      "$build_root"/*) [[ ! -e "$path" && ! -L "$path" ]] || rm -rf -- "$path" ;;
      *) printf 'build-aioncore-linux: refusing unsafe cleanup path: %s\n' "$path" >&2 ;;
    esac
  done
}

[[ "$(uname -s)" == Linux && "$(uname -m)" == x86_64 ]] || fail 'release target must be Linux x86_64'
[[ "$version" == v0.1.42-editfork.10 ]] || fail 'unexpected AionCore version'
[[ "$source_date_epoch" == 1784899380 ]] || fail 'unexpected AionCore SOURCE_DATE_EPOCH'
[[ "$jobs" =~ ^[1-9][0-9]*$ && "$jobs" -le 32 ]] || fail 'AIONCORE_BUILD_JOBS must be an integer from 1 to 32'
[[ "$full_tests" == 0 || "$full_tests" == 1 ]] || fail 'AIONCORE_FULL_TESTS must be 0 or 1'
for command in chmod curl cut env find flock grep install kill mkdir mv readelf realpath rm sed sha256sum sleep sort strings strip tail tar tr wc xargs; do
  command -v "$command" >/dev/null 2>&1 || fail "required command is missing: $command"
done
for directory in "$source_root" "$managed_root" "$cargo_home" "$rustup_home"; do
  [[ "$directory" == /* && -d "$directory" && ! -L "$directory" ]] || fail "input must be an absolute real directory: $directory"
  [[ "$(realpath -m -- "$directory")" == "$directory" ]] || fail "input directory must be canonical: $directory"
done
[[ -f "$component_root/BINARY.sha256" ]] || fail 'approved AionCore binary checksum is missing'
expected_binary="$(cut -d' ' -f1 < "$component_root/BINARY.sha256")"
[[ "$expected_binary" =~ ^[0-9a-f]{64}$ ]] || fail 'approved AionCore binary checksum is invalid'
expected_build_id="$(tr -d '\r\n' < "$component_root/BUILD-ID")"
[[ "$expected_build_id" =~ ^[0-9a-f]{40}$ ]] || fail 'approved AionCore build ID is invalid'
[[ "$output_dir" == /* && "$output_dir" == "$(realpath -m -- "$output_dir")" ]] || fail 'output directory must be absolute and canonical'
[[ ! -e "$output_dir" && ! -L "$output_dir" ]] || fail "output already exists; refusing to overwrite: $output_dir"

[[ -z "$(find "$source_root" -type l -print -quit)" ]] || fail 'AionCore source contains a symbolic link'
[[ -z "$(find "$source_root" ! -type d ! -type f -print -quit)" ]] || fail 'AionCore source contains a special file'
[[ "$(find "$source_root" -type f | wc -l)" == 1396 ]] || fail 'AionCore source file count mismatch'
[[ "$(canonical_tree_hash "$source_root")" == "$expected_source" ]] || fail 'AionCore source-tree checksum mismatch'
[[ "$(hash_of "$source_root/Cargo.lock")" == "$expected_cargo_lock" ]] || fail 'AionCore Cargo.lock checksum mismatch'
(cd "$source_root" && sha256sum --strict --check "$component_root/LICENSE.sha256") >/dev/null || fail 'AionCore license checksum mismatch'
[[ -z "$(find "$managed_root" -type l -print -quit)" ]] || fail 'managed resources contain a symbolic link'
[[ -z "$(find "$managed_root" ! -type d ! -type f -print -quit)" ]] || fail 'managed resources contain a special file'
[[ "$(canonical_tree_hash "$managed_root")" == "$expected_managed" ]] || fail 'managed-resource tree checksum mismatch'
(cd "$managed_root" && sha256sum --strict --check "$component_root/MANAGED-CONTENTS.sha256") >/dev/null || fail 'managed-resource content checks failed'
managed_node="$managed_root/node/node-v24.11.0-linux-x64/bin/node"
managed_codex="$managed_root/acp/codex-acp/0.16.0-aion-fork-steer.6/linux-x64"
managed_codex_entrypoint="$managed_codex/node_modules/@agentclientprotocol/codex-acp/dist/index.js"
[[ "$(hash_of "$managed_codex_entrypoint")" == 53db7dc43339e67ecfff817c35c822c35637695a119e77199b92e4d8ad08bdf9 ]] || fail 'managed Codex ACP patch checksum mismatch'
[[ "$(hash_of "$component_root/codex-acp-1.1.2-aionui-fork-steer.6.patch")" == f52e4ab6d6616df1572282ade8280465c26f842be0d6f8c86b13173e73942879 ]] || fail 'managed Codex ACP patch evidence mismatch'
[[ "$("$managed_node" -p "require('$managed_codex/node_modules/@agentclientprotocol/codex-acp/package.json').version")" == 1.1.2 ]] || fail 'managed Codex ACP version mismatch'
[[ "$("$managed_node" -p "require('$managed_codex/node_modules/@openai/codex/package.json').version")" == 0.144.4 ]] || fail 'managed OpenAI Codex version mismatch'
(cd "$managed_codex" && sha256sum --strict --check "$component_root/CODEX-ACP-LICENSES.sha256") >/dev/null || fail 'managed Codex license evidence mismatch'
"$managed_node" -e 'const fs=require("fs");const p=JSON.parse(fs.readFileSync(process.argv[1],"utf8"));const n=p.components.map((x)=>x.name+"@"+x.version);for(const e of ["node@24.11.0","@agentclientprotocol/codex-acp@1.1.2","@openai/codex@0.144.4","@agentclientprotocol/claude-agent-acp@0.39.0","@anthropic-ai/claude-agent-sdk@0.3.156"]){if(!n.includes(e))process.exit(1)}' \
  "$component_root/MANAGED-COMPONENTS.json" || fail 'managed component inventory mismatch'
[[ -f "$test_attestation" && ! -L "$test_attestation" ]] || fail 'AionCore test attestation is missing or unsafe'
[[ "$(hash_of "$test_attestation")" == "$expected_test_attestation" ]] || fail 'AionCore test attestation checksum mismatch'
"$managed_node" -e 'const fs=require("fs");const p=JSON.parse(fs.readFileSync(process.argv[1],"utf8"));const gates=["ai-agent-package","application-package","auth-package","cron-package","format","runtime-package","strict-clippy","task-manager-regressions","workagent-runtime-boundary"];const actual=Array.isArray(p.records)?p.records.map((r)=>r.gate).sort():[];if(p.schema_version!==1||p.component!=="aioncore"||p.version!=="v0.1.42-editfork.10"||p.source_tree_sha256!=="546ce672233f30e4821723c58d91bf6c868632388a3b55114d47c9d06981f317"||p.completed_at!=="2026-07-27T12:37:47+08:00"||p.result!=="passed"||actual.length!==gates.length||actual.some((gate,index)=>gate!==gates[index])||p.records.some((record)=>record.result!=="passed")){process.exit(1)}' \
  "$test_attestation" || fail 'AionCore test attestation content mismatch'

install -d -m 0700 -- "$build_root"
[[ ! -L "$build_root" && "$build_root" == "$(realpath -m -- "$build_root")" ]] || fail 'canonical build root is unsafe'
exec 9>"$build_root/.lock"
flock -n 9 || fail 'another canonical AionCore build is running'
for path in "$source_dir" "$target_dir" "$stage" "$smoke_root" "$executable_list"; do
  [[ ! -e "$path" && ! -L "$path" ]] || fail "stale canonical build path requires operator review: $path"
done
trap cleanup EXIT INT TERM

mkdir -m 0700 -- "$source_dir" "$target_dir"
(cd "$source_root" && tar -cf - .) | (cd "$source_dir" && tar -xf - --no-same-owner --no-same-permissions)

export PATH="$cargo_home/bin:/usr/local/bin:/usr/bin:/bin"
export CARGO_HOME="$cargo_home"
export RUSTUP_HOME="$rustup_home"
export RUSTUP_TOOLCHAIN="$toolchain"
export CARGO_TARGET_DIR="$target_dir"
export CARGO_NET_OFFLINE=true
export CARGO_INCREMENTAL=0
export SOURCE_DATE_EPOCH="$source_date_epoch"
unset CARGO_ENCODED_RUSTFLAGS
export RUSTFLAGS="--remap-path-prefix=$source_dir=/usr/src/workagent/aioncore --remap-path-prefix=$target_dir=/usr/lib/workagent/aioncore-target --remap-path-prefix=$cargo_home=/usr/lib/workagent/cargo --remap-path-prefix=$rustup_home=/usr/lib/workagent/rustup -C link-arg=-Wl,--build-id=sha1"
export LC_ALL=C
export LANG=C
export TZ=UTC
[[ "$(rustc --version)" == 'rustc 1.95.0 (59807616e 2026-04-14)' ]] || fail 'Rust compiler version mismatch'
rustc -vV | grep -F 'commit-hash: 59807616e1fa2540724bfbac14d7976d7e4a3860' >/dev/null || fail 'Rust compiler revision mismatch'
rustc -vV | grep -F 'host: x86_64-unknown-linux-gnu' >/dev/null || fail 'Rust compiler host mismatch'
[[ "$(cargo --version)" == 'cargo 1.95.0 (f2d3ce0bd 2026-03-21)' ]] || fail 'Cargo version mismatch'

cd "$source_dir"
cargo fmt --check
cargo clippy --workspace --all-targets --locked --offline -- -D warnings
cargo test --locked --offline -p aionui-channel --features weixin sanitizes_incoming_file_names
if [[ "$full_tests" == 1 ]]; then
  cargo test --workspace --locked --offline -- --test-threads=1
fi
cargo build --release --locked --offline -p aionui-app -j "$jobs"

binary="$target_dir/release/aioncore"
[[ -x "$binary" ]] || fail 'AionCore release binary was not produced'
unstripped_binary="$(hash_of "$binary")"
unstripped_size="$(wc -c < "$binary")"
printf 'AionCore unstripped ELF evidence: sha256=%s size=%s\n' "$unstripped_binary" "$unstripped_size"
install -d -m 0755 "$stage/bin" "$stage/share/workagent-components/aioncore"
install -m 0755 "$binary" "$stage/bin/aioncore"
strip --strip-unneeded "$stage/bin/aioncore"
actual_binary="$(hash_of "$stage/bin/aioncore")"
stripped_size="$(wc -c < "$stage/bin/aioncore")"
actual_build_id="$(readelf -n "$stage/bin/aioncore" | sed -n 's/.*Build ID: //p' | tail -n 1)"
if [[ "$actual_binary" != "$expected_binary" || "$actual_build_id" != "$expected_build_id" ]]; then
  fail "final AionCore identity mismatch: expected SHA-256 $expected_binary, got $actual_binary; expected Build ID $expected_build_id, got $actual_build_id"
fi
printf 'AionCore stripped ELF evidence: sha256=%s size=%s build_id=%s\n' \
  "$actual_binary" "$stripped_size" "$actual_build_id"
for leaked_path in "$source_dir" "$target_dir" "$cargo_home" "$rustup_home"; do
  ! strings -a "$stage/bin/aioncore" | grep -F "$leaked_path" >/dev/null || \
    fail "final AionCore binary leaks an unremapped build path: $leaked_path"
done
readelf -h "$stage/bin/aioncore" | grep -F 'Machine:' | grep -F 'Advanced Micro Devices X86-64' >/dev/null || fail 'AionCore architecture mismatch'
[[ "$("$stage/bin/aioncore" --version)" == 'aioncore 0.1.42-editfork.10' ]] || fail 'AionCore version smoke test failed'
"$stage/bin/aioncore" --help | grep -F 'AionUi Backend Server' >/dev/null || fail 'AionCore help smoke test failed'

install -d -m 0755 "$stage/bin/managed-resources"
(cd "$managed_root" && tar -cf - .) | \
  (cd "$stage/bin/managed-resources" && tar -xf - --no-same-owner --no-same-permissions)
[[ "$(canonical_tree_hash "$stage/bin/managed-resources")" == "$expected_managed" ]] || fail 'packaged managed-resource checksum mismatch'

mkdir -m 0700 -- "$smoke_root" "$smoke_root/home" "$smoke_root/data"
env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u http_proxy -u https_proxy -u all_proxy \
  HOME="$smoke_root/home" "$stage/bin/aioncore" --host 127.0.0.1 --port 0 --local \
  --data-dir "$smoke_root/data" --managed-resources-mode bundled > "$smoke_root/server.out" 2>&1 &
server_pid=$!
smoke_ready=0
for ((attempt = 1; attempt <= 240; attempt++)); do
  if grep -F 'startup: managed runtime background preparation completed' "$smoke_root/server.out" >/dev/null 2>&1; then
    smoke_ready=1
    break
  fi
  kill -0 "$server_pid" 2>/dev/null || break
  sleep 0.5
done
if [[ "$smoke_ready" != 1 ]]; then
  tail -n 120 "$smoke_root/server.out" >&2 || true
  fail 'bundled managed-resource activation smoke test failed'
fi
smoke_port="$(sed -n 's/^AIONCORE_LISTENING {"host":"127\.0\.0\.1","port":\([0-9][0-9]*\)}$/\1/p' "$smoke_root/server.out" | tail -n 1)"
[[ "$smoke_port" =~ ^[1-9][0-9]*$ && "$smoke_port" -le 65535 ]] || fail 'AionCore health smoke port is invalid'
health_json="$(curl --fail --silent --show-error --max-time 10 "http://127.0.0.1:$smoke_port/health")"
[[ "$health_json" == '{"status":"ok","version":"0.1.42-editfork.10","build_time":"1784899380"}' ]] || \
  fail "AionCore health response mismatch: $health_json"
printf 'AionCore health evidence: %s\n' "$health_json"
kill -TERM "$server_pid"
wait "$server_pid" || fail 'AionCore did not shut down cleanly after the bundled-resource smoke test'
server_pid=""
grep -F 'Server shut down gracefully' "$smoke_root/server.out" >/dev/null || fail 'AionCore graceful shutdown evidence is missing'

smoke_node="$smoke_root/data/runtime/node/node-v24.11.0-linux-x64"
smoke_codex="$smoke_root/data/runtime/managed-tools/acp/codex-acp/0.16.0-aion-fork-steer.6/linux-x64"
smoke_claude="$smoke_root/data/runtime/managed-tools/acp/claude-agent-acp/0.39.0/linux-x64"
[[ "$(PATH="$smoke_node/bin:/usr/local/bin:/usr/bin:/bin" "$smoke_node/bin/node" --version)" == v24.11.0 ]] || fail 'activated Node smoke test failed'
[[ "$(PATH="$smoke_node/bin:/usr/local/bin:/usr/bin:/bin" "$smoke_node/bin/npm" --version)" == 11.6.1 ]] || fail 'activated npm smoke test failed'
smoke_codex_entrypoint="$smoke_codex/node_modules/@agentclientprotocol/codex-acp/dist/index.js"
[[ "$(hash_of "$smoke_codex_entrypoint")" == 53db7dc43339e67ecfff817c35c822c35637695a119e77199b92e4d8ad08bdf9 ]] || fail 'activated Codex ACP patch checksum mismatch'
[[ "$("$smoke_node/bin/node" -p "require('$smoke_codex/node_modules/@agentclientprotocol/codex-acp/package.json').version")" == 1.1.2 ]] || fail 'activated Codex ACP version mismatch'
[[ "$("$smoke_node/bin/node" -p "require('$smoke_codex/node_modules/@openai/codex/package.json').version")" == 0.144.4 ]] || fail 'activated managed Codex version mismatch'
"$smoke_node/bin/node" --check "$smoke_codex_entrypoint"
"$smoke_node/bin/node" --check "$smoke_codex/node_modules/@openai/codex/bin/codex.js"
[[ "$("$smoke_node/bin/node" "$smoke_codex/node_modules/@openai/codex/bin/codex.js" --version)" == 'codex-cli 0.144.4' ]] || fail 'activated managed Codex executable smoke test failed'
"$smoke_node/bin/node" "$component_root/tests/codex-acp-wire-smoke.mjs" "$smoke_node/bin/node" "$smoke_codex"
(cd "$smoke_codex" && sha256sum --strict --check "$component_root/CODEX-ACP-LICENSES.sha256") >/dev/null || fail 'activated Codex ACP license evidence mismatch'
"$smoke_node/bin/node" --check "$smoke_claude/node_modules/@agentclientprotocol/claude-agent-acp/dist/index.js"

install -m 0444 "$component_root/VERSION" "$component_root/SOURCE" "$component_root/SOURCE.sha256" \
  "$component_root/CARGO-LOCK.sha256" "$component_root/RUST-TOOLCHAIN" "$component_root/NODE-ARCHIVE.sha256" \
  "$component_root/MANAGED-RESOURCES-SOURCE" "$component_root/MANAGED-RESOURCES.sha256" \
  "$component_root/MANAGED-CONTENTS.sha256" "$component_root/MANAGED-COMPONENTS.json" \
  "$component_root/MANAGED-REPRODUCIBILITY" \
  "$component_root/CODEX-ACP-RAW.sha256" "$component_root/CODEX-ACP-INPUTS.sha256" \
  "$component_root/CODEX-ACP-PATCH.sha256" "$component_root/CODEX-ACP-LICENSES.sha256" \
  "$component_root/CODEX-ACP-WINDOWS-REFERENCE" "$component_root/codex-acp-1.1.2-aionui-fork-steer.6.patch" \
  "$component_root/BINARY.sha256" "$component_root/SOURCE-DATE-EPOCH" \
  "$component_root/LICENSE.sha256" "$component_root/BUILD-ID" "$component_root/REPRODUCIBILITY" \
  "$component_root/TEST-ATTESTATION.json" \
  "$source_root/LICENSE" \
  "$stage/share/workagent-components/aioncore/"
install -d -m 0755 \
  "$stage/share/workagent-components/aioncore/managed-licenses/node" \
  "$stage/share/workagent-components/aioncore/managed-licenses/codex-acp" \
  "$stage/share/workagent-components/aioncore/managed-licenses/openai-codex" \
  "$stage/share/workagent-components/aioncore/managed-licenses/claude-agent-acp" \
  "$stage/share/workagent-components/aioncore/managed-licenses/claude-agent-sdk" \
  "$stage/share/workagent-components/aioncore/tests"
for managed_license in node codex-acp openai-codex claude-agent-acp claude-agent-sdk; do
  install -m 0444 "$component_root/managed-licenses/$managed_license/LICENSE-SOURCE" \
    "$component_root/managed-licenses/$managed_license/LICENSE.sha256" \
    "$stage/share/workagent-components/aioncore/managed-licenses/$managed_license/"
done
install -m 0444 "$managed_root/node/node-v24.11.0-linux-x64/LICENSE" \
  "$stage/share/workagent-components/aioncore/managed-licenses/node/LICENSE"
install -m 0444 "$managed_root/acp/codex-acp/0.16.0-aion-fork-steer.6/linux-x64/LICENSE" \
  "$stage/share/workagent-components/aioncore/managed-licenses/codex-acp/LICENSE"
install -m 0444 "$managed_root/acp/codex-acp/0.16.0-aion-fork-steer.6/linux-x64/LICENSE.openai-codex" \
  "$stage/share/workagent-components/aioncore/managed-licenses/openai-codex/LICENSE.openai-codex"
install -m 0444 "$managed_root/acp/claude-agent-acp/0.39.0/linux-x64/node_modules/@agentclientprotocol/claude-agent-acp/LICENSE" \
  "$stage/share/workagent-components/aioncore/managed-licenses/claude-agent-acp/LICENSE"
install -m 0444 "$managed_root/acp/claude-agent-acp/0.39.0/linux-x64/node_modules/@anthropic-ai/claude-agent-sdk/LICENSE.md" \
  "$stage/share/workagent-components/aioncore/managed-licenses/claude-agent-sdk/LICENSE.md"
install -m 0444 "$component_root/tests/codex-acp-wire-smoke.mjs" \
  "$stage/share/workagent-components/aioncore/tests/"
test_status='passed'
test_evidence='pinned-exact-source-attestation'
[[ "$full_tests" == 0 ]] || test_evidence='canonical-build-and-pinned-source-attestation'
printf '%s\n' \
  '{' \
  '  "schema_version": 1,' \
  '  "component": "aioncore",' \
  '  "version": "v0.1.42-editfork.10",' \
  '  "platform": "x86_64-unknown-linux-gnu",' \
  '  "source_tree_sha256": "546ce672233f30e4821723c58d91bf6c868632388a3b55114d47c9d06981f317",' \
  "  \"source_date_epoch\": $source_date_epoch," \
  '  "license_file": "LICENSE",' \
  "  \"binary_sha256\": \"$expected_binary\"," \
  "  \"gnu_build_id\": \"$actual_build_id\"," \
  '  "managed_resources_sha256": "4131c117b99b83d1c36980417ba4f9f1d860500e711ad54fea9ae007d7c9d567",' \
  '  "managed_codex_acp_version": "1.1.2",' \
  '  "managed_codex_version": "0.144.4",' \
  '  "managed_codex_acp_protocol_gate": "passed",' \
  '  "reproducibility_qualification": "two-clean-canonical-builds-byte-identical",' \
  "  \"workspace_test_suite\": \"$test_status\"," \
  "  \"workspace_test_evidence\": \"$test_evidence\"," \
  "  \"workspace_test_attestation_sha256\": \"$expected_test_attestation\"" \
  '}' > "$stage/share/workagent-components/aioncore/BUILD-INFO.json"

(cd "$stage" && find . -type f ! -path './share/workagent-components/aioncore/SHA256SUMS' -print0 | \
  LC_ALL=C sort -z | xargs -0 sha256sum > share/workagent-components/aioncore/SHA256SUMS)
find "$stage" -type f -perm /111 -printf '%P\0' | LC_ALL=C sort -z > "$executable_list"
find "$stage" -type f -exec chmod 0444 {} +
(cd "$stage" && xargs -0 -r chmod 0555 -- < "$executable_list")
find "$stage" -type d -exec chmod 0555 {} +
[[ -z "$(find "$stage" -type l -print -quit)" ]] || fail 'AionCore payload contains a symbolic link'
[[ -z "$(find "$stage" ! -type d ! -type f -print -quit)" ]] || fail 'AionCore payload contains a special file'
[[ -z "$(find "$stage" -perm /022 -print -quit)" ]] || fail 'AionCore payload contains a group/other-writable entry'

mkdir -p -- "$(dirname "$output_dir")"
mv -- "$stage" "$output_dir"
printf 'AionCore %s Linux release: %s\n' "$version" "$output_dir"
sha256sum "$output_dir/bin/aioncore"
