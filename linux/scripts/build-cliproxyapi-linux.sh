#!/usr/bin/env bash
set -euo pipefail

umask 022

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
component_root="$repo_root/components/cliproxyapi"
third_party_root="$repo_root/third_party/cliproxyapi"
core_archive="${CLIPROXYAPI_SOURCE_ARCHIVE:-$repo_root/.tools/downloads/cliproxyapi-7.2.81-per-key-models.4-source.tar.gz}"
policy_archive="${CPA_POLICY_SOURCE_ARCHIVE:-$repo_root/.tools/downloads/cpa-key-policy-0.4.4-src.tar.gz}"
output_dir="${CLIPROXYAPI_OUTPUT_DIR:-$repo_root/.tools/artifacts/cliproxyapi-7.2.81-per-key-models.4-cpa-0.4.5-linux-x64}"
go_binary="${GO_BIN:-go}"
node_binary="${NODE_BIN:-node}"
npm_binary="${NPM_BIN:-npm}"

fail() {
  printf 'build-cliproxyapi-linux: %s\n' "$*" >&2
  exit 1
}

hash_of() {
  sha256sum -- "$1" | cut -d' ' -f1
}

normalized_text_hash() {
  tr -d '\r' < "$1" | sha256sum | cut -d' ' -f1
}

[[ "$(uname -s)" == Linux && "$(uname -m)" == x86_64 ]] || fail 'release target must be Linux x86_64'
for command in chmod cmp cut dirname file find gcc git grep install ldd mkdir mktemp mv nm patch readelf realpath sed sha256sum sort tar tr xargs; do
  command -v "$command" >/dev/null 2>&1 || fail "required command is missing: $command"
done
go_binary="$(command -v -- "$go_binary")"
go_binary="$(readlink -f -- "$go_binary")"
node_binary="$(command -v -- "$node_binary")"
node_binary="$(readlink -f -- "$node_binary")"
npm_binary="$(command -v -- "$npm_binary")"
tool_path="$(dirname -- "$go_binary"):$(dirname -- "$node_binary"):$(dirname -- "$npm_binary")"
export PATH="$tool_path:$PATH"
[[ "$($go_binary version)" == 'go version go1.26.5 linux/amd64' ]] || fail 'Go 1.26.5 linux/amd64 is required'
[[ "$($node_binary --version)" == 'v20.20.0' ]] || fail 'Node.js 20.20.0 is required for the policy web build'
[[ "$($npm_binary --version)" == '10.8.2' ]] || fail 'npm 10.8.2 is required for the policy web build'

for archive in "$core_archive" "$policy_archive"; do
  [[ "$archive" == /* && -f "$archive" && ! -L "$archive" ]] || fail "source archive must be an absolute regular file: $archive"
done
[[ "$(hash_of "$core_archive")" == ca52365d3d123a1cff34a5020ce16507e3c2ef1032d57f171b9c26d2cd97eb16 ]] || fail 'CLIProxyAPI source archive checksum mismatch'
[[ "$(hash_of "$policy_archive")" == e5b373279ee5f1c34f4e2ed2abc6d967d0b82bea8a924d74e9a62c0bdcabff44 ]] || fail 'cpa-key-policy source archive checksum mismatch'
[[ "$(hash_of "$third_party_root/patches/cliproxyapi-per-key-models.patch")" == 1e2b8331b049d83bf8f4fcb91aa679234b35ea4b650de14e637c119008ec9fda ]] || fail 'CLIProxyAPI model patch checksum mismatch'
[[ "$(hash_of "$third_party_root/patches/cpa-key-policy-0.4.4-state-concurrency.patch")" == 3d2d12b2febb34ad245d1ff042b6a68123d8c548ff90976f48d45b7352d8a4ab ]] || fail 'policy concurrency patch checksum mismatch'
[[ "$(hash_of "$third_party_root/patches/cpa-key-policy-0.4.5-linux-directory-fsync.patch")" == 7707fee5123c5311523b219f9a1e7b20911a399a756a25233f14154ef3339cfe ]] || fail 'policy Linux durability patch checksum mismatch'
[[ "$(hash_of "$third_party_root/patches/cliproxyapi-go1.26-hardening.patch")" == 49f48a11c3c9e704ec31198b02cc65c0eba163b14c2e2f2442c60d3d6247d529 ]] || fail 'CLIProxyAPI Go 1.26 hardening patch checksum mismatch'
[[ "$output_dir" == /* && "$output_dir" == "$(realpath -m -- "$output_dir")" ]] || fail 'output directory must be absolute and canonical'
[[ ! -e "$output_dir" && ! -L "$output_dir" ]] || fail "output already exists; refusing to overwrite: $output_dir"

mkdir -p -- "$repo_root/.tools/build"
work_dir="$(mktemp -d "$repo_root/.tools/build/cliproxyapi.XXXXXX")"
cleanup() {
  case "$work_dir" in
    "$repo_root"/.tools/build/cliproxyapi.*) rm -rf -- "$work_dir" ;;
    *) printf 'build-cliproxyapi-linux: refusing unsafe cleanup path: %s\n' "$work_dir" >&2 ;;
  esac
}
trap cleanup EXIT INT TERM

mkdir -p "$work_dir/core" "$work_dir/cpa"
tar --extract --gzip --file "$core_archive" --directory "$work_dir/core" --strip-components=1 --no-same-owner --no-same-permissions
tar --extract --gzip --file "$policy_archive" --directory "$work_dir/cpa" --no-same-owner --no-same-permissions
for source_root in "$work_dir/core" "$work_dir/cpa"; do
  if find "$source_root" \( -type l -o \( ! -type d ! -type f \) \) -print -quit | grep -q .; then
    fail "source archive contains a link or special file: $source_root"
  fi
done

patch --batch --forward -p1 -d "$work_dir/core" < "$third_party_root/patches/cliproxyapi-per-key-models.patch"
(cd "$work_dir/core" && GIT_CEILING_DIRECTORIES="$work_dir" \
  git apply --recount "$third_party_root/patches/cliproxyapi-go1.26-hardening.patch")

# The Windows-authored policy patch was recorded byte-for-byte. Its base files
# contain mixed CRLF, while its modified files are LF, so normalize only the six
# paths that patch changes before applying it.
for file in \
  internal/policy/config.go \
  internal/policy/store.go \
  internal/policy/store_test.go \
  internal/plugin/app.go \
  internal/plugin/app_test.go \
  internal/plugin/types.go; do
  sed -i 's/\r$//' "$work_dir/cpa/$file"
done

set +e
patch --batch --forward -p1 -d "$work_dir/cpa" --reject-file="$work_dir/policy-state.rej" \
  < "$third_party_root/patches/cpa-key-policy-0.4.4-state-concurrency.patch" \
  > "$work_dir/policy-state-patch.log" 2>&1
policy_patch_status=$?
set -e
[[ "$policy_patch_status" -eq 1 ]] || fail "policy provenance patch returned unexpected status $policy_patch_status"
[[ "$(grep -c '^@@' "$work_dir/policy-state.rej")" -eq 1 ]] || fail 'policy provenance patch did not produce exactly its known single reject'
[[ "$(grep -Fxc -- $'-\tf := &usageFlusher{stop: stop, stopCh: stopCh, store: s}' "$work_dir/policy-state.rej")" -eq 1 ]] || fail 'policy provenance reject old line mismatch'
[[ "$(grep -Fxc -- $'+\tf := &usageFlusher{stop: stop, stopCh: stopCh, doneCh: make(chan struct{}), store: s}' "$work_dir/policy-state.rej")" -eq 1 ]] || fail 'policy provenance reject new line mismatch'
store_file="$work_dir/cpa/internal/policy/store.go"
[[ "$(grep -Fxc -- $'\tf := &usageFlusher{stop: stop, stopCh: stopCh, store: s}' "$store_file")" -eq 1 ]] || fail 'policy source does not contain exactly one expected initializer'
[[ "$(grep -Fxc -- $'\tf := &usageFlusher{stop: stop, stopCh: stopCh, doneCh: make(chan struct{}), store: s}' "$store_file")" -eq 0 ]] || fail 'policy source unexpectedly contains the patched initializer already'
sed -i 's/f := &usageFlusher{stop: stop, stopCh: stopCh, store: s}/f := \&usageFlusher{stop: stop, stopCh: stopCh, doneCh: make(chan struct{}), store: s}/' "$store_file"

patch --batch --forward -p1 -d "$work_dir/cpa" < "$third_party_root/patches/cpa-key-policy-0.4.5-linux-directory-fsync.patch"
(cd "$work_dir" && sha256sum --strict --check "$component_root/PATCHED-FILES.sha256") >/dev/null

# Rebuild the single-file policy UI. The Windows reference differs only in CRLF
# bytes inside preserved license comments; normalized content must be exact.
embedded_web="$work_dir/cpa/internal/plugin/web/dist/index.html"
[[ "$(normalized_text_hash "$embedded_web")" == fcfaaa4fdf9044af332ac7e4494654e2496236d3df2c241fe2397938315d6364 ]] || fail 'embedded Windows policy UI normalized checksum mismatch'
(
  cd "$work_dir/cpa/web"
  "$npm_binary" ci --ignore-scripts --no-audit --no-fund
  "$npm_binary" test
  VITE_HOSTED=1 "$npm_binary" run build
)
rebuilt_web="$work_dir/cpa/web/dist/index.html"
[[ "$(normalized_text_hash "$rebuilt_web")" == fcfaaa4fdf9044af332ac7e4494654e2496236d3df2c241fe2397938315d6364 ]] || fail 'rebuilt policy UI does not match the normalized Windows reference'
install -m 0644 "$rebuilt_web" "$embedded_web"

export GOTOOLCHAIN=local
export GOFLAGS=-mod=readonly
(
  cd "$work_dir/cpa"
  "$go_binary" mod verify
  "$go_binary" test ./...
  "$go_binary" test -race ./internal/policy ./internal/plugin
  "$go_binary" vet ./...
)
(
  cd "$work_dir/core"
  "$go_binary" mod verify
  "$go_binary" test ./...
  "$go_binary" test -race ./sdk/api/handlers ./sdk/api/handlers/openai \
    ./internal/logging ./internal/api/middleware ./internal/pluginhost
  "$go_binary" vet ./...
)

stage="$work_dir/artifact"
install -d -m 0755 "$stage/bin" "$stage/plugins" "$stage/share/workagent-components/cliproxyapi"
(
  cd "$work_dir/core"
  CGO_ENABLED=1 GOOS=linux GOARCH=amd64 "$go_binary" build -trimpath -buildvcs=false \
    -ldflags='-s -w -buildid= -X main.Version=7.2.81 -X main.Commit=per-key-models.4 -X main.BuildDate=2026-07-16T14:32:00Z' \
    -o "$stage/bin/cli-proxy-api" ./cmd/server/
)
(
  cd "$work_dir/cpa"
  CGO_ENABLED=1 GOOS=linux GOARCH=amd64 "$go_binary" build -trimpath -buildvcs=false \
    -tags cshared -buildmode=c-shared -ldflags='-s -w -buildid=' \
    -o "$work_dir/cpa-key-policy-v0.4.5.so" ./cmd/cpa-key-policy
)
install -m 0755 "$work_dir/cpa-key-policy-v0.4.5.so" "$stage/plugins/cpa-key-policy-v0.4.5.so"
chmod 0755 "$stage/bin/cli-proxy-api" "$stage/plugins/cpa-key-policy-v0.4.5.so"
(cd "$stage" && sha256sum --strict --check "$component_root/LINUX-ARTIFACTS.sha256") >/dev/null

readelf -h "$stage/bin/cli-proxy-api" | grep -F 'Machine:' | grep -F 'Advanced Micro Devices X86-64' >/dev/null || fail 'CLIProxyAPI ELF architecture mismatch'
readelf -h "$stage/plugins/cpa-key-policy-v0.4.5.so" | grep -F 'Machine:' | grep -F 'Advanced Micro Devices X86-64' >/dev/null || fail 'policy plugin ELF architecture mismatch'
nm -D --defined-only "$stage/plugins/cpa-key-policy-v0.4.5.so" | grep -Eq '[[:space:]]cliproxy_plugin_init$' || fail 'policy plugin ABI entry point is missing'
ldd "$stage/bin/cli-proxy-api" | grep -F 'not found' && fail 'CLIProxyAPI has an unresolved shared library'
ldd "$stage/plugins/cpa-key-policy-v0.4.5.so" | grep -F 'not found' && fail 'policy plugin has an unresolved shared library'
"$stage/bin/cli-proxy-api" --help > "$work_dir/cliproxy-help" 2>&1
grep -F 'CLIProxyAPI Version: 7.2.81, Commit: per-key-models.4, BuiltAt: 2026-07-16T14:32:00Z' "$work_dir/cliproxy-help" >/dev/null || fail 'CLIProxyAPI embedded identity mismatch'
grep -F -- '-codex-login' "$work_dir/cliproxy-help" >/dev/null || fail 'CLIProxyAPI OAuth command smoke test failed'

install -m 0444 "$component_root/VERSION" "$component_root/SOURCE" "$component_root/INPUTS.sha256" \
  "$component_root/LINUX-ARTIFACTS.sha256" \
  "$component_root/PATCHED-FILES.sha256" "$third_party_root/SHA256SUMS.sources" \
  "$third_party_root/windows-candidate-manifest.json" "$work_dir/core/LICENSE" \
  "$stage/share/workagent-components/cliproxyapi/"
install -m 0444 "$work_dir/cpa/LICENSE" "$stage/share/workagent-components/cliproxyapi/cpa-key-policy.LICENSE"
printf '%s\n' \
  '{' \
  '  "schema_version": 1,' \
  '  "platform": "linux-amd64",' \
  '  "cliproxyapi_version": "7.2.81",' \
  '  "cliproxyapi_commit": "per-key-models.4",' \
  '  "cliproxyapi_build_date": "2026-07-16T14:32:00Z",' \
  '  "cpa_key_policy_version": "0.4.5",' \
  '  "cpa_key_policy_abi": 1,' \
  '  "go_version": "1.26.5",' \
  '  "node_version": "20.20.0",' \
  '  "npm_version": "10.8.2",' \
  "  \"gcc_version\": \"$(gcc -dumpfullversion)\"" \
  '}' > "$stage/share/workagent-components/cliproxyapi/BUILD-INFO.json"

find "$stage" -type f -exec chmod 0444 {} +
chmod 0555 "$stage/bin/cli-proxy-api" "$stage/plugins/cpa-key-policy-v0.4.5.so"
(cd "$stage" && find . -type f ! -path './share/workagent-components/cliproxyapi/SHA256SUMS' -print0 | \
  LC_ALL=C sort -z | xargs -0 sha256sum > share/workagent-components/cliproxyapi/SHA256SUMS)
chmod 0444 "$stage/share/workagent-components/cliproxyapi/SHA256SUMS"
find "$stage" -type d -exec chmod 0555 {} +

mkdir -p -- "$(dirname "$output_dir")"
mv -- "$stage" "$output_dir"
printf 'CLIProxyAPI Linux release: %s\n' "$output_dir"
sha256sum "$output_dir/bin/cli-proxy-api" "$output_dir/plugins/cpa-key-policy-v0.4.5.so"
